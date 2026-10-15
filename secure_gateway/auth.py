import logging
from functools import wraps

from flask import (
    Blueprint,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_wtf.csrf import generate_csrf
from werkzeug.security import (
    check_password_hash,
    generate_password_hash,
)

from db import execute_insert, execute_query
from secure_gateway.audit import (
    log_login,
    log_logout,
    log_register,
)


auth_bp = Blueprint("auth", __name__)

logger = logging.getLogger(__name__)


def login_required(view_function):
    """
    Protect a route so only authenticated users can access it.
    """

    @wraps(view_function)
    def wrapped_view(*args, **kwargs):
        if "user_id" not in session:
            flash(
                "Please log in to continue.",
                "warning",
            )
            return redirect(url_for("auth.login"))

        return view_function(*args, **kwargs)

    return wrapped_view


def validate_registration_input(
    full_name,
    email,
    password,
    confirm_password,
    security_question,
    security_answer,
):
    """
    Validate all registration fields.

    Returns:
        None when valid.
        A user-friendly error message when invalid.
    """

    if not full_name or len(full_name) < 2:
        return "Please enter your full name."

    if len(full_name) > 150:
        return "Full name is too long."

    if not email or "@" not in email:
        return "Please enter a valid email address."

    if len(email) > 255:
        return "Email address is too long."

    if not password or len(password) < 8:
        return "Password must contain at least 8 characters."

    if password != confirm_password:
        return "Passwords do not match."

    if not security_question:
        return "Please select a security question."

    if not security_answer or len(security_answer.strip()) < 2:
        return "Please provide an answer to the security question."

    return None


@auth_bp.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "GET":
        return render_template("register.html")

    full_name = request.form.get(
        "full_name",
        "",
    ).strip()

    email = request.form.get(
        "email",
        "",
    ).strip().lower()

    password = request.form.get(
        "password",
        "",
    )

    confirm_password = request.form.get(
        "confirm_password",
        "",
    )

    security_question = request.form.get(
        "security_question",
        "",
    ).strip()

    security_answer = request.form.get(
        "security_answer",
        "",
    ).strip()

    validation_error = validate_registration_input(
        full_name=full_name,
        email=email,
        password=password,
        confirm_password=confirm_password,
        security_question=security_question,
        security_answer=security_answer,
    )

    if validation_error:
        flash(
            validation_error,
            "danger",
        )
        return render_template("register.html")

    existing_user = execute_query(
        """
        SELECT id
        FROM users
        WHERE email = %s
        LIMIT 1
        """,
        (email,),
        fetchone=True,
    )

    if existing_user:
        flash(
            "An account with this email already exists.",
            "warning",
        )
        return render_template("register.html")

    password_hash = generate_password_hash(
        password,
        method="scrypt",
    )

    security_answer_hash = generate_password_hash(
        security_answer.lower(),
        method="scrypt",
    )

    try:
        user_id = execute_insert(
            """
            INSERT INTO users (
                full_name,
                email,
                password_hash,
                security_question,
                security_answer_hash
            )
            VALUES (%s, %s, %s, %s, %s)
            """,
            (
                full_name,
                email,
                password_hash,
                security_question,
                security_answer_hash,
            ),
        )
    except Exception:
        logger.exception(
            "Registration database operation failed for email=%s",
            email,
        )

        flash(
            "Unable to create your account right now. Please try again.",
            "danger",
        )

        return render_template("register.html")

    try:
        log_register(user_id)
    except Exception:
        logger.exception(
            "Registration audit logging failed for user_id=%s",
            user_id,
        )

    flash(
        "Account created successfully. Please log in.",
        "success",
    )

    return redirect(url_for("auth.login"))


@auth_bp.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "GET":
        return render_template("login.html")

    email = request.form.get(
        "email",
        "",
    ).strip().lower()

    password = request.form.get(
        "password",
        "",
    )

    if not email or not password:
        flash(
            "Email and password are required.",
            "danger",
        )
        return render_template("login.html")

    user = execute_query(
        """
        SELECT
            id,
            full_name,
            email,
            password_hash
        FROM users
        WHERE email = %s
        LIMIT 1
        """,
        (email,),
        fetchone=True,
    )

    if not user or not check_password_hash(
        user["password_hash"],
        password,
    ):
        flash(
            "Invalid email or password.",
            "danger",
        )
        return render_template("login.html")

    csrf_session_token = session.get("csrf_token")
    session.clear()
    if csrf_session_token:
        session["csrf_token"] = csrf_session_token

    session["user_id"] = user["id"]
    session["full_name"] = user["full_name"]
    session["email"] = user["email"]

    try:
        log_login(user["id"])
    except Exception:
        logger.exception(
            "Login audit logging failed for user_id=%s",
            user["id"],
        )

    flash(
        "Welcome back!",
        "success",
    )

    return redirect(url_for("dashboard.dashboard"))


@auth_bp.route("/logout", methods=["POST"])
@login_required
def logout():

    user_id = session.get("user_id")

    try:
        log_logout(user_id)
    except Exception:
        logger.exception(
            "Logout audit logging failed for user_id=%s",
            user_id,
        )

    session.clear()

    flash(
        "You have been logged out successfully.",
        "success",
    )

    return redirect(url_for("auth.login"))