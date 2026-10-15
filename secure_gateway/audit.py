from flask import request, session

from db import execute_insert


def get_client_ip():
    """
    Return the client's direct remote IP address.

    We intentionally do not trust arbitrary forwarded headers.
    """
    return request.remote_addr or "unknown"


def get_user_agent():
    """
    Return the browser/client user-agent.

    The value is limited before database storage.
    """
    user_agent = request.headers.get("User-Agent", "")
    return user_agent[:1000] if user_agent else "unknown"


def get_current_user_id():
    """
    Return the currently authenticated user ID, if available.
    """
    return session.get("user_id")


def log_audit_event(
    action,
    user_id=None,
    file_id=None,
    file_name=None,
):
    """
    Store a security-related event in the audit_logs table.

    file_id is linked to the files table and may become NULL after
    the referenced file is permanently deleted.

    file_name is an optional immutable snapshot of the original
    filename, allowing important audit events such as DELETE to
    remain understandable after the files row is removed.

    Never store:
    - passwords
    - encryption keys
    - raw share tokens
    - security answers
    - full sensitive-data values
    """

    if not action:
        raise ValueError("Audit action is required.")

    if user_id is None:
        user_id = get_current_user_id()

    if file_name is not None:
        file_name = str(file_name)[:255]

    execute_insert(
        """
        INSERT INTO audit_logs (
            user_id,
            file_id,
            file_name,
            action,
            ip_address,
            user_agent
        )
        VALUES (%s, %s, %s, %s, %s, %s)
        """,
        (
            user_id,
            file_id,
            file_name,
            action[:50],
            get_client_ip(),
            get_user_agent(),
        ),
    )


def log_login(user_id):
    """Record a successful login."""
    log_audit_event(
        action="LOGIN",
        user_id=user_id,
    )


def log_logout(user_id=None):
    """Record a logout event."""
    log_audit_event(
        action="LOGOUT",
        user_id=user_id,
    )


def log_register(user_id):
    """Record a successful registration."""
    log_audit_event(
        action="REGISTER",
        user_id=user_id,
    )