from flask import Blueprint, render_template, session

from db import execute_query
from secure_gateway.auth import login_required


dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.route("/dashboard")
@login_required
def dashboard():
    """Display the authenticated user's dashboard."""

    user_id = session["user_id"]

    statistics = execute_query(
        """
        SELECT
            COUNT(*) AS total_files,
            COALESCE(
                SUM(CASE WHEN status = 'safe' THEN 1 ELSE 0 END),
                0
            ) AS safe_files,
            COALESCE(
                SUM(CASE WHEN status = 'encrypted' THEN 1 ELSE 0 END),
                0
            ) AS encrypted_files,
            COALESCE(
                SUM(CASE WHEN status = 'blocked' THEN 1 ELSE 0 END),
                0
            ) AS blocked_files
        FROM files
        WHERE user_id = %s
        """,
        (user_id,),
        fetchone=True,
    )

    files = execute_query(
        """
        SELECT
            id,
            original_filename,
            file_size,
            file_type,
            status,
            is_encrypted,
            encryption_algorithm,
            uploaded_at,
            updated_at
        FROM files
        WHERE user_id = %s
          AND status <> 'deleted'
        ORDER BY uploaded_at DESC
        """,
        (user_id,),
        fetchall=True,
    )

    shared_files = execute_query(
        """
        SELECT
            COUNT(*) AS total_shared
        FROM shared_files
        WHERE owner_id = %s
          AND revoked = FALSE
        """,
        (user_id,),
        fetchone=True,
    )

    return render_template(
        "dashboard.html",
        statistics=statistics,
        files=files,
        total_shared=shared_files["total_shared"],
    )