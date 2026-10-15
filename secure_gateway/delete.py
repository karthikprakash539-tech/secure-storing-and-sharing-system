from pathlib import Path

from flask import (
    Blueprint,
    current_app,
    flash,
    redirect,
    request,
    session,
    url_for,
)

from db import (
    execute_query,
    execute_transaction_insert,
    execute_transaction_update,
    get_transaction,
)
from secure_gateway.auth import login_required


delete_bp = Blueprint("delete", __name__)


def delete_encrypted_file(stored_filename):
    """
    Safely remove an encrypted file from the encrypted storage directory.

    The stored filename is never allowed to escape the configured
    encrypted directory.
    """

    if not stored_filename:
        raise ValueError("Stored filename is required.")

    encrypted_directory = Path(
        current_app.config["ENCRYPTED_FOLDER"]
    ).resolve()

    encrypted_path = (
        encrypted_directory / stored_filename
    ).resolve()

    if encrypted_path.parent != encrypted_directory:
        raise ValueError("Invalid encrypted file path.")

    if encrypted_path.exists():
        if not encrypted_path.is_file():
            raise ValueError("Encrypted storage path is not a regular file.")

        encrypted_path.unlink()

    return encrypted_path


@delete_bp.route("/delete/<int:file_id>", methods=["POST"])
@login_required
def delete_file(file_id):
    """
    Permanently delete a file owned by the authenticated user.

    Database operations are performed in one transaction:
        1. Remove shares.
        2. Remove encryption-key metadata.
        3. Preserve DELETE audit information.
        4. Remove the files row.

    Physical encrypted-file deletion happens after the database
    transaction commits because filesystem operations cannot
    participate in the MySQL transaction.
    """

    user_id = session["user_id"]

    file_record = execute_query(
        """
        SELECT
            id,
            user_id,
            stored_filename,
            original_filename
        FROM files
        WHERE id = %s
          AND user_id = %s
        LIMIT 1
        """,
        (file_id, user_id),
        fetchone=True,
    )

    if not file_record:
        flash(
            "File not found or you do not have permission to delete it.",
            "warning",
        )
        return redirect(url_for("dashboard.dashboard"))

    encrypted_path = None
    database_committed = False

    try:
        encrypted_directory = Path(
            current_app.config["ENCRYPTED_FOLDER"]
        ).resolve()

        encrypted_path = (
            encrypted_directory
            / file_record["stored_filename"]
        ).resolve()

        if encrypted_path.parent != encrypted_directory:
            raise ValueError("Invalid encrypted file path.")

        if encrypted_path.exists() and not encrypted_path.is_file():
            raise ValueError(
                "Encrypted storage path is not a regular file."
            )

        with get_transaction() as connection:

            # Remove any active/public share records.
            execute_transaction_update(
                connection,
                """
                DELETE FROM shared_files
                WHERE file_id = %s
                """,
                (file_id,),
            )

            # Remove encryption-key metadata.
            execute_transaction_update(
                connection,
                """
                DELETE FROM encryption_keys
                WHERE file_id = %s
                """,
                (file_id,),
            )

            # Preserve the original filename because the files row
            # will be deleted and file_id may become NULL through
            # the audit_logs foreign-key action.
            execute_transaction_insert(
                connection,
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
                    file_record["original_filename"][:255],
                    "DELETE",
                    request.remote_addr or "unknown",
                    request.headers.get(
                        "User-Agent",
                        "unknown",
                    )[:1000],
                ),
            )

            affected_rows = execute_transaction_update(
                connection,
                """
                DELETE FROM files
                WHERE id = %s
                  AND user_id = %s
                """,
                (file_id, user_id),
            )

            if affected_rows != 1:
                raise RuntimeError(
                    "The file database record could not be deleted."
                )

        database_committed = True

        # Filesystem deletion happens after the DB transaction.
        if encrypted_path.exists():
            encrypted_path.unlink()

        flash(
            f"File '{file_record['original_filename']}' deleted successfully.",
            "success",
        )

    except Exception:
        current_app.logger.exception(
            "Secure deletion failed for file_id=%s user_id=%s",
            file_id,
            user_id,
        )

        if database_committed and encrypted_path:
            current_app.logger.error(
                "Database deletion committed but physical encrypted "
                "file removal failed for file_id=%s",
                file_id,
            )

            flash(
                "The database record was removed, but the encrypted "
                "storage file could not be removed. Administrator "
                "cleanup is required.",
                "danger",
            )
        else:
            flash(
                "The file could not be securely deleted. "
                "No successful deletion was reported.",
                "danger",
            )

    return redirect(url_for("dashboard.dashboard"))