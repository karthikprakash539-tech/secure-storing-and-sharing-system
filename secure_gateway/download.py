import mimetypes
import uuid
from pathlib import Path

from flask import (
    Blueprint,
    current_app,
    flash,
    redirect,
    send_file,
    session,
    url_for,
)

from db import execute_query
from secure_gateway.audit import log_audit_event
from secure_gateway.auth import login_required
from secure_gateway.encryption import decrypt_file
from secure_gateway.key_management import get_file_key


download_bp = Blueprint("download", __name__)


def create_temporary_decryption_path():
    """
    Create a random server-side path for temporary plaintext output.

    The original filename is never used as a physical server path.
    """

    temp_name = f"download_{uuid.uuid4().hex}.tmp"

    temp_directory = (
        Path(current_app.config["UPLOAD_FOLDER"])
        / "temporary"
    )

    temp_directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    return temp_directory / temp_name


def cleanup_temporary_file(file_path):
    """
    Remove a temporary decrypted file if it exists.
    """

    if not file_path:
        return

    try:
        path = Path(file_path)

        if path.exists() and path.is_file():
            path.unlink()

    except OSError as exc:
        current_app.logger.warning(
            "Temporary decrypted file cleanup failed: %s",
            exc,
        )


@download_bp.route(
    "/download/<int:file_id>",
    methods=["GET"],
)
@login_required
def download_file(file_id):
    """
    Securely decrypt and download an encrypted file.

    Security checks:
        1. User must be authenticated.
        2. User must own the requested file.
        3. File must have encrypted status.
        4. File must use AES-256-GCM.
        5. Encrypted physical file must exist.
        6. Encryption metadata must exist.
        7. AES-256-GCM authentication must succeed.

    Audit events:
        - DECRYPT after successful decryption.
        - DOWNLOAD after successful download preparation.

    The decrypted plaintext exists only temporarily on the server
    and is removed after the response is closed.
    """

    user_id = session["user_id"]

    # ---------------------------------------------------------
    # 1. Authenticate + ownership check
    # ---------------------------------------------------------

    file_record = execute_query(
        """
        SELECT
            id,
            user_id,
            original_filename,
            stored_filename,
            status,
            is_encrypted,
            encryption_algorithm
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
            "The requested file was not found or you do not have access to it.",
            "danger",
        )

        return redirect(
            url_for("dashboard.dashboard")
        )

    file_name = file_record["original_filename"]

    # ---------------------------------------------------------
    # 2. Security status check
    # ---------------------------------------------------------

    if file_record["status"] != "encrypted":
        flash(
            "This file is not currently cleared for download.",
            "warning",
        )

        return redirect(
            url_for("dashboard.dashboard")
        )

    # ---------------------------------------------------------
    # 3. Encryption validation
    # ---------------------------------------------------------

    if not file_record["is_encrypted"]:
        flash(
            "This file does not have valid encryption metadata.",
            "danger",
        )

        return redirect(
            url_for("dashboard.dashboard")
        )

    if file_record["encryption_algorithm"] != "AES-256-GCM":
        flash(
            "This file uses an unsupported encryption configuration.",
            "danger",
        )

        return redirect(
            url_for("dashboard.dashboard")
        )

    # ---------------------------------------------------------
    # 4. Build encrypted physical path
    # ---------------------------------------------------------

    encrypted_directory = Path(
        current_app.config["ENCRYPTED_FOLDER"]
    )

    encrypted_path = (
        encrypted_directory
        / file_record["stored_filename"]
    )

    if (
        not encrypted_path.exists()
        or not encrypted_path.is_file()
    ):
        current_app.logger.error(
            "Encrypted file missing for file_id=%s",
            file_id,
        )

        flash(
            "The encrypted file is unavailable.",
            "danger",
        )

        return redirect(
            url_for("dashboard.dashboard")
        )

    temporary_path = None

    try:
        # -----------------------------------------------------
        # 5. Recover AES-256 key + nonce
        # -----------------------------------------------------

        key_metadata = get_file_key(file_id)

        # -----------------------------------------------------
        # 6. Create random temporary plaintext path
        # -----------------------------------------------------

        temporary_path = create_temporary_decryption_path()

        # -----------------------------------------------------
        # 7. AES-256-GCM decryption
        # -----------------------------------------------------

        decrypt_file(
            encrypted_path=encrypted_path,
            output_path=temporary_path,
            file_key=key_metadata["file_key"],
            nonce_encoded=key_metadata["nonce"],
        )

    except Exception:
        cleanup_temporary_file(
            temporary_path
        )

        current_app.logger.exception(
            "File decryption failed for file_id=%s",
            file_id,
        )

        flash(
            "The file could not be decrypted securely.",
            "danger",
        )

        return redirect(
            url_for("dashboard.dashboard")
        )

    # ---------------------------------------------------------
    # 8. Audit successful decryption
    # ---------------------------------------------------------

    try:
        log_audit_event(
            action="DECRYPT",
            user_id=user_id,
            file_id=file_id,
            file_name=file_name,
        )

    except Exception:
        cleanup_temporary_file(
            temporary_path
        )

        current_app.logger.exception(
            "Decryption audit logging failed for file_id=%s",
            file_id,
        )

        flash(
            "The download could not be completed.",
            "danger",
        )

        return redirect(
            url_for("dashboard.dashboard")
        )

    # ---------------------------------------------------------
    # 9. Audit successful download preparation
    # ---------------------------------------------------------

    try:
        log_audit_event(
            action="DOWNLOAD",
            user_id=user_id,
            file_id=file_id,
            file_name=file_name,
        )

    except Exception:
        cleanup_temporary_file(
            temporary_path
        )

        current_app.logger.exception(
            "Download audit logging failed for file_id=%s",
            file_id,
        )

        flash(
            "The download could not be completed.",
            "danger",
        )

        return redirect(
            url_for("dashboard.dashboard")
        )

    # ---------------------------------------------------------
    # 10. Send decrypted file to authenticated owner
    # ---------------------------------------------------------

    response = send_file(
        temporary_path,
        as_attachment=True,
        download_name=file_name,
        mimetype="application/octet-stream",
    )

    # ---------------------------------------------------------
    # 11. Delete temporary plaintext after response
    # ---------------------------------------------------------

    @response.call_on_close
    def remove_temporary_file():
        cleanup_temporary_file(
            temporary_path
        )

    return response