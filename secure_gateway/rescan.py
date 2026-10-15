import logging
import uuid
from pathlib import Path

from flask import Blueprint, current_app, flash, redirect, request, session, url_for

from db import (
    execute_query,
    execute_transaction_update,
    get_transaction,
)
from secure_gateway.audit import log_audit_event
from secure_gateway.auth import login_required
from secure_gateway.detection import scan_file
from secure_gateway.encryption import decrypt_file
from secure_gateway.key_management import get_file_key


rescan_bp = Blueprint("rescan", __name__)

logger = logging.getLogger(__name__)


def create_rescan_temporary_path():
    """
    Create a temporary location for decrypting a pending encrypted file.

    The plaintext file exists only for the duration of the malware scan.
    """
    temporary_directory = (
        Path(current_app.config["UPLOAD_FOLDER"])
        / "temporary_rescan"
    )

    temporary_directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    temporary_name = f"rescan_{uuid.uuid4().hex}.tmp"

    return temporary_directory / temporary_name


def cleanup_temporary_file(file_path):
    """Safely remove a temporary plaintext file."""
    if not file_path:
        return

    try:
        path = Path(file_path)

        if path.exists() and path.is_file():
            path.unlink()

    except OSError as exc:
        logger.warning(
            "Temporary rescan file cleanup failed: %s",
            exc,
        )


def rescan_pending_file(file_id, user_id):
    """
    Decrypt an encrypted pending file temporarily, scan it with VirusTotal,
    and update its status.

    The encrypted file is never replaced.

    Returns:
        dict:
            status
            message
            file_name
    """

    file_record = None
    temporary_path = None

    try:
        # ---------------------------------------------------------
        # 1. Verify ownership and retrieve file metadata
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
            return {
                "status": "not_found",
                "message": "File not found or access denied.",
                "file_name": None,
            }

        file_name = file_record["original_filename"]

        # ---------------------------------------------------------
        # 2. Only pending files can be rescanned
        # ---------------------------------------------------------
        if file_record["status"] != "pending":
            return {
                "status": "invalid_status",
                "message": "Only pending files can be rescanned.",
                "file_name": file_name,
            }

        if not file_record["is_encrypted"]:
            return {
                "status": "invalid_file",
                "message": "The pending file is not encrypted.",
                "file_name": file_name,
            }

        if file_record["encryption_algorithm"] != "AES-256-GCM":
            return {
                "status": "invalid_encryption",
                "message": (
                    "The file uses an unsupported encryption algorithm."
                ),
                "file_name": file_name,
            }

        # ---------------------------------------------------------
        # 3. Resolve encrypted physical path safely
        # ---------------------------------------------------------
        encrypted_directory = Path(
            current_app.config["ENCRYPTED_FOLDER"]
        ).resolve()

        encrypted_path = (
            encrypted_directory / file_record["stored_filename"]
        ).resolve()

        try:
            encrypted_path.relative_to(encrypted_directory)
        except ValueError:
            logger.error(
                "Unsafe encrypted file path detected for file ID %s.",
                file_id,
            )

            return {
                "status": "invalid_path",
                "message": "The file could not be accessed safely.",
                "file_name": file_name,
            }

        if not encrypted_path.exists() or not encrypted_path.is_file():
            logger.error(
                "Encrypted file missing for file ID %s.",
                file_id,
            )

            return {
                "status": "missing_file",
                "message": (
                    "The encrypted file is missing from secure storage."
                ),
                "file_name": file_name,
            }

        # ---------------------------------------------------------
        # 4. Recover existing key and nonce
        # ---------------------------------------------------------
        key_metadata = get_file_key(file_id)

        # ---------------------------------------------------------
        # 5. Create temporary plaintext
        # ---------------------------------------------------------
        temporary_path = create_rescan_temporary_path()

        decrypt_file(
            encrypted_path=encrypted_path,
            output_path=temporary_path,
            file_key=key_metadata["file_key"],
            nonce_encoded=key_metadata["nonce"],
        )

        # ---------------------------------------------------------
        # 6. Submit plaintext for VirusTotal analysis
        # ---------------------------------------------------------
        scan_result = scan_file(temporary_path)

        scan_status = scan_result.get("status")

        log_audit_event(
            action="SCAN",
            user_id=user_id,
            file_id=file_id,
            file_name=file_name,
        )

        # ---------------------------------------------------------
        # 7. Malware detected
        # ---------------------------------------------------------
        if scan_status == "infected":
            cleanup_temporary_file(temporary_path)
            temporary_path = None

            with get_transaction() as connection:
                execute_transaction_update(
                    connection,
                    """
                    UPDATE files
                    SET
                        status = 'blocked',
                        updated_at = CURRENT_TIMESTAMP
                    WHERE id = %s
                      AND user_id = %s
                    """,
                    (file_id, user_id),
                )

                execute_transaction_update(
                    connection,
                    """
                    UPDATE shared_files
                    SET revoked = 1
                    WHERE file_id = %s
                      AND owner_id = %s
                    """,
                    (file_id, user_id),
                )

            log_audit_event(
                action="BLOCK",
                user_id=user_id,
                file_id=file_id,
                file_name=file_name,
            )

            return {
                "status": "infected",
                "message": (
                    "The file was blocked because malware was detected."
                ),
                "file_name": file_name,
            }

        # ---------------------------------------------------------
        # 8. Scanner unavailable/error
        # ---------------------------------------------------------
        if scan_status in {
            "scan_unavailable",
            "scan_error",
        }:
            return {
                "status": scan_status,
                "message": (
                    "The malware scan could not be completed. "
                    "The file remains pending."
                ),
                "file_name": file_name,
            }

        # ---------------------------------------------------------
        # 9. Safe
        # ---------------------------------------------------------
        if scan_status == "safe":
            with get_transaction() as connection:
                execute_transaction_update(
                    connection,
                    """
                    UPDATE files
                    SET
                        status = 'encrypted',
                        is_encrypted = 1,
                        encryption_algorithm = 'AES-256-GCM',
                        updated_at = CURRENT_TIMESTAMP
                    WHERE id = %s
                      AND user_id = %s
                      AND status = 'pending'
                    """,
                    (file_id, user_id),
                )

            return {
                "status": "safe",
                "message": (
                    "Malware scan completed successfully. "
                    "The file is now available for secure download."
                ),
                "file_name": file_name,
            }

        # ---------------------------------------------------------
        # 10. Unexpected scanner response
        # ---------------------------------------------------------
        logger.error(
            "Unexpected VirusTotal scan status '%s' for file ID %s.",
            scan_status,
            file_id,
        )

        return {
            "status": "scan_error",
            "message": (
                "The malware scan returned an unexpected result."
            ),
            "file_name": file_name,
        }

    except Exception:
        logger.exception(
            "Pending-file rescan failed for file ID %s.",
            file_id,
        )

        return {
            "status": "error",
            "message": "The file could not be rescanned safely.",
            "file_name": (
                file_record["original_filename"]
                if file_record
                else None
            ),
        }

    finally:
        # Never leave decrypted plaintext behind.
        cleanup_temporary_file(temporary_path)


@rescan_bp.route(
    "/rescan/<int:file_id>",
    methods=["POST"],
)
@login_required
def rescan_file(file_id):
    """
    Authenticated owner-only endpoint for rescanning a pending file.
    """

    user_id = session["user_id"]

    if request.form.get("virustotal_consent") != "yes":
        flash(
            "Confirm that the decrypted file may be submitted to VirusTotal. "
            "Submitted files may be shared with its security community.",
            "warning",
        )
        return redirect(url_for("dashboard.dashboard"))

    result = rescan_pending_file(
        file_id=file_id,
        user_id=user_id,
    )

    status = result["status"]

    if status == "safe":
        flash(
            result["message"],
            "success",
        )

    elif status == "infected":
        flash(
            result["message"],
            "danger",
        )

    elif status in {
        "scan_unavailable",
        "scan_error",
    }:
        flash(
            result["message"],
            "warning",
        )

    else:
        flash(
            result["message"],
            "danger",
        )

    return redirect(url_for("dashboard.dashboard"))