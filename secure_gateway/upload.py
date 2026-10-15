import logging
import uuid
from pathlib import Path

from flask import Blueprint, current_app, flash, redirect, request, session, url_for
from werkzeug.utils import secure_filename

from db import execute_insert, execute_update
from secure_gateway.audit import log_audit_event
from secure_gateway.auth import login_required
from secure_gateway.detection import scan_file
from secure_gateway.encryption import encrypt_file
from secure_gateway.key_management import store_protected_file_key
from secure_gateway.sensitive_detection import detect_sensitive_file


upload_bp = Blueprint("upload", __name__)
logger = logging.getLogger(__name__)


def get_extension(filename):
    """Return the lowercase extension without the leading dot."""
    return Path(filename).suffix.lower().lstrip(".")


def validate_uploaded_filename(filename):
    """Validate and sanitize an uploaded filename."""
    if not filename:
        raise ValueError("Please select a file.")

    sanitized_filename = secure_filename(filename)

    if not sanitized_filename:
        raise ValueError("The uploaded filename is invalid.")

    extension = get_extension(sanitized_filename)

    if not extension:
        raise ValueError("Files without an extension are not allowed.")

    if extension in current_app.config["BLOCKED_EXTENSIONS"]:
        raise ValueError(
            f"Files with the .{extension} extension are not allowed."
        )

    if extension not in current_app.config["ALLOWED_EXTENSIONS"]:
        raise ValueError(
            f"Files with the .{extension} extension are not supported."
        )

    return sanitized_filename, extension


def create_temporary_filename(extension):
    """Create a random temporary physical filename."""
    return f"{uuid.uuid4().hex}.{extension}"


def create_encrypted_filename():
    """Create a random encrypted storage filename."""
    return f"{uuid.uuid4().hex}.enc"


def cleanup_file(file_path):
    """Safely remove a physical file."""
    if not file_path:
        return

    path = Path(file_path)

    try:
        if path.exists():
            if path.is_file():
                path.unlink()
            else:
                logger.error(
                    "Cleanup target is not a regular file: %s",
                    path,
                )
    except OSError:
        logger.exception(
            "Unable to clean up file: %s",
            path,
        )


def update_file_status(
    file_id,
    status,
    is_encrypted=False,
    algorithm=None,
):
    """Update upload status and encryption metadata."""
    execute_update(
        """
        UPDATE files
        SET status=%s,
            is_encrypted=%s,
            encryption_algorithm=%s,
            updated_at=CURRENT_TIMESTAMP
        WHERE id=%s
        """,
        (
            status,
            is_encrypted,
            algorithm,
            file_id,
        ),
    )


@upload_bp.route("/upload", methods=["POST"])
@login_required
def upload_file():
    user_id = session["user_id"]

    temporary_path = None
    encrypted_path = None
    file_id = None

    try:
        uploaded_file = request.files.get("file")

        if uploaded_file is None:
            flash("Please select a file to upload.", "warning")
            return redirect(url_for("dashboard.dashboard"))

        original_filename, extension = validate_uploaded_filename(
            uploaded_file.filename
        )

        upload_directory = Path(
            current_app.config["UPLOAD_FOLDER"]
        ).resolve()

        encrypted_directory = Path(
            current_app.config["ENCRYPTED_FOLDER"]
        ).resolve()

        upload_directory.mkdir(
            parents=True,
            exist_ok=True,
        )

        encrypted_directory.mkdir(
            parents=True,
            exist_ok=True,
        )

        temporary_directory = (
            upload_directory / "temporary"
        ).resolve()

        temporary_directory.mkdir(
            parents=True,
            exist_ok=True,
        )

        temporary_path = (
            temporary_directory
            / create_temporary_filename(extension)
        ).resolve()

        encrypted_path = (
            encrypted_directory
            / create_encrypted_filename()
        ).resolve()

        if temporary_path.parent != temporary_directory:
            raise ValueError("Invalid temporary upload path.")

        if encrypted_path.parent != encrypted_directory:
            raise ValueError("Invalid encrypted storage path.")

        uploaded_file.save(temporary_path)

        if not temporary_path.exists() or not temporary_path.is_file():
            raise RuntimeError(
                "The uploaded file could not be stored."
            )

        file_size = temporary_path.stat().st_size

        if file_size <= 0:
            cleanup_file(temporary_path)
            temporary_path = None
            raise ValueError("Empty files are not allowed.")

        if file_size > current_app.config["MAX_FILE_SIZE"]:
            cleanup_file(temporary_path)
            temporary_path = None
            raise ValueError(
                "The uploaded file exceeds the maximum allowed size."
            )

        file_id = execute_insert(
            """
            INSERT INTO files (
                user_id,
                original_filename,
                stored_filename,
                file_size,
                file_type,
                status,
                is_encrypted,
                encryption_algorithm
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                user_id,
                original_filename[:255],
                encrypted_path.name,
                file_size,
                extension[:100],
                "pending",
                False,
                None,
            ),
        )

        # ---------------------------------------------------------
        # 1. Malware scanning
        # ---------------------------------------------------------
        scan_result = scan_file(temporary_path)
        scan_status = scan_result.get("status")

        log_audit_event(
            "SCAN",
            user_id=user_id,
            file_id=file_id,
            file_name=original_filename,
        )

        # ---------------------------------------------------------
        # 2. Explicit infected state
        # ---------------------------------------------------------
        if scan_status == "infected":
            update_file_status(
                file_id,
                "blocked",
                is_encrypted=False,
                algorithm=None,
            )

            log_audit_event(
                "BLOCK",
                user_id=user_id,
                file_id=file_id,
                file_name=original_filename,
            )

            cleanup_file(temporary_path)
            temporary_path = None

            flash(
                "The uploaded file was detected as unsafe and has been blocked.",
                "danger",
            )

            return redirect(url_for("dashboard.dashboard"))

        # ---------------------------------------------------------
        # 3. Explicit scanner failure
        # ---------------------------------------------------------
        if scan_status == "scan_error":
            update_file_status(
                file_id,
                "blocked",
                is_encrypted=False,
                algorithm=None,
            )

            cleanup_file(temporary_path)
            temporary_path = None

            flash(
                "The file could not be safely scanned and was not accepted.",
                "danger",
            )

            return redirect(url_for("dashboard.dashboard"))

        # ---------------------------------------------------------
        # 4. Sensitive-data detection
        # ---------------------------------------------------------
        sensitive_result = detect_sensitive_file(
            temporary_path
        )

        sensitive_count = sensitive_result.get(
            "total_matches",
            0,
        )

        if sensitive_count > 0:
            log_audit_event(
                "SENSITIVE_DATA_DETECTED",
                user_id=user_id,
                file_id=file_id,
                file_name=original_filename,
            )

        # ---------------------------------------------------------
        # 5. Encrypt only after the previous security checks
        # ---------------------------------------------------------
        encryption_result = encrypt_file(
            temporary_path,
            encrypted_path,
        )

        store_protected_file_key(
            file_id=file_id,
            protected_key=encryption_result["protected_key"],
            nonce=encryption_result["nonce"],
        )

        # ---------------------------------------------------------
        # 6. Determine final state explicitly
        # ---------------------------------------------------------
        if scan_status == "safe":
            final_status = "encrypted"

        elif scan_status == "scan_unavailable":
            final_status = "pending"

        else:
            raise RuntimeError(
                f"Unexpected malware scan status: {scan_status}"
            )

        update_file_status(
            file_id,
            final_status,
            is_encrypted=True,
            algorithm=encryption_result["algorithm"],
        )

        # ---------------------------------------------------------
        # 7. Audit successful upload/encryption
        # ---------------------------------------------------------
        log_audit_event(
            "UPLOAD",
            user_id=user_id,
            file_id=file_id,
            file_name=original_filename,
        )

        log_audit_event(
            "ENCRYPT",
            user_id=user_id,
            file_id=file_id,
            file_name=original_filename,
        )

        cleanup_file(temporary_path)
        temporary_path = None

        # ---------------------------------------------------------
        # 8. User-facing result
        # ---------------------------------------------------------
        if final_status == "encrypted":
            if sensitive_count > 0:
                flash(
                    "File uploaded, scanned, encrypted, and stored securely. "
                    "Sensitive-data patterns were detected.",
                    "warning",
                )
            else:
                flash(
                    "File uploaded, scanned, encrypted, and stored securely.",
                    "success",
                )

        else:
            flash(
                "File was encrypted and stored, but malware scanning "
                "was unavailable. It remains pending until a successful "
                "security scan is available.",
                "warning",
            )

    except ValueError as exc:
        cleanup_file(temporary_path)
        cleanup_file(encrypted_path)

        if file_id is not None:
            try:
                update_file_status(
                    file_id,
                    "blocked",
                    is_encrypted=False,
                    algorithm=None,
                )
            except Exception:
                logger.exception(
                    "Unable to mark invalid upload as blocked: file_id=%s",
                    file_id,
                )

        flash(str(exc), "danger")

    except Exception:
        logger.exception(
            "Secure upload failed for user_id=%s file_id=%s",
            user_id,
            file_id,
        )

        cleanup_file(temporary_path)
        cleanup_file(encrypted_path)

        if file_id is not None:
            try:
                update_file_status(
                    file_id,
                    "blocked",
                    is_encrypted=False,
                    algorithm=None,
                )
            except Exception:
                logger.exception(
                    "Unable to mark failed upload as blocked: file_id=%s",
                    file_id,
                )

        flash(
            "The file could not be uploaded securely. "
            "No successful upload was reported.",
            "danger",
        )

    return redirect(url_for("dashboard.dashboard"))