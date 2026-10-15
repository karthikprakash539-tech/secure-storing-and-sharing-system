
import hashlib
import secrets
import uuid
from pathlib import Path

from flask import (
    Blueprint,
    current_app,
    flash,
    render_template,
    request,
    send_file,
    session,
    url_for,
)

from db import (
    execute_insert,
    execute_query,
    execute_transaction_update,
    get_transaction,
)
from secure_gateway.audit import log_audit_event
from secure_gateway.auth import login_required
from secure_gateway.encryption import decrypt_file
from secure_gateway.key_management import get_file_key


sharing_bp = Blueprint("sharing", __name__)


# =========================================================
# SECURITY HELPERS
# =========================================================

def hash_share_token(token):
    """Hash the raw share token before storing or comparing it."""
    if not token:
        raise ValueError("Share token is required.")

    return hashlib.sha256(
        token.encode("utf-8")
    ).hexdigest()


def create_share_token():
    """Generate a cryptographically secure share token."""
    return secrets.token_urlsafe(32)


def create_temporary_share_path():
    """Create a random server-side temporary plaintext path."""
    temporary_directory = (
        Path(current_app.config["UPLOAD_FOLDER"])
        / "temporary_shared"
    )

    temporary_directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    return temporary_directory / (
        f"shared_{uuid.uuid4().hex}.tmp"
    )


def cleanup_temporary_file(file_path):
    """Safely remove a temporary plaintext file."""
    if not file_path:
        return

    try:
        path = Path(file_path)

        if path.exists() and path.is_file():
            path.unlink()

    except OSError as exc:
        current_app.logger.warning(
            "Temporary shared file cleanup failed: %s",
            exc,
        )


def is_share_expired(expires_at):
    """Check whether a share has expired."""
    if expires_at is None:
        return False

    from datetime import datetime, timezone

    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(
            tzinfo=timezone.utc
        )

    return expires_at <= datetime.now(timezone.utc)


# =========================================================
# CREATE SHARE
# =========================================================

@sharing_bp.route(
    "/share/<int:file_id>",
    methods=["POST"],
)
@login_required
def create_share(file_id):
    """Create a secure share link for an encrypted file."""

    user_id = session["user_id"]

    file_record = execute_query(
        """
        SELECT
            id,
            user_id,
            original_filename,
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
        return redirect_to_dashboard()

    if file_record["status"] != "encrypted":
        flash(
            "Only encrypted files can be shared.",
            "warning",
        )
        return redirect_to_dashboard()

    if not file_record["is_encrypted"]:
        flash(
            "This file does not have valid encryption metadata.",
            "danger",
        )
        return redirect_to_dashboard()

    if file_record["encryption_algorithm"] != "AES-256-GCM":
        flash(
            "This file uses an unsupported encryption configuration.",
            "danger",
        )
        return redirect_to_dashboard()

    # -----------------------------------------------------
    # Read sharing options
    # -----------------------------------------------------

    expires_in = request.form.get(
        "expires_in",
        "24",
    ).strip()

    max_downloads_value = request.form.get(
        "max_downloads",
        "",
    ).strip()

    # -----------------------------------------------------
    # Validate expiration
    # -----------------------------------------------------

    allowed_expiration_hours = {
        "1": 1,
        "6": 6,
        "24": 24,
        "72": 72,
        "168": 168,
        "never": None,
    }

    if expires_in not in allowed_expiration_hours:
        flash(
            "Invalid share expiration option.",
            "danger",
        )
        return redirect_to_dashboard()

    expiration_hours = allowed_expiration_hours[
        expires_in
    ]

    # -----------------------------------------------------
    # Validate maximum downloads
    # -----------------------------------------------------

    max_downloads = None

    if max_downloads_value:
        try:
            max_downloads = int(
                max_downloads_value
            )
        except ValueError:
            flash(
                "Maximum downloads must be a valid number.",
                "danger",
            )
            return redirect_to_dashboard()

        if not 1 <= max_downloads <= 10000:
            flash(
                "Maximum downloads must be between 1 and 10000.",
                "danger",
            )
            return redirect_to_dashboard()

    # -----------------------------------------------------
    # Generate secure token
    # -----------------------------------------------------

    raw_token = create_share_token()
    token_hash = hash_share_token(raw_token)

    # -----------------------------------------------------
    # Calculate expiration in UTC
    # -----------------------------------------------------

    expires_at = None

    if expiration_hours is not None:
        from datetime import datetime, timedelta, timezone

        expires_at = (
            datetime.now(timezone.utc)
            + timedelta(hours=expiration_hours)
        ).replace(tzinfo=None)

    # -----------------------------------------------------
    # Store only token hash
    # -----------------------------------------------------

    try:
        share_id = execute_insert(
            """
            INSERT INTO shared_files (
                file_id,
                owner_id,
                share_token_hash,
                expires_at,
                max_downloads,
                download_count,
                revoked
            )
            VALUES (%s, %s, %s, %s, %s, 0, 0)
            """,
            (
                file_id,
                user_id,
                token_hash,
                expires_at,
                max_downloads,
            ),
        )

    except Exception:
        current_app.logger.exception(
            "Share creation failed for file_id=%s",
            file_id,
        )

        flash(
            "The secure share could not be created.",
            "danger",
        )
        return redirect_to_dashboard()

    # -----------------------------------------------------
    # Audit share creation
    # -----------------------------------------------------

    try:
        log_audit_event(
            action="SHARE_CREATE",
            user_id=user_id,
            file_id=file_id,
            file_name=file_record["original_filename"],
        )

    except Exception:
        current_app.logger.exception(
            "Share audit logging failed for share_id=%s",
            share_id,
        )

        flash(
            "The share was created, but audit logging failed.",
            "danger",
        )
        return redirect_to_dashboard()

    # -----------------------------------------------------
    # Build share URL
    # -----------------------------------------------------

    share_url = url_for(
        "sharing.access_shared_file",
        token=raw_token,
        _external=True,
    )

    # The raw token is returned to the owner only.
    return render_template(
        "share.html",
        share_url=share_url,
        file_name=file_record["original_filename"],
        expires_at=expires_at,
        max_downloads=max_downloads,
    )


def redirect_to_dashboard():
    """Redirect to the existing dashboard endpoint."""
    from flask import redirect

    return redirect(
        url_for("dashboard.dashboard")
    )


# =========================================================
# ACCESS SHARED FILE
# =========================================================

@sharing_bp.route(
    "/shared/<token>",
    methods=["GET", "POST"],
)
def access_shared_file(token):
    """
    GET:
        Display the download page without consuming a download.

    POST:
        Decrypt the file, reserve one download slot atomically,
        and send the file.

    Authentication is not required for a valid share link.
    """

    def show_error(message, status_code):
        return render_template(
            "error.html",
            status_code=status_code,
            message=message,
        ), status_code

    if not token:
        return show_error(
            "Invalid share link.",
            400,
        )

    token_hash = hash_share_token(token)

    def get_share_record():
        return execute_query(
            """
            SELECT
                sf.id,
                sf.file_id,
                sf.owner_id,
                sf.expires_at,
                sf.max_downloads,
                sf.download_count,
                sf.revoked,
                f.original_filename,
                f.stored_filename,
                f.status,
                f.is_encrypted,
                f.encryption_algorithm
            FROM shared_files sf
            INNER JOIN files f
                ON f.id = sf.file_id
            WHERE sf.share_token_hash = %s
            LIMIT 1
            """,
            (token_hash,),
            fetchone=True,
        )

    # -----------------------------------------------------
    # Look up the share
    # -----------------------------------------------------

    try:
        share_record = get_share_record()
    except Exception:
        current_app.logger.exception(
            "Shared link lookup failed."
        )
        return show_error(
            "The shared link could not be checked. Please try again.",
            500,
        )

    if not share_record:
        return show_error(
            "This share link is invalid or no longer available.",
            404,
        )

    # -----------------------------------------------------
    # Validate share status
    # -----------------------------------------------------

    if share_record["revoked"]:
        return show_error(
            "This share link has been revoked.",
            403,
        )

    if is_share_expired(share_record["expires_at"]):
        return show_error(
            "This share link has expired.",
            410,
        )

    max_downloads = share_record["max_downloads"]
    download_count = share_record["download_count"]

    if (
        max_downloads is not None
        and download_count >= max_downloads
    ):
        return show_error(
            "This share link has reached its download limit.",
            410,
        )

    if share_record["status"] != "encrypted":
        return show_error(
            "This file is not currently available for sharing.",
            403,
        )

    if not share_record["is_encrypted"]:
        return show_error(
            "This file does not have valid encryption metadata.",
            403,
        )

    if share_record["encryption_algorithm"] != "AES-256-GCM":
        return show_error(
            "This file uses an unsupported encryption configuration.",
            403,
        )

    # -----------------------------------------------------
    # GET: Render download page only.
    # No decryption and no counter increment.
    # -----------------------------------------------------

    if request.method == "GET":
        return render_template(
            "shared_download.html",
            token=token,
            file_name=share_record["original_filename"],
            downloads_remaining=(
                None
                if max_downloads is None
                else max_downloads - download_count
            ),
        )

    # -----------------------------------------------------
    # POST: Validate encrypted file location
    # -----------------------------------------------------

    encrypted_directory = Path(
        current_app.config["ENCRYPTED_FOLDER"]
    ).resolve()

    encrypted_path = (
        encrypted_directory
        / str(share_record["stored_filename"])
    ).resolve()

    # Prevent a stored filename from escaping its directory.
    if encrypted_path.parent != encrypted_directory:
        current_app.logger.error(
            "Unsafe stored filename for file_id=%s",
            share_record["file_id"],
        )
        return show_error(
            "The shared file is currently unavailable.",
            404,
        )

    if not encrypted_path.is_file():
        current_app.logger.error(
            "Encrypted shared file missing for file_id=%s",
            share_record["file_id"],
        )
        return show_error(
            "The shared file is currently unavailable.",
            404,
        )

    # -----------------------------------------------------
    # Decrypt to a temporary path
    # -----------------------------------------------------

    temporary_path = None

    try:
        key_metadata = get_file_key(
            share_record["file_id"]
        )

        temporary_path = create_temporary_share_path()

        decrypt_file(
            encrypted_path=encrypted_path,
            output_path=temporary_path,
            file_key=key_metadata["file_key"],
            nonce_encoded=key_metadata["nonce"],
        )

        if not Path(temporary_path).is_file():
            raise RuntimeError(
                "Decryption did not produce an output file."
            )

    except Exception:
        cleanup_temporary_file(temporary_path)

        current_app.logger.exception(
            "Shared file decryption failed for file_id=%s",
            share_record["file_id"],
        )

        return show_error(
            "The shared file could not be securely prepared.",
            500,
        )

    # -----------------------------------------------------
    # Atomically reserve one download slot
    # -----------------------------------------------------

    try:
        with get_transaction() as connection:
            updated = execute_transaction_update(
                connection,
                """
                UPDATE shared_files
                SET download_count = download_count + 1
                WHERE id = %s
                  AND revoked = 0
                  AND (
                      expires_at IS NULL
                      OR expires_at > UTC_TIMESTAMP()
                  )
                  AND (
                      max_downloads IS NULL
                      OR download_count < max_downloads
                  )
                """,
                (share_record["id"],),
            )

            if updated != 1:
                cleanup_temporary_file(temporary_path)

                # Recheck to return the correct error.
                latest = get_share_record()

                if latest and latest["revoked"]:
                    return show_error(
                        "This share link has been revoked.",
                        403,
                    )

                if latest and is_share_expired(
                    latest["expires_at"]
                ):
                    return show_error(
                        "This share link has expired.",
                        410,
                    )

                return show_error(
                    "This share link has reached its download limit or is no longer available.",
                    410,
                )

    except Exception:
        cleanup_temporary_file(temporary_path)

        current_app.logger.exception(
            "Download counter update failed for share_id=%s",
            share_record["id"],
        )

        return show_error(
            "The shared download could not be completed.",
            500,
        )

    # -----------------------------------------------------
    # Audit accepted download
    # -----------------------------------------------------

    try:
        log_audit_event(
            action="SHARE_ACCESS",
            user_id=None,
            file_id=share_record["file_id"],
            file_name=share_record["original_filename"],
        )

    except Exception:
        cleanup_temporary_file(temporary_path)

        current_app.logger.exception(
            "Shared access audit failed for share_id=%s",
            share_record["id"],
        )

        return show_error(
            "The shared download could not be completed.",
            500,
        )

    # -----------------------------------------------------
    # Send decrypted file
    # -----------------------------------------------------

    try:
        response = send_file(
            temporary_path,
            as_attachment=True,
            download_name=share_record["original_filename"],
            mimetype="application/octet-stream",
        )

        @response.call_on_close
        def remove_temporary_file():
            cleanup_temporary_file(temporary_path)

        return response

    except Exception:
        cleanup_temporary_file(temporary_path)

        current_app.logger.exception(
            "Sending shared file failed for share_id=%s",
            share_record["id"],
        )

        return show_error(
            "The shared download could not be sent.",
            500,
        )


# =========================================================
# REVOKE SHARE
# =========================================================

@sharing_bp.route(
    "/share/<int:file_id>/revoke",
    methods=["POST"],
)
@login_required
def revoke_share(file_id):
    """Revoke all active share links for an owned file."""

    user_id = session["user_id"]

    file_record = execute_query(
        """
        SELECT
            id,
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
            "The requested file was not found or you do not have access to it.",
            "danger",
        )
        return redirect_to_dashboard()

    try:
        with get_transaction() as connection:
            execute_transaction_update(
                connection,
                """
                UPDATE shared_files
                SET revoked = 1
                WHERE file_id = %s
                  AND owner_id = %s
                  AND revoked = 0
                """,
                (
                    file_id,
                    user_id,
                ),
            )

    except Exception:
        current_app.logger.exception(
            "Share revocation failed for file_id=%s",
            file_id,
        )

        flash(
            "The share could not be revoked.",
            "danger",
        )
        return redirect_to_dashboard()

    try:
        log_audit_event(
            action="SHARE_REVOKE",
            user_id=user_id,
            file_id=file_id,
            file_name=file_record["original_filename"],
        )

    except Exception:
        current_app.logger.exception(
            "Share revoke audit failed for file_id=%s",
            file_id,
        )

        flash(
            "The share was revoked, but audit logging failed.",
            "danger",
        )
        return redirect_to_dashboard()

    flash(
        "All active share links for this file have been revoked.",
        "success",
    )

    return redirect_to_dashboard()
