import logging
from pathlib import Path

from config import Config

logger = logging.getLogger(__name__)


def scan_file(file_path):
    """
    Scan a file for malware.

    Returns a dictionary with an explicit status:
        safe
        infected
        scan_unavailable
        scan_error

    Security rule:
    scan_unavailable must never be treated as safe.
    """
    path = Path(file_path)

    if not path.exists() or not path.is_file():
        return {
            "status": "scan_error",
            "message": "The file to scan does not exist.",
        }

    if not Config.CLAMAV_ENABLED:
        logger.warning(
            "ClamAV scanning is disabled. File remains unverified: %s",
            path.name,
        )

        return {
            "status": "scan_unavailable",
            "message": "Malware scanning is currently unavailable.",
        }

    try:
        import clamd
    except ImportError:
        logger.error(
            "ClamAV scanning is enabled but the clamd Python package is unavailable."
        )

        return {
            "status": "scan_unavailable",
            "message": "The ClamAV scanning dependency is unavailable.",
        }

    try:
        scanner = clamd.ClamdNetworkSocket(
            host=Config.CLAMAV_HOST,
            port=Config.CLAMAV_PORT,
            timeout=10,
        )

        scanner.ping()

        with path.open("rb") as file_handle:
            scan_result = scanner.instream(file_handle)

        if not scan_result:
            logger.error("ClamAV returned an empty scan response.")
            return {
                "status": "scan_error",
                "message": "The malware scanner returned no result.",
            }

        result = scan_result.get("stream")

        if not result:
            logger.error(
                "Unexpected ClamAV response for file: %s",
                path.name,
            )

            return {
                "status": "scan_error",
                "message": "The malware scanner returned an invalid result.",
            }

        scan_status = result[0]
        scan_signature = result[1] if len(result) > 1 else None

        if scan_status == "FOUND":
            logger.warning(
                "ClamAV detected malware in file: %s",
                path.name,
            )

            return {
                "status": "infected",
                "message": "Malware was detected in the uploaded file.",
                "signature": scan_signature,
            }

        if scan_status == "OK":
            logger.info(
                "ClamAV scan completed successfully: %s",
                path.name,
            )

            return {
                "status": "safe",
                "message": "ClamAV completed the scan successfully.",
            }

        logger.error(
            "Unexpected ClamAV scan status '%s' for file: %s",
            scan_status,
            path.name,
        )

        return {
            "status": "scan_error",
            "message": "The malware scanner returned an unexpected result.",
        }

    except Exception:
        logger.exception(
            "ClamAV scan failed for file: %s",
            path.name,
        )

        return {
            "status": "scan_unavailable",
            "message": "The malware scanning service is unavailable.",
        }