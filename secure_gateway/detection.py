import logging
import time
from pathlib import Path

import httpx

from config import Config

logger = logging.getLogger(__name__)

VIRUSTOTAL_API_URL = "https://www.virustotal.com/api/v3"
DIRECT_UPLOAD_LIMIT = 32 * 1024 * 1024
ANALYSIS_POLL_INTERVAL_SECONDS = 15
MAX_ANALYSIS_POLLS = 2


def _scan_result_from_analysis(attributes):
    if attributes.get("status") != "completed":
        return None

    stats = attributes.get("stats")

    if not isinstance(stats, dict):
        return {
            "status": "scan_error",
            "message": "VirusTotal returned an invalid analysis result.",
        }

    try:
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        assessed = sum(
            int(stats.get(category, 0))
            for category in ("malicious", "suspicious", "harmless", "undetected")
        )
    except (TypeError, ValueError):
        return {
            "status": "scan_error",
            "message": "VirusTotal returned invalid analysis statistics.",
        }

    if malicious > 0 or suspicious > 0:
        return {
            "status": "infected",
            "message": "VirusTotal detected malicious or suspicious content.",
            "malicious": malicious,
            "suspicious": suspicious,
        }

    if assessed == 0:
        return {
            "status": "scan_error",
            "message": "VirusTotal did not return a conclusive scan result.",
        }

    return {
        "status": "safe",
        "message": "VirusTotal completed the scan without detections.",
        "malicious": 0,
        "suspicious": 0,
    }


def _analysis_id(response):
    response.raise_for_status()
    data = response.json().get("data", {})
    analysis_id = data.get("id")

    if not isinstance(analysis_id, str) or not analysis_id:
        raise ValueError("VirusTotal did not return an analysis ID.")

    return analysis_id


def _upload_url(client, file_size):
    if file_size <= DIRECT_UPLOAD_LIMIT:
        return f"{VIRUSTOTAL_API_URL}/files"

    response = client.get(f"{VIRUSTOTAL_API_URL}/files/upload_url")
    response.raise_for_status()
    upload_url = response.json().get("data")

    if not isinstance(upload_url, str) or not upload_url.startswith("https://"):
        raise ValueError("VirusTotal returned an invalid large-file upload URL.")

    return upload_url


def scan_file(file_path):
    """Submit a file to VirusTotal and return a fail-closed scan status."""
    path = Path(file_path)

    if not path.exists() or not path.is_file():
        return {
            "status": "scan_error",
            "message": "The file to scan does not exist.",
        }

    api_key = Config.VIRUSTOTAL_API_KEY

    if not api_key:
        logger.warning(
            "VirusTotal scanning is unavailable because its API key is not configured."
        )
        return {
            "status": "scan_unavailable",
            "message": "VirusTotal scanning is not configured.",
        }

    headers = {"x-apikey": api_key}

    try:
        with httpx.Client(
            headers=headers,
            timeout=httpx.Timeout(20.0, connect=5.0),
        ) as client:
            upload_url = _upload_url(client, path.stat().st_size)

            with path.open("rb") as file_handle:
                response = client.post(
                    upload_url,
                    files={
                        "file": (
                            path.name,
                            file_handle,
                            "application/octet-stream",
                        )
                    },
                )

            analysis_id = _analysis_id(response)

            for attempt in range(MAX_ANALYSIS_POLLS):
                if attempt:
                    time.sleep(ANALYSIS_POLL_INTERVAL_SECONDS)

                analysis_response = client.get(
                    f"{VIRUSTOTAL_API_URL}/analyses/{analysis_id}"
                )
                analysis_response.raise_for_status()
                attributes = (
                    analysis_response.json()
                    .get("data", {})
                    .get("attributes", {})
                )
                result = _scan_result_from_analysis(attributes)

                if result is not None:
                    return result

    except httpx.HTTPStatusError as exc:
        logger.warning(
            "VirusTotal request failed with HTTP status %s.",
            exc.response.status_code,
        )
    except (httpx.HTTPError, ValueError, TypeError, KeyError):
        logger.exception("VirusTotal scan failed for file: %s", path.name)

    return {
        "status": "scan_unavailable",
        "message": "VirusTotal could not complete the malware scan.",
    }