import re
from pathlib import Path


EMAIL_PATTERN = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)

PHONE_PATTERN = re.compile(
    r"(?<!\d)(?:\+91[\s-]?)?[6-9]\d{9}(?!\d)"
)

AADHAAR_PATTERN = re.compile(
    r"(?<!\d)\d{4}[\s-]?\d{4}[\s-]?\d{4}(?!\d)"
)

CREDIT_CARD_PATTERN = re.compile(
    r"(?<!\d)(?:\d{4}[\s-]?){3}\d{4}(?!\d)"
)


def detect_sensitive_text(text):
    """
    Detect common sensitive-data patterns in text.

    Only match counts are returned.
    Actual sensitive values are never returned.
    """

    if not text:
        return {
            "email_count": 0,
            "phone_count": 0,
            "aadhaar_count": 0,
            "credit_card_count": 0,
            "total_matches": 0,
        }

    email_count = len(
        EMAIL_PATTERN.findall(text)
    )

    phone_count = len(
        PHONE_PATTERN.findall(text)
    )

    aadhaar_count = len(
        AADHAAR_PATTERN.findall(text)
    )

    credit_card_count = len(
        CREDIT_CARD_PATTERN.findall(text)
    )

    total_matches = (
        email_count
        + phone_count
        + aadhaar_count
        + credit_card_count
    )

    return {
        "email_count": email_count,
        "phone_count": phone_count,
        "aadhaar_count": aadhaar_count,
        "credit_card_count": credit_card_count,
        "total_matches": total_matches,
    }


def _empty_result():
    """
    Return a consistent empty detection result.
    """

    return {
        "email_count": 0,
        "phone_count": 0,
        "aadhaar_count": 0,
        "credit_card_count": 0,
        "total_matches": 0,
    }


def detect_sensitive_file(
    file_path,
    max_bytes=5 * 1024 * 1024,
):
    """
    Scan UTF-8 text files for configured sensitive-data patterns.

    Binary files are NOT treated as fully scanned.
    """

    path = Path(file_path)

    empty_result = _empty_result()

    if not path.exists():
        return {
            "status": "error",
            "reason": "File does not exist.",
            **empty_result,
        }

    if not path.is_file():
        return {
            "status": "error",
            "reason": "The supplied path is not a regular file.",
            **empty_result,
        }

    try:
        with path.open("rb") as file_handle:
            raw_data = file_handle.read(max_bytes + 1)

        if len(raw_data) > max_bytes:
            return {
                "status": "scan_limited",
                "reason": (
                    "Sensitive-data scanning was limited "
                    "to the configured text size."
                ),
                **empty_result,
            }

        text = raw_data.decode("utf-8")

    except UnicodeDecodeError:
        return {
            "status": "scan_unavailable",
            "reason": "The file is not UTF-8 text.",
            **empty_result,
        }

    except OSError:
        return {
            "status": "error",
            "reason": "The file could not be read.",
            **empty_result,
        }

    result = detect_sensitive_text(text)

    result["status"] = "scanned"

    result["reason"] = (
        "Text content was scanned for configured "
        "sensitive-data patterns."
    )

    return result