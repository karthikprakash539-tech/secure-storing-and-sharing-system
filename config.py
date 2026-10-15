import os
from pathlib import Path

from dotenv import load_dotenv


BASE_DIR = Path(__file__).resolve().parent

load_dotenv(BASE_DIR / ".env")


class Config:
    """Application configuration loaded from environment variables."""

    SECRET_KEY = os.getenv("SECRET_KEY")

    DATABASE_BACKEND = os.getenv("DATABASE_BACKEND", "mysql").lower()
    SUPABASE_DB_URL = os.getenv("SUPABASE_DB_URL")
    SUPABASE_URL = os.getenv("SUPABASE_URL") or os.getenv("NEXT_PUBLIC_SUPABASE_URL")
    SUPABASE_SECRET_KEY = (
        os.getenv("SUPABASE_SECRET_KEY")
        or os.getenv("SUPABASE_SERVICE_ROLE_KEY")
    )
    SUPABASE_KEY = (
        SUPABASE_SECRET_KEY
        or os.getenv("SUPABASE_PUBLISHABLE_KEY")
        or os.getenv("NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY")
    )
    SUPABASE_BUCKET = os.getenv("SUPABASE_BUCKET", "secure-files")

    MYSQL_HOST = os.getenv("MYSQL_HOST", "localhost")
    MYSQL_PORT = int(os.getenv("MYSQL_PORT", "3306"))
    MYSQL_USER = os.getenv("MYSQL_USER", "root")
    MYSQL_PASSWORD = os.getenv("MYSQL_PASSWORD", "")
    MYSQL_DB = os.getenv("MYSQL_DB", "secure_gateway")

    UPLOAD_FOLDER = os.getenv(
        "UPLOAD_FOLDER",
        str(BASE_DIR / "uploads"),
    )

    ENCRYPTED_FOLDER = os.getenv(
        "ENCRYPTED_FOLDER",
        str(BASE_DIR / "encrypted"),
    )

    QUARANTINE_FOLDER = os.getenv(
        "QUARANTINE_FOLDER",
        str(BASE_DIR / "uploads" / "quarantine"),
    )

    MAX_FILE_SIZE = int(
        os.getenv("MAX_FILE_SIZE", "52428800")
    )

    CLAMAV_ENABLED = (
        os.getenv("CLAMAV_ENABLED", "false").lower()
        == "true"
    )

    CLAMAV_HOST = os.getenv(
        "CLAMAV_HOST",
        "localhost",
    )

    CLAMAV_PORT = int(
        os.getenv("CLAMAV_PORT", "3310")
    )

    SESSION_COOKIE_SECURE = (
        os.getenv("SESSION_COOKIE_SECURE", "false").lower()
        == "true"
    )

    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"

    MAX_CONTENT_LENGTH = MAX_FILE_SIZE

    ALLOWED_EXTENSIONS = {
        "pdf",
        "txt",
        "doc",
        "docx",
        "xls",
        "xlsx",
        "ppt",
        "pptx",
        "jpg",
        "jpeg",
        "png",
        "zip",
    }

    BLOCKED_EXTENSIONS = {
        "exe",
        "bat",
        "cmd",
        "ps1",
        "vbs",
        "scr",
        "msi",
    }

    SECRET_KEY_REQUIRED = True

    @classmethod
    def validate(cls):
        """Validate required security configuration."""

        if not cls.SECRET_KEY:
            raise RuntimeError(
                "SECRET_KEY is missing from the environment."
            )

        if cls.SECRET_KEY == "replace-with-a-random-secret-key":
            raise RuntimeError(
                "SECRET_KEY must be replaced with a real random value."
            )

        if cls.DATABASE_BACKEND not in {"mysql", "supabase"}:
            raise RuntimeError(
                "DATABASE_BACKEND must be either 'mysql' or 'supabase'."
            )

        if cls.DATABASE_BACKEND == "supabase" and not cls.SUPABASE_DB_URL:
            raise RuntimeError(
                "SUPABASE_DB_URL is required when DATABASE_BACKEND=supabase."
            )