import base64
import hashlib

from cryptography.fernet import Fernet
from cryptography.fernet import InvalidToken
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from config import Config
from db import execute_query, execute_update


AES_KEY_SIZE = 32


def _get_master_key():
    """
    Derive a stable key from the application SECRET_KEY.

    This derived key protects individual AES-256 file keys.
    The raw SECRET_KEY is never stored in the database.
    """

    if not Config.SECRET_KEY:
        raise RuntimeError("Application SECRET_KEY is not configured.")

    digest = hashlib.sha256(
        Config.SECRET_KEY.encode("utf-8")
    ).digest()

    return base64.urlsafe_b64encode(digest)


def _get_fernet():
    """
    Create the key-protection mechanism.
    """

    return Fernet(_get_master_key())


def generate_file_key():
    """
    Generate a cryptographically secure 256-bit AES key.
    """

    return AESGCM.generate_key(bit_length=256)


def protect_file_key(file_key):
    """
    Protect a raw AES-256 key before database storage.

    Returns:
        str: protected key
    """

    if not isinstance(file_key, bytes):
        raise TypeError("file_key must be bytes.")

    if len(file_key) != AES_KEY_SIZE:
        raise ValueError(
            "AES-256 file keys must contain exactly 32 bytes."
        )

    protected_key = _get_fernet().encrypt(file_key)

    return protected_key.decode("utf-8")


def recover_file_key(protected_key):
    """
    Recover the original AES-256 key from its protected representation.
    """

    if not protected_key:
        raise ValueError("Protected file key is required.")

    try:
        file_key = _get_fernet().decrypt(
            protected_key.encode("utf-8")
        )
    except InvalidToken as exc:
        raise ValueError(
            "The protected file key could not be validated."
        ) from exc

    if len(file_key) != AES_KEY_SIZE:
        raise ValueError(
            "Recovered key is not a valid AES-256 key."
        )

    return file_key


def store_protected_file_key(file_id, protected_key, nonce):
    """
    Store already-protected AES key metadata.

    The raw AES key never reaches this database operation.
    """

    if not file_id:
        raise ValueError("file_id is required.")

    if not protected_key:
        raise ValueError("protected_key is required.")

    if not nonce:
        raise ValueError("nonce is required.")

    if Config.DATABASE_BACKEND == "supabase":
        query = """
            INSERT INTO encryption_keys (
                file_id,
                key_reference,
                nonce
            )
            VALUES (%s, %s, %s)
            ON CONFLICT (file_id) DO UPDATE
            SET key_reference = EXCLUDED.key_reference,
                nonce = EXCLUDED.nonce
        """
        params = (file_id, protected_key, nonce)
    else:
        query = """
            INSERT INTO encryption_keys (
                file_id,
                key_reference,
                nonce
            )
            VALUES (%s, %s, %s)
            ON DUPLICATE KEY UPDATE
                key_reference = %s,
                nonce = %s
        """
        params = (
            file_id,
            protected_key,
            nonce,
            protected_key,
            nonce,
        )

    execute_update(query, params)


def store_file_key(file_id, file_key, nonce):
    """
    Protect a raw AES-256 key and store its protected metadata.
    """

    if not isinstance(file_key, bytes):
        raise TypeError("file_key must be bytes.")

    if len(file_key) != AES_KEY_SIZE:
        raise ValueError(
            "AES-256 file keys must contain exactly 32 bytes."
        )

    protected_key = protect_file_key(file_key)

    store_protected_file_key(
        file_id=file_id,
        protected_key=protected_key,
        nonce=nonce,
    )

def get_file_key(file_id):
    """
    Retrieve and recover the AES key and nonce for a file.

    Returns:
        {
            "file_key": bytes,
            "nonce": str
        }
    """

    if not file_id:
        raise ValueError("file_id is required.")

    record = execute_query(
        """
        SELECT
            key_reference,
            nonce
        FROM encryption_keys
        WHERE file_id = %s
        LIMIT 1
        """,
        (file_id,),
        fetchone=True,
    )

    if not record:
        raise ValueError(
            "Encryption key metadata was not found."
        )

    file_key = recover_file_key(
        record["key_reference"]
    )

    return {
        "file_key": file_key,
        "nonce": record["nonce"],
    }


def delete_file_key(file_id):
    """
    Delete encryption metadata associated with a file.
    """

    if not file_id:
        raise ValueError("file_id is required.")

    execute_update(
        """
        DELETE FROM encryption_keys
        WHERE file_id = %s
        """,
        (file_id,),
    )