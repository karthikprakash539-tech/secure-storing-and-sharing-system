import base64
import os
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from secure_gateway.key_management import (
    generate_file_key,
    protect_file_key,
)


NONCE_SIZE = 12
AES_KEY_SIZE = 32


def _validate_file_key(file_key):
    """
    Validate that the supplied key is a 256-bit AES key.
    """

    if not isinstance(file_key, bytes):
        raise TypeError("file_key must be bytes.")

    if len(file_key) != AES_KEY_SIZE:
        raise ValueError(
            "AES-256 encryption requires a 32-byte key."
        )


def encrypt_file(input_path, output_path):
    """
    Encrypt a file using AES-256-GCM.

    Returns metadata required for later key storage and decryption.
    The raw AES key is never returned.
    """

    source = Path(input_path)
    destination = Path(output_path)

    if not source.exists():
        raise FileNotFoundError(
            "The source file does not exist."
        )

    if not source.is_file():
        raise ValueError(
            "The source path is not a regular file."
        )

    destination.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    file_key = generate_file_key()

    _validate_file_key(file_key)

    nonce = os.urandom(NONCE_SIZE)

    aes = AESGCM(file_key)

    with source.open("rb") as file_handle:
        plaintext = file_handle.read()

    ciphertext = aes.encrypt(
        nonce,
        plaintext,
        None,
    )

    with destination.open("wb") as file_handle:
        file_handle.write(ciphertext)

    protected_key = protect_file_key(file_key)

    return {
        "protected_key": protected_key,
        "nonce": base64.urlsafe_b64encode(nonce).decode("ascii"),
        "algorithm": "AES-256-GCM",
    }


def decrypt_file(
    encrypted_path,
    output_path,
    file_key,
    nonce_encoded,
):
    """
    Decrypt an AES-256-GCM encrypted file.

    The caller must provide the already-recovered raw AES-256 key.
    The key is used only in memory and is never written to disk.

    The decrypted plaintext is written only to the supplied
    server-side temporary output path.
    """

    encrypted_file = Path(encrypted_path)
    destination = Path(output_path)

    if not encrypted_file.exists():
        raise FileNotFoundError(
            "The encrypted file does not exist."
        )

    if not encrypted_file.is_file():
        raise ValueError(
            "The encrypted path is not a regular file."
        )

    _validate_file_key(file_key)

    if not nonce_encoded:
        raise ValueError(
            "Encryption nonce is required."
        )

    try:
        nonce = base64.urlsafe_b64decode(
            nonce_encoded.encode("ascii")
        )
    except Exception as exc:
        raise ValueError(
            "The stored encryption nonce is invalid."
        ) from exc

    if len(nonce) != NONCE_SIZE:
        raise ValueError(
            "The encryption nonce has an invalid length."
        )

    with encrypted_file.open("rb") as file_handle:
        ciphertext = file_handle.read()

    aes = AESGCM(file_key)

    try:
        plaintext = aes.decrypt(
            nonce,
            ciphertext,
            None,
        )
    except Exception as exc:
        raise ValueError(
            "File decryption failed or authentication validation failed."
        ) from exc

    destination.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with destination.open("wb") as file_handle:
        file_handle.write(plaintext)

    return destination