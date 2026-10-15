import sys
from pathlib import Path
from uuid import uuid4

PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


from db import execute_insert, execute_query, execute_update

from secure_gateway.key_management import (
    generate_file_key,
    store_file_key,
    get_file_key,
    delete_file_key,
)


TEST_EMAIL = f"step21-test-{uuid4().hex}@example.local"

user_id = None
file_id = None


try:
    print("STEP 21.4: Starting key-management database test...")

    # ---------------------------------------------------------
    # 1. Create temporary test user
    # ---------------------------------------------------------
    user_id = execute_insert(
        """
        INSERT INTO users (
            full_name,
            email,
            password_hash,
            security_question,
            security_answer_hash
        )
        VALUES (%s, %s, %s, %s, %s)
        """,
        (
            "STEP 21 Test User",
            TEST_EMAIL,
            "test-only-password-hash",
            "Test question?",
            "test-only-answer-hash",
        ),
    )

    # ---------------------------------------------------------
    # 2. Create temporary file metadata
    # ---------------------------------------------------------
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
            "step21-test.txt",
            f"{uuid4().hex}.enc",
            64,
            "txt",
            "encrypted",
            True,
            "AES-256-GCM",
        ),
    )

    # ---------------------------------------------------------
    # 3. Generate AES-256 key
    # ---------------------------------------------------------
    original_key = generate_file_key()

    if len(original_key) != 32:
        raise RuntimeError(
            "Generated key is not 256-bit."
        )

    # ---------------------------------------------------------
    # 4. Store protected key + nonce
    # ---------------------------------------------------------
    test_nonce = "STEP21_TEST_NONCE"

    store_file_key(
        file_id=file_id,
        file_key=original_key,
        nonce=test_nonce,
    )

    # ---------------------------------------------------------
    # 5. Retrieve and recover key
    # ---------------------------------------------------------
    recovered = get_file_key(file_id)

    recovered_key = recovered["file_key"]
    recovered_nonce = recovered["nonce"]

    # ---------------------------------------------------------
    # 6. Verify recovered values
    # ---------------------------------------------------------
    if recovered_key != original_key:
        raise RuntimeError(
            "Recovered AES key does not match original key."
        )

    if recovered_nonce != test_nonce:
        raise RuntimeError(
            "Recovered nonce does not match stored nonce."
        )

    print("AES-256 key generation: PASS")
    print("Protected key storage: PASS")
    print("Key recovery: PASS")
    print("Nonce storage/recovery: PASS")

    # ---------------------------------------------------------
    # 7. Delete encryption metadata
    # ---------------------------------------------------------
    delete_file_key(file_id)

    remaining_key = execute_query(
        """
        SELECT id
        FROM encryption_keys
        WHERE file_id = %s
        LIMIT 1
        """,
        (file_id,),
        fetchone=True,
    )

    if remaining_key:
        raise RuntimeError(
            "Encryption key metadata was not deleted."
        )

    print("Key metadata deletion: PASS")
    print("STEP 21.4: Database key-management test PASSED")


finally:
    # ---------------------------------------------------------
    # Cleanup temporary test records
    # ---------------------------------------------------------
    if file_id is not None:
        execute_update(
            """
            DELETE FROM files
            WHERE id = %s
            """,
            (file_id,),
        )

    if user_id is not None:
        execute_update(
            """
            DELETE FROM users
            WHERE id = %s
            """,
            (user_id,),
        )

    print("STEP 21.4: Test records cleaned up.")