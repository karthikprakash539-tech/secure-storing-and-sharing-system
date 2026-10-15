CREATE DATABASE IF NOT EXISTS secure_gateway
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci;

USE secure_gateway;


-- =========================================================
-- USERS
-- =========================================================

CREATE TABLE IF NOT EXISTS users (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    full_name VARCHAR(150) NOT NULL,
    email VARCHAR(255) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    security_question VARCHAR(255) NOT NULL,
    security_answer_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (id),
    UNIQUE KEY uq_users_email (email),
    KEY idx_users_created_at (created_at)
) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_unicode_ci;


-- =========================================================
-- FILES
-- =========================================================

CREATE TABLE IF NOT EXISTS files (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    user_id BIGINT UNSIGNED NOT NULL,
    original_filename VARCHAR(255) NOT NULL,
    stored_filename VARCHAR(255) NOT NULL,
    file_size BIGINT UNSIGNED NOT NULL,
    file_type VARCHAR(100) NOT NULL,
    status ENUM(
        'pending',
        'safe',
        'blocked',
        'deleted',
        'encrypted'
    ) NOT NULL DEFAULT 'pending',
    is_encrypted TINYINT(1) NOT NULL DEFAULT 0,
    encryption_algorithm VARCHAR(50) NULL,
    uploaded_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        ON UPDATE CURRENT_TIMESTAMP,

    PRIMARY KEY (id),

    UNIQUE KEY uq_files_stored_filename (stored_filename),

    KEY idx_files_user_id (user_id),
    KEY idx_files_status (status),
    KEY idx_files_uploaded_at (uploaded_at),

    CONSTRAINT fk_files_user
        FOREIGN KEY (user_id)
        REFERENCES users(id)
        ON DELETE CASCADE
        ON UPDATE CASCADE
) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_unicode_ci;


-- =========================================================
-- ENCRYPTION KEYS
-- =========================================================

CREATE TABLE IF NOT EXISTS encryption_keys (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    file_id BIGINT UNSIGNED NOT NULL,
    key_reference TEXT NOT NULL,
    nonce VARCHAR(255) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (id),

    UNIQUE KEY uq_encryption_keys_file_id (file_id),

    CONSTRAINT fk_encryption_keys_file
        FOREIGN KEY (file_id)
        REFERENCES files(id)
        ON DELETE CASCADE
        ON UPDATE CASCADE
) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_unicode_ci;


-- =========================================================
-- SHARED FILES
-- =========================================================

CREATE TABLE IF NOT EXISTS shared_files (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    file_id BIGINT UNSIGNED NOT NULL,
    owner_id BIGINT UNSIGNED NOT NULL,
    share_token_hash VARCHAR(255) NOT NULL,
    expires_at TIMESTAMP NULL,
    max_downloads INT UNSIGNED NULL,
    download_count INT UNSIGNED NOT NULL DEFAULT 0,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    revoked TINYINT(1) NOT NULL DEFAULT 0,

    PRIMARY KEY (id),

    UNIQUE KEY uq_shared_files_token_hash (share_token_hash),

    KEY idx_shared_files_file_id (file_id),
    KEY idx_shared_files_owner_id (owner_id),
    KEY idx_shared_files_expires_at (expires_at),
    KEY idx_shared_files_revoked (revoked),

    CONSTRAINT fk_shared_files_file
        FOREIGN KEY (file_id)
        REFERENCES files(id)
        ON DELETE CASCADE
        ON UPDATE CASCADE,

    CONSTRAINT fk_shared_files_owner
        FOREIGN KEY (owner_id)
        REFERENCES users(id)
        ON DELETE CASCADE
        ON UPDATE CASCADE
) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_unicode_ci;


-- =========================================================
-- AUDIT LOGS
-- =========================================================

CREATE TABLE IF NOT EXISTS audit_logs (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    user_id BIGINT UNSIGNED NULL,
    file_id BIGINT UNSIGNED NULL,
    file_name VARCHAR(255) NULL,
    action VARCHAR(50) NOT NULL,
    ip_address VARCHAR(45) NULL,
    user_agent TEXT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (id),

    KEY idx_audit_logs_user_id (user_id),
    KEY idx_audit_logs_file_id (file_id),
    KEY idx_audit_logs_action (action),
    KEY idx_audit_logs_created_at (created_at),

    CONSTRAINT fk_audit_logs_user
        FOREIGN KEY (user_id)
        REFERENCES users(id)
        ON DELETE SET NULL
        ON UPDATE CASCADE,

    CONSTRAINT fk_audit_logs_file
        FOREIGN KEY (file_id)
        REFERENCES files(id)
        ON DELETE SET NULL
        ON UPDATE CASCADE
) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_unicode_ci;