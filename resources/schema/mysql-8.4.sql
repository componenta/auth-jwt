CREATE TABLE auth_refresh_token_families (
    family_id CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL PRIMARY KEY,
    subject_uuid CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    evidence TEXT NOT NULL,
    expires_at BIGINT UNSIGNED NOT NULL,
    revoked_at BIGINT UNSIGNED NULL,
    compromised_at BIGINT UNSIGNED NULL,
    lock_nonce CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    INDEX idx_auth_refresh_family_subject (subject_uuid),
    INDEX idx_auth_refresh_family_expiry (expires_at)
) ENGINE=InnoDB;

CREATE TABLE auth_refresh_tokens (
    token_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL PRIMARY KEY,
    family_id CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    subject_uuid CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    expires_at BIGINT UNSIGNED NOT NULL,
    consumed_at BIGINT UNSIGNED NULL,
    revoked_at BIGINT UNSIGNED NULL,
    INDEX idx_auth_refresh_token_family (family_id),
    INDEX idx_auth_refresh_token_subject (subject_uuid),
    INDEX idx_auth_refresh_token_expiry (expires_at),
    CONSTRAINT fk_auth_refresh_family
        FOREIGN KEY (family_id)
        REFERENCES auth_refresh_token_families(family_id)
) ENGINE=InnoDB;
