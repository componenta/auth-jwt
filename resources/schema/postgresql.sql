CREATE TABLE auth_refresh_token_families (
    family_id CHAR(64) PRIMARY KEY,
    subject_uuid UUID NOT NULL,
    evidence TEXT NOT NULL,
    expires_at BIGINT NOT NULL,
    revoked_at BIGINT NULL,
    compromised_at BIGINT NULL,
    lock_nonce CHAR(32) NOT NULL
);

CREATE INDEX idx_auth_refresh_family_subject
    ON auth_refresh_token_families(subject_uuid);
CREATE INDEX idx_auth_refresh_family_expiry
    ON auth_refresh_token_families(expires_at);

CREATE TABLE auth_refresh_tokens (
    token_hash CHAR(64) PRIMARY KEY,
    family_id CHAR(64) NOT NULL
        REFERENCES auth_refresh_token_families(family_id),
    subject_uuid UUID NOT NULL,
    expires_at BIGINT NOT NULL,
    consumed_at BIGINT NULL,
    revoked_at BIGINT NULL
);

CREATE INDEX idx_auth_refresh_token_family
    ON auth_refresh_tokens(family_id);
CREATE INDEX idx_auth_refresh_token_subject
    ON auth_refresh_tokens(subject_uuid);
CREATE INDEX idx_auth_refresh_token_expiry
    ON auth_refresh_tokens(expires_at);
