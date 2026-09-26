CREATE TABLE auth_refresh_token_families (
    family_id TEXT PRIMARY KEY,
    subject_uuid TEXT NOT NULL,
    evidence TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    revoked_at INTEGER NULL,
    compromised_at INTEGER NULL,
    lock_nonce TEXT NOT NULL
);

CREATE INDEX auth_refresh_family_subject
    ON auth_refresh_token_families(subject_uuid);
CREATE INDEX auth_refresh_family_expiry
    ON auth_refresh_token_families(expires_at);

CREATE TABLE auth_refresh_tokens (
    token_hash TEXT PRIMARY KEY,
    family_id TEXT NOT NULL,
    subject_uuid TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    consumed_at INTEGER NULL,
    revoked_at INTEGER NULL,
    FOREIGN KEY (family_id)
        REFERENCES auth_refresh_token_families(family_id)
);

CREATE INDEX auth_refresh_token_family
    ON auth_refresh_tokens(family_id);
CREATE INDEX auth_refresh_token_subject
    ON auth_refresh_tokens(subject_uuid);
CREATE INDEX auth_refresh_token_expiry
    ON auth_refresh_tokens(expires_at);
