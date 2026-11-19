CREATE TABLE secret (
    token_hash CHAR(64) PRIMARY KEY,
    encrypted_payload BYTEA NOT NULL
);
