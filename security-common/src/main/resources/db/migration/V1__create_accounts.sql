CREATE TABLE account (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    email VARCHAR(254) NOT NULL UNIQUE,
    password_hash VARCHAR(100) NOT NULL,
    CONSTRAINT normalized_email CHECK (email = lower(btrim(email)))
);

CREATE TABLE account_permission (
    account_id BIGINT NOT NULL REFERENCES account(id) ON DELETE CASCADE,
    permission VARCHAR(30) NOT NULL CHECK (permission IN ('VIEW_INFO', 'VIEW_ADMIN', 'STANDARD')),
    PRIMARY KEY (account_id, permission)
);
