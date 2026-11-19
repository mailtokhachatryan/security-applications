CREATE TABLE login_attempt (
    email VARCHAR(254) PRIMARY KEY,
    failures INTEGER NOT NULL DEFAULT 0 CHECK (failures BETWEEN 0 AND 3),
    blocked_until TIMESTAMP WITH TIME ZONE
);
