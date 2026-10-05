-- Spent proof-of-work challenges (spec 7.4): single-use across relay nodes and restarts.
-- Keyed by SHA-256("xchonnect v1 pow spent" || challenge); rows expire with the challenge.
CREATE TABLE pow_spent (
    hash       BYTEA  PRIMARY KEY,
    expires_at BIGINT NOT NULL
);
CREATE INDEX pow_spent_expiry ON pow_spent (expires_at);
