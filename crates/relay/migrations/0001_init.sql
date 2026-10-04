-- Xchonnect relay schema (spec 7.1). Only the fields of the spec's data model:
-- token hashes, optional sealed push registration, optional business customer,
-- day-granular mailbox timestamps, ciphertext with exact expiry, sponsorship tickets.
-- No IPs, user agents, plaintext tokens, Chia addresses or public keys.

CREATE TABLE mailboxes (
    id            BYTEA   PRIMARY KEY,            -- 16 random bytes
    read_hash     BYTEA   NOT NULL,               -- SHA-256("xchonnect v1 token" || read token)
    write_hash    BYTEA   NOT NULL,
    push_url      TEXT,
    push_token    BYTEA,                          -- sealed to the push gateway
    customer      TEXT,                           -- business customer id (never end users)
    created_day   INTEGER NOT NULL,               -- unix days
    last_used_day INTEGER NOT NULL
);
CREATE INDEX mailboxes_last_used ON mailboxes (last_used_day);

CREATE TABLE messages (
    seq        BIGSERIAL PRIMARY KEY,             -- acceptance order
    mailbox_id BYTEA     NOT NULL REFERENCES mailboxes (id) ON DELETE CASCADE,
    msg_id     BYTEA     NOT NULL,
    envelope   BYTEA     NOT NULL,                -- ciphertext envelope
    expires_at BIGINT    NOT NULL                 -- unix seconds
);
CREATE INDEX messages_mailbox ON messages (mailbox_id, seq);
CREATE INDEX messages_expiry ON messages (expires_at);

CREATE TABLE tickets (
    hash       BYTEA  PRIMARY KEY,                -- SHA-256("xchonnect v1 ticket" || ticket)
    customer   TEXT   NOT NULL,
    expires_at BIGINT NOT NULL
);
