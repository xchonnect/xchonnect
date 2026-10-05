# Relay HTTP API v1 (normative)

## Conventions

- All requests and responses are `application/json` (UTF-8). Binary values are
  base64url without padding. Unknown request fields are ignored.
- Request bodies are limited to **400 KiB**; larger bodies get `413 too_large`.
- Capability tokens are sent as `Authorization: Bearer <base64url token>`.
- Optional API keys are sent as `Xchonnect-Api-Key: <key>`.
- Relays MUST NOT set cookies and MUST NOT require any client identifier.
- Responses MUST carry `Cache-Control: no-store`. Relays serving browser dApps MUST answer
  CORS preflights allowing `Authorization`, `Content-Type` and `Xchonnect-Api-Key` from any
  origin and MUST NOT allow credentials.
- Every endpoint is also reachable through the relay's OHTTP gateway (spec 10).

### Identifiers and hashes

| Value | Format |
|---|---|
| `mailbox_id` | 16 random bytes chosen by the relay |
| `msg_id` | 16 random bytes chosen by the relay |
| read/write token | 32 bytes from a CSPRNG chosen by the client |
| token hash | `SHA-256("xchonnect v1 token" \|\| token)` (32 bytes), computed by the client |

The relay compares `SHA-256("xchonnect v1 token" || presented_token)` against the stored
hash in constant time. Read and write hashes MUST differ; the relay rejects creation
requests where they are equal.

### Errors

Errors have the body `{"error": "<code>"}` and no other fields. This holds for **every**
error response, including the ones a relay's HTTP framework produces before any handler
runs (an unmatched path, a method a path does not accept, a path that does not
percent-decode to UTF-8). The one exception is the OHTTP key-configuration mismatch,
which RFC 9458 Section 5.3 fixes as a `application/problem+json` document (spec 10.3).

| HTTP | `error` | Meaning |
|---|---|---|
| 400 | `bad_request` | malformed JSON, field, encoding or envelope |
| 403 | `auth_required` | mailbox creation needs an API key, ticket or proof-of-work |
| 403 | `pow_invalid` | proof-of-work wrong, expired or already used |
| 403 | `ticket_invalid` | ticket unknown, expired or already used |
| 403 | `api_key_invalid` | API key unknown or disabled |
| 403 | `gateway_not_allowed` | `gateway_url` rejected by policy or rules (spec 7.3.1) |
| 404 | `not_found` | unknown mailbox **or** wrong token **or** deleted mailbox **or** unknown path |
| 405 | `method_not_allowed` | the path exists but not for this method; `Allow` lists the methods |
| 409 | `mailbox_full` | per-mailbox message or byte quota reached |
| 413 | `too_large` | body above limit |
| 429 | `rate_limited` | rate limit or quota; `Retry-After` header in seconds |
| 503 | `unavailable` | temporary failure |

`not_found` responses MUST be byte-identical (status, headers, body) whether the mailbox
does not exist or the token is wrong, and the relay MUST perform the same hash and
comparison work in both cases.

## Endpoints

### `GET /v1/info`

```json
{
  "protocol": 1,
  "max_wait_s": 25,
  "max_wait_ohttp_s": 0,
  "default_ttl_s": 86400,
  "max_ttl_s": 604800,
  "max_envelope_bytes": 262400,
  "max_messages_per_mailbox": 256,
  "mailbox_creation": ["api_key", "ticket", "pow"],
  "pow_difficulty": 18,
  "gateway_policy": "allowlist",
  "gateway_allowlist": ["https://push.example-wallet.app/"],
  "ohttp": true
}
```

`mailbox_creation` lists the accepted methods; `"open"` means no proof is required.
`gateway_allowlist` is present when `gateway_policy` is `allowlist` and lists URL prefixes.

### `POST /v1/challenge`

Response `200`: `{"challenge": b64url(42 bytes), "difficulty": 18, "expires_at": 1790000000}`
(spec 7.4).

### `POST /v1/tickets`

Requires `Xchonnect-Api-Key`; a missing or unknown key gives `403 api_key_invalid`. Response `200`: `{"ticket": b64url(32), "expires_at": uint}`.

### `POST /v1/mailboxes`

```json
{
  "read_token_hash": "b64url(32)",
  "write_token_hash": "b64url(32)",
  "push_reg": { "gateway_url": "https://...", "sealed_token": "b64url" },
  "pow": { "challenge": "b64url(42)", "nonce": "b64url(8)" },
  "ticket": "b64url(32)"
}
```

`push_reg`, `pow`, `ticket` are optional (subject to `mailbox_creation`). At most one of
API key, `ticket`, `pow` is used; if several are present the relay uses the first of API
key, ticket, pow. Response `201`: `{"mailbox_id": "b64url(16)"}`.

### `POST /v1/mailboxes/{mailbox_id}/messages`

Write token. Body: `{"env": b64url(envelope), "ttl_s": 86400}` (`ttl_s` optional; clamped
to `[60, max_ttl_s]`).

The relay MUST validate the outer envelope: canonical CBOR, exactly the keys of
`Envelope` in `envelope.cddl`, `v = 1`, `kind` 1 or 2, `n` of the right length, `ct`
length a bucket size (kind 1) or exactly 1024 (kind 2), total at most
`max_envelope_bytes`. It does not (cannot) inspect the ciphertext. Structural violations
give `400 bad_request`; an envelope larger than `max_envelope_bytes` gives `413 too_large`.
Rate limits are checked before a ticket or proof-of-work is consumed, so a `429` never
spends the client's single-use proof.

Response `202`: `{"msg_id": "b64url(16)"}`. Triggers a wake-up if the mailbox has a push
registration (spec 7.3).

### `GET /v1/mailboxes/{mailbox_id}/messages?wait=<seconds>&limit=<n>`

Read token. `wait` defaults to 0 and is clamped to `max_wait_s` (`max_wait_ohttp_s`
through OHTTP); `limit` defaults to 32 (max 32). Returns as soon as at least one message
is available or the wait expires.

Response `200`: `{"messages": [{"msg_id": "b64url(16)", "env": "b64url"}]}` in the order
the relay accepted them. Messages stay until acknowledged or expired.

### `POST /v1/mailboxes/{mailbox_id}/ack`

Read token. Body `{"msg_ids": ["b64url(16)", ...]}` (at most 256). Unknown ids are ignored.
Response `204`.

### `PUT /v1/mailboxes/{mailbox_id}/push`

Read token. Body `{"push_reg": {...}}` to set or replace, `{"push_reg": null}` to remove.
Response `204`.

### `DELETE /v1/mailboxes/{mailbox_id}`

Read token. Deletes the mailbox and all its messages immediately. Response `204`.

## OHTTP gateway (spec 10)

Relays with `"ohttp": true` in `/v1/info` run an Oblivious HTTP gateway (RFC 9458) with
binary HTTP (RFC 9292) inner messages.

### `GET /.well-known/ohttp-keys`

Response `200`, `Content-Type: application/ohttp-keys`: the key configuration list (RFC 9458
section 3.2), **newest first**. Every configuration uses DHKEM(X25519, HKDF-SHA256) and
offers HKDF-SHA256 with AES-128-GCM and ChaCha20-Poly1305. During a rotation the previous
configuration stays listed and accepted (overlap). `GET /.well-known/ohttp-gateway`
returns the same list (RFC 9540). `404 not_found` when the gateway is disabled.

### `POST /.well-known/ohttp-gateway`

Body: an encapsulated request (`Content-Type: message/ohttp-req`) of at most 513 KiB (the
largest padded inner request, 512 KiB, plus encapsulation overhead). The inner request is
a binary HTTP request for any endpoint above or for `GET /.well-known/ohttp-keys`; only its
method, path (origin-form) and the `Authorization`, `Content-Type` and `Xchonnect-Api-Key`
fields are used. It is handled exactly like a direct request (400 KiB body limit,
authentication, rate limits), except that `wait` is clamped to `max_wait_ohttp_s`.

Inner messages are padded with zero bytes to the size buckets of spec 10.5 in both
directions; the padding is ignored on receipt and an unpadded inner request is accepted.

| Outcome | Response |
|---|---|
| decapsulated | `200`, `Content-Type: message/ohttp-res`, the encapsulated inner response (any status, including errors, is inside) |
| unknown key id, or the request does not decrypt | `400`, `Content-Type: application/problem+json`, `type` = `https://iana.org/assignments/http-problem-types#ohttp-key` (RFC 9458 section 5.3); the client refreshes its key configuration |
| wrong media type, truncated, or a replay | `400 bad_request` |
| body above the limit | `413 too_large` |

The inner response carries the status, `Content-Type`, `Retry-After` and the body.
Gateway replay handling (spec 10.4): a relay node refuses an encapsulated request whose
HPKE `enc` it accepted in the last 600 s, with a `400 bad_request` byte-identical to the
one for a malformed encapsulation, and the inner endpoint is not reached. The `enc` is
recorded only after the encapsulation decrypted, so a forgery that reuses an observed
`enc` cannot block the genuine request. Replay state is in memory, per node and bounded;
older replays, or replays to another node, are processed like a repeated direct request
(the endpoints tolerate repeats as described in `docs/operating.md`).

## Retention (spec 7.1)

- Messages: deleted on ack or at expiry (`ttl_s`).
- Mailboxes: deleted after 30 days without any authenticated request, or on `DELETE`.
- Mailbox timestamps (`created`, `last_used`) are stored at day granularity.
