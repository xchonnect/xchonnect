# Xchonnect data inventory

This is the published inventory of what the Xchonnect services hold and expose, and it
is **machine-checked**. `privacy/tests/full_session.rs` runs a complete pairing, signing
and push-wake session through the real relay and gateway code and then verifies this
document against what it observed; `scripts/privacy-scan.sh` does the same against
relay and gateway processes with a Postgres database behind them. Both fail the build
when this file and the code disagree, in either direction:

- a class listed under **Must never appear** that shows up is a leak;
- a class listed under **Must be observed** that does *not* show up means the check
  stopped exercising that path, so a passing run would have proved nothing.

Sources: threat model and invariants in `docs/spec/xchonnect-spec.md` §13.4 (invariants 2
and 5), the logging policy in §13.5, and the data inventory in §14. Backlog: TASK-54.

## Data classes

| Class | Meaning |
|---|---|
| `client_ip` | Client IP address, from the socket or from a forwarding header |
| `user_agent` | Client `User-Agent` |
| `device_token` | APNs/FCM device token in the clear |
| `chia_address` | Chia address (bech32m `xch1`/`txch1`) |
| `public_key` | A wallet public key (BLS or X25519) in the clear |
| `plaintext_token` | Mailbox read or write capability token value |
| `token_hash` | `SHA-256("xchonnect v1 token" \|\| token)` |
| `mailbox_id` | Mailbox identifier |
| `msg_id` | Relay-assigned message identifier |
| `ciphertext` | An encrypted envelope |
| `message_plaintext` | Plaintext of an end-to-end encrypted message: methods, params, amounts |
| `sealed_push_token` | Device token sealed to the vendor gateway's key |
| `gateway_url` | Vendor push gateway URL |
| `customer_id` | Business customer identifier (billing) |
| `api_key` | Business API key value |

## Surfaces

Every class must be listed exactly once per surface. "Shape scan" additionally runs the
value-independent detectors (IPv4 literals, bech32m addresses, 64/96-character hex runs,
user agents, bearer tokens), which catch data the checks never planted.

| Surface | Must be observed | Must never appear | Shape scan |
|---|---|---|---|
| `database` | mailbox_id, token_hash, msg_id, ciphertext, sealed_push_token, gateway_url, customer_id | client_ip, user_agent, device_token, chia_address, public_key, plaintext_token, message_plaintext, api_key | no |
| `service_logs` | none | client_ip, user_agent, device_token, chia_address, public_key, plaintext_token, token_hash, mailbox_id, msg_id, ciphertext, message_plaintext, sealed_push_token, gateway_url, customer_id, api_key | yes |
| `relay_metrics` | none | client_ip, user_agent, device_token, chia_address, public_key, plaintext_token, token_hash, mailbox_id, msg_id, ciphertext, message_plaintext, sealed_push_token, gateway_url, customer_id, api_key | yes |
| `gateway_metrics` | none | client_ip, user_agent, device_token, chia_address, public_key, plaintext_token, token_hash, mailbox_id, msg_id, ciphertext, message_plaintext, sealed_push_token, gateway_url, customer_id, api_key | yes |
| `relay_billing` | customer_id | client_ip, user_agent, device_token, chia_address, public_key, plaintext_token, token_hash, mailbox_id, msg_id, ciphertext, message_plaintext, sealed_push_token, gateway_url, api_key | yes |
| `wake_request` | sealed_push_token, gateway_url | client_ip, user_agent, device_token, chia_address, public_key, plaintext_token, token_hash, mailbox_id, msg_id, ciphertext, message_plaintext, customer_id, api_key | no |
| `push_delivery` | device_token | client_ip, user_agent, chia_address, public_key, plaintext_token, token_hash, mailbox_id, msg_id, ciphertext, message_plaintext, sealed_push_token, gateway_url, customer_id, api_key | no |

Notes on the three surfaces that legitimately carry something:

- `database` is everything the relay hands to storage. The in-process check records every
  store write; the live check dumps Postgres. Ciphertext, token hashes, mailbox ids,
  message ids, the sealed push token, the gateway URL and the business customer are the
  spec's data model (§7.1, §14) — nothing else may be there.
- `wake_request` is the relay-to-gateway HTTP request (§7.3). Its body is exactly
  `{"sealed_token": "<base64url>"}`; the mailbox id, the message and its size must not
  travel with it.
- `push_delivery` is what the gateway hands to APNs/FCM. The device token is the address
  it delivers to; nothing about the request, the session or the amount may be attached
  (§13.6, T11: Apple and Google learn only that a device received a push).

`database` and the two push surfaces skip the shape scan because they legitimately
contain values the detectors are looking for: a `bytea` dump renders a 32-byte token hash
as exactly 64 hex characters, a device token is 64 hex characters, and the gateway URL
contains a host. The value-based scan covers them instead.

## Relay database schema

The columns in `crates/relay/migrations/*.sql` must be exactly these. A new column has to
be added here, which is the point: it forces a decision about what the relay stores.

| Table | Columns |
|---|---|
| mailboxes | id, read_hash, write_hash, push_url, push_token, customer, created_day, last_used_day |
| messages | seq, mailbox_id, msg_id, envelope, expires_at |
| tickets | hash, customer, expires_at |
| pow_spent | hash, expires_at |

## Benign literals

Literals that may match a shape detector on a surface, with the reason. Anything else
that looks like an IP, an address, a key or a user agent fails the build.

| Surface | Literal | Why |
|---|---|---|
| `service_logs` | 127.0.0.1 | Relay and gateway log their own loopback bind address at startup |
| `service_logs` | 0.0.0.0 | Containers log the wildcard bind address |

## Retention in the reference implementation

Spec §14 gives the bounds; these are the values the shipped relay and gateway apply, and
the settings that change them (`crates/relay/src/config.rs`).

| Data | Kept | Setting |
|---|---|---|
| Ciphertext messages | Until acknowledged, else until their TTL: 24 hours by default, 7 days at most (a longer request is clamped) | `XCHONNECT_DEFAULT_TTL_S`, `XCHONNECT_MAX_TTL_S` |
| Mailbox, token hashes, sealed push registration, customer id | Until the owner deletes the mailbox (`DELETE /v1/mailboxes/{id}`) or it has been unused for 30 days; the sweep runs in the relay, with day-granular timestamps | not configurable |
| Sealed push token | With the mailbox: the relay does not learn when the token expires. The token itself carries an expiry of at most 90 days (spec 7.3), after which the gateway refuses it | — |
| Spent proof-of-work challenges, tickets | Until they expire: a challenge is valid for two minutes, a ticket for ten | — |
| Device push token (gateway) | For the duration of one delivery; the gateway keeps per-device rate-limit state in memory and forgets a device the platform rejects | — |
| Logs | Nothing per request is written; keep whatever the platform retains at 14 days or less (spec 13.5) | `XCHONNECT_LOG` sets the level |

## Spec §14 mapping

Every row of the spec's own data-inventory table (`docs/spec/xchonnect-spec.md` §14) maps
to the surfaces above. The checks parse the spec table and fail if a row is missing here.

| Spec row | Where it is verified |
|---|---|
| Ciphertext messages | `database` (observed), `service_logs` / `relay_metrics` (forbidden) |
| Mailbox ID + token hashes | `database` (observed), `service_logs` / `relay_metrics` (forbidden) |
| Sealed push token | `database`, `wake_request` (observed); `push_delivery` (forbidden) |
| Device push token | `push_delivery` only; forbidden on every relay surface |
| Business API key usage | `relay_billing` as `customer_id`; the key value itself is forbidden everywhere |
| Session keys, permissions | Never leaves the devices: `message_plaintext` and `public_key` are forbidden on every surface |
| Signed bundles | Public on chain; carried only as `ciphertext`, forbidden as `message_plaintext` |

## What these checks do not cover

Recorded here so the gaps are explicit input to the pre-audit threat model (TASK-62):

- **Client IPs at the network layer.** The checks prove the services never read or store a
  client IP, including from `X-Forwarded-For`. They cannot prove an operator's reverse
  proxy, CDN or kernel does not log one (spec 13.6, §10.3).
- **Oblivious HTTP.** That OHTTP hides the client IP from the relay is a property of the
  deployment and of the independent OHTTP relay operator, not of this code. The relay's
  own tests cover the gateway's encapsulation.
- **Timing and size correlation.** Day-granular timestamps and padding bound what the
  relay learns, but a global observer correlating traffic is out of scope (T9).
- **Third-party log output.** The live check filters dependency logs to warnings, so a
  dependency logging at `debug` is not covered; the project's own code is checked at
  `trace`.
- **Push payload content for real senders.** The reference gateway sends content-free
  wake-ups. Once APNs and FCM senders build a real payload, `push_delivery` covers what
  they are handed, but not what the platform SDKs then transmit.
