# Specification changelog

All normative changes to `xchonnect-spec.md` are recorded here. Versions are tagged
`spec-vX.Y` in git.

## Unreleased (v0.2)

- **10.1–10.3, 13.6 (TASK-7):** OHTTP clients use bounded waits advertised as `max_wait_ohttp_s` (default 0) with a defined polling schedule; minimum requirements on OHTTP relays (body size, CORS, timeouts, no forwarding headers); TLS-terminating edges must be disclosed in the data inventory.

- **7.3.1, 7.3.2, T21 (TASK-6):** mandatory relay egress rules for wake-ups (HTTPS, globally routable destinations validated after resolution and pinned, no redirects, timeouts), gateway policy modes `allowlist`/`open` published via `GET /v1/info`, wake coalescing; sealed token gains `exp`, gateways rate-limit per device token. New threat T21.

- **6.2–6.4, T3 (TASK-5):** pairing uses a single-use pairing mailbox P that the dApp deletes as soon as the first valid reply is accepted; the session mailbox D is created afterwards and sent in `session.confirm`. Losing wallets get `not_found` or time out and must warn the user. The dApp must obtain explicit user SAS confirmation and `session.ready` before activating. Timeouts specified.

- **5.2, 6.3, 13.4.1 (TASK-4):** new key schedule. The dApp pairing key is used only as the HPKE recipient key (previously reused in a raw X25519); the wallet's key contribution is the HPKE `enc`. `root_0` comes from the HPKE exporter over a byte-exact transcript hash; direction keys, chaining key and SAS are domain-separated HKDF-Expand outputs. SAS reduction specified. Rotation key schedule specified. Cryptographic properties and non-goals stated.

- **5, 5.3 (TASK-3):** session AEAD changed from ChaCha20-Poly1305 with `seq`-derived nonces to XChaCha20-Poly1305 with a random 192-bit nonce carried in the outer envelope (`n`). Outer envelope gains `kind`; AAD made byte-exact and includes `kind`. Padding now pads the *ciphertext* to exact bucket sizes. `seq` is used only for replay/ordering; senders that lose state must re-pair. T5/T20 updated.

## v0.1 — 2026-10-04

Baseline imported from the internal wiki (`00-protocol-spec.md`). Tagged `spec-v0.1`.
