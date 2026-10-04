# Specification changelog

All normative changes to `xchonnect-spec.md` are recorded here. Versions are tagged
`spec-vX.Y` in git.

## Unreleased (v0.2)

- **11.2 (TASK-56):** binding made precise: settlement-payment puzzle announcements (direct) and coin announcements of bound user spends (transitive) bind; other announcements do not; every user spend must be bound.

- **7.4 (review):** spent proof-of-work challenges are recorded in storage shared by all relay nodes; rate limits are charged after verification and before spending.

- **wire/relay-api.md (TASK-36 review):** `Cache-Control: no-store` and CORS behaviour made normative; `413 too_large` for envelopes above `max_envelope_bytes`; `403 api_key_invalid` for ticket requests without a valid key; rate limits checked before consuming tickets or proof-of-work.

- **5.1, 6.3, wire/pairing-uri.md (TASK-24 review):** clarifications found while writing test vectors: pairing replies must be one canonical `PairingReply` plus zero padding; the dApp applies no clock skew to `x`; error kind for non-v1 structures is unspecified (rejection is mandatory); URI strings are not unique and are compared by decoded fields, with a recommended canonical encoder order.

- **9.2.1 (TASK-37):** the rotation responder keeps its previous mailbox until a message from the initiator arrives on its new mailbox; the initiator sends `session.ping` right after switching. Found by the interop test: retiring early made the initiator post to a deleted mailbox.

- **9.2.1 (TASK-22):** rotation procedure made explicit: accept sent under the old epoch to the old mailbox, drain order, `seq` continuity, deterministic resolution of concurrent offers; `session.pong` added as the answer to `session.ping`.

- **wire/, 6.1, 6.2, 7.2 (TASK-9):** normative wire definitions added: CDDL for all CBOR structures, pairing URI ABNF and byte-exact signature input (now a canonical CBOR array; adds `m` mailbox id, `i` key id, optional `t`; `s` not signed), origin document JSON Schema with fetch rules, full relay API with error model, token hashing and limits. Pairing reply padded to a 1024-byte ciphertext. New endpoints `GET /v1/info`, `POST /v1/challenge`, `POST /v1/tickets`; message bodies carry the envelope as base64url `env`.

- **5.4, 7.4, 7.5, 19 (TASK-8):** canonical CBOR profile specified; stateless proof-of-work for keyless mailbox creation; single-use sponsorship tickets (URI param `t`) so wallets can create mailboxes billed to the dApp customer; OQ-2, OQ-3, OQ-6 decided; remaining open questions have owners or are out of scope for v1.

- **9.1, Appendix A, OQ-4 (TASK-11):** method layer aligned with CHIP-0002 Final: bare method names with `chip0002_` aliases, required set adds `chainId`, params/result carried as JSON text, hex/amount encodings fixed, `partialSign` semantics stated, CHIP-0002 error codes plus 4100/4101, optional `rpc.received` receipt. Informative appendix of Sage/Goby deviations.

- **12.1 (TASK-10):** browser session storage requirements (IndexedDB, optional non-extractable WebCrypto wrapping, no localStorage), logout and lifetime rules, cross-tab serialisation of `seq`, explicit XSS residual risk.

- **10.1–10.3, 13.6 (TASK-7):** OHTTP clients use bounded waits advertised as `max_wait_ohttp_s` (default 0) with a defined polling schedule; minimum requirements on OHTTP relays (body size, CORS, timeouts, no forwarding headers); TLS-terminating edges must be disclosed in the data inventory.

- **7.3.1, 7.3.2, T21 (TASK-6):** mandatory relay egress rules for wake-ups (HTTPS, globally routable destinations validated after resolution and pinned, no redirects, timeouts), gateway policy modes `allowlist`/`open` published via `GET /v1/info`, wake coalescing; sealed token gains `exp`, gateways rate-limit per device token. New threat T21.

- **6.2–6.4, T3 (TASK-5):** pairing uses a single-use pairing mailbox P that the dApp deletes as soon as the first valid reply is accepted; the session mailbox D is created afterwards and sent in `session.confirm`. Losing wallets get `not_found` or time out and must warn the user. The dApp must obtain explicit user SAS confirmation and `session.ready` before activating. Timeouts specified.

- **5.2, 6.3, 13.4.1 (TASK-4):** new key schedule. The dApp pairing key is used only as the HPKE recipient key (previously reused in a raw X25519); the wallet's key contribution is the HPKE `enc`. `root_0` comes from the HPKE exporter over a byte-exact transcript hash; direction keys, chaining key and SAS are domain-separated HKDF-Expand outputs. SAS reduction specified. Rotation key schedule specified. Cryptographic properties and non-goals stated.

- **5, 5.3 (TASK-3):** session AEAD changed from ChaCha20-Poly1305 with `seq`-derived nonces to XChaCha20-Poly1305 with a random 192-bit nonce carried in the outer envelope (`n`). Outer envelope gains `kind`; AAD made byte-exact and includes `kind`. Padding now pads the *ciphertext* to exact bucket sizes. `seq` is used only for replay/ordering; senders that lose state must re-pair. T5/T20 updated.

## v0.1 — 2026-10-04

Baseline imported from the internal wiki (`00-protocol-spec.md`). Tagged `spec-v0.1`.
