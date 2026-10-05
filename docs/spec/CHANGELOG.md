# Specification changelog

All normative changes to `xchonnect-spec.md` are recorded here. Versions are tagged
`spec-vX.Y` in git.

## Unreleased (v0.2)

- **9.1, wire/envelope.cddl:** two new method-layer messages and one error code. `rpc.cancel { request_id }` lets either side withdraw a request the user has not decided; the wallet removes it from its queue and answers 4102 `RequestCancelledError`. `rpc.status { request_id, state, tx_id? }` lets a wallet report `shown`, `approved` and `broadcast` (with the transaction id) while the user decides and the wallet sends. Both are additive: an implementation that does not know them treats them as unknown message types, and the request still ends with its `rpc.response`.

- **Header, 7, 8, 10–13, 15, 18 (editorial, public release):** the spec no longer reads as an internal product document. The header states the version as 0.2 (draft) and the audit status; requirements written as "Klimper MUST" or "the Pengui SDK MUST" now say "the wallet" and "dApp SDKs", and section titles drop product names. Sections 15 (hosted relay product) and 18 (milestones) are marked informative. **No normative change:** every requirement applies to the same party as before, now named by role.

- **6.3, 9.3 (editorial):** the handshake sequence diagram was wrong. It drew the wallet's final message as `session.ready { meta, permissions }`, but no version of this protocol has ever carried permissions in that body: `SessionReady` in `wire/envelope.cddl` has only the optional `meta`, and the declaration has its own message `session.permissions` (`SessionPermissions`, defined in the same grammar and in 9.3). The diagram now shows `session.ready { meta }` followed by its own `session.permissions` arrow, and 9.3 says in prose that the declaration is a message of its own, optional, and may be re-sent when the grant changes. **No wire format change:** the grammar, the message table in 9.2, the signature inputs and the test vectors are untouched, and the three implementations (`crates/core`, `bindings/*`, `sdk-ts`) already agreed with the grammar rather than with the picture. Only the picture and the prose around it moved.

- **6.2, 7.3, 8.2, wire/pairing-uri.md (editorial):** the illustrative examples now use the RFC 2606 placeholder domains `dapp.example` and `wallet.example` instead of `pengui.xyz`, `klimper.app` and `push.klimper.app`, which name hosts the project does not control. No normative requirement, grammar, signature input or test vector changes; the entry is here because 6.1 requires the origin document to come from the exact domain claimed and `return_url` to share that authority byte for byte, so the old examples contradicted the rules they illustrate, and because downstream implementers copy these strings verbatim. The published vectors already use `dapp.example` and `relay.example`, and their `d=` bytes are signed and were left untouched.

- **wire/xchonnect.schema.json (review):** the origin document's `return_url` same-domain rule made precise and mandatory: its authority MUST be byte-identical to the pairing URI's `d` — not a subdomain, no port, no userinfo, no trailing dot, written in the same lowercase A-label form — and a wallet MUST reject the whole document otherwise. `icon` carries no such rule. Previously the rule existed only as prose in the schema's description, so every wallet had to re-implement the host check and a dApp whose origin key leaked could point the user at another host (T18, and it undercut the verified-domain display T3 relies on).

- **wire/relay-api.md (review):** the uniform error model is stated to cover *every* error response, including the ones a relay's HTTP framework raises before a handler runs, with `application/problem+json` for the OHTTP key mismatch (RFC 9458 §5.3) as the only exception. New row `405 method_not_allowed` for a path that exists but not for the request's method, which carries `Allow`. `404 not_found` also covers an unknown path.

- **10.6, T10, 13.6 (TASK-70):** node requests (`push_tx`) are sent through OHTTP to a gateway operated by the node operator, reached through the same independent OHTTP relay; relays MUST NOT offer a forwarding endpoint for node requests, because the relay would otherwise see plaintext spend bundles (T7, T10, 4.1). Nodes without a pinned gateway configuration are submitted to directly and the client must report that per node. Node requests carry no relay credential, mailbox id or session material.

- **10.5, 10.2, T9, 13.6 (TASK-69):** inner binary HTTP requests and responses are padded with zero bytes (RFC 9292 §3.8) to size buckets — powers of two from 2 KiB to 256 KiB, then multiples of 256 KiB up to 16 MiB — so the OHTTP relay cannot infer the endpoint or the number of envelopes in a fetch from the encapsulated length. The 2 KiB floor makes every control request, a one-envelope post and an empty or one-envelope fetch response identical in length. Recipients ignore padding and must not reject unpadded messages. The OHTTP relay body-size requirements in 10.2 are restated for padded messages (528 KiB requests, 12 MiB responses).

- **10.4, 16, wire/relay-api.md (TASK-51):** gateway replay handling specified: refuse an encapsulated request whose HPKE `enc` was accepted within a window of at least 600 s, record `enc` only after successful decryption (so an `enc`-reusing forgery cannot block the genuine request), answer byte-identically to a malformed encapsulation and never reach the inner endpoint, keep replay state in memory, per node and bounded, and never in shared storage. Undetected repeats are explicitly allowed because every endpoint tolerates them. Operators publish the window and the bound. T9.

- **7.3.2, 7.3.3, wire/envelope.cddl (TASK-48):** encrypted notification preview specified: `NotificationPreview` sealed with XChaCha20-Poly1305 under `HKDF-Expand(mailbox_hint_key, "xchonnect v1 preview key")`, zero-padded to a single 168-byte wire size so the length leaks nothing, carried opaquely by the gateway in the APNs `xcp` key or the FCM `data.xcp` member, with a 600 s expiry, an opt-in-only detail line that rejects control characters and bidi overrides, and a mandatory fallback to the generic alert. 7.3.2 also made the gateway's forget path normative: an invalidated device token is discarded with its rate-limit state and never reported in the (uniform) wake response. T11, T12.

- **wire/relay-api.md, 10 (TASK-51):** OHTTP gateway resource defined: key configurations at `/.well-known/ohttp-keys` (newest first, previous key kept during rotation, X25519 with AES-128-GCM and ChaCha20-Poly1305), gateway at `POST /.well-known/ohttp-gateway`, inner header allowlist, RFC 9458 `ohttp-key` problem for unknown keys, per-node replay window. T9.

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

Baseline version of the specification. Tagged `spec-v0.1`.
