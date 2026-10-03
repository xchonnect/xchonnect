# CHIP-XXXX: Xchonnect — Push-native, privacy-preserving signing relay for dApps and wallets

| Field | Value |
|---|---|
| CHIP Number | TBD (assigned by CHIP editors) |
| Title | Xchonnect: Push-native signing relay transport for CHIP-0002 |
| Description | An open, end-to-end encrypted, store-and-forward transport that lets dApps send CHIP-0002 requests to mobile wallets via content-free push wake-ups, without persistent connections and without the relay learning identities, contents or IPs |
| Author | Beidwerk (Pengui / Klimper / nodexch) — contact TBD |
| Editor | TBD |
| Comments-URI | TBD (CHIPs repository pull request) |
| Status | Draft |
| Category | Standards Track |
| Sub-Category | Interface |
| Created | 2026-10-04 |
| Requires | CHIP-0002 (dApp protocol) |
| Replaces | — |
| Superseded-By | — |

---

## Abstract

Xchonnect defines a transport between a dApp and a wallet in which messages are end-to-end encrypted, stored in anonymous mailboxes on a relay, and delivered to mobile wallets by content-free push wake-ups through a vendor-controlled push gateway. The method layer is CHIP-0002 unchanged. The transport is designed for the realities of iOS and Android background execution, where WebSocket-based sessions are suspended, and for strong metadata privacy: a relay stores no addresses, keys, IPs or plaintext, and can be reached through Oblivious HTTP so it never sees client IPs.

## Motivation

1. **Mobile reliability.** WalletConnect v2 keeps a WebSocket to a relay. iOS suspends background apps within seconds, so signing requests do not reach a wallet unless it is in the foreground. Chia dApps targeting phones (payments, trading, lending with time-critical actions) need requests that arrive while the wallet app is closed.
2. **Privacy.** Existing relays can observe who talks to whom, when, and from which IP, and link that to on-chain activity. Chia's coin-set model gives users strong on-chain privacy properties that a leaky transport undermines.
3. **Openness and vendor control.** Push delivery requires the wallet vendor's APNs/FCM credentials. A standard must let every vendor keep its own credentials while any party can run a relay.
4. **Multi-party spends.** Chia-native flows (offers, options, lending) combine spends from several parties. The transport must carry partial signing requests and responses safely and asynchronously.
5. **Alignment with existing work.** CHIP-0002 already defines the methods wallets expose to dApps; Chia's own Signer app demonstrates push-based signing but through a closed channel. An open transport lets any wallet, including vault- and passkey-based ones, participate.

## Backwards Compatibility

- No changes to consensus, puzzles or wallet RPCs.
- The method layer is CHIP-0002; dApps and wallets that implement CHIP-0002 add Xchonnect as an additional transport. A dApp MAY offer WalletConnect and Xchonnect side by side.
- Xchonnect does not deprecate WalletConnect; it is an alternative transport optimized for mobile and privacy.

## Rationale

- **Store-and-forward instead of sessions:** phones cannot hold connections; mailboxes with TTL and push wake-ups match platform constraints.
- **Push gateway model (as in Web Push and Matrix):** the relay sends a content-free wake-up to a vendor-run gateway holding that vendor's push credentials; the device token is sealed to the gateway's public key so the relay never sees it.
- **Capability tokens for mailboxes:** random 256-bit read/write tokens, stored hashed, instead of accounts. No registration, no identity.
- **HPKE for pairing and ChaCha20-Poly1305 for sessions:** standard primitives (RFC 9180, RFC 8439); no custom cryptography.
- **Origin keys in `/.well-known/xchonnect.json`:** binds a pairing to a verified domain, defending against QR and link phishing.
- **Oblivious HTTP (RFC 9458) as the IP-privacy layer:** an independent OHTTP relay sees IPs but not content; the Xchonnect relay sees content size and mailboxes but not IPs.
- **Padding and day-granular timestamps:** reduce traffic-analysis and linkage.
- **CBOR envelopes:** compact and deterministic; spend bundles can be large.

## Specification

The normative specification is the Xchonnect Protocol Specification ([`docs/spec/xchonnect-spec.md`](../spec/xchonnect-spec.md), version stated in its header). This section summarizes the normative parts.

### 1. Roles

dApp, Wallet, Relay, Push Gateway, OHTTP Relay (optional), as defined in the specification.

### 2. Pairing

- The dApp creates a mailbox D on a relay and encodes a pairing URI: `xchonnect:v1?r=…&w=…&k=…&s=…&d=…&x=…&o=…` (relay, write token, ephemeral X25519 key, 32-byte pairing secret, dApp domain, expiry ≤ 5 min, Ed25519 origin signature with key id).
- The wallet MUST fetch `https://<d>/.well-known/xchonnect.json`, verify `o`, display the verified domain, and abort on failure.
- The wallet creates mailbox W and sends `{wpk, wW, meta}` to D sealed with HPKE in PSK mode (PSK = `s`).
- Both derive direction-specific session keys with HKDF-SHA256 over the X25519 shared secret, the pairing secret and the transcript hash, and display a 6-digit SAS. The wallet requires user confirmation of the SAS.

### 3. Envelope

Outer: `{v, ct}` (CBOR). Inner plaintext: `{seq, iat, exp, id, type, body}`, encrypted with ChaCha20-Poly1305, nonce derived from `seq`, AAD = `"xchonnect" || v || direction || recipient mailbox id`, padded to 1/4/16/64/256 KiB buckets. Receivers MUST reject replays, stale or far-future messages, and unknown versions.

### 4. Relay API

`POST /v1/mailboxes`, `POST|GET /v1/mailboxes/{id}/messages`, `POST /v1/mailboxes/{id}/ack`, `PUT /v1/mailboxes/{id}/push`, `DELETE /v1/mailboxes/{id}`. Tokens are bearer secrets compared in constant time against stored hashes. Message TTL ≤ 7 days; mailboxes expire after 30 days of inactivity. A relay MUST NOT persist client IPs, user agents, Chia addresses or public keys. A relay SHOULD be reachable via OHTTP.

### 5. Push

`push_reg = {gateway_url, sealed_token}`; the relay POSTs `{sealed_token}` to `gateway_url` on new messages. Gateways MUST NOT retain device tokens beyond delivery and MUST NOT receive mailbox identifiers or content. Push payloads MUST be content-free or encrypted to the device.

### 6. Method layer

`rpc.request {method, params}` / `rpc.response {request_id, result | error}` carrying CHIP-0002 methods. Session control: `session.confirm`, `session.ready`, `session.rotate`, `session.permissions`, `session.end`, `session.ping`. `chip0002_signCoinSpends` MAY carry `partialSign: true`; wallets MUST verify multi-party binding (announcement or message conditions) before producing a partial signature and MUST refuse `AGG_SIG_UNSAFE` by default.

### 7. Same-device flow

A dApp running in a mobile browser on the same device as the wallet SHOULD use an app-link round trip (open wallet → sign → return URL) with push as fallback.

## Test Cases

To be provided with the reference implementation:

- Pairing vectors: fixed keys and pairing secret → expected session keys and SAS.
- Envelope vectors: plaintext, keys, `seq` → ciphertext (with padding) and AAD.
- Negative cases: wrong origin signature, expired URI, replayed `seq`, oversized message, unknown version, tampered AAD.
- Relay conformance: token hashing, identical error responses, TTL eviction, rate limits.
- Multi-party: unbound partial spend must be refused; bound partial spend must be signed.

## Reference Implementation

- `xchonnect-core` (Rust): envelope, pairing, session state; WASM and UniFFI bindings.
- `xchonnect-relay` (Rust): reference relay, including OHTTP gateway.
- `xchonnect-gateway` (Rust): reference push gateway (APNs, FCM).
- `@xchonnect/dapp` (TypeScript): browser SDK with CHIP-0002 adapter.
- Wallet integration: Klimper (first), with guidance for Sage and others.

Repository: TBD. License: Apache-2.0 for code.

## Security

See Section 13 of the protocol specification (threat model T1–T20, invariants, logging policy, known limitations). Key points: relay cannot read or forge; replay protection via `seq`/`exp`; origin verification and SAS against phishing; mandatory local simulation and binding checks in wallets; sealed push tokens; OHTTP for IP privacy; separation of relay and transaction-submission infrastructure. An external audit of the reference implementation is planned before "Final" status.

## Additional Assets

- [`docs/spec/xchonnect-spec.md`](../spec/xchonnect-spec.md) (full specification)
- `.well-known/xchonnect.json` schema
- Test vectors (JSON)

## Copyright

Copyright and related rights waived via [CC0](https://creativecommons.org/publicdomain/zero/1.0/).
