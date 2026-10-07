# CHIP-XXXX: Xchonnect — Push-native, privacy-preserving signing relay for dApps and wallets

| Field | Value |
|---|---|
| CHIP Number | TBD (assigned by CHIP editors) |
| Title | Xchonnect: Push-native signing relay transport for CHIP-0002 |
| Description | An open, end-to-end encrypted, store-and-forward transport that lets dApps send CHIP-0002 requests to mobile wallets via content-free push wake-ups, without persistent connections and without the relay learning identities, contents or IPs |
| Author | Maxim Edogawa ([@maximedogawa](https://github.com/maximedogawa)), Beidwerk — Pengui / Klimper / nodexch |
| Contact | GitHub issues at <https://github.com/xchonnect/xchonnect/issues>; security reports via <https://github.com/xchonnect/xchonnect/security/advisories/new> (see [`SECURITY.md`](../../SECURITY.md)) |
| Repository | <https://github.com/xchonnect/xchonnect> (Apache-2.0 code, CC0 specification) |
| Editor | TBD (assigned by CHIP editors) |
| Comments-URI | TBD (CHIPs repository pull request) |
| Status | Draft |
| Category | Standards Track |
| Sub-Category | Interface |
| Created | 2026-10-04 |
| Last-Updated | 2026-10-05 |
| Requires | CHIP-0002 (dApp protocol, Final, apiVersion 1.0.0) |
| Replaces | — |
| Superseded-By | — |

> **Draft status note (not part of the submission text).** This draft tracks
> [`docs/spec/xchonnect-spec.md`](../spec/xchonnect-spec.md) as of its 0.2 draft, with the
> amendments listed as *Unreleased (v0.2)* in
> [`docs/spec/CHANGELOG.md`](../spec/CHANGELOG.md). Per
> [`docs/spec/PROCESS.md`](../spec/PROCESS.md) the v0.2 entries must be released and tagged
> `spec-v0.2` before this CHIP is submitted, and the reference below must then cite that
> tag. **This draft is behind the spec** in one place, listed under "Open items
> before submission": the OHTTP padding of spec 10.5.

---

## Abstract

Xchonnect defines a transport between a dApp and a wallet in which messages are end-to-end
encrypted, stored in anonymous mailboxes on a relay, and delivered to mobile wallets by
content-free push wake-ups through a vendor-controlled push gateway. The method layer is
CHIP-0002 unchanged. The transport is designed for the realities of iOS and Android
background execution, where WebSocket-based sessions are suspended, and for strong metadata
privacy: a relay stores no addresses, keys, IPs or plaintext, and can be reached through
Oblivious HTTP so it does not see client IP addresses.

## Motivation

1. **Mobile reliability.** WalletConnect v2 keeps a WebSocket to a relay. iOS suspends
   background apps within seconds, so signing requests do not reach a wallet unless it is
   in the foreground. Chia dApps targeting phones (payments, trading, lending with
   time-critical actions) need requests that arrive while the wallet app is closed.
2. **Privacy.** Existing relays can observe who talks to whom, when, and from which IP,
   and link that to on-chain activity. Chia's coin-set model gives users strong on-chain
   privacy properties that a leaky transport undermines.
3. **Openness and vendor control.** Push delivery requires the wallet vendor's APNs/FCM
   credentials. A standard must let every vendor keep its own credentials while any party
   can run a relay.
4. **Multi-party spends.** Chia-native flows (offers, options, lending) combine spends from
   several parties. The transport must carry partial signing requests and responses safely
   and asynchronously, and the wallet must be able to prove its spend cannot be used
   without the counterparty's payment.
5. **Alignment with existing work.** CHIP-0002 already defines the methods wallets expose
   to dApps; Chia's own Signer app demonstrates push-based signing but through a closed
   channel. An open transport lets any wallet, including vault- and passkey-based ones,
   participate.

## Backwards Compatibility

- No changes to consensus, puzzles or wallet RPCs.
- The method layer is CHIP-0002; dApps and wallets that implement CHIP-0002 add Xchonnect
  as an additional transport. A dApp MAY offer WalletConnect and Xchonnect side by side.
- Wallets MUST accept both the bare CHIP-0002 method names and the `chip0002_`-prefixed
  aliases used by WalletConnect deployments, so one handler can serve both transports.
- Xchonnect does not deprecate WalletConnect; it is an alternative transport optimized for
  mobile and privacy.

## Rationale

- **Store-and-forward instead of sessions:** phones cannot hold connections; mailboxes with
  TTL and push wake-ups match platform constraints.
- **Push gateway model (as in Web Push and Matrix):** the relay sends a content-free wake-up
  to a vendor-run gateway holding that vendor's push credentials; the device token is sealed
  to the gateway's public key so the relay never sees it.
- **Capability tokens for mailboxes:** random 128-bit mailbox ids with 256-bit read/write
  tokens, stored only as hashes and compared in constant time, instead of accounts. No
  registration, no identity.
- **HPKE for pairing and XChaCha20-Poly1305 for sessions:** standard primitives (RFC 9180,
  RFC 8439, draft-irtf-cfrg-xchacha). No key pair is used in two constructions: the dApp's
  pairing key is only an HPKE recipient key and the wallet's contribution is the HPKE
  encapsulated key. Session nonces are random 192-bit values, so state rollback in a browser
  cannot cause nonce reuse; `seq` carries replay protection instead. No custom cryptography.
- **Transcript-bound key derivation:** the session root is an HPKE exporter output over a
  byte-exact transcript hash, so both sides derive equal keys only if they agree on the
  signed URI, the encapsulated key and the sealed reply. The short authentication string is
  derived from the same root.
- **Single-use pairing mailbox with first-reply-wins:** a photographed QR code lets an
  attacker pair *instead of* the user, never *alongside* them, and the losing device is told
  the code was already used.
- **Origin keys in `/.well-known/xchonnect.json`:** binds a pairing to a verified domain
  without a third-party attestation service, defending against QR and link phishing.
- **Oblivious HTTP (RFC 9458) as the IP-privacy layer:** an independent OHTTP relay sees IPs
  but not content; the Xchonnect relay sees content size and mailboxes but not IPs.
- **Padding to fixed ciphertext buckets and day-granular timestamps:** reduce
  traffic-analysis and linkage.
- **Canonical CBOR envelopes:** compact, deterministic (exactly one valid encoding per
  message), and able to carry large spend bundles.
- **Proof-of-work or sponsorship tickets for mailbox creation:** anonymous, accountless
  anti-abuse that needs no client identifier.

## Specification

The normative specification is the Xchonnect Protocol Specification
([`docs/spec/xchonnect-spec.md`](../spec/xchonnect-spec.md), version stated in its header),
with byte layouts in [`docs/spec/wire/`](../spec/wire/):

| File | Content |
|---|---|
| [`wire/envelope.cddl`](../spec/wire/envelope.cddl) | CDDL for every CBOR structure: envelopes, inner plaintext, pairing reply, session and RPC bodies, sealed push token |
| [`wire/pairing-uri.md`](../spec/wire/pairing-uri.md) | Pairing URI grammar, field rules, byte-exact origin signature input |
| [`wire/xchonnect.schema.json`](../spec/wire/xchonnect.schema.json) | `/.well-known/xchonnect.json` JSON Schema and fetch rules |
| [`wire/relay-api.md`](../spec/wire/relay-api.md) | Relay HTTP API, error model, token hashing, limits, OHTTP gateway resources |

This section summarizes the normative parts. Where it is shorter than the specification,
the specification governs.

### 1. Roles

dApp, Wallet, Relay, Push Gateway, and an optional OHTTP Relay operated by an independent
organization, as defined in Section 4 of the specification.

### 2. Cryptography

One fixed suite per protocol version; implementations MUST reject unknown versions and
there is no downgrade negotiation. X25519 key agreement, HKDF-SHA256, HPKE (RFC 9180) in
`mode_psk` with DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / ChaCha20-Poly1305 for pairing,
XChaCha20-Poly1305 with a random 192-bit nonce for session messages, Ed25519 for dApp origin
signatures, SHA-256 for hashing, 256-bit CSPRNG tokens.

Key schedule (specification 5.2):

```
info       = "xchonnect v1 pairing" || h_uri          h_uri = SHA-256(uri_sig_input)
psk        = s (32-byte pairing secret)               psk_id = "xchonnect v1 psk"
(enc, ctx) = SetupPSKS(pkR = dpk, info, psk, psk_id)  // wallet; enc is its contribution
aad_pair   = "xchonnect v1 pairing reply" || mbx_P
ct_pair    = ctx.Seal(aad_pair, canonical_cbor(PairingReply) || zeros)   // |ct_pair| = 1024
th         = SHA-256("xchonnect v1 transcript" || h_uri || enc || ct_pair)
root_0     = ctx.Export("xchonnect v1 root" || th, 32)
```

Per epoch `e`, `root_e` is the HKDF PRK for the direction keys
`k_d2w` / `k_w2d`, the chaining key `ck_e`, and (epoch 0 only) an 8-byte `sas` reduced to
six decimal digits. Rotation mixes a fresh X25519 exchange into `ck_e` over a rotation
transcript; an all-zero X25519 output MUST be rejected, and both sides MUST erase the
previous epoch's keys. After the handshake completes the dApp MUST erase its pairing
private key and the pairing secret, and the wallet MUST erase the pairing secret and the
HPKE context.

### 3. Pairing

- The dApp creates a single-use **pairing mailbox** P on a relay and encodes a pairing URI:
  `xchonnect:v1?r=…&m=…&w=…&k=…&s=…&d=…&x=…&i=…&o=…[&t=…]` — relay base URL, pairing
  mailbox id, its write token, dApp pairing X25519 public key, 32-byte pairing secret, dApp
  domain, expiry (≤ 5 minutes), origin key id, and the Ed25519 origin signature, with an
  optional sponsorship ticket. All binary values are base64url without padding. The
  signature input is
  `canonical_cbor(["xchonnect pairing uri v1", r, mbx_P, wP, dpk, d, x, kid])`; the pairing
  secret is deliberately **not** signed. Universal links carry the same parameters in the
  URL **fragment** so they never reach a web server.
- The wallet MUST fetch `https://<d>/.well-known/xchonnect.json` over HTTPS from the exact
  domain (no redirects, ≤ 16 KiB, 10 s timeout, re-fetched on every pairing), verify the
  origin signature, display the verified domain with homograph warnings, and abort on any
  failure without offering a "continue anyway" option.
- The wallet creates its own mailbox W and posts a pairing reply (envelope kind 2) to P,
  sealing `{mbx_W, wW, meta?}` with HPKE in PSK mode.
- **First reply wins.** The dApp accepts the first reply that decrypts to exactly one
  canonical `PairingReply` followed only by zero bytes, while `now ≤ x` (no clock-skew
  allowance, since the dApp issued `x`). It MUST then delete P immediately, so any later
  reply receives `not_found`, and create a separate session mailbox D which it sends in
  `session.confirm`. The URI's write token is useless after pairing.
- The wallet MUST receive a valid `session.confirm` within 5 minutes of posting its reply;
  a `not_found` on posting, or a timeout, MUST be reported to the user as "this code was
  already used or expired — another device may have paired with it".
- **Both sides display the 6-digit SAS and both require explicit user confirmation.** The
  wallet MUST NOT send `session.ready` until the user confirms the codes match; the dApp
  MUST NOT treat the session as active or send any request until it has both that
  confirmation and a valid `session.ready`. On mismatch either side sends `session.end` and
  deletes the session. Either side abandons the pairing after 5 minutes.
- The relay stores no session record — only mailboxes.

### 4. Envelope

Outer envelope, visible to the relay (CBOR map with small unsigned integer keys):
`{1: v, 2: kind, 3: n, 4: ct}`, where `kind` is 1 for a session message or 2 for a pairing
reply, `n` is a 24-byte random nonce (kind 1) or the 32-byte HPKE encapsulated key (kind 2),
and `ct` is the padded AEAD ciphertext including its 16-byte tag.

Inner plaintext (kind 1): `{seq, iat, exp, id, type, body}`, encrypted with
XChaCha20-Poly1305 under the direction key. The AAD is the 28-byte string
`"xchonnect" || u8 v || u8 kind || u8 direction || recipient_mailbox_id`, with `direction`
`0x01` for dApp→wallet and `0x02` for wallet→dApp.

Padding: the plaintext is canonical CBOR followed by zero bytes such that the **ciphertext**
length is exactly one of 1, 4, 16, 64 or 256 KiB (the smallest that fits). Receivers MUST
reject a ciphertext whose length is not a bucket size and a plaintext whose bytes after the
first CBOR item are not all zero.

Receivers MUST reject: decryption failure; `seq` not greater than the last accepted `seq`
for that direction; `exp` in the past; `exp − iat` greater than 7 days; `iat` more than
5 minutes in the future; unknown versions. `seq` is used only for replay protection and
ordering — never to derive a nonce. A sender that cannot guarantee a strictly increasing
`seq` (restored backup, storage loss) MUST stop sending and re-pair.

All CBOR in the protocol uses a canonical profile (specification 5.4): RFC 8949 §4.2.1
deterministic encoding, definite lengths only, map keys sorted bytewise with duplicates
rejected, no tags or floating point, nesting depth ≤ 16, ≤ 1024 entries per array or map,
exactly one top-level item. Unknown keys in inner maps are ignored; unknown keys in the
outer envelope are an error.

### 5. Relay API

```
GET    /v1/info                              limits, creation methods, gateway policy, max_wait_s, max_wait_ohttp_s
POST   /v1/challenge                         proof-of-work challenge
POST   /v1/tickets             (API key)     single-use sponsorship ticket
POST   /v1/mailboxes                         { read_token_hash, write_token_hash, push_reg?, pow?, ticket? } -> { mailbox_id }
POST   /v1/mailboxes/{id}/messages  (write)  { env, ttl_s? } -> 202 { msg_id }; triggers a wake-up
GET    /v1/mailboxes/{id}/messages?wait=&limit=   (read) -> { messages: [ { msg_id, env } ] }
POST   /v1/mailboxes/{id}/ack       (read)   { msg_ids }
PUT    /v1/mailboxes/{id}/push      (read)   { push_reg | null }
DELETE /v1/mailboxes/{id}           (read)
```

Envelopes are carried as base64url text in `env`. Token hashes are
`SHA-256("xchonnect v1 token" || token)`, computed by the client; the relay stores only the
hashes and MUST compare them in constant time. Responses for "unknown mailbox" and "wrong
token" MUST be identical, so the API is not an enumeration oracle. The relay MUST validate
the outer envelope (canonical CBOR, version, kind, nonce length, bucketed ciphertext
length) and reject malformed envelopes; an envelope above `max_envelope_bytes` gives
`413 too_large`. Responses MUST carry `Cache-Control: no-store`, and relays serving browser
dApps MUST answer CORS preflights. Message TTL is at most 7 days (default 24 h); mailboxes
expire after 30 days of inactivity. A relay MUST NOT persist client IPs, User-Agent strings,
Chia addresses or public keys, and MUST NOT log mailbox ids, token values or ciphertext.
A relay SHOULD be reachable via OHTTP.

**Anti-abuse without identity.** A relay that allows mailbox creation without an API key
SHOULD require a stateless proof-of-work: `POST /v1/challenge` returns a MAC-protected
42-byte challenge with a difficulty (default 18 bits) and an expiry at most 120 s ahead; the
client finds an 8-byte nonce such that `SHA-256("xchonnect v1 pow" || challenge || nonce)`
has at least `difficulty` leading zero bits. The relay verifies the MAC, expiry and hash,
charges its rate limit, and records the challenge as spent in storage shared by all nodes,
so a solution is single-use across nodes and restarts. Alternatively a hosting customer
obtains a single-use **sponsorship ticket** (`POST /v1/tickets`, valid ≤ 10 minutes, stored
only as a hash) and puts it in the pairing URI, so the wallet's mailbox is billed to that
customer. A creation request carries exactly one of: API key, ticket, or proof-of-work.

### 6. Push wake-ups

`push_reg = { gateway_url, sealed_token }`, where `sealed_token` is
`HPKE_base(gateway_pk){ platform, device_token, mailbox_hint_key, exp }`. The relay POSTs
`{sealed_token}` to `gateway_url` on a new message — no mailbox id, no content. Gateways
MUST NOT receive mailbox identifiers or content and MUST NOT retain device tokens beyond
delivery. Push payloads to the device MUST be content-free or encrypted to the device, and
lock-screen text MUST NOT contain amounts or addresses unless the user opts in. Wallets
SHOULD use a fresh sealed token per session so the relay cannot link sessions.

Because `gateway_url` comes from an anonymous client, every wake-up is an attacker-chosen
outbound request. Relays MUST enforce (specification 7.3.1):

1. `https` only, port 443 unless the operator allowlists another, no userinfo, URL ≤ 512
   bytes;
2. resolve the host and reject if **any** resolved address is not globally routable, then
   connect only to the validated address (no second resolution, defeating DNS rebinding),
   with mandatory certificate validation for the original host name;
3. no redirects — any 3xx is a failure;
4. connect timeout 3 s, total timeout 10 s, request body = the sealed token only, response
   body read at most 4 KiB and discarded;
5. at most one wake-up per mailbox per 10 s; a wake-up failure never affects acceptance of
   the message;
6. one of two documented gateway policies, published at `GET /v1/info`: `allowlist`
   (RECOMMENDED for hosted relays) or `open` (any URL passing rules 1–4);
7. validation at registration time and again at dispatch time.

Gateways MUST (specification 7.3.2) reject sealed tokens whose `exp` (at most 90 days ahead)
has passed, rate-limit per device token using in-memory state only — RECOMMENDED at most
1 wake per 10 s and 60 per hour — so a replayed sealed token cannot flood a device, respond
uniformly so they are not an oracle for token validity, and never fetch any resource on
behalf of a wake request.

### 7. Method layer

`rpc.request {method, params}` / `rpc.response {request_id, result | error}`, with an
optional `rpc.received {request_id}` delivery receipt that carries no user decision,
`rpc.cancel {request_id}` (either side withdraws a request the user has not decided; the
wallet drops it and answers `4102`) and `rpc.status {request_id, state, tx_id?}` (the
wallet reports `shown`, `approved` or `broadcast`, informative only). `params`, `result`
and `error.data` are UTF-8 JSON texts exactly as CHIP-0002 defines them, carried
unchanged so that mojo amounts above 2^53 − 1 survive and existing CHIP-0002 code stays
byte-compatible.

`method` is the bare CHIP-0002 name; wallets MUST also accept the `chip0002_` aliases.
Methods outside CHIP-0002 MUST use a vendor prefix; unknown methods are answered with
`4004`. Required methods: `chainId`, `connect`, `getPublicKeys`, `signCoinSpends`,
`signMessage`, `xchonnect_submitCoinSpends`. Optional: `filterUnlockedCoins`,
`getAssetCoins`, `getAssetBalance`, `sendTransaction`, `walletSwitchChain`, and the
wallet-built `chia_*` methods (Section 11). Receivers MUST accept hex with or without a
`0x` prefix in either case and senders SHOULD emit lowercase with the prefix; `amount`
MUST be accepted as a JSON number or a decimal string. Error codes are CHIP-0002's, plus
`4100` (request expired before the user decided), `4101` (spend could not be decoded and
unknown contracts are disabled) and `4102` (withdrawn with `rpc.cancel`).

**The wallet broadcasts what it signs alone** (specification 8.3). A dApp MUST NOT submit
a bundle it obtained over Xchonnect; `signCoinSpends` is for a contribution another party
completes. For a bundle the dApp built — a custom spend the wallet has no builder for —
it sends `xchonnect_submitCoinSpends { coinSpends, aggregatedSignature?, intent? }` and
receives `{ transactionId, status }`: the wallet applies every rule of `signCoinSpends`,
verifies binding when `aggregatedSignature` completes the bundle (taking an offer),
checks that the aggregate satisfies every requirement of the bundle before anything
leaves it, broadcasts through its own peers or OHTTP, and counts the loss against limits
only once the transaction left. For a spend the wallet can build itself the dApp names
what the user wants (`chia_send { address, amount, fee?, assetId? }`) and the wallet
builds it from its own coins and runs it through the same checks and the same single
prompt. So a dApp needs neither the user's coins nor keys to make a payment, and no third
party sees address, IP address and transaction together.

An **intent** is a set of claims the dApp may attach to `xchonnect_submitCoinSpends`
(`kind`, every `recipients` payment to others, the `fee`, the user's `netChange` per
asset) that the wallet verifies one by one against its own simulation and shows as
verified facts; a claim that does not hold, or an undeclared payment, refuses the request
(`4001`, `intent_mismatch`) before the user sees anything. `kind` is the one free text, a
short machine label shown as the website's description.

Session control: `session.confirm`, `session.ready`, `session.rotate`,
`session.permissions`, `session.end`, `session.ping` and `session.pong`. Rotation
(specification 9.2.1) is a two-message exchange under the current epoch: the initiator
offers a fresh key and a new mailbox, the responder accepts to the initiator's **old**
mailbox and switches; each side reads its previous mailbox before its current one, the
responder keeps its previous mailbox until a message arrives on its new one (so the
initiator sends `session.ping` right after switching), `seq` continues across epochs, and
concurrent offers resolve deterministically in the dApp's favour.

`signCoinSpends` MAY carry `partialSign: true`. Wallets MUST verify multi-party binding
before producing a partial signature: a user spend is bound only if it asserts a puzzle
announcement created by an offer settlement-payments spend in the same request, or a coin
announcement of another bound user spend. Announcements from other puzzles do not bind,
because their creator can re-create them without paying, and **every** user spend in a
partial request must be bound. Wallets MUST refuse `AGG_SIG_UNSAFE` by default — stricter
than CHIP-0002 — and MUST refuse requests for another network.

### 8. IP privacy (OHTTP)

Clients MUST be able to send all relay requests via Oblivious HTTP (RFC 9458). The
Xchonnect relay runs the OHTTP **gateway**; the OHTTP **relay** MUST be operated by an
independent organization under contract not to collude or log request bodies. Clients fetch
and pin the key configuration from `GET /.well-known/ohttp-keys` and send encapsulated
requests to `POST /.well-known/ohttp-gateway`; rotation keeps the previous configuration
listed during an overlap period and is learned through the gateway under the pinned key, so
it is authenticated and does not reveal the client's address. An unknown key yields the
RFC 9458 `ohttp-key` problem, which clients MUST treat as a hard error rather than falling
back to direct requests. The gateway applies an inner-header allowlist and a per-node
replay window.

Because OHTTP is strictly request/response and third-party relays may cut long requests, the
relay advertises `max_wait_s` (direct) and `max_wait_ohttp_s` (encapsulated, default **0**)
in `GET /v1/info`. A client using OHTTP MUST NOT request a longer wait than
`max_wait_ohttp_s`; when the effective wait is 0 it polls every 2 s for the first 30 s after
sending, then every 10 s, with ±20 % jitter, and only while the page is visible or the app
is in the foreground. Push wake-ups remain the primary signal for wallets.

An OHTTP relay used with Xchonnect MUST forward `POST` with `Content-Type:
message/ohttp-req` and bodies of at least 400 KiB, answer CORS preflights for browser
clients and expose no identifying response headers, use a request timeout of at least 15 s,
and not log request bodies or add client-identifying headers toward the gateway.

Without OHTTP a relay MUST still not persist IPs, and MUST document that it sees them. A
TLS-terminating edge in front of a relay sees client IPs, mailbox ids in URLs, bearer tokens
and timing for direct traffic; operators MUST list any such edge and what it observes in
their published data inventory.

### 9. Client requirements

**Wallets** MUST simulate every requested spend locally and display the net effect per
asset computed from the conditions, never from dApp-supplied labels; sign only coin-bound
`AGG_SIG_*` variants for their own keys; show undecodable spends as "unknown contract" with
the puzzle hash and require a second confirmation (or refuse); approve a request once,
as a whole, and require **one** fresh biometric or passkey authentication per request
that covers every signature it needs, with no prompt per signature and no "remember for
N minutes"; enforce
user-configured per-dApp and per-day limits; and verify the network. Session keys are stored
in the platform keychain, **separate** from signing keys, which stay hardware-wrapped and
biometric-gated.

**dApps** MUST publish `/.well-known/xchonnect.json` and keep the origin key in an HSM or
KMS, show the pairing QR only inside an authenticated page, construct multi-party bundles
with binding, never request `AGG_SIG_UNSAFE`, and apply a strict CSP with no third-party
scripts on signing pages. Browser session state MUST live in IndexedDB (never
`localStorage`, cookies or URLs), SHOULD be encrypted with a non-extractable WebCrypto key,
and all tabs MUST serialise sending and `seq` allocation (for example with the Web Locks
API), persisting the new `seq` before a message leaves the browser. The specification states
the residual risk explicitly: an XSS on the dApp origin can use a live session, which is
bounded by the wallet (simulation, biometrics, permissions, limits), not by the transport.

### 10. Same-device flow

A dApp running in a mobile browser on the same device as the wallet SHOULD use an app-link
round trip (open wallet → sign → return URL) with push as the fallback.

### 11. Versioning

Every envelope and pairing URI carries `v`, with one cipher suite per version. New methods
are added at the method layer, not in the transport, in three namespaces: the bare
CHIP-0002 names (and `chip0002_` aliases); `chia_*`, wallet-built methods with the names
and JSON shapes of the Sage wallet's WalletConnect method set (`chia_send`,
`chia_takeOffer`, …), offered per wallet and answered `4004` otherwise; and
`xchonnect_*`, the methods the specification defines. Unknown extension fields in the inner
plaintext MUST be ignored; the outer envelope has no extension fields. Future key types
(passkey/secp256r1 members, Chia vault signatures) are carried by the method layer without
transport changes.

## Test Cases

Published as JSON in [`docs/spec/vectors/`](../spec/vectors/) (format and conventions in
its [`README.md`](../spec/vectors/README.md)). They are generated by the reference
implementation from fixed inputs, checked byte-for-byte by the test suite, re-derived from the recorded
inputs using the specification formulas, and verified independently by the Rust core and the
TypeScript SDK through its WASM build:

- [`pairing.json`](../spec/vectors/pairing.json): fixed keys, pairing secret, HPKE ephemeral
  input and origin key → pairing URI, `uri_sig_input`, `h_uri`, origin signature, HPKE
  `info` / `psk_id` / `aad_pair`, `enc`, `ct_pair`, transcript hash, `root_0`, epoch-0
  direction and chaining keys, and the SAS.
- [`envelope.json`](../spec/vectors/envelope.json): inner plaintext, key, nonce, direction
  and recipient mailbox → AAD, padded length and envelope, one case per padding bucket
  (1, 4, 16, 64, 256 KiB) including the boundary sizes.
- [`rotation.json`](../spec/vectors/rotation.json): chaining key and ephemeral X25519 keys →
  rotation transcript, next root and epoch keys.
- [`multiparty.json`](../spec/vectors/multiparty.json): `signCoinSpends` requests with
  `partialSign: true` — both sides of an atomic two-party swap through offer settlement
  payments (must be signed), the same swap with one side not asserting its payment (must be
  refused), and a spend asserting a settlement-looking announcement made by an
  anyone-can-spend coin (must be refused).
- [`negative.json`](../spec/vectors/negative.json): inputs that MUST be rejected, each with
  the expected error kind — wrong or tampered origin signatures, unknown key id, expired or
  over-long URI lifetimes, tampered and late pairing replies, unknown versions, oversized
  envelopes and plaintexts, ciphertext lengths that are not a bucket, wrong nonce length,
  unknown outer keys, a broad set of non-canonical CBOR encodings, tampered AAD (direction
  and recipient mailbox), tampered tags, non-zero padding, replayed and reordered `seq`,
  expired messages, over-long lifetimes and future `iat`.

A black-box **relay conformance suite** is published with the reference implementation and
can be run against any relay:

```
cargo run -p xchonnect-conformance -- relay https://relay.example.org
```

It covers token hashing, identical error responses for unknown mailbox and wrong token,
envelope validation, TTL eviction, quotas and rate limits, mailbox creation methods and
gateway policy, in both a hosted and a self-hosted profile.

Still to be provided: an equivalent wallet conformance suite (simulation, binding refusal
and approval behaviour are covered by the multi-party vectors, but not yet as a runnable
black-box suite).

## Reference Implementation

Repository: <https://github.com/xchonnect/xchonnect>. Code is Apache-2.0; everything
under `docs/`, including the specification and the test vectors, is dedicated to the public
domain under CC0 1.0.

| Component | Package |
|---|---|
| Protocol core: canonical CBOR, envelopes, pairing, sessions. No Chia dependency, no `unsafe` | `crates/core` (`xchonnect-core`, Rust) |
| Reference relay: mailboxes, TTL, rate limits, proof-of-work, tickets, push dispatch, OHTTP gateway | `crates/relay` (`xchonnect-relay`) |
| Reference push gateway: sealed token handling, expiry, per-device rate limits | `crates/gateway` (`xchonnect-gateway`) |
| Wallet-side signing safety on `chia-wallet-sdk`: simulation, signature policy, binding checks, permissions and limits | `crates/wallet-kit` (`xchonnect-wallet-kit`) |
| Browser/Node WASM build of the core | `bindings/wasm` (`xchonnect-wasm`) |
| Swift and Kotlin bindings for wallets (UniFFI) | `bindings/uniffi` (`xchonnect-uniffi`) |
| TypeScript dApp SDK with a CHIP-0002 provider adapter | `sdk-ts` (`@xchonnect/dapp`) |
| Black-box conformance suite | `conformance` (`xchonnect-conformance`) |
| Minimal web dApp and CLI wallet | `examples/` |

The parsers are fuzzed (`docs/fuzzing.md`) and the handshake is modelled in ProVerif
([`docs/spec/model/`](../spec/model/)). Wallet integration guidance for third-party wallets
is in [`docs/wallet-integration.md`](../wallet-integration.md); relay operation in
[`docs/operating.md`](../operating.md).

**Maturity.** The reference implementation is pre-1.0; only pre-releases are published
(`@xchonnect/dapp` on npm under the `next` tag, and `xchonnect-core` and
`xchonnect-wallet-kit` on crates.io from 0.1.0-rc.2). No external security audit has been
completed; one is planned before any mainnet recommendation. The reference push gateway implements sealed-token handling but not
yet the APNs and FCM senders. These limitations are stated in the project's public
documentation ([`docs/guides/security-and-privacy.md`](../guides/security-and-privacy.md))
and should be weighed when assessing readiness for "Final" status.

## Security

See Section 13 of the protocol specification: assets, nine adversary classes (A1–A9), the
threat table **T1–T21** with mitigations and residual risks, the security invariants, the
logging policy, and the known limitations. Key points:

- The relay cannot read or forge any envelope, even with full database and log access, and
  holds no key material. Replay and reordering are rejected inside the AEAD.
- Origin verification plus a two-sided SAS defends against pairing phishing; the single-use
  pairing mailbox and first-reply-wins rule turn a photographed QR code into a detectable
  race rather than a silent compromise.
- Wallets must simulate locally, display the net effect, verify multi-party binding, and
  require biometric approval per signature.
- Sealed push tokens keep device tokens from the relay; relay egress rules and gateway
  rate limits prevent the wake-up path being used as an SSRF proxy or device flooder (T21).
- OHTTP separates who from what; relay and transaction-submission infrastructure are kept
  separate.

Properties 1–4 of the pairing and session key schedule (session-key secrecy against relay
and network attackers even with a leaked origin key; the need for both the pairing secret
and the dApp pairing key to read a reply; origin authentication; transcript agreement) are
machine-checked by the ProVerif model in [`docs/spec/model/`](../spec/model/) under
unbounded sessions with the relay and network as attacker, including leaked-QR and
leaked-origin-key scenarios. The specification also states what is **not** provided: no
post-compromise security within an epoch (no double ratchet in v1), and no protection
against a phishing site that relays a genuine, live pairing QR code of the real dApp — for
which wallet-side simulation and net-effect display remain the defence.

Known limitations are stated in specification 13.6 and in the project's public
documentation, and include: the push gateway operator can link sessions of one device via
the device token; Apple and Google learn that a device received a push; without OHTTP the
relay host sees client IPs at the network layer; a TLS-terminating edge sees IPs, mailbox
ids and bearer tokens for direct traffic; there is no long-poll through OHTTP by default so
responses may be delayed by up to one poll interval; and standard (non-vault) keys have no
on-chain recovery or rotation.

An external audit of the reference implementation is planned before "Final" status.

## Additional Assets

| Asset | Location |
|---|---|
| Full specification | [`docs/spec/xchonnect-spec.md`](../spec/xchonnect-spec.md) |
| Specification changelog and change process | [`CHANGELOG.md`](../spec/CHANGELOG.md), [`PROCESS.md`](../spec/PROCESS.md) |
| CDDL for all CBOR structures | [`wire/envelope.cddl`](../spec/wire/envelope.cddl) |
| Pairing URI grammar and signature input | [`wire/pairing-uri.md`](../spec/wire/pairing-uri.md) |
| `/.well-known/xchonnect.json` JSON Schema | [`wire/xchonnect.schema.json`](../spec/wire/xchonnect.schema.json) |
| Relay HTTP API, error model, limits, OHTTP resources | [`wire/relay-api.md`](../spec/wire/relay-api.md) |
| Test vectors | [`docs/spec/vectors/`](../spec/vectors/) |
| ProVerif model of pairing and sessions | [`docs/spec/model/`](../spec/model/) |
| Known CHIP-0002 implementation deviations (informative) | Appendix A of the specification |

## Open items before submission

Tracked so the CHIP editors are not the ones to discover them:

1. **Specification version.** Release and tag `spec-v0.2` per
   [`PROCESS.md`](../spec/PROCESS.md), then cite that tag rather than the working file.
2. **OHTTP padding.** Spec 10.5 now pads OHTTP inner requests and responses to size
   buckets (and clarifies replay semantics); this draft does not describe it yet. Until
   it is carried over, Section 8 and
   the Security section need one more pass after it merges.
3. **Contact field.** Confirm the public contact address for the CHIP header; the entry
   above points at the repository's GitHub issue and security-advisory endpoints.
4. **CHIP number, Editor and Comments-URI** are assigned by the CHIP editors on submission.

## Copyright

Copyright and related rights waived via
[CC0](https://creativecommons.org/publicdomain/zero/1.0/).
