# Xchonnect — Technical Stack and Improvements over WalletConnect

**Date: 2026-10-04 · Status: Draft v0.1 · Companion to [`docs/spec/xchonnect-spec.md`](../spec/xchonnect-spec.md)**

---

## 1. Is Xchonnect a "better WalletConnect"?

For **Chia on phones**: yes. For a universal, multi-chain wallet network: no, and it does not try to be. WalletConnect's strengths are its multi-chain reach, SDK ecosystem and the hundreds of wallets already integrated; none of that helps a Chia dApp whose users are on iPhones. Xchonnect wins on the four things that matter there: delivery while the wallet is closed, privacy by construction, no gatekeeper, and native support for Chia's multi-party spends.

### 1.1 What we keep from WalletConnect (credit where due)
- QR / deep-link pairing with a shared secret.
- Symmetric end-to-end encryption of all payloads; relay as a dumb pipe.
- JSON-RPC-style method layer with per-session permissions.
- Mobile linking (return-to-dApp redirects).

### 1.2 Technical improvements

| Area | WalletConnect v2 | Xchonnect | Why it matters |
|---|---|---|---|
| Transport | Persistent WebSocket to relay ("irn") | Store-and-forward mailboxes + HTTPS round trips | iOS suspends apps; sockets die; mailboxes don't |
| Mobile delivery | Optional push via Reown push server; wallets must implement; many don't | Push is first-class; vendor-run push gateway; content-free wake-ups | Requests reach a closed wallet reliably |
| Push credentials | Centralized push service | Each wallet vendor keeps its own APNs/FCM keys; device token sealed to the gateway, invisible to relay | Openness and vendor control |
| Relay operator | Reown's relay by default; project ID required | Anyone can run a relay; no accounts; capability tokens | No gatekeeper, self-hosting trivial |
| Metadata | Relay sees topics, timing, IPs, client metadata | Random rotating mailboxes, hashed tokens, padding, day-granular timestamps, no IP storage, OHTTP option | Privacy by construction, not policy |
| IP privacy | None | Oblivious HTTP (RFC 9458) with independent relay | Relay never sees client IPs |
| dApp authenticity | Verify API (Reown-hosted attestation) | Origin keys in `/.well-known/xchonnect.json` + Ed25519 signature on the pairing URI + SAS | Decentralized phishing defense |
| Pairing crypto | X25519 + symmetric key from URI | HPKE PSK handshake, transcript-bound keys, direction-specific keys, SAS, rotation | Standardized, auditable, forward secrecy across sessions |
| Payload format | JSON-RPC over JSON | Deterministic CBOR, padded buckets, 256 KiB max | Large spend bundles, traffic-analysis resistance |
| Method layer | CAIP-based, chain-agnostic | CHIP-0002 as-is | Zero semantic migration for Chia dApps |
| Multi-party spends | Not modeled | `partialSign` + mandatory binding checks in wallet | Offers, options, lending work safely async |
| Time-critical actions | dApp must be online and connected | Chain-event webhooks (nodexch) post pre-encrypted requests to the mailbox | Repay/exercise/liquidation prompts even if the dApp tab is closed |
| Replay/ordering | Relay-side message ids | `seq` + `exp` + `id` inside the AEAD | Relay cannot replay or reorder |
| SDK weight | Large JS bundle, many deps | Small core (Rust → WASM/UniFFI) + thin TS | Fits PWAs and native apps |

### 1.3 UX improvements

| Moment | WalletConnect today | Xchonnect |
|---|---|---|
| Pairing | QR → wallet; "session proposal" dialog with chain/method lists | QR or one tap link → wallet shows verified domain + 6-digit code; one approve |
| Request arrives (phone locked) | Nothing, until the wallet is opened and reconnects | Notification: "Pengui: signing request"; tap → simulate → Face ID → done |
| Same device (mobile browser) | Manual app switching; often loses the request | App-link round trip with automatic return to the dApp |
| What am I signing? | Wallet-dependent; often raw | Net-effect display computed on device: sent / received / fees / locked / expiry |
| Multi-party trade | Both sides online, fragile | Sign your part now; counterparty signs later; settlement submitted by whoever completes |
| Connection health | "Session expired", reconnect loops | No session to drop; status is simply "delivered / signed / expired" |
| Reliability feedback | Silent failure | dApp sees delivery state; wallet fetches pending on every open |
| Privacy | Not visible to user | Wallet can show "relay cannot see your IP or addresses" (verifiable, open source) |

---

## 2. Technical stack

### 2.1 Repository layout (monorepo `xchonnect`)

```
xchonnect/
  docs/                 spec, CHIP, business, this file
  core/                 Rust: envelope, pairing, sessions, test vectors
  bindings/
    wasm/               wasm-bindgen for browsers (dApp SDK)
    uniffi/             Swift + Kotlin bindings for wallets
  relay/                Rust service (axum): mailboxes, TTL, rate limits, OHTTP gateway
  gateway/              Rust service: push gateway (APNs HTTP/2, FCM v1)
  sdk-ts/               @xchonnect/dapp — TypeScript, CHIP-0002 adapter, WalletConnect shim
  conformance/          black-box tests any relay/wallet can run
  deploy/               Terraform/Nomad or Helm, EU regions
  examples/             minimal dApp, minimal wallet
```

### 2.2 Core (Rust)

| Concern | Choice | Notes |
|---|---|---|
| Key agreement | `x25519-dalek` | audited, constant time |
| HPKE | `hpke` crate (RFC 9180) | mode PSK, X25519/HKDF-SHA256/ChaCha20-Poly1305 |
| AEAD | `chacha20poly1305` | RustCrypto |
| Signatures | `ed25519-dalek` (origin keys) | — |
| KDF/hash | `hkdf`, `sha2` | — |
| Encoding | `ciborium` or `minicbor` (deterministic) | strict decode limits, fuzzed |
| Randomness | `getrandom` / platform CSPRNG | — |
| Chia | `chia-wallet-sdk` (simulation, conditions, signing) | wallet side only |
| Bindings | `wasm-bindgen` + `uniffi` | one core, three platforms |
| Testing | property tests (`proptest`), `cargo-fuzz` on CBOR/envelope, fixed test vectors | vectors published with the CHIP |

### 2.3 Relay (relayxch)

| Concern | Choice | Notes |
|---|---|---|
| Framework | Rust, `axum` + `tokio` | small, fast, memory-safe |
| Mailbox store | Redis (or Valkey) with TTL; AOF persistence | native expiry = retention policy enforced by the store |
| Metering | Postgres (per-customer counters only) | no per-user data |
| OHTTP gateway | `ohttp` + `bhttp` crates | key config at `/.well-known/ohttp-keys` |
| Rate limiting | in-memory token buckets per hashed write token + per customer key | no IP-based limits in logs |
| Long-poll | 25 s max, for web dApps while visible | no WebSockets |
| Edge | Cloudflare/Fastly in front for DoS, with IP logging disabled on the edge config | document residual visibility |
| Deployment | 2 EU regions (e.g. Hetzner Falkenstein + Helsinki, or Fly.io EU), active-active | strictly separate from nodexch `push_tx` fleet |
| Observability | Prometheus metrics (aggregates), OpenTelemetry traces without identifiers | 14-day log retention |
| Secrets | HSM/KMS for TLS and OHTTP keys | — |

### 2.4 Push gateway

| Concern | Choice |
|---|---|
| APNs | HTTP/2 with token-based auth (`.p8`), `a2` crate; `interruption-level: time-sensitive`; `mutable-content` for encrypted previews |
| FCM | HTTP v1 API, data messages (not notification messages) so the app decrypts and renders |
| Token sealing | HPKE to the gateway's long-term X25519 key; gateway key published in wallet app and rotated yearly |
| Statelessness | decrypt → send → forget; delivery failures counted, not stored with tokens |
| Multi-tenant hosting (relayxch Pro) | one isolated gateway instance per wallet vendor; vendor's APNs/FCM credentials in a dedicated KMS key; vendor can revoke anytime |

### 2.5 dApp SDK (TypeScript)

- `@xchonnect/dapp`: `pair()`, `request(method, params)`, `onDelivery()`, `rotate()`, `end()`; WASM core underneath.
- **CHIP-0002 adapter:** exposes `window.chia`-style `request({method, params})` so existing code paths work unchanged.
- **WalletConnect shim:** a drop-in that mirrors the `@walletconnect/sign-client` surface used by Chia dApps (`connect`, `request`, `disconnect`), so migration is a dependency swap plus a pairing UI change.
- Transport privacy: OHTTP client in the browser via the WASM core; fallback to direct HTTPS with a visible privacy indicator.
- Visibility handling: fetch mailbox on `visibilitychange`; never rely on a live socket.

### 2.6 Wallet integration (Klimper first)

- Rust core via UniFFI; SwiftUI (iOS) and Kotlin/Compose (Android) UI.
- Signing core: `chia-wallet-sdk` for simulation and net-effect computation; BLS keys wrapped by Secure Enclave / StrongBox; biometric per signature.
- Notification Service Extension (iOS) / FCM data handler (Android) for encrypted previews.
- Universal links: `https://klimper.app/pair` and `/req` with parameters in the URL fragment.
- Integration guide for other wallets: ~2 weeks for a wallet already built on the Wallet SDK (Sage-class), mostly UI.

### 2.7 Security engineering

- Threat model maintained in the spec (T1–T20); every PR touching crypto or parsing references a threat ID.
- Reproducible builds for Klimper and the relay; SBOM published; signed releases (2-person).
- External audit before mainnet GA; public bug bounty afterwards.
- Conformance suite runnable against any relay or wallet claiming compatibility.

---

## 3. Migration path for existing WalletConnect dApps

1. Add `@xchonnect/dapp` next to the existing WalletConnect client.
2. Offer both in the connect dialog: "Connect with Xchonnect (recommended on mobile)" and "WalletConnect".
3. Route the same CHIP-0002 method calls through whichever transport is active.
4. Measure: completion rate of signing flows on iOS per transport.
5. Keep WalletConnect for wallets that have not integrated Xchonnect yet; switch defaults once the main wallets support it.

---

## 4. Open technical questions (to decide before M1)

- CBOR vs JSON for the inner payload (CBOR chosen; JSON only if adoption suffers).
- Double ratchet in v1 or v2.
- Exact CHIP-0002 method set to require; `partialSign` semantics; confirm with Sage's implementation.
- OHTTP relay partner (commercial) vs community-run OHTTP relays (both?).
- Proof-of-work vs privacy-pass tokens for abuse control on the keyless Community tier.
- Whether relayxch Pro push-gateway hosting can be offered with provable credential isolation (per-tenant KMS + attestation) good enough for large wallet vendors.
