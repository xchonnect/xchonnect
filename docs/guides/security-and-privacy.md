# Security and privacy

What Xchonnect protects, what data exists and where, and — in the last section — what it
does **not** protect against. Spec Section 13.6 requires those limitations to be stated
honestly in public documentation, so they are not buried: read
[Known limitations](#known-limitations) before you decide to depend on this project.

The normative source is [`docs/spec/xchonnect-spec.md`](../spec/xchonnect-spec.md)
Sections 13 (security), 14 (privacy, data inventory) and 16 (operations). To report a
vulnerability, see [SECURITY.md](../../SECURITY.md).

## Guarantees

These hold for a correct implementation of the protocol (spec 13.4). They are design
invariants, not audited facts — see the limitations below.

1. **No component other than the wallet ever holds a signing key or seed.** Relays,
   gateways and dApps cannot sign. Xchonnect is non-custodial by construction: there is
   no key escrow and no "recovery" path through any server.
2. **The relay cannot read or forge a message**, even with a full database and log dump.
   Every message is sealed end-to-end with XChaCha20-Poly1305 under direction-specific
   keys (spec 5.2, 5.3); the relay holds no key material, and the AAD binds each envelope
   to its version, kind, direction and recipient mailbox, so a message can never be
   reflected or re-routed.
3. **A signature is produced only after on-device simulation, display of the net effect
   and biometric approval.** The wallet derives what a spend does from the conditions,
   never from dApp-supplied labels (spec 11.1).
4. **A partial signature is never produced for an unbound multi-party spend** (spec 11.2):
   every user spend must assert the counterparty's settlement payment, so the user's coin
   cannot be submitted without the payment it was traded for.
5. **The relay stores no Chia addresses, public keys, device push tokens or client IPs**
   (spec 7.1, 13.5). Mailbox ids are random 128-bit values, tokens are stored only as
   salted-label hashes and compared in constant time, timestamps are day-granular, and
   push tokens are sealed to the wallet vendor's gateway key.
6. **Pairing is bound to a verified domain.** A wallet derives session keys only for a
   pairing key signed by an origin key published at the claimed domain, and both sides show
   a 6-digit short authentication string the user must compare (spec 6.1–6.3).
7. **Replay and reordering are rejected** inside the authenticated envelope, independently
   of nonce uniqueness, so browser state rollback cannot weaken confidentiality — it only
   forces a re-pair (spec 5.3).

Properties 1–4 of the pairing and session key schedule (session-key secrecy against the
relay and the network even with a leaked origin key; the need for both the pairing secret
and the dApp key; origin authentication; transcript agreement) are machine-checked by the
ProVerif model in [`docs/spec/model/`](../spec/model/). Its README states the model's
limits; a model is not a proof about the code.

## Threat model in one page

Nine adversaries (A1–A9) and 21 threats (T1–T21) are tabulated in spec 13.2–13.3. The
shape of it:

| If this is hostile | What it can do | What stops it |
|---|---|---|
| The dApp frontend (A1) | Send any well-formed request through a live session | Wallet-side simulation, net-effect display, per-signature biometrics, per-dApp permissions and daily limits |
| A phishing site (A2) | Show its own QR or link | Origin signature against the claimed domain, domain display with homograph warnings, two-sided SAS, 5-minute single-use pairing code |
| The relay operator (A3) | Read the database and traffic; drop, delay, replay, reorder | End-to-end encryption, `seq`/`exp` replay rejection, day-granular storage, OHTTP, fallback relays |
| The network (A4) | Observe and modify outside TLS | TLS plus end-to-end AEAD; single fixed cipher suite per version, no downgrade negotiation |
| Apple/Google or the push gateway (A5) | See push metadata; suppress or spoof pushes | Content-free wake-ups; push only triggers a fetch and never carries a decision |
| A thief with the phone (A6) | Attempt to sign | Hardware-wrapped keys, biometrics per signature, spending limits |
| A supply-chain attacker (A7) | Ship a malicious dependency or build | Pinned dependencies, SBOM, reproducible builds, signed commits, no `unsafe` outside FFI glue |
| A spammer (A8) | Flood the relay or one mailbox | Proof-of-work on keyless mailbox creation, per-token rate limits, wake coalescing, egress rules |
| Legal compulsion (A9) | Demand stored data | Data minimisation: there is very little to hand over |

## Data inventory

From spec 14. "Relay" is the reference relay as shipped; a hosted operator must publish
its own version of this table, including any TLS-terminating edge (spec 10.3).

| Data | Where it lives | Why | Retention |
|---|---|---|---|
| Ciphertext messages | Relay | Store and forward | Until acknowledged; at most 7 days (default 24 h) |
| Mailbox id + token hashes | Relay | Routing and access control | Deleted after 30 days of inactivity or on request |
| Sealed push registration | Relay | Wake-ups (opaque to the relay) | With the mailbox; the sealed token itself expires within 90 days |
| Device push token | Push gateway, transiently | Deliver the push | Not stored beyond delivery |
| Business API key usage | Relay billing | Metering per customer, never per end user | As billing law requires |
| Session keys, permissions, limits | Wallet and dApp devices only | End-to-end encryption and policy | Until the session ends |
| Signed spend bundles | The Chia network | Settlement | Public and permanent |

What the relay **must not** store or log (spec 13.5): IP addresses, User-Agent strings,
mailbox ids in logs, token values, ciphertext, or per-request timestamps tied to a mailbox.
Log retention is capped at 14 days. The reference relay logs only startup, shutdown and
backend error descriptions.

## Known limitations

Spec 13.6 and the state of this repository, stated plainly. None of these are
hypothetical.

### The project has not been audited

**No external security audit has been completed.** The planned cryptography and
implementation audit (spec 16, backlog TASK-63) has not started: no firm is engaged, no
report exists, and nothing in this repository has been reviewed by anyone outside the
project. The code has been through an internal six-stage security review, fuzzing of the
CBOR and envelope parsers, property tests and a ProVerif model of the handshake — that is
not a substitute. Xchonnect is pre-1.0; do not use it to protect mainnet funds without
your own review (see [SECURITY.md](../../SECURITY.md), "Supported versions").

### Apple and Google learn that a device was woken

Push delivery goes through APNs and FCM. They necessarily learn that a particular device
received a push, and when. Payloads are content-free or encrypted and push text never
drives a signing decision (spec T11, T12), but the *fact* and *timing* of a wake-up are
visible to the platform vendor and cannot be hidden by this protocol.

The wallet vendor's **push gateway operator can link several sessions of the same device**,
because it decrypts the sealed token and therefore sees the same device token across
sessions. The relay cannot: wallets use a fresh sealed token per session, so the relay only
sees unrelated opaque blobs.

### OHTTP only helps when it is actually used

OHTTP hides the user's IP address from the Xchonnect relay **only while requests really go
through an independent OHTTP relay**. Specifically:

- Without OHTTP configured, the relay host sees client IPs at the network layer even
  though the relay software stores none of them.
- A TLS-terminating edge (CDN, load balancer, DDoS scrubber) in front of a relay sees
  client IPs, mailbox ids in URLs, bearer tokens and request timing for all direct
  traffic (spec 10.3). Operators must disclose such an edge.
- The OHTTP relay must be run by an independent organisation. If the same party runs both
  the OHTTP relay and the Xchonnect relay, the split buys nothing.
- The dApp SDK makes the current transport visible: `client.privacy` is `"ohttp"` or
  `"direct"`, and a `privacy` event fires on every change
  (`sdk-ts/src/ohttp.ts`). Falling back to direct HTTPS is **opt in**
  (`allowDirectFallback`, off by default) precisely so that a degraded transport cannot go
  unnoticed; a pinned-key mismatch never falls back. dApps are expected to show that state
  to users — a dApp that configures OHTTP but hides the state is not giving the privacy
  property it appears to.
- Through OHTTP there is normally **no long-poll** (`max_wait_ohttp_s` defaults to 0), so
  clients poll and a response can be delayed by up to one poll interval (spec 10.1).
- **Inner request and response sizes are not padded yet.** The OHTTP relay, which knows
  the client's IP, can infer from body sizes which endpoint was called and roughly how many
  envelopes a fetch returned. OHTTP today hides *who* talks to the relay, not the size
  pattern of their traffic. A spec amendment introducing OHTTP padding buckets is in
  progress; until it lands and is implemented, this limitation stands.
- The gateway's replay defence is a per-node, in-memory cache of recently seen
  encapsulated keys (10 minutes, 200 000 entries). Older replays, replays to another node
  and replays after a restart are processed. They are harmless for message delivery, but a
  replayed push-registration change or API-key mailbox creation is a real residual effect
  (see [operating.md](../operating.md), "Replays").
- The reference OHTTP gateway has been tested against Mozilla's `ohttp` crate and the
  independent `ohttp-js` implementation, but **not behind a production OHTTP relay**
  (for example Cloudflare Privacy Gateway or Fastly). Do that with your partner before
  going live.

### The relay is trusted for availability, not for confidentiality

The relay cannot read or forge messages, but it is on the delivery path, so it **can drop,
delay or reorder them** (spec T6). Nothing in the protocol prevents an operator — or an
outage, or a targeted DoS — from making a time-critical request arrive late or not at all.
The mitigations are operational, not cryptographic: the wallet fetches everything pending
on each wake-up, the dApp shows delivery state (`delivery` events) instead of pretending a
request was received, deployments use a documented fallback relay, and time-sensitive
contracts must be designed with timing buffers measured in hours, not seconds. A chain
settlement that cannot tolerate a late signature must not depend on this transport.

The relay also sees traffic *metadata* it cannot avoid seeing: that some mailbox received a
message of a bucketed size at some time. Padding to fixed buckets and day-granular storage
blunt this, but a global observer correlating timing across the network is outside what
this design defends against (spec T9, T10).

### Compromise, phishing and key recovery

- **Standard (non-vault) keys have no recovery and no rotation.** A lost seed or a stolen
  key cannot be remedied on-chain. Spending limits and biometrics reduce the damage from a
  stolen phone; they do not undo a key compromise (spec T13, T14).
- **A phishing site that relays a genuine, live pairing QR code of the real dApp** will
  pair the victim with the real dApp under the attacker's account. Origin verification does
  not catch this, because the origin really is the real dApp. The defence is wallet-side:
  simulation and net-effect display of what the user is actually signing (spec 13.4.1,
  property 6).
- **An XSS on the dApp's own origin can use a live session** to send arbitrary well-formed
  requests. Non-extractable storage keys stop exfiltration, not use. This is bounded by the
  wallet (simulation, biometrics per signature, permissions, limits), not by the transport
  (spec 12.1, residual risk).
- **No post-compromise security within an epoch.** There is no double ratchet in v1: an
  attacker who extracts the current epoch's keys can read that epoch until the session
  rotates. Earlier epochs stay confidential after erasure (spec 5.2, 13.4.1 property 5).
- A **compromised dApp origin key** can sign pairing URIs until it is removed from the
  published document. Wallets re-fetch on every pairing, so removal revokes it — but there
  is a window (spec T18).
- A **malicious app update or dependency** remains the highest-impact threat (spec T15).
  Pinned dependencies, SBOM, reproducible builds and two-person release signing are
  mitigations, not guarantees.

### Unfinished parts of the reference implementation

Documented so nobody discovers them in production:

- **No push wake-up has been observed on a real device.** `crates/gateway` implements
  sealed token handling, expiry, per-device rate limiting and senders for APNs
  (`apns.rs`, token authentication with a `.p8` key) and FCM (`fcm.rs`, HTTP v1 with a
  service account), but neither has been run against Apple or Google with real
  credentials, and no wake-up of a closed app has been recorded (backlog TASK-46 and
  TASK-47; the kit for that run is `examples/push-probe`). Until then, treat delivery
  as untested.
- **Encrypted notification previews are untested end to end for the same reason.**
  The format, the on-device helper (`xchonnect_core::preview`, exposed to wallets as
  `openNotificationPreview`) and the gateway's opaque carriage are implemented
  (TASK-48); what a real platform shows on the lock screen has not been seen. A preview never names an amount or an address unless the wallet
  passes `allowDetail`, and anything that does not authenticate shows the generic
  alert.
- **`SEND_MESSAGE` / `RECEIVE_MESSAGE` bindings are not recognised** by the reference
  wallet-kit; partial requests relying on them are refused rather than accepted
  unverified (spec 11.2). Only offer settlement-payment announcements and coin
  announcements of already-bound spends count as binding.
- **The native bindings do not bridge a `Broadcaster`, `ChainData`, `rpc.cancel` or
  `rpc.status`.** A Swift or Kotlin wallet built on `bindings/uniffi` answers 4004 to
  `xchonnect_submitCoinSpends` and the optional chain methods, and cannot withdraw or
  report progress on a request; it can still refuse and sign. The reference wallet uses
  the Rust crate directly and has all of it; the bridge is TASK-75's follow-up.
- **The dependency tree has not been through `cargo vet`.** The pre-release crates on
  crates.io (`xchonnect-core`, `xchonnect-wallet-kit`) are published with the checks of
  [`../dependency-policy.md`](../dependency-policy.md) — a reviewed lockfile and
  `cargo deny` — but without imported third-party audits of their dependencies (T15).
  `cargo vet` is planned before 1.0.
- Hosted-relay product features — how an operator packages, meters and bills a relay —
  are not part of this repository or of the specification.

### Out of scope by design

Xchonnect is a transport. It does not provide on-chain privacy, does not hide the spend
bundle from the public mempool once submitted (spec T7), does not define new signing
methods (that is CHIP-0002), and does not protect a user who reads an accurate prompt and
approves it anyway. Coercion of a key holder is out of scope for standard keys (spec T14).

## Reporting and response

Vulnerability reporting, scope, safe harbour and response targets:
[SECURITY.md](../../SECURITY.md). Operator and maintainer runbooks for key compromise,
relay compromise, a leaked sealed push token and malicious updates:
[incident-response.md](incident-response.md).
