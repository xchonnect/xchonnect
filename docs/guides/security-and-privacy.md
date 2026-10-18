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
   cannot be submitted without the payment it was traded for. Only a bundle the wallet
   built and broadcasts itself, whose signatures never leave it, may rely on links between
   the user's own spends instead.
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

The inventory is one table, spec Section 14: what each kind of data is, where it lives,
why, and for how long. It is not repeated here, because a second copy drifts, and this
one did. What the shipped relay and gateway actually hold and expose is
[`docs/privacy/data-inventory.md`](../privacy/data-inventory.md): the same rows mapped
to the surfaces the checks observe (database, logs, metrics, billing, the wake request,
the push delivery), the exact relay schema, the retention the reference implementation
applies, and what the checks do not cover. That file is machine-checked in both
directions — `privacy/tests/full_session.rs` and `scripts/privacy-scan.sh` fail when it
and the code disagree, and `privacy/tests/source_policy.rs` fails when it and the spec's
table disagree — so it is the one to read for what is true of this code, and the one a
hosted operator starts from for their own published inventory, which must add any
TLS-terminating edge and what it observes (spec 10.3).

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
- **The dApp SDK assumes the origin is the dApp's alone.** Tabs of one origin share the
  session (IndexedDB) and pass decrypted answers, statuses, `session.end` and
  `session.permissions` to each other over a `BroadcastChannel` (`xchonnect:<storageKey>`),
  tagged with a hash of the session's mailbox and epoch and checked for shape, but not
  authenticated: any script on the origin can read or post there, as it can read the
  session store. Do not run the SDK on an origin shared by several tenants or with
  untrusted pages (a hosting domain that serves many sites from one origin); give the
  dApp its own origin.
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
  unverified (spec 11.2). Only offer settlement-payment announcements bind; links between
  the user's own spends count only in a sealed wallet-built request (below).
- **Links between the user's spends do not bind once the signatures are released**
  (spec 11.2, re-audit N2 and final audit F1 of rc.5). `ASSERT_CONCURRENT_SPEND` names a
  coin, not a spend, and a coin announcement names a coin and a message: a dApp that holds
  another signed spend of the linked coin (one the user signed for another request) and
  the signature of the linking spend on its own can put the one in place of the other and
  keep the user's coin without paying. So for `signCoinSpends`, every dApp-built bundle
  and a signed offer (a loan request), every user spend must assert every payment it
  depends on itself, the spend that creates an option's collateral must assert the launch,
  and every user spend of an exercise must assert the collateral's payment to the user.
  Compatibility cost: offers and dApp-built bundles whose user spends rely on such links
  (the Wallet SDK's `Relation::AssertConcurrent`, a ring of coin announcements, possibly
  the Chia reference wallet's offers) are refused with `unbound_partial`,
  `unbound_exercise` or a mint that is not guaranteed.
- **A sealed wallet-built request rests on the wallet's record of its signatures.** When
  the wallet builds a bundle, broadcasts it itself and returns only the transaction id,
  the kit counts the user's own links (Sage's bundles pass unmodified), because each user
  signature exists only inside the broadcast aggregate, which validates only whole. That
  holds only while the wallet never makes any of those signatures again: the aggregate is
  public once broadcast and BLS signatures are deterministic, so one more signature over
  the same message would split it. The host must list every coin with a signature outside
  the wallet (`SignedCoins::released`) and keep, until every coin the wallet signed for
  in that bundle is spent on chain, the exact signatures of every sealed bundle it
  broadcast or tried to (`SignedCoins::sealed` and `sealed_bundles`, which the kit
  refuses to sign again in any request; the kit hands both over through
  `Broadcaster::record` before each broadcast, and `SignedCoins::spent` prunes per
  bundle). A host that forgets a released signature, drops a sealed entry early (for
  example when the coin it names, or another coin of the bundle, is spent, or the bundle
  expires), or hands the signed bundle of a request it declared sealed to anyone, reopens
  the attack above for that bundle. Never pruning is the safe default. A bundle is sealed
  only when its user spends all require one another (with more than one); spends that
  were each bound but not tied together could otherwise be separated once one coin is
  spent and pruned (rc.5 audit round 5, S1). The kit records
  the coins of a `signCoinSpends` answer itself (through `Broadcaster::record`, before it
  returns the signature) only when the host gives it a broadcaster; signatures the wallet
  makes outside the kit (its own interface, offers, other dApp protocols) are recorded by
  the host or not at all. "Spent on chain" is the host's call: dropping an entry on a
  peer's report or a spend that is later reorganised away lets the wallet sign the
  recorded message again (spec 11.2 recommends a verified spend at least 6 blocks deep).
  The kit reads the record when a request starts, before the prompt, and does not lock
  it: a host that runs two signing requests at once (two dApps, or a dApp and its own
  interface) lets a request opened before a sealed bundle was recorded sign one of that
  bundle's messages after it; hosts must process them one at a time (spec 11.2). None of this can be seen from
  outside the wallet, and the conformance suite cannot reach a sealed request: the kit's
  `host_checks` module checks a host's record storage and request lock, but only in the
  tests of a host that runs it. The uniffi binding
  takes no record: a wallet that answers `signCoinSpends` through it must not broadcast
  sealed bundles. The fee a sealed exercise reserves is credited up to the fee the host
  says the wallet chose (`SubmitRequest::wallet_fee`); a request whose user spends
  reserve another fee is read as released. A host that passes a fee a dApp chose as
  `wallet_fee` lets the dApp spend the user's collateral on fees. The user approves it
  as shown.
- **Spends the wallet signs inside an unknown contract are user spends** (spec 11.1 item
  3, 11.2; rc.5 audit round 5, U1). Any spend the wallet would sign counts for binding,
  the sealed rules and the limits, its coin counts as leaving the user and its outputs
  are marked unaccounted (`Summary::unaccounted_spends`, `OutputInfo::unaccounted`),
  never received. A multi-party request containing one is refused (`unknown_partial`).
  The kit cannot value what such a contract holds (an NFT): the limits count only its
  mojos.
- **A request that spends another party's coin needs binding even without
  `partialSign`** (spec 11.2; rc.5 audit round 5, N-b): otherwise the dApp could drop
  the other party's spends and use the user's signature alone. Coins the request itself
  creates (an option's launcher and eve) do not count as another party's.
- **Coin-bound signatures other than `AGG_SIG_ME`** (`AGG_SIG_PARENT`, `_PUZZLE`, `_AMOUNT`
  and their pairs) bind a signature to a parent, puzzle hash or amount that other coins
  can share, so the same signature authorises the same conditions for any such coin (spec
  11.1 item 2, note). The kit signs them for the wallet's keys but never treats a request
  that uses them as sealed. The quoted-program rule of spec 11.1 item 2 guarantees that
  the signed conditions are the shown ones for the standard puzzle only; for another
  puzzle the user allowed as an unknown contract it only limits which messages are signed.
- **Option contracts are recognised only in part** (spec 11.1.1, TASK-78). wallet-kit
  shows a mint, transfer, exercise or clawback of an XCH- or CAT-backed option with an
  XCH or CAT strike; spends it cannot verify stay unknown contracts and are refused
  unless the user allows those. Not recognised: NFT strikes and NFT collateral,
  revocable-CAT strikes and collateral, a launcher of more than 1 mojo or an eve of
  other than 1, and a mint whose collateral coin is created outside the request. A
  transfer shows the option and its new owner but not its terms (the bundle carries only
  their hash). A clawback is recognised by its shape (a two-leaf `p2_1_of_n` revealing an
  `augmented_condition` time lock to the creator) and names the option only when the
  request also spends it.
- **The option limit counts options, not their value** (spec 11.1 item 5). The
  collateral the user locks and the strike the user pays count against the limits of
  their assets (and XCH an option singleton pays out counts as XCH). An option leaving
  the user (a transfer to anyone else, an offer through the settlement puzzle; not an
  exercise) counts against `DappPermissions::options`: one per request and five per day
  by default. A valuable option and a worthless one count the same. Options carried no
  limit at all before this was added in rc.5 (audit round 5, T13/T14).
- **A loan request depends on the wallet's clock.** The kit refuses a request locking the
  user's collateral under another creator (a lender) within an hour of the option's
  expiry, using the time the host passes (`RequestContext::now`); a wrong device clock
  weakens this. The prompt shows the expiry; after it, the lender can take the collateral.
- **A mint funded by someone else is never guaranteed**, so an intent `loan.take` (the
  user lends against a borrower's collateral) is always refused: the borrower's funding
  spend can be replaced by one that keeps the money, and no condition in the user's
  spends can make the collateral coin exist. Lending needs the collateral on chain (or a
  binding for it) first.
- **An option exercise is signed only when the user's spends are co-required** and the
  user's guaranteed outcome contains the collateral (spec 11.1.1): with the signatures
  released, every user spend asserts the settlement payment of the collateral to the user;
  in a sealed wallet-built request, the user's spends are linked to one another. An
  exercise bundle that also makes any other payment in the collateral's asset (beyond the
  strike and the fee) is refused. Each option counts its own strike, at most its own
  collateral, so an exercise that loses value in the collateral's own asset is refused even
  when the user means it; in a sealed request the mojos of a melted option count as one
  mojo per option, whatever the option held; and with the signatures released the fee is credited only up to
  the XCH the user's own spends put in, so such an XCH-collateral exercise that pays its
  fee out of collateral absorbed into the change is refused.
- **A CAT's ring announcements never bind** (spec 11.2): the CAT layer derives them from
  the solution, which the user's signature does not cover. A partial request whose extra
  CAT coins are linked to the bound spend only through the CAT ring is refused
  (`unbound_partial`).
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
- **Agent sessions (spec 9.4) are a draft with no wallet behind them yet.** The agent
  plugin (`agent-mcp`, TASK-80) reads the rules and names the refusals, and its test wallet
  enforces them, but neither the wallet kit nor Klimper implements the rules
  (clapandpay-backlog TASK-143): until one does, a real wallet answers
  `xchonnect_getAgentRules` with 4004 and treats an agent like any dApp, asking the user for
  every request. Within the rules, once implemented, a wallet answers an agent without a
  prompt, so whoever controls the agent's machine can trade up to the user's limits; the
  plugin's README states it.
- **An agent pairs only with an origin.** A local agent has no domain: the plugin signs as
  the user's own domain (which must serve the origin document) or, in developer mode, as
  `localhost`, which only wallets in developer mode accept. Pairing an agent by a name the
  user gives and the SAS alone is not specified.
- **The agent plugin keeps its session key in the system keychain on macOS and Linux only.**
  On Windows, and with `XCHONNECT_MCP_KEY_FILE`, the key sits in a file next to the
  encrypted session, protected by file permissions alone.
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
