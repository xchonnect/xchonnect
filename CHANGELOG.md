# Changelog

All notable changes to the Xchonnect implementation. The specification has its own
changelog in [`docs/spec/CHANGELOG.md`](docs/spec/CHANGELOG.md); the policy that governs
both, and the mapping between the protocol version and package versions, is in
[`docs/versioning.md`](docs/versioning.md).

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Protocol version: 1
Spec version: 0.2 (draft)

### Changed

- Specification: wallet-side execution (TASK-75) — the wallet broadcasts what it signs
  alone, `xchonnect_submitCoinSpends` with its intent schema, the `chia_*` wallet-built
  methods, one decision and one authentication per request (spec 8.3, 9.1, 11.1, 17;
  `docs/spec/CHANGELOG.md`). The code shipped this in 0.1.0-rc.1 (TASK-74); the text
  now says what it does. `docs/wallet-integration.md` and the CHIP draft follow.
- The data inventory has one informative copy, `docs/privacy/data-inventory.md`, which now
  also states the retention the reference implementation applies; the second table in
  `docs/guides/security-and-privacy.md` is replaced by a pointer. The normative table
  stays spec Section 14.
- **Relay: a missing database is a startup error.** Without `XCHONNECT_DATABASE_URL` the
  relay used to fall back to an in-memory store with a warning, and every redeploy
  dropped every mailbox, so every pairing. It now refuses to start unless
  `XCHONNECT_STORE=memory` asks for the in-memory store (development and tests);
  `XCHONNECT_STORE=memory` together with a database URL is refused too. The relay logs
  the store it runs at start (`store: postgres` / `store: memory`). Operators: production needs no change if
  it sets `XCHONNECT_DATABASE_URL` (`deploy/compose.yaml` does); a relay that ran in
  memory on purpose needs `XCHONNECT_STORE=memory`. The development commands, scripts and
  the quickstart set it. Threats affected: none.

### Fixed

- dApp SDK on phones, where the page is frozen while the user is in the wallet app:
  - Every relay call has a client-side deadline (a long poll `wait` + 10 s, others 15 s;
    `ClientOptions.timeouts`, `RelayClientOptions.timeoutMs`/`longPollGraceMs`), and a
    fetch that never settles no longer stops polling for good.
  - `visibilitychange` (visible), `pageshow`, `focus` and `online` abort the poll in
    flight and poll again at once; the new `client.resume()` does the same on demand.
    A hidden page checks again within a second instead of up to ten. After a reload the
    client resumes polling where it has something to wait for.
  - Request expiry runs on its own timer, so a request rejects with `4100` on time even
    while a poll is stuck.
  - A message that cannot be persisted (IndexedDB or lock failure) stays on the relay for
    the next pass; only invalid messages (replay, bad tag, wrong epoch) are acknowledged
    unread. Before, such a failure deleted the wallet's answer.
  - `IndexedDbSessionStore` opens the database again after the connection is lost
    (`close`, `InvalidStateError`, iOS's "Connection to Indexed Database server lost").
  - The cross-tab session lock gives up after 10 s (`lock_timeout`, retried) instead of
    waiting forever for a frozen tab.
  - `close()` aborts the long poll in flight and stops the loop; nothing fetched after
    `close()` is processed or acknowledged, so a new client on the same session gets it.
    Requests after `close()` reject with `closed`.
  - After `session.ready` the client keeps polling until the wallet's
    `session.permissions` arrives (at most 10 s), instead of reading it with the first
    request.
  - Answers, statuses and receipts that one tab reads for another tab's request are passed
    on to that tab (BroadcastChannel, same origin), as are `session.end` and
    `session.permissions`; each is tagged with a hash of the session's mailbox and epoch
    and checked for shape, and the SDK must not run on an origin shared with untrusted
    pages (`docs/guides/security-and-privacy.md`).
  - The poll loop pauses after any pass that brought no new valid message, also with long
    polls, so a relay that answers at once or keeps returning junk cannot make it spin.
    `Retry-After` is clamped to 1–300 s.
  - A session another tab ended (deleted from storage) ends in this client too, instead
    of being written back from memory.

  Threats affected: none (transport timing and local state handling; no wire change).
- Gateway: the APNs payload carries `content-available: 1` next to the alert and
  `mutable-content`, so iOS also wakes the wallet app in the background, with the phone
  locked, and the wallet can fetch the request before the user opens it. APNs
  `apns-expiration` and FCM `ttl` default to 600 s instead of 120 s. A wake inside a
  device's 10 s interval is no longer dropped: it goes out at the end of the interval,
  once (at most one pending per device; further wakes are coalesced into it), and counts
  against the hourly cap; new `deferred` counter on `/metrics`. Threats affected: T11
  (payload still identical for every device), T21 (rate per device unchanged).
- Relay: a message posted within 10 s of a mailbox's last wake-up no longer goes without
  one. One deferred wake-up goes out at the end of the window if the mailbox then still
  holds unacknowledged messages (at most one pending per mailbox; later ones are
  coalesced into it). Threats affected: T21 (still at most one wake-up per mailbox per
  10 s).

### Added

- dApp SDK: keep-alive polling. While the page is visible and a session is active the
  client keeps one long poll open (one request per `max_wait_s`), so a wallet's
  `session.end` or new `session.permissions` arrives within seconds. On by default where
  `document` exists, off elsewhere (`ClientOptions.keepAlive`). New `ended` event
  (`{ by: "wallet" | "dapp", reason? }`) next to `status`. `FakeWallet.end()` in
  `@xchonnect/dapp/testing`.
- `@xchonnect/dapp/testing`: the SDK's own test wallet (`FakeWallet`) and in-memory relay
  (`MockRelay`) are part of the npm package, so a dApp can pair and send requests in its
  tests and in the quickstart with no wallet app, no server and no Rust toolchain.
  `FakeWallet` takes a relay URL as well as a `RelayClient`. Not covered by semantic
  versioning.
- `deploy/README.md` and `deploy/compose.release.yaml`: self-hosting with the signed
  release images instead of a local build.
- The dApp quickstart starts from npm and a relay container; the repository build is the
  second path.

## [0.1.0-rc.3] - 2026-10-06

Protocol version: 1
Spec version: 0.2 (draft)

### Added

- Started with none of their settings, the relay and the gateway wait for them instead of
  exiting: `/up` answers, every other request gets `503 unavailable`, and what is missing
  is logged at start and every ten minutes. A host that deploys a container first and
  takes its settings afterwards (ONCE) can therefore deploy the images as they are; with
  `0.1.0-rc.2` such a deploy timed out, and the guide's `once update` never ran. As soon
  as one setting is given, a missing or wrong one ends the process as before, so a mistake
  in an update never replaces a running service.
  [`docs/operating.md`](docs/operating.md), "Waiting for settings" and "Running under
  ONCE". Threats affected: none (no protocol route, key or stored data is reachable while
  a service waits).
- The gateway stops on `SIGTERM`, as the relay does, so stopping its container no longer
  waits for the runtime's kill timeout.

### Changed

- The release images (`deploy/Dockerfile.dist`) listen on port 80 instead of 8787 (relay)
  and 8788 (gateway). Where a port mapping names the old port, or where the runtime does
  not let a non-root container bind a low port (host networking, some Kubernetes and
  Podman set-ups), set `XCHONNECT_LISTEN` or `XCHONNECT_GATEWAY_LISTEN`. The images built
  by `deploy/compose.yaml` keep 8787 and 8788.
- The gateway reads all of its settings before it listens and before it logs a platform
  as enabled, and names the address and the reason when it cannot listen.

## [0.1.0-rc.2] - 2026-10-06

Protocol version: 1
Spec version: 0.2 (draft)

### Added

- crates.io publishing of `xchonnect-core` and `xchonnect-wallet-kit` from the release
  workflow (TASK-76), so Rust wallets can depend on a released version instead of a path
  into a checkout: crates.io trusted publishing over GitHub OIDC, no
  `CARGO_REGISTRY_TOKEN`; core before wallet-kit, after every other artifact and npm.
  `scripts/release-crates.sh` packages both crates with `cargo package --locked`, builds
  them from the tarballs and checks the contents; the release gate refuses a tag whose
  crate versions differ from it. One-time setup and yanking in
  [`docs/release.md`](docs/release.md). Threats affected: T15 (no long-lived registry
  token exists to steal).

### Changed

- The workspace crates require each other with an exact version (`=X.Y.Z`): a published
  `xchonnect-wallet-kit` resolves to the `xchonnect-core` of the same release and nothing
  newer. Both crates now carry the `LICENSE` file in their package.
- The repository moved from `maximedogawa/xchonnect` to
  [`xchonnect/xchonnect`](https://github.com/xchonnect/xchonnect). Package metadata, READMEs
  and docs link to the new path, new container images are published as
  `ghcr.io/xchonnect/…`, and releases from this one on are signed under it. `v0.1.0-rc.1`
  was signed under the old path and is verified against it
  ([`docs/release.md`](docs/release.md)).

## [0.1.0-rc.1] - 2026-10-06

Protocol version: 1
Spec version: 0.2 (draft)

### Added

- wallet-kit answers the optional CHIP-0002 methods (spec 9.1) `getAssetCoins`,
  `getAssetBalance`, `filterUnlockedCoins` and `sendTransaction` when the wallet supplies
  its view of the chain through the new `ChainData` trait (`RequestContext::chain`), and
  `walletSwitchChain` for the session's own chain. Params are validated and bounded in
  the kit, every read is scoped to the keys exposed to the dApp, and the results have the
  CHIP-0002 shapes, with amounts above 2^53 − 1 and balances as strings. They are not in
  the default grant (`permissions::OPTIONAL_METHODS`); without `ChainData` they still
  answer `4004`. The UniFFI binding does not bridge `ChainData` yet.

- The relay and the gateway answer `/up`, the health route a ONCE app needs, and the gateway
  accepts the APNs key as text (`XCHONNECT_GATEWAY_APNS_KEY`) for hosts that cannot mount
  files. [`docs/operating.md`](docs/operating.md), "Running under ONCE". Threats affected: none
  (the key is read once at start-up, held zeroizing and never logged, as before).
- Push probe (TASK-46): `examples/push-probe` checks a gateway's APNs delivery on a real
  iPhone, with a CLI that seals a device token and wakes the gateway like a relay, and a
  minimal iOS app that shows its device token.
- Pre-release tags (`v0.1.0-rc.1`) are drafted as GitHub pre-releases.
- npm publishing of `@xchonnect/dapp` from the release workflow (TASK-67): trusted
  publishing over GitHub OIDC with provenance, no `NPM_TOKEN`; pre-releases go to the
  `next` dist-tag. One-time setup in [`docs/release.md`](docs/release.md).
- Release pipeline (TASK-59): reproducible builds of the relay and gateway binaries
  (`scripts/release-build.sh`) with a two-build digest gate
  (`scripts/release-repro-check.sh`), CycloneDX SBOMs for every artifact
  (`scripts/sbom.sh`), Sigstore keyless signatures and SLSA build provenance over the
  release manifest and the container images, a two-person release rule, and a
  verification procedure a third party can run (`scripts/release-verify.sh`,
  [`docs/release.md`](docs/release.md)).
- Continuous fuzzing and coverage (TASK-60): nightly ten-minutes-per-target fuzzing with
  a persistent corpus, crashes reported as private draft advisories, a request-level
  fuzz target for the relay's HTTP surface (`relay_http`), and coverage reporting for
  core, relay, gateway and wallet-kit (`scripts/coverage.sh`,
  [`docs/fuzzing.md`](docs/fuzzing.md)).
- Encrypted notification previews (TASK-48) exposed to native wallets:
  `openNotificationPreview(hintKey, sealed, now, allowDetail)` with `PreviewKind`,
  `Preview` and the `OpenedPreview` outcome in the Swift and Kotlin packages. The call
  cannot fail — anything that does not authenticate, decode or pass the wallet's policy
  returns the generic alert — and the sender's detail line is dropped unless the wallet
  passes `allowDetail` (T11, T12).
- Versioning and changelog policy ([`docs/versioning.md`](docs/versioning.md)) and this
  changelog.
- Per-crate READMEs and complete registry metadata for the publishable crates and for
  `@xchonnect/dapp` (TASK-67).

### Fixed

- Relay: every error response now uses the uniform `{"error":"<code>"}` model
  (`docs/spec/wire/relay-api.md` §Errors). Rejections raised by the HTTP framework
  before a handler ran — an unmatched path, a method a route does not declare, a path
  that does not percent-decode to UTF-8 — used to answer with an empty or plain-text
  body (found by the `relay_http` fuzz target, F-1). 405 responses keep their `Allow`
  header and now carry the new `method_not_allowed` code.

### Security

- Core enforces the origin document's `return_url` same-domain rule
  (`xchonnect_core::origin::OriginDocument::check_bound_to`, called from
  `pairing::VerifiedUri::new`): the URL's authority must be byte-identical to the domain
  the pairing URI claims, so a dApp whose origin key leaked cannot turn a wallet's
  same-device return into a one-tap redirect off the domain the wallet just displayed
  (T18, T3). The rule previously existed only as prose in
  `docs/spec/wire/xchonnect.schema.json`, leaving every wallet to re-implement the host
  check. The comparison is on the whole authority and exact, so a subdomain, a port,
  userinfo, a trailing dot, a lookalike registration and a differently-spelled form of
  the same name are all refused; the document is rejected, not silently stripped.
- The `relay_http` fuzz target asserts that no request produces a 500, that every
  response carries the privacy headers, that a presented capability token is never
  echoed back (spec 13.5, T15), and that every error body is the uniform model.
- Regression tests for two pieces of hardening that had none: the redacting `Debug`
  impls of the HPKE contexts cannot emit key material (T5, T13), and `ed25519_verify`
  refuses all eight small-order Ed25519 public keys (T20).

## Initial implementation - before 0.1.0-rc.1

Protocol version: 1
Spec version: 0.1

Protocol core, reference relay, reference push gateway, wallet-kit, WASM and UniFFI
bindings, TypeScript dApp SDK, conformance suites and examples, built up to the first
release candidate. Nothing before 0.1.0-rc.1 reached a registry.
