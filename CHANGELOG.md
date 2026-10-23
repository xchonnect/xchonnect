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

### Added

- The release publishes the MCP plugin `@xchonnect/mcp` (`agent-mcp/`) to npm with the
  SDK, under the same guarantees: packed in `npm-pack` without an OIDC token, again by
  `npm-pack-repro` with the same SHA-256, published unchanged after `@xchonnect/dapp` by
  the `npm` job (provenance, `next` for an rc, a re-run passes when npm has the tarball),
  with an SBOM of its own (`xchonnect-mcp-npm.cdx.json`). `agent-mcp` is now a member of
  the root npm workspace (its own `package-lock.json` is gone) and requires
  `@xchonnect/dapp` at exactly the release's version, which the workspace links to
  `sdk-ts`: the plugin is built, tested and packed on the SDK it ships with. The gate
  requires both at the tag's version, the link in `package-lock.json` and a sha512
  integrity for every package the lockfile fetches; the pack runs `npm audit signatures`
  after `npm ci`. The second build catches non-determinism and a compromise of one
  runner, not a bad pinned dependency: the lockfile is that control. No version of the
  plugin is published by hand; its trusted publisher is the owner's:
  [`docs/release.md`](docs/release.md), "`@xchonnect/mcp`
  and the SDK it requires" and "Once, before the first automated publish".

### Changed

- Release workflow: pushing a signed tag only verifies (gate, reproducible builds, SBOMs,
  crate packaging, image builds); publishing a GitHub release for the tag in the web UI
  publishes (images, signed assets attached to that release, npm, crates.io). The gate
  requires the release's pre-release flag to match the version.
  [`docs/release.md`](docs/release.md), "Cutting a release".
- Release workflow hardening (T15): every job that pushes, signs or publishes runs in the
  GitHub environment `release` (maintainer approval, `v*` tags only), only on a
  `refs/tags/v*` ref and only after every build and package job passed, and re-checks the
  release state, that the tag has not moved and the approval itself
  (`scripts/release-state-check.sh`, `scripts/release-approval-check.sh`). The gate pins
  the tag's signer: an SSH signing key of a login in `.github/release-maintainers.txt`,
  verified with `ssh-keygen`; with two listed maintainers the approver must not be the
  signer. Every job checks out the commit the gate resolved, by SHA. The npm tarball is
  built in `npm-pack` without an OIDC token and published unchanged (digest checked) by a
  job that builds nothing; a re-run passes when npm already has that tarball. The npm and
  crates.io trusted publishers must name the environment `release`; the owner's steps are
  in [`docs/release.md`](docs/release.md), "What the owner configures".
- Release workflow, second audit (T15): artifacts are no longer trusted between jobs.
  Each job that uploads one states its SHA-256 digests as a job output and every job that
  downloads it checks them (`scripts/release-artifact-sums.sh`); the binaries are built in
  two named jobs, the images job outputs the index and per-platform digests that
  `images-publish` must push, and `crates` uploads only `.crate` files with the digests
  `crates-package` stated. The npm tarball is built twice on separate runners and must
  match. The gate requires the tagged commit to be on `main`, and both the gate and the
  approval check read `.github/release-maintainers.txt` from `main`, which now pins each
  maintainer's SSH signing key fingerprints. BuildKit and the Dockerfile frontend are
  pinned by digest. `images-publish` pushes with the `release` environment's
  `GHCR_PUSH_TOKEN` when the owner sets one.
- Release workflow, third audit (T15): the workflow file is now
  `.github/workflows/release-publish.yml` ("Release publish"). Every tag up to
  `v0.1.0-rc.4` carries an older `release.yml` that any writer could run by hand on that
  tag to sign their own code under `release.yml@refs/tags/v0.1.0-rc.N`; the owner disables
  it by its workflow ID, and the npm and crates.io trusted publishers and the Sigstore
  verification identity name the new file. **Verifiers: the identity is now
  `…/.github/workflows/release-publish.yml@refs/tags/vX.Y.Z`**; the old one is untrusted
  for anything logged from 2026-10-14 on, and `docs/release.md` ("The old `release.yml`")
  records what rc.1 to rc.4 contained. Each binary and the SBOMs are rebuilt on a second
  runner (`binaries-<arch>-repro`, `sbom-repro`) and must match before anything is
  signed. `scripts/release-verify.sh` now checks the attestation of every versioned
  binary (it silently checked none), requires the release workflow on the tag as the
  signer (`--signer-workflow`, `--source-ref`) and fails when no binary is found. The
  owner checklist adds a write-access review and states plainly what a stolen
  administrator credential can still do while there is one maintainer.
- Release images run by digest only (T15): `deploy/compose.release.yaml` no longer reads
  `XCHONNECT_VERSION`; it runs `ghcr.io/xchonnect/xchonnect-relay@${XCHONNECT_RELAY_DIGEST}`
  (and `XCHONNECT_GATEWAY_DIGEST` for the gateway), and refuses to start without it.
  **Operators: replace `XCHONNECT_VERSION` in `deploy/.env` with the digests**
  `scripts/release-verify.sh --image` prints after verifying the signature. A tag verified
  with `cosign verify` and pulled afterwards could have been re-pointed in between;
  `deploy/README.md`, `docs/operating.md` (ONCE) and the quickstart now verify, then pull
  by the verified digest. `release-verify.sh` takes `--image` more than once, prints the
  verified digests, fails when an image's attestation cannot be checked unless
  `--skip-image-attestation` is given, fails on files in `--dir` that `SHA256SUMS` does not
  name, and warns when `--no-provenance` is used on a public repository.
  `docs/release.md`: the Rekor time of the legacy bundles cosign v2.6.0 writes is at
  `.rekorBundle.Payload.integratedTime`; npm's `latest` still names the hand-published
  `0.1.0-rc.1`; the owner checklist disables the old `release.yml` before the merge and
  adds the Actions settings and the review of every reachable secret.

### Documentation

- Security limitations brought up to date (security audit L1, L2, L4):
  [`docs/guides/security-and-privacy.md`](docs/guides/security-and-privacy.md) no longer says
  OHTTP inner sizes are unpadded (padding landed in 9b22b53) and states what is left (the
  bucket, rate and timing, spec 13.6); the agent plugin reaches the relay without OHTTP, so
  the relay operator sees the agent machine's IP for the pairing's life (also in spec 14 and
  the data inventory); without elicitation the pairing-code comparison rests on the agent
  repeating the user's answer (T3). Both are in `agent-mcp/README.md`, "Security".
### Security

- Relay (T16): mailbox creation with an API key and `POST /v1/tickets` are limited per
  customer (`XCHONNECT_CUSTOMER_CREATE_RATE`, default 600 a minute; a ticket is charged
  when minted). The key is publishable (it ships in dApps), and only posting had a
  per-customer limit, so anyone holding a key could create mailboxes without bound.
  `429 rate_limited` with `Retry-After`, before anything is stored.
  [`docs/operating.md`](docs/operating.md), [`relay-api.md`](docs/spec/wire/relay-api.md).
- Relay (T21): `XCHONNECT_GATEWAY_ALLOWLIST` entries are matched by scheme, host and
  effective port, then path prefix, instead of by string prefix. An entry without a final
  `/` (`https://push.wallet.app`) admitted `https://push.wallet.app.evil.com/…` and, since an
  allowlisted URL may use another port when waking, `https://push.wallet.app:8443/…`.
  Entries must be `https://host[:port]/[path/]` (a missing `/` is added; `http://` only
  with `XCHONNECT_DEV_ALLOW_INSECURE_GATEWAYS`), or the relay does not start; a URL with
  dot segments in its path matches no entry. An allowlisted gateway on another port can now
  be registered (it was refused at registration but accepted when waking). In allowlist
  mode every wake checks the stored URL against the list again, so push registrations made
  on an earlier relay under the old matching reach nothing the list does not admit now.
  [`docs/operating.md`](docs/operating.md).
- MCP plugin (T22): amounts in the wallet's answers (the rules' limits, balances) are
  checked as 1 to 40 digits (or a safe whole number) before they are converted; a malformed
  one gives a fixed `internal` error. Before, `BigInt` threw on it and its message, which
  carries the wallet's text however long, went back to the agent. The rules' limit periods (`day` or
  `week`), times and asset ids are checked the same way, with fixed messages that do not
  repeat the wallet's text; the wallet's name is shown only up to 64 characters, and
  `cancel_request` bounds the wallet's answer as `request_status` does.

## [0.1.0-rc.5] - 2026-10-13

Protocol version: 1
Spec version: 0.2 (draft)

### Added

- wallet-kit: Chia option contracts (TASK-78, spec 11.1.1). The simulation recognises
  the singleton launcher of an option minted in the request, the option singleton (mint,
  transfer, exercise) and its collateral coin (exercise, clawback), verifying every
  commitment within the request and leaving anything else `Unknown`. The prompt gains
  `AssetId::Option`, `Summary::options` (typed mint, transfer, exercise and clawback
  effects with their proven terms) and `OutputInfo::option` (collateral and launcher
  outputs, no longer payments to a stranger). An exercise by the user requires binding to
  the settlement payment of the collateral (4001 `unbound_exercise`). Intent kinds
  `option.*` and `loan.request` / `loan.take` are verified (`IntentReport::kind_verified`).
  Limits count locked collateral and the strike paid; options leaving the user count
  against an option limit of their own (Security, round 5). New fuzz
  target `option_spends`.

### Changed

- wallet-kit API (breaking for code that builds or matches these types): `AssetId`,
  `SpendKind` gain variants; `Summary` gains `options`, `OutputInfo` gains `option`,
  `ExecutedSpend` gains `outputs_bound`, `IntentReport` gains `kind_verified`. The implied
  fee counts option singletons' mojos as XCH. The native bindings store an option's
  daily total as `option:<id>` (never written: the day's option count is stored as
  `options`, see Security, round 5).
- wallet-kit API: `Intent::verify` takes the wallet's current unix time
  (`verify(&summary, now)`); the handlers pass `RequestContext::now`. New
  `option::MIN_OPTION_LIFETIME_SECONDS`, `option::expires_too_soon`,
  `option::collateral_lost_to_expiry`.
- wallet-kit API, so that later releases stop breaking it: `AssetId`, `SpendKind`,
  `OptionEffect` (and its variants), `OptionTerms`, `OptionOutput`, `Summary`,
  `OutputInfo`, `ExecutedSpend`, `BindingReport` and the new `ExerciseCover` are
  `#[non_exhaustive]`. A `match` on `AssetId` or `SpendKind` needs a wildcard arm; a wallet
  that builds a `Summary` or `OutputInfo` in its tests starts from `Default::default()`
  and sets the fields (`AssetId` defaults to XCH, `SpendKind` to `Unknown`).
- wallet-kit API (spec 11.2, final audit): `RequestContext` gains `signed_coins:
  &SignedCoins` (`released`, `sealed`: the host's record of its coins and signatures
  outside the wallet, with `add`, `spent`, `is_sealed`); `Broadcaster` gains the
  required `record(&BroadcastRecord)`, called before every broadcast, and by
  `handle_with_host` for every `signCoinSpends` it answers (all of the request's coins,
  `sealed` empty) after signing and before the signature is returned, with what the host
  must add to that record (`SignedCoins::sealed` maps each `sealed_digest` to the coins it
  is held for); new `sealed_digest`; `SubmitRequest` gains `signatures_released` (`true` is the strict
  default; `false` only for a wallet-built bundle the host broadcasts itself, returning
  only `{ transactionId, status }`). New `Linking` (`direct`, `sealed`),
  `BindingReport::linking`, `Prompt::SubmitCoinSpends::linking` and
  `verify_binding_as(spends, ownership, max_cost, linking)`; `verify_binding` is the
  `direct` rule. New 4001 reason `sealed_signature`, 4000 reason `record_failed`. The
  native bindings and the example
  wallet answer only methods whose signatures go to the dApp and pass an empty record.

### Security

Found by a security audit and a code review of the option support above before this
release was tagged; rc.5 never shipped without these fixes (spec 9.1, 11.1.1, 11.2;
`docs/spec/CHANGELOG.md`). Threats affected: T1, T2.

- wallet-kit: value could leave for a stranger inside an option mint while an intent
  declared no payments. A mint's collateral and launcher outputs are exempt from
  `recipients` only when the user holds the new option and its launch is guaranteed
  (`OptionOutput::user_holds_option`); otherwise they are payments to the option's owner,
  unnamed when the launch is not guaranteed. A mint whose eve is not 1 mojo, or whose
  launcher is more than 1, is not recognised.
- wallet-kit: a mint was shown as guaranteed though the counterparty funding its
  collateral could swap that spend and keep the money. `guaranteed` now requires the
  collateral to be created by the user's spends, linked to the user's spend asserting the
  launch; `option.mint`, `loan.request` and `loan.take` require it, so `loan.take` (a
  borrower funds the collateral) no longer verifies.
- wallet-kit: an exercise was accepted when a refund of the user's own money "covered"
  the collateral while the released collateral went to someone else. The exercise check
  now needs the user's spends to require one another and the user's guaranteed outcome
  in each collateral asset to contain the collateral less the strike and the fee; every
  other payment counts as spent, a clawback in the same request as nothing
  (`BindingReport::co_required`, `exercises`, `exercises_covered`).
- wallet-kit: XCH an option singleton pays out as even outputs is counted as XCH sent
  (and against the XCH limit); revocable-CAT collateral and strikes are no longer shown
  (unknown contracts).
- wallet-kit binding (spec 11.2): a CAT's ring announcements no longer bind a user spend
  transitively: the CAT layer derives them from the solution, which the signature does
  not cover. A partial request whose extra CAT coins are linked only through the ring is
  now refused with `unbound_partial`.

A re-audit of those fixes, also before the tag, found five more (N1-N5):

- wallet-kit binding (spec 11.2): `ASSERT_CONCURRENT_SPEND` no longer binds or links the
  user's spends. It names a coin, not a spend: a later spend of that coin the user signs
  (a send to oneself) satisfied it, and the dApp attached the user's earlier signed spend
  to that one, taking the user's coin without paying (a partial trade) or claiming the
  collateral of an exercise. Only coin announcements that one user spend of the request
  creates and another asserts link spends (`BindingReport::co_required`, guaranteed
  mints). The final audit below narrowed this further.
- wallet-kit: an option whose strike exceeds its collateral (airdropped by the attacker,
  strike paid to herself) padded the coverage of another exercise in the same request.
  Each option now counts its own strike, at most its own collateral, and only when the
  strike is in the collateral's asset; an exercise that loses value in the collateral's
  own asset is refused.
- wallet-kit: a fee the user's melt reserved counted as the user's own spending even
  when the released collateral paid it. The fee is credited only up to the XCH the user's
  own spends put into the bundle.
- wallet-kit: an even payment of an option held by the settlement puzzle was reported as
  a bound payment of the option; only an odd payment carries the option, an even one is
  XCH (`BindingReport::bound_payments`).
- wallet-kit: a loan request whose option had already expired verified as `loan.request`
  with no recipients, and the lender clawed the collateral back in the next block. The
  wallet refuses (4001 `option_expires`) a request locking the user's collateral under
  another creator within an hour of its expiry, whatever is declared; the mint kinds need
  an expiry more than an hour away (`Intent::verify(summary, now)`); and such collateral
  is a payment to the creator in `recipients`.
- wallet-kit: offers and partial requests whose user spends rely on a CAT's ring
  (`0xcb`) announcements or on `ASSERT_CONCURRENT_SPEND` to tie them together, as the
  Chia reference wallet's and the Wallet SDK's bundles may, are refused with
  `unbound_partial` (compatibility cost, `docs/guides/security-and-privacy.md`).

A final audit, also before the tag, found that binding through a link between two of the
user's spends could still be defeated (F1), and that Sage's own bundles were refused
(spec 11.1, 11.1.1, 11.2; `docs/spec/CHANGELOG.md`). Threats affected: T2.

- wallet-kit binding (spec 11.2): a coin announcement that one user spend makes and
  another asserts no longer binds when the request's signatures are released (every
  `signCoinSpends`, every dApp-built bundle, a signed offer such as a loan request). A
  dApp holding another signed spend of the announcing coin with the same announcement, and
  the signature of the announcing spend on its own, could swap the one for the other and
  take the user's coin without the payment. Now every user spend of a partial request
  must itself assert every payment the request's user spends assert; a mint is
  guaranteed only when the spend that creates the collateral asserts the launch; an
  exercise is co-required only when every user spend asserts the collateral's payment to
  the user, and each user spend counts in its cover only when it loses. Regression tests
  for the audit's proof of concept, and two new `multiparty.json` cases.
- wallet-kit: a wallet-built bundle the host broadcasts itself, with no signature leaving
  the wallet (`signatures_released: false`), no user coin with a signature outside it
  (`SignedCoins::released`) and every user spend signed with `AGG_SIG_ME` only, is
  **sealed**: its user spends are included together or not at all, so the links Sage's
  builders make (`ASSERT_CONCURRENT_SPEND`, coin announcements between user spends) count
  again there, and the fee the wallet reserved is credited up to the bundle's fee. Sage's
  unmodified bundles are accepted, shown and valid on chain: a mint with CAT collateral
  (guaranteed, `option.mint` holds), an exercise, an exercise whose fee comes out of the
  released XCH collateral, and offer takes (a CAT for a CAT with fees on both sides,
  several CATs for one, one for several). A signature the wallet made in a sealed bundle
  is never made again (`sealed_signature`, below).
- wallet-kit (spec 11.2, a focused audit of the sealed rule before the tag): the first
  version refused, until any coin of a sealed bundle was spent on chain, every request
  spending one of its coins. A bundle that could no longer be included because a coin in
  it that is not the user's was spent elsewhere then released its coins while they were
  unspent, and a signature over one of its spends, asked for alone, would have let the
  public aggregate be split and the user's other spends used without the payment; a
  bundle that expired or was refused with no coin spent kept its coins locked. The
  wallet's record now holds the exact signatures of each sealed bundle, per coin, until
  that coin is spent on chain (`SignedCoins::sealed`, reported to the host before the
  broadcast through `Broadcaster::record`, also for a bundle the network refuses), and
  the kit never signs one of them again in any request (`signCoinSpends`,
  `xchonnect_submitCoinSpends`, `signMessage`; 4001 `sealed_signature`); a different
  spend of the same coin is signed as usual. The documentation says that the fee of a
  sealed bundle must be the wallet's own choice, never a dApp's parameter. Regression test
  for the audit's proof of concept.
- wallet-kit (spec 11.2, round-4 audit): the kit records the coins of every
  `signCoinSpends` answer as released itself, through `Broadcaster::record`, before the
  signature is returned; when the host cannot store it the dApp gets 4000
  `record_failed` and no signature. A wallet that forgot to record them could treat a
  later bundle spending those coins as sealed. Through `handle` (no broadcaster) the
  host still records them. Sealed lookups are one hash lookup (`SignedCoins::sealed` is
  keyed by digest). The documentation now requires hosts to process signing requests
  (`signCoinSpends`, `xchonnect_submitCoinSpends`, `signMessage`, wallet-built spends,
  from any source) one at a time, holding the record across the approval prompt, since
  the kit reads it when a request starts; to record into `released` every signature made
  outside the kit (the wallet's own interface, offers, other dApp protocols); and to
  forget a coin only once its spend is final in the wallet's own verified sync (at least
  6 blocks recommended), never on a peer's report.

A fifth audit round, also before the tag, found that a sealed bundle could be split after
pruning, that spends the wallet signs inside unknown contracts escaped the binding check,
that the sealed fee credit trusted the host, and three smaller gaps (spec 9.1, 9.3, 11.1,
11.1.1, 11.2, 13.6; `docs/spec/CHANGELOG.md`). Threats affected: T1, T2, T13, T14.

- wallet-kit (S1, spec 11.2): a wallet-built bundle whose user spends were each bound
  but did not require one another was read as sealed; once one of its coins was spent
  and the host pruned that coin's record, a second signature over its message let the
  public aggregate be split. A request with more than one user spend is now sealed only
  when every user spend requires every other through the sealed links (else it is read
  as released, where it needs direct binding). The record is now per bundle:
  `SignedCoins::sealed` maps each signature's digest to the bundles it was made in,
  `SignedCoins::sealed_bundles` holds each bundle's unspent user coins, and
  `SignedCoins::spent` forgets a bundle's signatures only when every coin the wallet
  signed for in it is spent. Never pruning is documented as the safe default.
- wallet-kit (U1, spec 11.1 item 3, 11.2): a spend the wallet signs but does not
  recognise as the user's (an unknown contract around the user's key: an NFT, a vault, a
  wrapped standard coin) was left out of the binding check and the net effect. Every
  spend the kit would sign is now a user spend (`simulate::claim_signed`) for binding,
  linking, the sealed rules and the limits; its coin counts as sent, its outputs are
  marked `OutputInfo::unaccounted` and never received, and `Summary::unaccounted_spends`
  lists it. A multi-party request containing one is refused (4001 `unknown_partial`).
- wallet-kit (H1, spec 11.1.1, 11.2): the sealed fee credit trusted whatever fee the
  bundle reserved. `SubmitRequest` gains `wallet_fee`, the fee the wallet itself chose
  (never a dApp's parameter); the credit is at most that fee, and a request whose user
  spends reserve another fee is read as released.
- wallet-kit (N-a, spec 11.1.1): in a sealed exercise the mojos of a melted option beyond
  one, landing in the user's change, counted as XCH received toward the collateral. Each
  option now counts one mojo.
- wallet-kit (N-b, spec 11.2): binding ran only for `partialSign` and
  `aggregatedSignature`; a request that spends another party's coin without them was not
  checked, so the dApp could drop those spends. Binding now runs whenever the request
  spends a coin that is neither the user's nor created within the request
  (`unbound_partial`). An exercise that is both unbound and not covered is reported as
  `unbound_exercise`.
- wallet-kit (T13/T14 residual, spec 11.1 item 5, 9.3): options had no spending limit.
  `DappPermissions::options` limits the number of options leaving the user (a transfer
  to anyone else, an offer; not an exercise), one per request and five per day by
  default (`DEFAULT_OPTION_LIMIT`, `DEFAULT_OPTIONS_PER_DAY`); `DailySpend::options` holds
  the day's count; refusals are 4029 `options_per_request` / `options_per_day`.
  `guaranteed_loss` lists each option leaving as `AssetId::Option(id) => 1`.
- wallet-kit: new `host_checks` module (`HostRecord`, `RequestGate`,
  `check_sealed_record`, `check_one_at_a_time`) that a wallet host runs from its own
  tests against its real record storage and request lock (stored before the broadcast,
  refused after a reload, pruned per bundle, a storage failure stops the broadcast, one
  request at a time): the conformance suite reaches a wallet only as a dApp, which
  cannot ask for a sealed request.
- wallet-kit API (breaking): `SubmitRequest::wallet_fee: u64`; `BroadcastRecord::sealed`
  is `Option<SealedBundle { id, digests, coins }>`; `SignedCoins` gains `sealed_bundles`
  and `sealed` maps a digest to bundle ids; `DappPermissions::options: AssetLimit`;
  `DailySpend::options: u128`; `OutputInfo::unaccounted`, `Summary::unaccounted_spends`;
  new `simulate::claim_signed`, `ExecutedSpend::signed_unrecognised`,
  `verify_binding_signed`, `SealedBundle`. The native bindings apply the default option
  limit and store the day's count as `options` in their limit JSON.
- The `option_spends` fuzz target also runs the request handlers: a partial request that
  reaches the prompt is bound and has no unrecognised user-key spend, and a wallet-built
  request read as sealed has co-required user spends. Regression tests for each finding
  (`round5_audit_tests.rs`, `option_sage_tests.rs`, `binding.rs`, `permissions.rs`).
- Documentation: the signed-conditions rule guarantees the shown conditions for the
  standard puzzle only; coin-bound variants other than `AGG_SIG_ME` are noted (spec 11.1
  item 2).

Signature policy, affecting every release since 0.1.0-rc.1 (spec 11.1 item 2;
`docs/spec/CHANGELOG.md`). Threats affected: T1.

- wallet-kit: the wallet signs an `AGG_SIG_ME` for its keys only when its message is the
  tree hash of a quoted program `(q . conditions)` the spend's solution reveals, and only
  one such message per key and spend; otherwise `signCoinSpends` and
  `xchonnect_submitCoinSpends` refuse with 4001 `unsigned_conditions` before the prompt
  (`Refusal::UnsignedConditions`). The conditions the wallet simulated and showed are then
  the only ones its signature authorises, wherever the standard puzzle sits (bare, CAT,
  option, option collateral). dApps must build the user's standard spends with a quoted
  delegated puzzle, as the Wallet SDK's `StandardLayer` does; wallet-built and SDK-built
  bundles are unaffected.
- wallet-kit: an `AGG_SIG_UNSAFE` for the wallet's keys whose message ends with the
  additional data of a coin-bound `AGG_SIG_*` variant (this network, mainnet or testnet11)
  or is 32 bytes long (a `signMessage` digest) is refused (`agg_sig_unsafe`) even when the
  user allowed `AGG_SIG_UNSAFE` for the dApp.
- wallet-kit: a request that spends the same coin more than once is refused (4000).
- conformance: `W-SIGN-06` checks that a wallet refuses a spend of its own coin whose
  delegated puzzle is not quoted; `W-SIGN-05` uses an `AGG_SIG_PARENT`, so it isolates
  the unknown-contract rule. The `option_spends` fuzz target checks the policy.

### Fixed

- wallet-kit: bundles built by the Wallet SDK's action system, as Sage builds them, are
  accepted unmodified when the wallet builds and broadcasts them itself without releasing
  their signatures (sealed, spec 11.2; `docs/wallet-integration.md`): a mint whose eve is
  the user's own puzzle (and launches from a 0-mojo launcher) is guaranteed; an exercise
  whose released collateral lands in the user's change is covered. With the signatures
  released, an exercise is covered when every user spend asserts the settlement payment
  of the collateral to the user, and an XCH-collateral mint from one coin is guaranteed.
- wallet-kit: a mint the user holds shows the option received (`net` +1, the eve is not
  counted as sent); a clawback shows the collateral returned (`net` + the collateral),
  not 0.
- wallet-kit: an intent can declare an option: `assetId` `option:<launcher id>` in
  `recipients` and `netChange` (a transfer with a declared recipient could not verify).
- wallet-kit: taking an offer that gives the user an option (an option singleton owned
  by the settlement puzzle) is bound like any settlement payment, and was refused with
  `unbound_partial` before. `OutputInfo::settlement` marks outputs to the settlement
  puzzle; `OptionEffect::Transfer::to_settlement` marks an option put on offer.
- The `option_spends` fuzz target also runs the binding and exercise-coverage check, under
  both linkings, with Sage-built seeds, raw and linked.

## [0.1.0-rc.4] - 2026-10-09

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
