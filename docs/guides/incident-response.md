# Incident response runbooks

Runbooks for the scenarios spec Section 16 requires: compromise of origin keys, OHTTP
gateway keys or push credentials, a leaked sealed push token, relay compromise, and a
malicious update or dependency. They are written to be followed under pressure — in order,
without needing to re-derive the protocol.

**Audience.** Maintainers of this repository, and operators of the reference relay and
push gateway. If you run a third-party relay, gateway or wallet, these are a template:
your users report to you, and you own the disclosure.

For reporting a vulnerability (as opposed to responding to one), see
[SECURITY.md](../../SECURITY.md). For what the system does not protect against, see
[security-and-privacy.md](security-and-privacy.md).

## Before anything happens

Have these ready, or the runbooks below will stall:

| Item | Where |
|---|---|
| Secret store access (origin key, OHTTP seeds, PoW key, APNs `.p8` / FCM service account, DB password) | Your KMS/HSM; `deploy/example.env` lists every variable |
| Out-of-band contact for the OHTTP relay partner, push platform accounts and relay operators you serve | Operator runbook, not in this repository |
| A way to publish: repository, GitHub Security Advisories, status page, app-store release channel | — |
| `deploy/.env` and the current `XCHONNECT_OHTTP_KEYS` / `XCHONNECT_GATEWAY_KEYS` key ids | Your deployment |
| This repository checked out, toolchain installed | `cargo build --workspace` works |

**Honest note on roles.** This project currently has a single maintainer
(`.github/CODEOWNERS`). Every "decides" below therefore resolves to the same person, and
spec 16's two-person release signing is an aspiration, not a control that exists today. If
you depend on this project, that concentration is part of your risk; the roles are written
out so they can be assigned to different people as soon as there is more than one.

| Role | Decides |
|---|---|
| **Incident lead** | Declares and closes the incident; owns the timeline; the single voice to reporters and users |
| **Maintainer / code owner** | Whether a fix is correct; cuts the release; approves the advisory text |
| **Relay operator** | Whether to rotate keys, degrade service or take a node out; owns their own users' disclosure |
| **Wallet vendor** | Push credential rotation, forced app update, in-app warnings |
| **Project owner** | Anything outward-facing with legal or commercial weight: public statements beyond a security advisory, law-enforcement contact, engaging an auditor, paying a bounty |

## The clock

Spec 16 commits to **user-facing disclosure within 72 hours of confirming active
exploitation**. That clock starts at confirmation, not at the first report, and it is not
negotiable against "we would rather ship the fix first". A disclosure may say "we are still
investigating"; it may not say nothing.

```
T+0      Confirmed exploitation or confirmed compromise
T+1h     Incident declared, lead named, timeline file opened, containment started
T+24h    Preliminary scope: what was reachable, what was not, what we cannot rule out
T+72h    Public user-facing disclosure — required, even if incomplete
then     Fix, coordinated release, full advisory, post-mortem
```

For a reported vulnerability with no evidence of exploitation, the targets in
[SECURITY.md](../../SECURITY.md) apply instead (3 working days to acknowledge, 10 to
assess, normally 30 to fix critical/high).

## Step 0 — common to every incident

1. **Declare it.** One person is the incident lead. Say so in writing.
2. **Open a timeline file** and append every action with a UTC timestamp, including the
   ones that turned out to be wrong. Private repository or secret gist — never a public
   issue.
3. **Do not discuss it in public** (issues, PRs, chat, commit messages). A commit message
   like "fix pairing replay" is a disclosure.
4. **Preserve evidence before you change anything.** Snapshot the relay database and
   container logs; note that relay logs deliberately contain almost nothing (spec 13.5),
   so most of your evidence will be aggregate metrics and the client side.
5. **Decide: contain now or observe?** Default to contain. Observing is only worth it when
   containment would destroy the only evidence of who is exploiting it.
6. **Classify.** Does it break a spec 13.4 invariant (no component but the wallet holds
   keys; the relay cannot read or forge; no signature without simulation and biometrics; no
   unbound partial signature; the relay stores no identifiers)? If yes, it is critical,
   full stop.
7. **Start the 72-hour clock** if exploitation is confirmed.

---

## Runbook A — dApp origin key compromise

**Symptom.** The Ed25519 private key behind an entry in
`https://<domain>/.well-known/xchonnect.json` is leaked, or a pairing URI appears that you
did not sign.

**Impact.** The holder can sign pairing URIs that wallets will accept as *your domain*. It
does **not** let them read sessions, sign spends, or decrypt anything: session-key secrecy
holds even against an attacker who has the origin key (spec 13.4.1, property 1). The attack
is phishing — pairing a user with a dApp frontend the attacker controls. Wallet-side
simulation and the SAS comparison remain in the way (spec T18).

**Who decides.** The dApp operator, immediately; no upstream approval needed.

1. **Stop signing.** Disable the backend signing endpoint, so no new URI gets the
   compromised `kid`. Expect pairing to fail; that is correct.
2. **Generate a new key in the HSM/KMS** with a new `kid` (date-based, e.g. `2026-10b`).
3. **Publish a document containing only the new key** — *remove* the compromised entry
   rather than letting it expire. Wallets re-fetch on every pairing, so removal is the
   revocation mechanism (spec 6.1).

   ```sh
   curl -sS https://<domain>/.well-known/xchonnect.json | jq .
   ```

   Confirm the compromised `kid` is gone and that the file is served over HTTPS from the
   exact domain, with no redirect.
4. **Purge caches.** CDN, edge and anything else in front of the document. Wallets may
   cache for up to 24 hours (spec 6.1), so assume up to a day of stragglers.
5. **Point the SDK at the new key** (`kid`, and `originPublicKey` if you set it) and
   re-enable signing.
6. **Existing sessions are unaffected** and need not be ended: they were established with
   keys the origin key never had access to. Do not mass-revoke out of reflex — you would
   log every user out for no security gain. Do end sessions that were paired with URIs you
   can attribute to the attacker.
7. **Tell users** what to look for: sessions to your domain that they do not recognise, in
   the wallet's connected-dApps screen.
8. **Root cause.** How did the key leave the HSM? If it was ever outside one, that is the
   finding.

## Runbook B — OHTTP gateway key compromise

**Symptom.** An `XCHONNECT_OHTTP_KEYS` seed leaked, or a key id is being used in ways you
cannot account for.

**Impact.** The holder can decrypt encapsulated requests it can observe — so the OHTTP
relay partner, combined with this key, could see both client IPs and request content,
collapsing the privacy split. It does **not** break end-to-end encryption: envelope
contents stay sealed to the wallet and dApp.

**Who decides.** Relay operator, immediately. Notify the OHTTP relay partner.

1. **Remove the compromised key id at once** — do not keep it for the normal overlap
   period. Prepend a fresh key with a *new id* and drop the old one:

   ```sh
   openssl rand -base64 32 | tr '+/' '-_' | tr -d '='    # new seed
   # XCHONNECT_OHTTP_KEYS=3:<new seed>          (compromised id removed entirely)
   ```

   Roll it to **every** node — keys are derived deterministically, so all nodes must carry
   the same value or clients get inconsistent configurations
   ([operating.md](../operating.md), "OHTTP").
2. **Expect clients to break.** A client pinned to the removed key gets the RFC 9458
   `ohttp-key` problem and treats it as a hard error rather than falling back. That is the
   designed behaviour: a silent downgrade would be worse.
3. **Announce the new key configuration out of band** to dApp and wallet developers who
   pinned it, and publish `/.well-known/ohttp-keys`:

   ```sh
   curl -sS https://<relay>/.well-known/ohttp-keys | xxd | head
   curl -sS https://<relay>/v1/info | jq '{ohttp, max_wait_ohttp_s}'
   ```
4. **Consider the window.** Everything encapsulated under the compromised key that the
   partner (or anyone with a traffic capture) retained is readable: endpoints, mailbox ids,
   bearer tokens and envelope ciphertext. Treat the **mailbox tokens** as exposed for any
   session that used it, and ask affected wallets and dApps to rotate
   (`session.rotate` moves to new mailboxes and new tokens).
5. **If the leak was through the partner**, that contract is the incident. Spec 10 requires
   an independent operator under contract not to collude; a partner that leaked your key
   material is not that.
6. **If you cannot rotate immediately**, `XCHONNECT_OHTTP=false` is better than serving a
   compromised key: the relay then sees client IPs, which you must say in your data
   inventory, but nobody is misled into believing their IP is hidden when it is not.

## Runbook C — push credential compromise (APNs `.p8` / FCM service account)

**Symptom.** A wallet vendor's APNs key or FCM service account leaked.

**Impact.** The holder can send pushes to that app's users. It **cannot** make them sign
anything: a push only triggers a mailbox fetch, and all content comes from the
authenticated, encrypted mailbox (spec T12). The damage is notification spam and phishing
pressure ("open your wallet now").

**Who decides.** The wallet vendor. The relay operator's part is allowlisting.

1. **Revoke at the platform.** Apple Developer portal: revoke the `.p8` key. Google Cloud:
   disable and delete the service account key. Do this first — rotation without revocation
   leaves the attacker working.
2. **Issue new credentials** and load them into the gateway's secret store (HSM/KMS, spec
   16). They belong only to the gateway service.
3. **Restart the gateway** with the new credentials and verify delivery end to end on a
   test device.
4. **The sealed-token key is a separate key.** `XCHONNECT_GATEWAY_KEYS` (X25519) is what
   wallets seal device tokens to; it is unaffected by a platform-credential leak and does
   not need rotating. If *it* leaked, see Runbook D.
5. **Warn users** not to act on notifications: the real flow always shows the simulated
   effect and asks for biometrics. A push that leads anywhere else is not from you.
6. **Note what has not been exercised.** The reference gateway's APNs and FCM senders
   have not been run against Apple or Google with real credentials (TASK-46/47); if you
   run the reference gateway, this runbook applies to those senders as shipped and to
   any sender of your own.

## Runbook D — leaked sealed push token (or gateway X25519 key)

**Symptom.** A sealed push token from a `push_reg` was copied — from a relay database dump,
a replayed OHTTP request, or a backup — and is being POSTed to a gateway. Or the gateway's
own `XCHONNECT_GATEWAY_KEYS` secret leaked.

**Impact, sealed token only.** The token is opaque: whoever holds it cannot read the device
token inside it, cannot learn which mailbox it belongs to, and cannot put content in the
push. They can make the gateway wake that one device repeatedly. The defences that are
already in place (spec 7.3.2):

- the sealed token carries `exp`, at most 90 days ahead, and the gateway rejects expired
  tokens;
- the gateway rate-limits per device token — recommended at most 1 wake per 10 s and 60
  per hour — using in-memory state, so a replay cannot flood a device;
- the relay coalesces wake-ups to at most one per mailbox per 10 s;
- the gateway answers uniformly, so it is not an oracle for token validity.

1. **Confirm the rate limits are actually in force** on the running gateway, and tighten
   them for the affected device token if your deployment allows it.
2. **Re-register, which invalidates the old token.** The wallet creates a fresh sealed
   token and calls `PUT /v1/mailboxes/{id}/push`; the relay keeps only the newest
   registration, so the leaked one stops being used. Rotating the session
   (`session.rotate`) gives a new mailbox as well.
3. **Set `push_reg` to `null`** for that mailbox if the wallet cannot re-register promptly:
   wake-ups stop, messages still arrive, the user just has to open the app.
4. **If the gateway's X25519 key leaked**, this is much worse: the holder can decrypt every
   sealed token it sees and recover **device push tokens**, which link sessions to devices.
   Then: prepend a new key to `XCHONNECT_GATEWAY_KEYS` (newest first), keep the old key only
   as long as you must accept in-flight registrations, ship the new public key in an app
   update, and force re-registration of every session. The gateway logs its public keys at
   startup and serves them at `GET /v1/keys`; verify clients see the new one. Users whose
   device tokens were exposed should be told that the holder can link their sessions —
   that is a privacy breach and goes in the disclosure.

## Runbook E — relay compromise

**Symptom.** Unauthorised access to a relay host, its database, or its container registry.

**Impact first, because it bounds the panic.** An attacker with full database and log
access **cannot** read or forge any message: there is no key material on the relay (spec
13.4, invariant 2), and the AAD binds every envelope to its direction and recipient
mailbox. There are no stored addresses, public keys, device tokens or client IPs to steal
(invariant 5). What the attacker **can** do:

- drop, delay, duplicate or reorder messages — denial and timing manipulation, not forgery
  (spec T6);
- read mailbox ids, ciphertext and day-granular timestamps, and bearer tokens *in flight*
  (not at rest — tokens are stored only as hashes);
- see client IPs at the network layer for direct, non-OHTTP traffic, and everything a
  TLS-terminating edge sees (spec 10.3);
- tamper with push registrations to suppress or redirect wake-ups;
- if they control the binary or the container image, change all of the above — treat that
  as Runbook F as well.

1. **Take the affected nodes out of rotation** before investigating. A relay that is down
   is a correct relay: clients see delivery failures, and messages are not lost on other
   nodes.
2. **Snapshot** the database and logs for evidence, then stop the containers.
3. **Rotate every relay secret**, assuming all of them leaked: `XCHONNECT_POW_KEY`,
   `XCHONNECT_API_KEYS` (issue new keys to each business customer), `XCHONNECT_OHTTP_KEYS`
   (Runbook B), `XCHONNECT_DB_PASSWORD`, TLS material.
4. **Rebuild from a known-good image** — do not clean a compromised host in place. The
   images are distroless, run as uid 65532 with a read-only root filesystem and no
   capabilities ([operating.md](../operating.md)); a successful compromise means one of
   those assumptions broke, so find out which.
5. **Decide about the mailbox store.** Losing it only forces users to re-pair
   ([operating.md](../operating.md), "Backups and retention"). If you cannot establish that
   stored push registrations were untouched, dropping the store is the safer option.
6. **Verify the rebuilt relay** before taking traffic:

   ```sh
   curl -fsS https://<relay>/readyz                       # "ok (postgres store)"
   curl -fsS https://<relay>/v1/info                      # limits, creation methods, gateway policy, ohttp
   cargo run -p xchonnect-conformance -- relay https://<relay> --api-key <key>
   ```

   The suite checks token hashing, identical error responses for unknown mailbox and wrong
   token, envelope validation, TTL eviction, rate limits, creation methods and gateway
   policy. Pass `--api-key` or the API-key checks report "needs --api-key", and expect the
   gateway-registration check to fail against a relay whose `allowlist` is empty — neither
   is a compromise signal. A rebuilt relay that fails anything else is not fixed.
7. **Tell your users what the relay could and could not see**, in those terms. Resist both
   extremes: "no user data was affected" is false if direct traffic exposed IPs and
   mailbox ids; "your funds may be at risk" is false — the relay cannot sign.
8. **Advise clients to rotate.** `session.rotate` moves every session to new mailboxes and
   new tokens; dApps can call `client.rotate()`, wallets `session.beginRotation`.
9. **If a hosted customer's API key was used**, tell that customer: their metering and
   quota are affected even though their users' content is not.

## Runbook F — malicious update or dependency (supply chain)

**Symptom.** A dependency advisory lands on something we ship, a release artifact does not
match a reproducible rebuild, or a commit appears on a protected branch that no maintainer
made. This is spec T15, the highest-impact threat in the model.

**Who decides.** Maintainer and code owner, with the project owner for anything said in
public.

1. **Stop distribution.** Yank or unpublish the suspect release; pull the container image
   tag; pause the app-store rollout. A malicious signing core can exfiltrate seeds — speed
   matters more than tidiness here.
2. **Establish the blast radius.** Which released versions contain the bad code? Does it
   reach `crates/core`, `crates/wallet-kit` or the bindings (key material and signing), or
   only the relay (no key material)?
3. **Check the supply-chain gates** — if they were green when they should have been red,
   that is a second finding:

   ```sh
   cargo deny check                 # licences, bans, RustSec advisories, crates.io only
   npm audit --omit=dev
   cargo tree -i <suspect-crate>    # who pulled it in
   git log --show-signature -20     # unsigned or unexpected commits
   ```
4. **Verify the lockfiles.** `Cargo.lock` and `package-lock.json` are committed and CI
   `scripts/verify.sh` builds `--locked` / `npm ci`, as does the release workflow
   ([dependency-policy.md](../dependency-policy.md)). An unexplained lockfile diff is the
   fastest way to spot an injected dependency.
5. **Rebuild reproducibly from source** at the tag and diff against the published artifact.
   If they differ and you cannot explain why, treat the build infrastructure as
   compromised, not just the artifact.
6. **Rotate build and signing credentials**: CI tokens, registry tokens, release signing
   keys, and any maintainer credential that could have pushed.
7. **Fix forward.** Remove or pin the dependency under
   [dependency-policy.md](../dependency-policy.md) rule 2 (purpose, maintainer, licence,
   `unsafe` usage, audit status, why nothing existing suffices), then release.
8. **Disclose with version ranges and hashes**, so downstreams can tell whether they shipped
   it. Downstream wallets have app-store review latency measured in days — they need the
   exact affected versions, not a narrative.

---

## Security advisory process

For a reported or discovered vulnerability, as opposed to an active compromise.

### 1. Private intake

Reports arrive through GitHub private vulnerability reporting
([SECURITY.md](../../SECURITY.md)). Downstream projects route findings here rather than
fixing locally — the Klimper wallet (clapandpay) forwards Sage engine findings to
`xch-dev/sage` and findings in the Xchonnect libraries to **this** process. That makes
this intake path load-bearing for a project we do not control, so it must stay reachable
and answered within the SECURITY.md targets even when nobody expects a report.

Acknowledge within 3 working days. Open a **private** GitHub security advisory draft
immediately: it is the working surface for the fix and the audit trail.

### 2. Triage

Reproduce, then assign severity. Anything that breaks a spec 13.4 invariant is critical.
Record the threat ID (T1–T21) the finding maps to, or state that it is a new threat — in
which case the spec's threat table needs an entry (`docs/spec/PROCESS.md`).

Decide whether the specification is wrong or only the implementation. A spec flaw means
every implementation is affected, not just ours, and the advisory must say so.

### 3. Private fix

Develop on a **private fork** of the advisory, never on a public branch. The commit
message says what the code does, not what it exploits, until the release is out. Add a
regression test, and a test vector if bytes on the wire change (`CONTRIBUTING.md`).
`scripts/verify.sh --full` must pass:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
./scripts/relay-conformance.sh
npm run typecheck && npm test
```

### 4. Coordinated release

Agree an embargo date with the reporter. Give downstream wallet vendors advance notice
under embargo where a mobile release is needed — app review takes days and a published
advisory without an available fix leaves their users exposed. Publish the fix, tag the
release, and publish the advisory in the same window, not hours apart.

### 5. Advisory

The advisory states: affected versions and components, the impact in terms a user can act
on, the fix version, workarounds, the CVSS vector if assigned, the threat ID, and credit
to the reporter unless they decline. Where the spec changed, link the
`docs/spec/CHANGELOG.md` entry. Where the finding showed a documented limitation is worse
than described, update [security-and-privacy.md](security-and-privacy.md) — that page is
only useful if it stays true.

### 6. Post-mortem

Within two weeks: what the gap was, why tests and review did not catch it, and the one
concrete change that would have. Append new invariants to the spec's security invariants or
the fuzz corpus rather than to a wiki nobody reads.

## Dry run — 2026-10-05

The process above was exercised end to end on a deliberately chosen non-issue, to confirm
the mechanics work before a real report arrives.

**Scenario.** "The relay accepts an envelope whose ciphertext length is not one of the
padding buckets, so a malicious dApp can fingerprint traffic by size." Plausible, maps to
T9, and testable.

**What was exercised.**

| Step | Result |
|---|---|
| Triage against the spec | Spec 5.3 requires receivers to reject ciphertexts whose length is not a bucket size, and 7.2 requires the relay to validate the outer envelope including the bucketed length |
| Reproduce | Not reproducible. `docs/spec/vectors/negative.json` already contains a "ciphertext not a bucket size" case, and the relay conformance suite exercises envelope validation |
| Verification commands | `cargo test --workspace --locked` passes, and `./scripts/relay-conformance.sh` reports 34 passed / 0 failed / 10 skipped against the reference relay (hosted and self-hosted profiles, in-memory store; the skips are opt-in slow checks and checks not observable in `open` gateway mode) |
| Severity | Not a vulnerability: behaviour is as specified and tested |
| Disposition | Would be closed as "not reproducible", with the negative vector and the conformance check cited to the reporter, inside the 10-working-day assessment target |

**What the dry run found.** Three process gaps, all of which this document now closes: the
response targets existed but no runbook said who decides a rotation; the 72-hour clock had
no defined start; and the downstream intake obligation (Klimper forwarding Xchonnect
findings here) was recorded only in the downstream backlog, not in our own process.

**What the dry run did not exercise**, and nobody should read it as covering: no external
reporter was involved, no embargo was negotiated with a third party, no advisory was
published, no key was actually rotated in a production deployment, and no bounty was paid.
Those steps remain untested. The next real report is still the first real test.
