---
name: security-audit
description: Security audit of Xchonnect, or of one change to it, against the spec's threats (T1–T21), invariants (13.4) and privacy inventory (14): maps each to the code and tests that hold it, runs the checks that exist, and reports findings with evidence. Use before a release, before the external audit (TASK-62/63), after a change to core, relay, gateway, wallet-kit or the SDK, or when asked to "audit", "review for security" or "threat model" something.
---

# Security audit

Audit, not fix. The result is a report of findings with evidence, a list of what was
checked and found sound, and the gaps; fixes are separate branches with regression tests.
DRAFT: this skill has not been run end to end yet; correct it when a run shows a better order.

## Inputs

- **Scope:** the whole workspace (release audit) or one diff (`git diff <base>...HEAD`,
  a branch, a PR). For a diff, still read the surrounding code: a change is safe or not
  in its context.
- **Normative texts:** `docs/spec/xchonnect-spec.md` (threats 13.3, invariants 13.4,
  cryptographic properties 13.4.1, logging 13.5, limitations 13.6, data inventory 14),
  `docs/spec/wire/` (CDDL, URI grammar, relay API, JSON schema),
  `docs/privacy/data-inventory.md`, `SECURITY.md` (scope, out of scope).
- **What already proves things:** `docs/spec/model/` (ProVerif, properties 13.4.1 1–4),
  `docs/spec/vectors/`, `fuzz/fuzz_targets/`, `privacy/` + `scripts/privacy-scan.sh`,
  `conformance/`, the `tests` modules of each crate.

Read the spec sections and `SECURITY.md` first, every time. Do not audit from memory of
the protocol: the spec changes (`docs/spec/CHANGELOG.md`).

## Procedure

1. **Freeze the scope.** Record the commit, tag and the versions in `Cargo.toml` and
   `sdk-ts/package.json`. For a diff, list the files and the crates they belong to.
2. **Run what exists** (each is a fact, not an opinion; record pass/fail and output):
   ```sh
   cargo fmt --all --check && cargo clippy --workspace --all-targets --locked -- -D warnings
   cargo test --workspace --locked
   cargo deny check                     # advisories, bans, licences, sources
   ./scripts/relay-conformance.sh       # add a postgres:// URL for the Postgres store
   ./scripts/privacy-scan.sh            # relay + gateway live; logs, dump, metrics scanned
   cargo test -p xchonnect-privacy-check
   ./scripts/wallet-conformance.sh
   ```
   Fuzzing and coverage are not in CI: `docs/fuzzing.md` (`cargo fuzz run <target>` per
   target in `fuzz/fuzz_targets/`, `scripts/coverage.sh`). For a release audit run every
   target at least briefly and note the corpus state. `fuzz/Cargo.lock` may be stale.
3. **Map threats to code.** For each row T1–T21 of spec 13.3 and each invariant of 13.4,
   find the code that holds it and the test that would fail if it did not. Write the map
   as a table: threat, mitigation in the spec, code (file:line), test (file::name),
   verdict (held / held without a test / not held / not applicable to this scope).
   Where the spec says "MUST" and no test exists, that is a finding of its own.
4. **Read the code paths an attacker reaches**, in this order, because the network
   reaches them first:
   - parsers: envelope (CBOR, padding, `exp`, `seq`), pairing URI, origin document,
     relay JSON bodies, push registration, sealed tokens, OHTTP (core `envelope`,
     `pairing`, `push`, `ohttp`; relay `api.rs`, `creation.rs`; gateway `lib.rs`);
   - authentication and authorisation: capability tokens, API keys, proof-of-work,
     tickets, gateway allowlist (`relay/creation.rs`, `config.rs`, `push.rs`);
   - key handling: derivation, zeroization, what is logged (`core/crypto.rs`,
     `gateway/creds.rs`, every `tracing::` call in relay and gateway);
   - the privacy structure: handlers must not read client identity (the relay test
     `handlers_do_not_read_client_identity` lists what is forbidden), no request
     logging, store keeps token hashes and ciphertext only (`relay/store/`);
   - wallet-kit: simulation before signing, net-effect display inputs, signature scope,
     binding of partial spends (invariants 3 and 4), limits.
   For each area note: input bounds (sizes, counts, time), constant-time comparisons
   where secrets meet, error uniformity (`relay-api.md` §Errors), what happens on the
   failure path (fail closed?).
5. **Dependencies.** `cargo deny check` output, `docs/dependency-policy.md`, and for the
   crypto crates whether versions match `docs/design/crate-selection.md`. New
   dependencies in a diff: who maintains them, do they run build scripts, are they
   already in the tree.
6. **Operational surface.** `docs/operating.md`: defaults that are safe (OHTTP on,
   allowlist policy, metrics protected), what a wrong setting does (the services exit;
   with none of their settings they wait and serve nothing), what `--env` exposes under
   ONCE, what the images contain (`deploy/Dockerfile.dist`, non-root, pinned base).
7. **Spec conformance of the change.** Does the diff change bytes on the wire, an error
   code, a limit, a derivation? Then `docs/spec/` and the vectors must change with it
   (`docs/spec/PROCESS.md`), and the CHANGELOG entry must carry `Threats affected:`.

## Report

One Markdown document, written for the maintainer and for the external auditor:

1. **Scope:** commit, versions, what was and was not audited, which checks ran with
   their results.
2. **Findings**, most severe first. Each: id, severity (critical / high / medium / low /
   note), the threat or invariant it touches, where (file:line), what an attacker gets,
   evidence (a failing input, a test, a quote), and a recommended fix with the test that
   would prove it. A finding without evidence is a question, listed separately.
3. **Threat map** (the table from step 3).
4. **Sound**: what was checked and found to hold, so the next audit does not repeat it.
5. **Gaps**: MUSTs without tests, code never executed by tests or fuzzers
   (`scripts/coverage.sh`), limitations the public docs should state (spec 13.6).

Severity: critical = key or plaintext disclosure, signature without approval, relay can
forge; high = replay, enumeration, SSRF, DoS with small effort, privacy inventory
violated; medium = defence in depth missing, uniform-error or bound not enforced; low =
hygiene; note = question or improvement.

## Rules

- Evidence over opinion: quote the code, run the input, or say "not verified".
- Never print a secret, token or key in the report or in a test fixture; the privacy
  scan is the model for how to look at logs.
- Do not fix while auditing. A fix is its own branch with a regression test; the audit
  notes it as "fixed in <branch>" only after the test exists.
- Do not weaken a MUST to make a finding go away; a disagreement with the spec is a spec
  amendment (`docs/spec/PROCESS.md`), not a code change.
- Track the audit in the backlog: a release audit is a task of its own (the model is
  TASK-72); findings become tasks with the finding id in the title.
