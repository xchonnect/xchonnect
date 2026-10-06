# Continuous fuzzing and coverage

Short fuzz runs find shallow bugs. The parsers in this protocol are reached directly by
anything on the network (spec threats T17, T20), so they get sustained fuzzing with a
corpus that survives between runs, and coverage tells us which code neither the tests nor
the fuzzer ever execute.

Fuzzing and coverage are not run in GitHub Actions — the only workflow is the release
pipeline ([`release.yml`](../.github/workflows/release.yml)). Both are run locally with
the commands below: at minimum every target and `scripts/coverage.sh` before a release
is cut.

Target list, input formats and invariants: [`../fuzz/README.md`](../fuzz/README.md).
Findings ledger: the "Findings" section of [`../fuzz/README.md`](../fuzz/README.md).

## Running it yourself

```sh
rustup toolchain install nightly --profile minimal
cargo install cargo-fuzz --locked

# one target, one hour, keeping new inputs out of the committed seed corpus
mkdir -p /tmp/xc-corpus/relay_http
cargo +nightly fuzz run relay_http /tmp/xc-corpus/relay_http fuzz/corpus/relay_http \
  -- -max_total_time=3600

# coverage (needs the llvm-tools component)
rustup component add llvm-tools-preview
cargo install cargo-llvm-cov --locked
XCHONNECT_TEST_DATABASE_URL=postgres://postgres:test@127.0.0.1:5432/xchonnect \
  ./scripts/coverage.sh
```

Without `XCHONNECT_TEST_DATABASE_URL` the Postgres store is not exercised and its
coverage reads near zero.

## Corpus persistence

Keep a scratch corpus directory per target (e.g. `/tmp/xc-corpus/<target>`) between
runs so each run continues from the previous one, and minimise it from time to time
(`cargo fuzz cmin`) so it does not grow without bound.

The committed `fuzz/corpus/<target>/seed-*` files are passed as a second, read-only
corpus directory and are never modified by a run. They are generated: the core targets'
seeds come from the `fuzz_seeds` test in `crates/core`, and the `relay_http` seeds from
`scripts/fuzz-seeds-relay-http.py` (`--check` verifies they match the generator).

## When a crash is found

A crashing parser input may be exploitable, so it never becomes a public issue
([`../SECURITY.md`](../SECURITY.md)):

1. The run uploads `fuzz/artifacts/<target>/` as a workflow artifact, visible to
   collaborators only, kept 30 days.
2. `scripts/fuzz-crash-report.sh` opens a **draft GitHub security advisory** — private to
   maintainers — with the reproducer base64 inline, the commit, the run URL and the
   triage checklist. One advisory per target.
3. The job fails, so the crash is visible on the Actions tab even if filing failed.

Triage:

1. `cargo +nightly fuzz tmin <target> fuzz/artifacts/<target>/<file>` to minimise.
2. Add the minimised input as a regression unit test in the crate that owns the parser,
   and as a seed if it exercises something new.
3. Fix the crate. If the finding has a security consequence, name the threat ID (T1–T21)
   in the commit message.
4. Record it under "Findings" in [`../fuzz/README.md`](../fuzz/README.md) with the fix
   commit, and publish or dismiss the advisory.

### Configuration a human must do once

`scripts/fuzz-crash-report.sh` needs a token that can create advisories; the default
`GITHUB_TOKEN` cannot. Create a fine-grained personal access token for this repository
with **Contents: read** and **Security advisories: read and write**, and store it as the
repository secret `FUZZ_ADVISORY_TOKEN`. Until it exists, the job still fails and still
uploads the artifact; it simply cannot file the advisory.

## Coverage review

`scripts/coverage.sh` reports line, region and function coverage for the four crates with
protocol logic, and pulls the crypto and parsing files into `crypto-parsing.txt` because
that is where a gap matters most.

### Run of 2026-10-05 (commit on `feature/release-fuzzing-pipeline`, no Postgres)

Totals: **92.86 % of regions, 93.44 % of lines, 88.63 % of functions** (20 518 regions).

Crypto and parsing files, all above 87 %:

| File | Regions | Lines |
|---|---|---|
| `core/src/b64.rs` | 100.00 % | 100.00 % |
| `core/src/origin.rs` | 97.96 % | 100.00 % |
| `core/src/envelope.rs` | 96.61 % | 96.74 % |
| `core/src/cbor.rs` | 96.55 % | 97.98 % |
| `core/src/pow.rs` | 95.91 % | 99.11 % |
| `core/src/session.rs` | 95.10 % | 96.59 % |
| `core/src/uri.rs` | 94.57 % | 97.17 % |
| `core/src/pairing.rs` | 93.92 % | 94.55 % |
| `core/src/push.rs` | 93.08 % | 96.09 % |
| `core/src/crypto.rs` | 92.58 % | 93.89 % |
| `core/src/message.rs` | 90.03 % | 95.86 % |
| `core/src/domain.rs` | 89.52 % | 90.48 % |
| `core/src/keys.rs` | 87.67 % | 92.68 % |
| `relay/src/ohttp.rs` | 97.55 % | 98.44 % |
| `relay/src/creation.rs` | 98.26 % | 98.98 % |
| `relay/src/push.rs` | 94.70 % | 96.69 % |
| `wallet-kit/src/binding.rs` | 96.23 % | 96.81 % |
| `wallet-kit/src/policy.rs` | 94.67 % | 92.48 % |

What the gaps actually are, reviewed file by file:

- **Accepted, no test value.** `Debug`/`Display` impls (`core/src/keys.rs` 106–109,
  `wallet-kit/src/policy.rs` 82–91, every `error.rs`), the `main.rs` of both binaries, and
  unused accessor arms of `cbor::Value` (`as_u64`, `as_i64`, `as_bytes`, … returning
  `None` for the wrong variant). These are total functions over an enum; a test would
  assert the obvious.
- **Worth a test, security-relevant.** Two gaps stand out and are the only ones in this
  review that touch a security property:
  1. `core/src/crypto.rs` 349–358: the redacting `Debug` impls for `HpkeSender` and
     `HpkeReceiver` are never executed, so nothing asserts that formatting a
     key-bearing type cannot print key material. That is exactly the invariant "no
     secret material in logs or panic messages".
  2. `core/src/crypto.rs` 474–475: the `vk.is_weak()` rejection in `ed25519_verify` —
     small-order public keys — is never taken. It is a deliberate hardening of signature
     verification (T20) and should have a vector with a known small-order key.
  Both are recorded as follow-ups (F-3, F-4) under "Findings" in
  [`../fuzz/README.md`](../fuzz/README.md); they are gaps in the tests, not known bugs.
- **Worth a test, ordinary.** `core/src/crypto.rs` 198–205 (`MailboxId::from_slice` with
  a wrong length), `core/src/domain.rs` 52–57 (`display_domain` on a label `idna`
  rejects, which produces the `InvalidIdn` warning a wallet shows), and
  `core/src/crypto.rs` 86–95 (`RngAdapter::try_next_u32`/`u64`, which `hpke` never calls
  — dead adapter methods rather than untested logic).
- **Covered only with Postgres.** `relay/src/store/postgres.rs` reads 2.79 % without
  `XCHONNECT_TEST_DATABASE_URL`; set it to cover the Postgres store, and the
  conformance suite runs against both stores.

Every one of these is reachable only through code the fuzzers already drive, so there is
no parsing path that is both untested and unfuzzed.

### Cadence

`scripts/coverage.sh` writes `lcov.info`, an HTML report and the two summaries. The numbers are reviewed, and this
section updated, when a release is cut and before the external audit (TASK-62) — not on
every run; no coverage percentage is a gate, because a threshold invites tests written for
the number rather than for the bug.
