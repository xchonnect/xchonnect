# Fuzz targets for `xchonnect-core`

A [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) (libFuzzer) project covering every
parser in the protocol core and the session receive path. It is a standalone crate,
excluded from the main workspace, because it needs a nightly toolchain.

## Running

```sh
rustup toolchain install nightly --profile minimal
cargo install cargo-fuzz --locked

cargo +nightly fuzz list
# Keep the committed seeds read-only: new inputs go to the first (scratch) directory.
mkdir -p /tmp/xc-corpus/envelope_decode
cargo +nightly fuzz run envelope_decode /tmp/xc-corpus/envelope_decode fuzz/corpus/envelope_decode \
  -- -max_total_time=60
```

Builds use debug assertions and overflow checks (cargo-fuzz default), so arithmetic
overflow counts as a crash. CI runs every target for 30 seconds on each push and pull
request (`fuzz` job in `.github/workflows/ci.yml`).

A crash is written to `fuzz/artifacts/<target>/`. Minimise it with
`cargo +nightly fuzz tmin <target> <file>`, turn it into a regression unit test in
`crates/core`, then fix the core.

## Targets

| Target | Entry point | Invariants checked besides "no panic" |
|---|---|---|
| `envelope_decode` | `cbor::decode`, `Envelope::decode`, `envelope::unpad` | accepted CBOR and envelopes re-encode byte-identically; envelope field sizes match the kind; `unpad` output is a canonical prefix followed only by zeros |
| `inner_decode` | `cbor::decode` → `Inner::from_value`, `PairingReply::from_value` | canonical re-encoding; `seq` in `1..=2^53-1`; decode → encode → decode is stable |
| `uri_parse` | `PairingUri::parse` (normal and developer mode) | developer mode accepts everything normal mode accepts, with the same result; `to_uri` and universal-link forms re-parse to the same URI |
| `origin_parse` | `OriginDocument::parse` | size, name, key-count, kid syntax and uniqueness, URL rules; `not_after` is 23:59:59 UTC; key lookup honours expiry |
| `session_state` | `Session::from_bytes`, then seal / rotate / open / end on the restored state | persistence is a fixed point after one round trip; corrupted host state never panics later calls |
| `pending_requests` | `PendingRequests::from_bytes` | restored tracker has at most `MAX` entries and unique ids (as `insert` guarantees); round trip; correlation works |
| `push_reg` | `PushToken::open` with a fixed gateway key | opened tokens have a non-empty device token within the size limit and an expiry in `now..=now + MAX_LIFETIME_S` |
| `session_open` | `Session::open` on correctly sealed, fuzzer-chosen inner plaintexts (sequence of frames) | only owned mailboxes accepted; `seq` strictly increases; the same envelope never opens twice; rotation offers can be accepted; state persists |

`session_open` knows the session keys so the fuzzer gets past the AEAD and reaches the
state machine. Input format: one flags byte (bit 0 receiver is the dApp, bit 1 SAS
confirmed, bit 2 peer ready) followed by frames `u16be length || inner plaintext`.

## Seed corpus

`fuzz/corpus/<target>/seed-*` are valid inputs produced by the real encoders. They are
generated (and checked to parse) by the `fuzz_seeds` unit test in `crates/core`:

```sh
XCHONNECT_FUZZ_SEEDS=$PWD/fuzz/corpus cargo test -p xchonnect-core fuzz_seeds
```

Do not commit the corpus libFuzzer grows locally; only the `seed-*` files are tracked.
