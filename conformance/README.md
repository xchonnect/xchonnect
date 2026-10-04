# xchonnect-conformance

Black-box conformance suites for Xchonnect implementations. The suite in this crate
checks a **relay** against the relay HTTP API
([`docs/spec/wire/relay-api.md`](../docs/spec/wire/relay-api.md)) and spec sections
7.1–7.5 and 7.3.1. It talks to the relay only over HTTP(S), the same way wallets and
dApps do, so you can point it at any relay implementation.

## Running it against your relay

```sh
cargo run -p xchonnect-conformance -- relay https://relay.example.com
```

Or build once and run the binary:

```sh
cargo build --release -p xchonnect-conformance
./target/release/xchonnect-conformance relay https://relay.example.com [options]
```

| Option | Meaning |
|---|---|
| `--only <id>[,<id>…]` | Run only these checks (repeatable). Naming an opt-in check runs it without its flag. |
| `--json` | Print a JSON report (`summary`, and per check `id`, `status`, `detail`, `spec`). |
| `--api-key <key>` | Business API key (`Xchonnect-Api-Key`) for ticket and API-key checks. You can also set `XCHONNECT_CONFORMANCE_API_KEY`. |
| `--aggressive` | Also run checks that deliberately exhaust rate limits. |
| `--slow` | Also run checks that take over a minute. |

`xchonnect-conformance list` prints every check id with its title and spec reference.

Output is one line per check, plus the reason for each failure or skip:

```text
[PASS] R-AUTH-01 read and write tokens are not interchangeable (relay-api.md §Identifiers)
[SKIP] R-PUSH-02 allowlist mode rejects private, … (spec 7.3.1 rules 6 and 7)
       -> relay is in open gateway mode: …
```

Exit code: `0` when nothing failed (skips are fine), `1` when any check failed, `2` for
usage errors.

### What the suite needs from your relay

- `GET /v1/info` must work: the suite reads limits and creation methods from it. If it
  fails, every other check is skipped.
- **Mailbox creation.** The suite picks a method from `mailbox_creation`: `open`, then
  `pow` (it solves the challenge itself, up to difficulty 26), then `ticket` or
  `api_key` if you pass `--api-key`. If none of these works, checks that need a mailbox
  are skipped.
- **Quota.** Each check creates its own mailboxes (about 60 for a full run) and posts a
  few hundred messages in total. When the relay answers `429` with a `Retry-After` of
  15 s or less, the suite waits and retries, so default rate limits are fine. The
  `--aggressive` check deliberately sends writes until it gets a `429`.
- **Test-friendly settings.** `R-QUOTA-01` runs only when `max_messages_per_mailbox`
  is 64 or less, and the 32-message cap in `R-MSG-03` is checked only when the quota is
  at least 33. A quota of 33–64 covers both. `R-PUSH-03` needs a non-empty
  `gateway_allowlist` (or `open` gateway policy).

Run the suite against a staging relay rather than production if you can: it leaves
behind mailboxes and messages, which expire under the normal retention rules.

## Checks

The default run takes about 15–20 s. Every check is independent and can be run alone
with `--only`.

| Id | What it checks | Notes |
|---|---|---|
| `R-INFO-01` | `GET /v1/info` returns JSON with `protocol: 1`, integer limits, `default_ttl_s` within `[60, max_ttl_s]`, `max_ttl_s` at most 7 days, `max_wait_ohttp_s` ≤ `max_wait_s`, known creation methods, `gateway_policy`, boolean `ohttp`. | |
| `R-INFO-02` | `gateway_allowlist` is present in allowlist mode; `pow_difficulty` is present when `pow` is offered. | |
| `R-CREATE-01` | Creating a mailbox with the default method returns `201` and a 16-byte `mailbox_id`; ids are unique; new mailboxes are empty. | |
| `R-CREATE-02` | Unknown request fields are ignored. | |
| `R-CREATE-03` | Malformed JSON, hashes of the wrong length or encoding, or a missing hash: `400 bad_request`. | |
| `R-CREATE-04` | Creation without any proof: `403 auth_required`. | Skipped on `open` relays. |
| `R-POW-01` | `POST /v1/challenge` returns a 42-byte challenge whose embedded difficulty and expiry match the response and `/v1/info`, valid for at most 120 s; a solution creates a mailbox. | Needs `pow`. |
| `R-POW-02` | Reused challenge, a nonce that misses the difficulty, or a tampered MAC: `403 pow_invalid`. | Needs `pow`. |
| `R-TICKET-01` | `POST /v1/tickets` with an API key returns a 32-byte ticket valid for at most 10 minutes; the ticket creates exactly one mailbox; reused or unknown tickets: `403 ticket_invalid`. | Needs `ticket` and `--api-key`. |
| `R-TICKET-02` | `POST /v1/tickets` without a key: `403` (`api_key_invalid` or `auth_required`); with an unknown key: `403 api_key_invalid`. | Needs `ticket`. |
| `R-APIKEY-01` | Creation with an unknown API key: `403 api_key_invalid`; with `--api-key`, a valid key creates a mailbox. | Needs `api_key`. |
| `R-AUTH-01` | The read token cannot post; the write token cannot fetch, ack or set push (`404 not_found`). | |
| `R-AUTH-02` | The relay hashes the presented token: sending the token *hash* as bearer fails. | |
| `R-AUTH-03` | Equal read and write token hashes: `400 bad_request`. | |
| `R-NF-01` | For every mailbox endpoint (GET/POST messages, ack, push, DELETE), the `404 not_found` responses for unknown mailbox, wrong token, the other capability's token, malformed mailbox id, missing or malformed `Authorization`, and a deleted mailbox are identical: status, body, and all header names and values except `Date`. | |
| `R-MSG-01` | A posted envelope comes back byte-identical with the `msg_id` from the `202`, and it is still there on a second fetch. | |
| `R-MSG-02` | Messages come back in acceptance order, also after acknowledging some in the middle. | |
| `R-MSG-03` | `limit=2` returns the oldest two; without `limit` and with `limit=1000`, 32 of 33 messages are returned; ack empties the mailbox. | Cap needs a quota of at least 33. |
| `R-MSG-04` | Ack deletes exactly the listed messages, ignores unknown ids, is idempotent, accepts 256 ids, and rejects 257 ids or a non-array with `400`. | |
| `R-MSG-05` | `ttl_s` of 0, 1, 59, above `max_ttl_s`, and 10^12 are accepted (`202`, clamped, not rejected); after 2.5 s all messages are still there, which shows short TTLs were raised to 60 s. | |
| `R-MSG-06` | A message with `ttl_s=60` is gone after 63 s; one with `ttl_s=600` is not. | Opt-in `--slow` (63 s). |
| `R-ENV-01` | Envelopes that are not CBOR (empty, break byte, truncated, trailing bytes, array instead of map): `400`. Nothing is stored. | |
| `R-ENV-02` | Non-canonical CBOR (unsorted keys, non-minimal integer, indefinite-length map, duplicate key): `400`. | |
| `R-ENV-03` | Wrong nonce/enc length, or a ciphertext length that is not a bucket size (session) or not 1024 (pairing): `400`. | |
| `R-ENV-04` | Extra keys (integer or text), missing keys, or the wrong value type: `400`. | |
| `R-ENV-05` | Version other than 1, or kind other than 1 or 2: `400`. | |
| `R-ENV-06` | A pairing envelope and session envelopes of every bucket size (up to 262144 bytes) are accepted and returned byte-identical. | Buckets above `max_envelope_bytes` are not tested. |
| `R-ENV-07` | An envelope above `max_envelope_bytes` (body still under 400 KiB) is rejected with `400 bad_request` or `413 too_large`. | The spec does not say which; the reference relay answers `413`. |
| `R-ENV-08` | `env` that is not base64url (bad characters, standard alphabet with padding), missing `env`, `env` as a number, malformed JSON, or `ttl_s` as a string: `400`. | |
| `R-SIZE-01` | A 401 KiB body on POST messages and on POST `/v1/mailboxes`: `413 too_large`. | |
| `R-QUOTA-01` | Filling a mailbox to `max_messages_per_mailbox` and posting one more gives `409 mailbox_full`; after one ack, posting works again. | Skipped when the quota is above 64. |
| `R-POLL-01` | A long-poll (`wait` up to 15 s) returns within the wait time, about 1 s after another client posts a message, and returns that message. | Needs `max_wait_s` ≥ 4. |
| `R-POLL-02` | A long-poll on an empty mailbox returns `200` with an empty list after the wait (2 s); without `wait` the fetch returns immediately. | |
| `R-POLL-03` | `wait=3600` returns within `max_wait_s` + 5 s. | Opt-in `--slow` (up to `max_wait_s`). |
| `R-RATE-01` | Writing quickly to one mailbox eventually gives `429 rate_limited` with an integer `Retry-After` ≥ 1; after waiting that long, a write succeeds. Skipped (not failed) if no `429` comes within 2000 writes. | Opt-in `--aggressive`: uses up the write budget of a test mailbox and adds load. |
| `R-PUSH-01` | `PUT …/push` and creation with `push_reg` reject `http://`, `ftp://`, port 8443, userinfo, URLs over 512 bytes and URLs without a scheme with `403 gateway_not_allowed`. | Scheme or port variants that match your allowlist are not tested. |
| `R-PUSH-02` | In allowlist mode, loopback, RFC 1918, CGNAT, link-local/metadata (`169.254.169.254`, `metadata.google.internal`), IPv6 loopback/ULA, unlisted hosts and look-alike hosts of allowlisted prefixes are rejected at registration. | Skipped in `open` mode, where these checks happen at dispatch (rule 7) and cannot be seen from outside. |
| `R-PUSH-03` | A mailbox can be created with an accepted gateway, and its registration replaced, removed (`null`) and set again (`204`); a non-base64url `sealed_token` gives `400`; message posting still works. | Needs a non-empty allowlist or `open` mode. |
| `R-DEL-01` | DELETE with the write token is `404` and changes nothing; with the read token it is `204` with no body; afterwards fetch, post and a second DELETE get `404 not_found`. | |
| `R-ERR-01` | Error responses are exactly `{"error": "<code>"}` with `Content-Type: application/json`. | |
| `R-CORS-01` | Preflights for POST/GET/PUT/DELETE on mailbox endpoints and POST `/v1/mailboxes` from any origin succeed, list `authorization` explicitly (a `*` does not cover it) and `content-type`, and do not allow credentials. | Browser interop; not yet normative text for relays. |
| `R-CORS-02` | Normal and error responses carry `Access-Control-Allow-Origin` (`*` or the origin) and do not allow credentials. | Same as above. |
| `R-HTTP-01` | Responses (info, 201, 202, 200, 204, 400, 404) carry `Cache-Control: no-store`. | Hardening; not yet normative text. |
| `R-HTTP-02` | No response sets a cookie (sample requests plus everything seen during the run). | |

### Not covered

- **Push wake-up dispatch** (spec 7.3.1 rules 2–5): it needs a gateway the suite
  controls, reachable from the relay.
- **OHTTP** (spec 10) and `max_wait_ohttp_s` enforcement.
- **Mailbox inactivity expiry** (30 days) and the per-mailbox byte quota.
- **Constant-time comparison**: `R-NF-01` checks that the responses are identical, not
  that their timing is.

## Running against the reference relay

`scripts/relay-conformance.sh` starts `target/debug/xchonnect-relay` with two profiles,
`hosted` (pow + tickets + API keys, gateway allowlist, quota 40) and `self-hosted` (open
creation, open gateway policy), and runs the suite with `--aggressive` against each:

```sh
./scripts/relay-conformance.sh                              # in-memory store
./scripts/relay-conformance.sh postgres://user:pw@host/db   # Postgres store
CONFORMANCE_FLAGS=--slow ./scripts/relay-conformance.sh      # include slow checks
```

CI runs it on both storage backends. `cargo test -p xchonnect-conformance` also runs the
suite (`tests/reference_relay.rs`) against the reference relay, which it serves
in-process on a free port. It uses both profiles in memory, and the hosted profile on
Postgres when `XCHONNECT_TEST_DATABASE_URL` is set.

## Using the suite as a library

```rust
use xchonnect_conformance::relay::{run, Options};

let report = run(&Options {
    base_url: "http://127.0.0.1:8787".into(),
    ..Options::default()
});
assert!(report.is_success(), "{}", report.to_text());
```
