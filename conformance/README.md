# xchonnect-conformance

Black-box conformance suites for Xchonnect implementations. Two suites live here:

| Suite | What it tests | Jump to |
|---|---|---|
| `relay` | A relay's HTTP API ([`docs/spec/wire/relay-api.md`](../docs/spec/wire/relay-api.md)) and spec 7.1–7.5, 7.3.1. | [below](#the-relay-suite) |
| `wallet` | A wallet's protocol and signing behaviour: spec 5.3, 6, 9 and 11. | [below](#the-wallet-suite) |

Both talk to the implementation under test only over the wire, the way a real peer
would, so you can point them at any implementation. `xchonnect-conformance list`
prints every check of both suites with its spec reference; exit code is `0` when
nothing failed (skips are fine), `1` when any check failed, `2` for usage errors.

# The relay suite

It talks to the relay only over HTTP(S), the same way wallets and dApps do, so you can
point it at any relay implementation.

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

`xchonnect-conformance list relay` prints every check id with its title and spec
reference.

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

# The wallet suite

The suite plays the dApp. It publishes an origin document, shows the wallet a pairing
URI and then judges the wallet **only by what it does on the relay**: whether it
replies, what it signs and what it refuses. Nothing about the wallet's internals is
assumed, so the same run works against the example CLI wallet, a wallet in another
repository, or a phone wallet paired by hand.

The negative cases are the point. A wallet that accepts a forged origin document,
pairs from an expired URI, acts on a replayed or tampered message, hands out a
signature for a key it never exposed, ignores a spending limit, signs an unrecognised
contract, or produces a partial signature for an unbound multi-party spend **fails**.
Those checks need no cooperation from the wallet at all: the suite can see that a
pairing reply was posted, and it can see what came back in an `rpc.response`.

## Running it

```sh
./scripts/wallet-conformance.sh                 # the example CLI wallet, with a relay
```

Against your own wallet, with your own relay:

```sh
cargo run -p xchonnect-conformance -- wallet \
  --relay http://127.0.0.1:8787 \
  --wallet "my-wallet pair '{uri}' --developer-mode" \
  --xch-per-request-limit 1000000
```

`--wallet` is a shell command in which `{uri}` is replaced by the pairing URI. It runs
through `sh -c`, so quote `'{uri}'`: the URI contains `&`. The command must not need
interactive input — either auto-approve everything, or pipe the answers in (see
[variants](#wallets-that-say-no)).

| Option | Meaning |
|---|---|
| `--relay <url>` | Relay both sides meet on. Required. |
| `--wallet <command>` | Pairs the wallet. `{uri}` is the pairing URI. |
| `--wallet-sas-mismatch <command>` | Same, for a wallet whose user reports that the codes differ. |
| `--wallet-reject <command>` | Same, for a wallet whose user declines signing requests. |
| `--manual` | Pair by hand instead of running a command (phone wallets). |
| `--domain <domain>` | Domain the suite claims. Default `localhost:<port>`, which needs the wallet's developer mode. |
| `--listen <addr>` | Where the origin-document server binds. Default `127.0.0.1:0`. |
| `--xch-per-request-limit <mojos>` | The per-request XCH limit you configured in the wallet, for `W-LIMIT-01`. |
| `--timeout <s>` | Wait for a pairing reply, `session.ready` or an `rpc.response`. Default 30. |
| `--refusal-timeout <s>` | How long to wait before concluding that the wallet will *not* answer. Default 8; every negative check costs this much. |
| `--only <id>[,<id>…]` | Run only these checks. Each check pairs its own session, so any check can run alone. |
| `--json` | Print a JSON report. |
| `--slow` | Also run `W-PAIR-02`, which waits five minutes for a pairing timeout. |

A full default run takes about 90 seconds and pairs roughly twenty sessions.

### What the suite needs from your wallet

- **Developer mode, or a real domain.** By default the suite claims
  `localhost:<port>` and serves its origin document over plain HTTP from its own
  server, which only a wallet in developer mode accepts. For a wallet without a
  developer mode, see [below](#against-a-phone-wallet).
- **A relay it can create mailboxes on**, in `open` or `pow` mode. The suite creates
  about forty mailboxes per run and deletes them again.
- **A key, for the signing checks.** `W-SIGN-01` asks the wallet to sign a spend of a
  standard coin derived from the key it returned from `getPublicKeys`, and verifies that
  the signature is exactly the aggregate of the `AGG_SIG_ME` messages the spec
  prescribes. If the wallet refuses that control request, the signing checks below it
  are still run but say so: a wallet that refuses *everything* would otherwise look
  conformant. Nothing in the suite needs funded coins; the spends are never submitted.
- **A configured spending limit**, if `W-LIMIT-01` is to run. The suite reads the limit
  from `session.permissions` when the wallet sends it, and otherwise from
  `--xch-per-request-limit`.

The suite assumes the exposed key pays to the standard puzzle
(`p2_delegated_puzzle_or_hidden_puzzle`), which is what Chia wallets use for receive
addresses. If that does not hold, `W-SIGN-01` says so and the dependent checks report
it rather than reading the resulting refusals as conformance.

### Wallets that say no

Two requirements are about the wallet refusing something its *user* told it to refuse,
which cannot be observed from a wallet that approves everything. Give the suite a second
command for each, and it will use it for that check only (they are skipped otherwise):

```sh
  --wallet-sas-mismatch "printf 'y\nn\n' | my-wallet pair '{uri}'" \
  --wallet-reject       "printf 'y\ny\nn\n' | my-wallet pair '{uri}'"
```

That is all it takes for a wallet that prompts on stdin — no special build and no test
hook in the wallet. For other wallets, use `--manual` and answer on the device.

### Against a phone wallet

A production wallet will not accept a `localhost` domain over plain HTTP, and a phone
cannot reach the suite's loopback server. Two things change:

1. **Serve the origin document from a domain you control, over HTTPS.** The suite keeps
   control of the document (it has to publish a forged and an expired one), so put a TLS
   reverse proxy in front of its server and forward one path:

   ```
   conformance.example.com {
     reverse_proxy /.well-known/xchonnect.json 10.0.0.5:8099
   }
   ```

   ```sh
   cargo run -p xchonnect-conformance -- wallet \
     --relay https://relay.example.com \
     --domain conformance.example.com --listen 0.0.0.0:8099 --manual
   ```

   Nothing else may be served from that path while the suite runs, and the relay has to
   be reachable from the phone.

2. **Pair by hand** with `--manual`. For each check the suite prints what the wallet is
   expected to do and the pairing URI, and waits for you to press Enter:

   ```text
   --- the wallet should now: refuse: the domain publishes a different key, …
       pairing URI (scan it, or pipe it to `qrencode -t ANSIUTF8`):

   xchonnect:v1?r=https%3A%2F%2F…

       press Enter once the wallet has been given the URI
   ```

   Turn the URI into a QR code with `qrencode -t ANSIUTF8 <uri>` and scan it, or send
   yourself the universal link. For the three checks that need to know what the device
   showed — the SAS, a refusal, a five-minute timeout — the suite asks a yes/no question,
   and answering "no" fails the check. Everything else is still judged on the wire.

   Expect about twenty pairings. Use `--only` to work through the suite in groups.

## Checks

`W-PAIR-01` is the control for the negative pairing checks: it shows that this wallet
*does* pair when the document and URI are correct, through the same code that watches
the pairing mailbox in the checks below. A wallet that simply never pairs fails it.

| Id | What it checks | Spec |
|---|---|---|
| `W-PAIR-01` | The wallet fetches the origin document, replies with a canonical pairing reply sealed to the URI's key, and the handshake completes with `session.ready`. | 6.3 steps 2–9 |
| `W-ORIGIN-01` | The domain publishes a **different** key, so the URI signature is a forgery: no pairing reply at all. | 6.3 step 2; 13.4 property 3 |
| `W-ORIGIN-02` | The document does not contain the key id the URI names: no reply. | 6.1; 6.3 step 2 |
| `W-ORIGIN-03` | The origin key's `not_after` has passed: no reply. | 6.1 |
| `W-ORIGIN-04` | The domain publishes no document (`404`): no reply. | 6.1 |
| `W-ORIGIN-05` | The document announces an unsupported version: no reply. | 6.1; `xchonnect.schema.json` |
| `W-URI-01` | The URI expired five minutes ago, with a perfectly valid document: no reply. | 6.2; 6.3 step 2 |
| `W-URI-02` | The URI's expiry was changed after signing, so the signature no longer covers it: no reply. | 6.2; 6.3 step 2 |
| `W-SAS-01` | The wallet shows the same six-digit code the dApp derives. Found in the wallet's output, or confirmed by the operator with `--manual`; skipped with a note when neither is possible. | 5.2; 6.3 step 8 |
| `W-SAS-02` | A wallet whose user reports different codes never sends `session.ready`, and answers nothing. Needs `--wallet-sas-mismatch`. | 6.3 step 8 |
| `W-PAIR-02` | A wallet that replies and then gets no `session.confirm` gives up within five minutes. Opt-in `--slow`. | 6.3 step 7 |
| `W-SESSION-01` | `session.ping` is answered with `session.pong`. | 9.2 |
| `W-END-01` | After `session.end` the wallet posts nothing further. | 9.2; 6.3 step 8 |
| `W-MSG-01` | An envelope with one ciphertext byte flipped is ignored, the intact one right after it is still answered (a rejected message must not end the session), and re-posting the same bytes produces no second answer. | 5.3 |
| `W-MSG-02` | Two requests posted newest-first: the newer is answered, the one whose `seq` is below it is not. | 5.3 |
| `W-MSG-03` | A request whose `exp` is ten minutes past is not acted on. An error answer is tolerated with a note; a result is a failure. | 5.3 |
| `W-RPC-01` | `chainId` returns a string, `connect` returns `true`, `getPublicKeys` returns hex keys, and the `chip0002_` alias is accepted. Notes how many `rpc.received` receipts arrived. | 9.1 |
| `W-RPC-02` | An unknown method is answered with code `4004`. | 9.1 |
| `W-RPC-03` | `signMessage` without a message, and `coinSpends` as a string, are answered with an error and never a signature. | 9.1 |
| `W-SIGN-01` | A spend of the wallet's own coin, under its limits, is signed — and the signature is exactly the aggregate of the `AGG_SIG_ME` messages this request needs for that key, not something else. | 11.1 items 1 and 2 |
| `W-SIGN-02` | `signMessage` for a valid key the wallet never exposed returns **no** signature. Runs even when the wallet cannot be profiled. | 9.3; 11.1 item 2 |
| `W-SIGN-03` | A spend of somebody else's coin, needing a key the wallet does not hold, returns no signature (the identity element is accepted with a note). | 11.1 item 2 |
| `W-SIGN-04` | A standard spend whose solution asks for `AGG_SIG_UNSAFE` with the wallet's key is refused. | 11.1 item 2; 9.1 |
| `W-SIGN-05` | A spend of an unrecognised puzzle that wants the wallet's signature is refused, not signed blindly. | 11.1 item 3 |
| `W-LIMIT-01` | A spend whose guaranteed loss is 1000 mojos above the configured per-request limit is refused. Needs the limit, from `session.permissions` or `--xch-per-request-limit`. | 9.3; 11.1 item 5 |
| `W-PARTIAL-01` | An offer-shaped `partialSign` request in which the wallet's spend does **not** assert the counterparty's settlement payment produces no signature: the counterparty could take the coin and drop the payment. | 11.2; 13.4 property 4 |
| `W-PARTIAL-02` | The same request *with* the binding is signed, and the signature verifies. Skipped with a note when the wallet refuses `partialSign` altogether, which is safe but stricter than the spec. | 11.2 |
| `W-REJECT-01` | A request the user declines is answered with `4002` and no signature. Needs `--wallet-reject`. | 9.1 |
| `W-ROT-01` | The wallet accepts a key rotation and the session keeps working in the new epoch. | 9.2.1 |

### How refusals are judged

"Refused" means an `rpc.response` carrying an error, or nothing at all. Returning
something a dApp could use — in particular anything that parses as a BLS signature —
where the spec requires a refusal is always a failure, whatever the wallet called it.

The *code* is treated more leniently than the refusal: a check that expects `4029` and
sees another error code passes with a note naming the expected one. Spec Appendix A
records CHIP-0002 wallets that answer every error as `4001`, and refusing is the
security requirement while the code is an interoperability one. `W-RPC-02` is the
exception — an unknown method must be `4004`, which is pure protocol shape.

### Not covered

- **Anything that is not visible on the relay**: biometric prompts per signature
  (spec 11.1 item 4), hardware-backed key storage (11.3), what the approval screen
  actually renders (11.1 item 1), lock-screen notification content (7.3). Those need
  the device and a reviewer.
- **Push wake-ups** (7.3): the suite is a dApp, and registration is between the wallet
  and the relay.
- **OHTTP** (10): the wallet's transport is invisible to a dApp.
- **The 24-hour origin-document cache bound** (6.1). `W-PAIR-01` does check that the
  wallet fetched the document during the pairing it is testing.

## Running against the example wallet

`cargo test -p xchonnect-conformance` runs the suite against the example CLI wallet
(`conformance/tests/reference_wallet.rs`) with the reference relay served in-process,
so CI covers it through `cargo test --workspace`. The wallet runs with `--dev-key`
there: without one it answers every signing request with the BLS identity element and
exposes a placeholder public key, which the suite reports as failures — correctly, since
`getPublicKeys` must return real keys and `signMessage` must not answer for a key that
was never exposed.

## Using the wallet suite as a library

```rust
use xchonnect_conformance::wallet::{run, Options};

let report = run(&Options {
    relay: "http://127.0.0.1:8787".into(),
    wallet: "my-wallet pair '{uri}'".into(),
    ..Options::default()
});
assert!(report.is_success(), "{}", report.to_text());
```
