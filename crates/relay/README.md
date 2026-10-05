# xchonnect-relay

> [!WARNING]
> **Pre-audit pre-release: testnet only, no real funds.** Xchonnect has not had an
> external security audit. Do not use any 0.x release to move, sign for or protect mainnet
> funds. Report vulnerabilities privately:
> [SECURITY.md](https://github.com/maximedogawa/xchonnect/blob/main/SECURITY.md).

Reference relay for the Xchonnect protocol: anonymous, capability-token mailboxes that
store end-to-end encrypted envelopes until the recipient fetches them
(spec Section 7, API in `docs/spec/wire/relay-api.md`).

```sh
cargo run -p xchonnect-relay                      # in-memory store on 127.0.0.1:8787
XCHONNECT_DATABASE_URL=postgres://… cargo run -p xchonnect-relay
```

All settings are environment variables; see the table in `src/config.rs`. The OHTTP
settings:

| Variable | Default | Meaning |
|---|---|---|
| `XCHONNECT_OHTTP` | `true` | run the OHTTP gateway (`POST /.well-known/ohttp-gateway`, keys at `/.well-known/ohttp-keys`); `false` disables it; `ephemeral` uses a throwaway key per process (development only) |
| `XCHONNECT_OHTTP_KEYS` | required while `XCHONNECT_OHTTP=true` (startup error otherwise) | `id:base64url(32-byte seed)`, comma-separated, newest first; keep the previous key during rotation |
| `XCHONNECT_OHTTP_KEYS_FILE` | unset | read the keys from a file (secret mount); takes precedence |
| `XCHONNECT_MAX_WAIT_OHTTP_S` | `0` | long-poll limit through OHTTP; at most the OHTTP relay's timeout minus 5 s |

See `docs/operating.md` (OHTTP) for enabling, key rotation, replay behaviour and the
requirements on the independent OHTTP relay.

## Storage

- **In-memory** (default): single process, data lost on restart. For development and
  small self-hosted relays.
- **Postgres** (`XCHONNECT_DATABASE_URL`): migrations run at startup; several relay nodes
  can share one database (long-polls are woken across nodes with `LISTEN/NOTIFY`; set the
  same `XCHONNECT_POW_KEY` on all nodes). Disable statement/parameter logging on the
  database server (`log_statement = none`): bound parameters include mailbox ids and token
  hashes. Run the backend tests with `XCHONNECT_TEST_DATABASE_URL=postgres://… cargo test -p xchonnect-relay`
  against a disposable database (the test drops and recreates the tables).

## TLS

The relay speaks plain HTTP and must run behind a TLS-terminating reverse proxy (Caddy,
nginx, a load balancer) in production. Clients require `https` relay URLs except in
explicit developer mode. Configure the proxy **not** to log request URLs (they contain
mailbox ids), `Authorization` headers or client IPs beyond what the provider enforces,
and disclose it in your data inventory (spec 10.3, 13.5).

## What the relay never does

- read client IP addresses, `User-Agent` or forwarding headers (enforced by a source test);
- log request paths, tokens, mailbox ids or ciphertext;
- store anything except token hashes, day-granular timestamps, optional sealed push
  registrations, the optional customer id, and ciphertext with its expiry.

## Logging and metrics policy (spec 13.5)

- Logs contain only startup/shutdown events and backend error descriptions; there is no
  request logging. Set `XCHONNECT_LOG` (e.g. `warn`) to control verbosity.
- `/metrics` exposes aggregates only: request counts by **route template** and status
  class, latency histograms, and the number of mailboxes. Restrict access to it at the
  reverse proxy, or disable it with `XCHONNECT_METRICS=0`.
- Per-customer usage for billing is available in-process (`AppState::usage()`), never
  per end user.
- Recommended retention for any logs the proxy or platform keeps: at most 14 days.
- A test (`api::privacy_tests`) runs every endpoint at TRACE level and fails if any
  mailbox id, token, token hash, message id or envelope appears in logs or metrics.

## Licence and security

Apache-2.0 ([`LICENSE`](https://github.com/maximedogawa/xchonnect/blob/main/LICENSE)).

Report vulnerabilities privately - **not** as a public issue - per
[`SECURITY.md`](https://github.com/maximedogawa/xchonnect/blob/main/SECURITY.md).
Pre-audit software: a relay sees no plaintext, but review it yourself before running one
for other people.
