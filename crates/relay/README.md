# xchonnect-relay

> [!WARNING]
> **Pre-audit pre-release: testnet only, no real funds.** Xchonnect has not had an
> external security audit. Do not use any 0.x release to move, sign for or protect mainnet
> funds. Report vulnerabilities privately:
> [SECURITY.md](https://github.com/maximedogawa/xchonnect/blob/main/SECURITY.md).

Reference relay for the Xchonnect protocol: anonymous, capability-token mailboxes that
store end-to-end encrypted envelopes until the recipient fetches them
(spec Section 7, API in `docs/spec/wire/relay-api.md`).

## Run a development relay

One command, no keys, no database, from the repository root:

```sh
XCHONNECT_OHTTP=ephemeral cargo run -p xchonnect-relay
```

It listens on `http://127.0.0.1:8787` with an in-memory store. Check it:

```sh
curl http://127.0.0.1:8787/healthz     # ok
curl http://127.0.0.1:8787/v1/info     # limits, creation methods, "ohttp": true
```

`XCHONNECT_OHTTP=ephemeral` makes a throwaway OHTTP key on every start. Without it the
relay refuses to start, because OHTTP is on by default and needs a key (see below). Use
`XCHONNECT_OHTTP=false` instead if you want no OHTTP gateway at all.

Useful additions for local work:

| Add | Why |
|---|---|
| `XCHONNECT_POW_DIFFICULTY=12` | mailbox creation proof-of-work in milliseconds instead of seconds |
| `XCHONNECT_CREATION=open` | create mailboxes with no proof at all |
| `XCHONNECT_GATEWAY_POLICY=open XCHONNECT_DEV_ALLOW_INSECURE_GATEWAYS=true` | let wake-ups go to a push gateway on `http://127.0.0.1` |
| `XCHONNECT_LOG=debug` | more startup and backend output (never request details) |

Clients accept a plain-`http` relay only in developer mode **and** only on a loopback
address (`127.0.0.1`, `localhost`, `[::1]`): the SDK's `developerMode: true`, the CLI
wallet's `--dev`, or Pengui with `NEXT_PUBLIC_XCHONNECT_RELAY_URL=http://127.0.0.1:8787`
(Pengui turns developer mode on by itself for a loopback relay).

**Testing with a real phone.** A phone cannot use `http://<your LAN IP>:8787`, even in
developer mode. Give the dev relay an `https` URL with a tunnel and use that URL on both
sides, for example `cloudflared tunnel --url http://127.0.0.1:8787` or
`tailscale serve 8787`.

For the relay together with the example dApp and a CLI wallet, run
`./scripts/dev.sh` instead (see the [dApp quickstart](../../docs/guides/dapp-quickstart.md)).

## Run a production relay

Generate the two keys a production relay needs, once, and keep them in your secret store:

```sh
# 32 random bytes, base64url without padding (macOS and Linux)
openssl rand -base64 32 | tr '+/' '-_' | tr -d '='
```

| Key | Set as | Same on every node? |
|---|---|---|
| OHTTP gateway key | `XCHONNECT_OHTTP_KEYS=1:<key>` (`1` is the key id, 0–255) | yes |
| Proof-of-work key | `XCHONNECT_POW_KEY=<key>` | yes |

```sh
XCHONNECT_OHTTP_KEYS=1:<key> XCHONNECT_POW_KEY=<key> \
XCHONNECT_DATABASE_URL=postgres://… \
  cargo run --release -p xchonnect-relay
curl http://127.0.0.1:8787/readyz      # ok once the database is reachable
```

Put it behind a TLS proxy (below). The Docker Compose setup in `deploy/`, every setting,
and key rotation are in [Operating a relay](../../docs/operating.md).

dApps and wallets that use OHTTP pin your gateway's key configuration. Hand it to them as
base64url:

```sh
curl -fsS https://relay.example.org/.well-known/ohttp-keys | openssl base64 -A | tr '+/' '-_' | tr -d '='
```

(Pengui reads it as `NEXT_PUBLIC_XCHONNECT_OHTTP_KEY_CONFIG`.)

## Settings

All settings are environment variables; every one, with its default, is listed in
[Operating a relay](../../docs/operating.md#configuration-reference). The OHTTP settings:

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
