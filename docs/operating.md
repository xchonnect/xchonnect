# Operating an Xchonnect relay

This guide covers self-hosting the reference relay and push gateway with the files in
[`deploy/`](../deploy). Hosted operators should read it together with spec Sections 10,
13.5, 14 and 16.

## Quick start

```sh
cp deploy/example.env deploy/.env          # set XCHONNECT_DB_PASSWORD and XCHONNECT_POW_KEY
docker compose -f deploy/compose.yaml --env-file deploy/.env up -d
curl http://127.0.0.1:8787/readyz           # "ok"
```

The relay listens on `127.0.0.1:8787` only; publish it through a TLS reverse proxy.
Add `--profile gateway` (and `XCHONNECT_GATEWAY_KEYS`) to also run a push gateway.

## Hardening defaults

Images are distroless and run as uid 65532 with a read-only root filesystem, all Linux
capabilities dropped and `no-new-privileges`. Postgres has no published port and runs
with statement and connection logging disabled (bound parameters include mailbox ids and
token hashes). Container logs use the `local` driver with rotation.

## Configuration

All relay settings are environment variables (table in `crates/relay/src/config.rs`). Key
choices:

| Setting | Recommendation |
|---|---|
| `XCHONNECT_CREATION` | Public relays: `pow,ticket,api_key`. Private relays behind authentication: `open`. |
| `XCHONNECT_POW_KEY` | Set the same random 32-byte key on all nodes; otherwise challenges only verify on the node that issued them. |
| `XCHONNECT_GATEWAY_POLICY` | `allowlist` with the push gateways of the wallets you support. `open` lets anyone make the relay contact arbitrary public HTTPS endpoints (rate-limited, never private networks). |
| `XCHONNECT_METRICS` | Keep `/metrics` reachable only from your monitoring network, or disable it. |

## TLS and edge proxies

Terminate TLS in a reverse proxy (Caddy, nginx, a load balancer). Configure it to:

- not log request URLs (they contain mailbox ids), `Authorization` headers or bodies;
- avoid logging client IPs, or keep them only as long as your provider forces you to;
- allow request bodies of at least 400 KiB and requests lasting at least 30 s (long-poll);
- not cache responses.

**What you can observe without OHTTP** (state this in your public data inventory,
spec 10.3, 14): your proxy and the relay host see client IP addresses, mailbox ids in URLs,
bearer tokens and request timing. The relay software stores none of it, but the network
layer sees it. OHTTP support (spec 10, milestone M4) removes client IPs from your view.

## Backups and retention

The database holds only ciphertext with expiry (at most 7 days), token hashes, sealed push
registrations and day-granular timestamps. Backups are optional: losing the database
only forces users to re-pair. If you back it up, encrypt backups and keep them no longer
than 7 days so they do not extend message retention.

## Upgrades

Migrations run automatically at relay start. Upgrade one node at a time; the API and
schema are backward compatible within a release line. Check `docs/spec/CHANGELOG.md` for
protocol changes.

## Conformance

After deploying, run the black-box suite against your public URL:

```sh
cargo run -p xchonnect-conformance -- relay https://relay.example.org
```

## Logging policy

The relay logs only startup, shutdown and backend error descriptions, never request
details. Keep any logs your platform retains for at most 14 days (spec 13.5).
