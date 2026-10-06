# Operating an Xchonnect relay

This guide covers self-hosting the reference relay and push gateway with the files in
[`deploy/`](../deploy). Hosted operators should read it together with spec Sections 10,
13.5, 14 and 16.

Just want a relay on your machine for development? That is one command and needs no
keys: see [Run a development relay](../crates/relay/README.md#run-a-development-relay).

## Quick start

```sh
cp deploy/example.env deploy/.env
# edit deploy/.env: XCHONNECT_DB_PASSWORD, XCHONNECT_POW_KEY and XCHONNECT_OHTTP_KEYS
# (generate the keys as below)
docker compose -f deploy/compose.yaml --env-file deploy/.env up -d
curl http://127.0.0.1:8787/readyz           # "ok"
```

The relay listens on `127.0.0.1:8787` only; publish it through a TLS reverse proxy.
Add `--profile gateway` (and `XCHONNECT_GATEWAY_KEYS`) to also run a push gateway.

## Generating the keys

Every key is 32 random bytes written as base64url without padding. This works on macOS and
Linux:

```sh
openssl rand -base64 32 | tr '+/' '-_' | tr -d '='
```

Run it once per key and store the results in your secret store, never in git:

| Setting | Value | Notes |
|---|---|---|
| `XCHONNECT_DB_PASSWORD` | any long random string (the command above works) | Compose only |
| `XCHONNECT_POW_KEY` | `<key>` | same on every relay node |
| `XCHONNECT_OHTTP_KEYS` | `1:<key>` | `1` is the key id (0–255); same on every node; rotation below |
| `XCHONNECT_GATEWAY_KEYS` | `<key>` | push gateway only (wallet vendors) |

The relay does not serve while OHTTP is enabled (the default) and
`XCHONNECT_OHTTP_KEYS` is missing. That is deliberate: a key made up at start would change
on every restart and break every client that pinned it.

### Waiting for settings

With settings that are missing or wrong, the relay and the gateway do not exit: they stay
up and serve nothing. `/up` answers `ok`, every other request (`/healthz`, `/readyz` and
the protocol routes included) gets `503` with `{"error":"unavailable"}`, and the reason
is written to the log at start and every ten minutes after that, never into a response.
A restart with working settings ends it.

This is for hosts that start a container first and take its settings afterwards, such as
[ONCE](#running-under-once): a process that exited there would make the host give the
deployment up before anybody could enter a setting. Nothing is served on settings the
relay or the gateway would not start with, so a typing mistake cannot open anything. If
your orchestrator restarts on a failed health check, point it at `/healthz` or `/readyz`,
not at `/up`: both fail while a service waits. A database that cannot be reached, or a
listen address that cannot be bound, still ends the process with an error, so the
container runtime restarts it until its dependency is back.

After the relay is up, give dApp and wallet developers your OHTTP key configuration as
base64url (they pin it; Pengui reads it as `NEXT_PUBLIC_XCHONNECT_OHTTP_KEY_CONFIG`):

```sh
curl -fsS https://relay.example.org/.well-known/ohttp-keys | openssl base64 -A | tr '+/' '-_' | tr -d '='
```

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
| `XCHONNECT_METRICS` | Keep `/metrics` reachable only from your monitoring network, or disable it. (It is never reachable through the OHTTP gateway.) |
| `XCHONNECT_OHTTP_KEYS` | Set in production, same on all nodes; see [OHTTP](#ohttp-spec-10). |

### Configuration reference

Every setting the relay reads, with its default:

| Variable | Default | Meaning |
|---|---|---|
| `XCHONNECT_LISTEN` | `127.0.0.1:8787` | address and port to listen on |
| `XCHONNECT_DATABASE_URL` | unset (in-memory) | Postgres URL; migrations run at start |
| `XCHONNECT_CREATION` | `pow,ticket,api_key` | accepted mailbox creation methods: `pow`, `ticket`, `api_key`, `open` |
| `XCHONNECT_POW_DIFFICULTY` | `18` | proof-of-work bits, 0–32 |
| `XCHONNECT_POW_KEY` | random per process | shared proof-of-work key, base64url 32 bytes; set it for more than one node |
| `XCHONNECT_API_KEYS` | none | `customer:key` pairs, comma separated, keys at least 16 characters |
| `XCHONNECT_GATEWAY_POLICY` | `allowlist` | `allowlist` or `open` |
| `XCHONNECT_GATEWAY_ALLOWLIST` | empty | push gateway URL prefixes, comma separated, each ending in `/` |
| `XCHONNECT_DEV_ALLOW_INSECURE_GATEWAYS` | `false` | allow `http` and private-network gateways; development only |
| `XCHONNECT_OHTTP` | `true` | `true`, `false`, or `ephemeral` (throwaway key, development only) |
| `XCHONNECT_OHTTP_KEYS` | required while `XCHONNECT_OHTTP=true` | `id:key`, comma separated, newest first |
| `XCHONNECT_OHTTP_KEYS_FILE` | unset | read the OHTTP keys from a file; wins over `XCHONNECT_OHTTP_KEYS` |
| `XCHONNECT_MAX_WAIT_S` | `25` (at most 60) | long-poll limit for direct requests, seconds |
| `XCHONNECT_MAX_WAIT_OHTTP_S` | `0` | long-poll limit through OHTTP, at most `XCHONNECT_MAX_WAIT_S` |
| `XCHONNECT_DEFAULT_TTL_S` | `86400` | message lifetime when the sender gives none, seconds |
| `XCHONNECT_MAX_TTL_S` | `604800` (at least 60, at most 604800) | longest message lifetime, seconds |
| `XCHONNECT_MAX_MESSAGES` | `256` | messages per mailbox |
| `XCHONNECT_MAX_BYTES` | `4194304` | bytes per mailbox |
| `XCHONNECT_WRITE_RATE` | `120` | messages per minute per write token |
| `XCHONNECT_READ_RATE` | `600` | requests per minute per read token |
| `XCHONNECT_CUSTOMER_RATE` | `60000` | messages per minute per API-key customer |
| `XCHONNECT_CREATE_RATE` | `600` | keyless mailbox creations per minute, whole relay |
| `XCHONNECT_METRICS` | `true` | serve `/metrics`; `0` or `false` turns it off |
| `XCHONNECT_LOG` | `info` | log filter (`warn`, `debug`, …); never includes request details |

Health checks: `/healthz` (process up) and `/readyz` (storage reachable), both answer `ok`.
`/up` is `/healthz` under the name a ONCE app's health check expects (see
[Running under ONCE](#running-under-once)).

## TLS and edge proxies

Terminate TLS in a reverse proxy (Caddy, nginx, a load balancer). Configure it to:

- not log request URLs (they contain mailbox ids), `Authorization` headers or bodies;
- avoid logging client IPs, or keep them only as long as your provider forces you to;
- allow request bodies of at least 400 KiB and requests lasting at least 30 s (long-poll);
- not cache responses.

**What you can observe without OHTTP** (state this in your public data inventory,
spec 10.3, 14): your proxy and the relay host see client IP addresses, mailbox ids in URLs,
bearer tokens and request timing. The relay software stores none of it, but the network
layer sees it. With OHTTP (below) your proxy sees only the OHTTP relay's address and
opaque bodies for clients that use it.

## OHTTP (spec 10)

The relay includes an Oblivious HTTP gateway (RFC 9458). Clients encrypt each request to
the gateway key and send it through an **independent OHTTP relay** operated by another
organisation; that relay sees client IPs but not content, you see content metadata but
not client IPs. The gateway is only useful together with such a partner.

**Enabling.**

1. Generate a key seed (same format as `XCHONNECT_POW_KEY`) and pick a key id (0–255):
   `XCHONNECT_OHTTP_KEYS=1:<seed>`. Use the same value on every node (keys are derived
   deterministically, so all nodes serve the same configuration). Treat it like a TLS
   private key: keep it in your secret store; `XCHONNECT_OHTTP_KEYS_FILE` reads it from a
   mounted file instead of the environment.
2. Without `XCHONNECT_OHTTP_KEYS` the relay does not serve while the gateway is enabled
   ([it waits for settings](#waiting-for-settings)).
   `XCHONNECT_OHTTP=ephemeral` generates a throwaway key at start instead (logged); that is
   for development only: clients pin the key configuration, and that key changes on every
   restart and differs between nodes.
3. Set `XCHONNECT_MAX_WAIT_OHTTP_S` to at most your OHTTP relay's request timeout minus
   5 s, or keep `0` (no long-polls through OHTTP; clients poll, spec 10.1).
4. Ask the OHTTP relay partner to forward to `https://<your relay>/.well-known/ohttp-gateway`
   and publish your key configuration (`/.well-known/ohttp-keys`) to dApp and wallet
   developers, who pin it in their configuration.
5. `XCHONNECT_OHTTP=false` disables the gateway (`/v1/info` then reports `"ohttp": false`).
   A relay without OHTTP must say in its documentation that it sees client IPs (spec 10).

**Rotating keys.** Prepend the new key and keep the old one:
`XCHONNECT_OHTTP_KEYS=2:<new seed>,1:<old seed>` (ids must differ). Roll this out to all
nodes. Clients holding the old configuration keep working and learn the new one through
the gateway (they fetch `/.well-known/ohttp-keys` encapsulated under their pinned key, so
the rotation is authenticated and does not reveal their address). Keep the old key for at
least as long as clients may stay offline (recommendation: 30 days), and tell integrators
to update their pinned configuration, then remove it. Requests under a removed key get the
RFC 9458 `ohttp-key` problem; clients treat a key list that no longer contains their
pinned key as a hard error. On key compromise remove the key immediately and announce the
new configuration out of band.

**Requirements on the OHTTP relay partner** (spec 10.2). It must:

- forward `POST` requests with `Content-Type: message/ohttp-req` and bodies of at least
  528 KiB (inner requests are padded to at most 512 KiB, spec 10.5; the gateway accepts up
  to 513 KiB);
- for browser clients, answer CORS preflights allowing `POST` and `Content-Type` from any
  origin, and expose no identifying response headers;
- use a request timeout of at least 15 s (and at least `XCHONNECT_MAX_WAIT_OHTTP_S` + 5 s);
- not log request bodies and not add client-identifying headers (forwarding headers,
  client IP headers) toward the gateway;
- be operated by an independent organisation under contract not to collude with you
  (spec 10).

Responses can be large (a fetch returns up to 32 envelopes, padded to at most 11 MiB);
agree on a response size limit of at least 12 MiB with the partner, or tell clients to use
the `limit` parameter of `GET .../messages`.

**Replays** (spec 10.4). An OHTTP relay could resend an encapsulated request. Each relay
node refuses an `enc` it accepted in the last 10 minutes (in memory, per node, at most
200 000 entries, oldest forgotten first) with the same `400 bad_request` it returns for a
malformed encapsulation, and the inner endpoint is not reached — so the answer tells a
replayer nothing it did not already know. An `enc` is only remembered once the
encapsulation decrypted, so a forged copy of an observed `enc` cannot keep the genuine
request out. Publish the window and the entry limit.

Older replays, replays to another node, or replays after a restart are processed as
repeated requests: they are harmless for message delivery (envelopes carry end-to-end
replay protection), proofs of work and tickets are single-use, ack and delete are
idempotent; a replayed push registration change or API-key mailbox creation is the
residual effect. Their responses are encrypted to the replayer's own encapsulation only if
the replayer re-encapsulated; a verbatim replay's response is readable only by the original
client. The cache is not a hard guarantee: anyone with the public key configuration can
send valid requests and, at 200 000 within the window, evict entries early; the residual
effects above apply then as well.

**Sizes.** Inner requests and responses are padded with zero bytes to size buckets
(spec 10.5: powers of two from 2 KiB to 256 KiB, then multiples of 256 KiB), so the OHTTP
relay — which knows client IPs — sees only which bucket a request falls into, not which
endpoint was called or whether a fetch returned a message. The 2 KiB floor costs about
2 KiB per poll. The bucket, the request rate and timing are still visible.

**Interop status.** The gateway is tested with Mozilla's `ohttp` crate (Rust, in
process) and with `ohttp-js` (an independent TypeScript implementation, against the relay
binary). It has not yet been tested behind a production OHTTP relay (e.g. Cloudflare
Privacy Gateway or Fastly OHTTP Relay); do that with your partner before going live.

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

## Push gateway (spec 7.3)

Each **wallet vendor** runs its own gateway with its own APNs and FCM credentials; relay
operators do not. It opens sealed push tokens, rate-limits per device in memory
(1 per 10 s, 60 per hour), delivers a content-free wake-up, and forgets the token. It
never learns mailbox ids or message content, and answers every wake request with the same
`202 {}` so it is not an oracle for token validity.

```sh
docker compose -f deploy/compose.yaml --env-file deploy/.env --profile gateway up -d
curl http://127.0.0.1:8788/healthz           # "ok"
```

`XCHONNECT_GATEWAY_KEYS` is required (base64url X25519 secret keys, newest first — keep
the previous key through a rotation). Publish the matching public keys from
`GET /v1/keys` so wallets can seal to them.

### Credentials

Credentials are read from a **file** at start-up, held in zeroizing memory and never
logged. Mount them read-only; do not pass keys in the environment. The one exception is a
host that can only pass settings, such as a ONCE app: there the APNs key may be given as
text (`XCHONNECT_GATEWAY_APNS_KEY`, see [Running under ONCE](#running-under-once)).

| Variable | Meaning |
|---|---|
| `XCHONNECT_GATEWAY_APNS_TEAM_ID` | Apple Developer Team ID |
| `XCHONNECT_GATEWAY_APNS_KEY_ID` | Key ID of the `.p8` key |
| `XCHONNECT_GATEWAY_APNS_KEY_FILE` | path to the `.p8` (unencrypted PKCS#8 P-256) |
| `XCHONNECT_GATEWAY_APNS_KEY` | the `.p8` text instead of the file (ONCE apps); set one of the two, not both |
| `XCHONNECT_GATEWAY_APNS_TOPIC` | app bundle id (`apns-topic`) |
| `XCHONNECT_GATEWAY_APNS_ENV` | `production` (default), `sandbox` or `both` |
| `XCHONNECT_GATEWAY_APNS_ALERT_TITLE` / `_BODY` | generic alert text |
| `XCHONNECT_GATEWAY_APNS_ALERT_TITLE_LOC_KEY` / `_LOC_KEY` | localisation keys instead of text (preferred: no user-visible text leaves the gateway) |
| `XCHONNECT_GATEWAY_FCM_SERVICE_ACCOUNT_FILE` | path to the service account JSON |
| `XCHONNECT_GATEWAY_FCM_ACCESS_TOKEN`, `..._FCM_PROJECT_ID` | a pre-issued OAuth token instead (development only; it is never refreshed) |

Setting `XCHONNECT_GATEWAY_APNS_TEAM_ID` without the other three APNs variables is an error
the gateway [waits on](#waiting-for-settings): one that silently drops iOS wake-ups is
worse than one that does not serve.
Without any platform configured every wake-up is counted as failed.

### What the device receives

Nothing that identifies the user or the request (T11, T12). iOS gets a static generic
alert with `interruption-level: time-sensitive` and `mutable-content: 1`; Android gets a
high-priority **data** message with no `notification` block, so the app renders it. The
payload is a pure function of this configuration — it does not vary per device, session or
message. If the wallet uses encrypted previews (spec 7.3.3) the gateway passes the sealed
168-byte blob through in the APNs `xcp` key or the FCM `data.xcp` member; it cannot read
it, and a preview of any other size is dropped while the wake-up still goes out.

### Metrics

`/metrics` exposes aggregate counters only: `requests`, `invalid`, `limited`,
`delivered`, `failed`, `invalid_device`, `forgotten`, `previews`. A rising
`invalid_device` means devices are uninstalling or tokens are expiring; `forgotten`
counts the device state dropped in response. Device tokens never appear in logs or
metrics.

## Running under ONCE

[ONCE](https://github.com/basecamp/once) runs a container behind its own TLS proxy. Its
contract is small: plain HTTP on **port 80**, a **`/up`** route, and settings as environment
variables. The release images meet it as they are: they listen on port 80 (the non-root
user may bind it in a container, Docker 20.10 and later), and without settings they
[wait for them](#waiting-for-settings) instead of exiting.

| App | Image |
|---|---|
| relay | `ghcr.io/<owner>/xchonnect-relay:<tag>` |
| gateway | `ghcr.io/<owner>/xchonnect-gateway:<tag>` |

Deploy first, then give the app its settings in ONCE (its settings screen, "Environment",
or `once update`). ONCE restarts the app with them:

```sh
once deploy ghcr.io/<owner>/xchonnect-relay:<tag> --host relay.example.org
curl https://relay.example.org/up        # ok: deployed, waiting for settings
curl https://relay.example.org/readyz    # 503 until the settings are in

once update relay.example.org \
  --env XCHONNECT_DATABASE_URL='postgres://xchonnect:<password>@<host>:<port>/xchonnect' \
  --env XCHONNECT_POW_KEY=<key> \
  --env XCHONNECT_OHTTP=false \
  --env XCHONNECT_GATEWAY_ALLOWLIST=https://push.example.org/
curl https://relay.example.org/readyz    # ok
```

`once update --env` replaces the whole set, so repeat every `--env` when one changes; the
same flags can go on `once deploy` to do both steps in one. While `/readyz` still says
`503`, the app's log in ONCE names the setting that is missing or wrong. Images up to
`0.1.0-rc.2` listen on 8787 and 8788 and exit without settings: for those, the settings
(`XCHONNECT_LISTEN=0.0.0.0:80` or `XCHONNECT_GATEWAY_LISTEN=0.0.0.0:80` among them) have to
be on the `once deploy` itself.

Keys given with `--env` are visible to whoever can run `once` or `docker inspect`
on that server, the same as any other ONCE setting. For the gateway that covers
`XCHONNECT_GATEWAY_KEYS` and, as the text of the `.p8`, `XCHONNECT_GATEWAY_APNS_KEY`:

```sh
once deploy ghcr.io/<owner>/xchonnect-gateway:<tag> --host push.example.org
once update push.example.org \
  --env XCHONNECT_GATEWAY_KEYS=<base64url X25519 secret key> \
  --env XCHONNECT_GATEWAY_APNS_TEAM_ID=<team id> \
  --env XCHONNECT_GATEWAY_APNS_KEY_ID=<key id> \
  --env XCHONNECT_GATEWAY_APNS_TOPIC=<bundle id> \
  --env XCHONNECT_GATEWAY_APNS_ENV=both \
  --env XCHONNECT_GATEWAY_APNS_KEY="$(awk 'NF {printf "%s\\n", $0}' AuthKey_<KEYID>.p8)"
```

The `awk` turns each line break into the two characters `\n`, which the gateway reads back as
a line break (ONCE's `--env` does not carry a raw one reliably). A key that does not parse
leaves the gateway [waiting](#waiting-for-settings) with the reason in its log, so a wrong
value shows at once and not at the first wake-up. Setting both
`XCHONNECT_GATEWAY_APNS_KEY` and `XCHONNECT_GATEWAY_APNS_KEY_FILE` is refused the same way.

The health check cannot tell a relay with a broken database from a healthy one (`/up` is
process liveness, so ONCE does not restart a relay for a database it cannot fix); watch
`/readyz` from outside.
