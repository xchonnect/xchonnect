# deploy/

What it takes to run a relay, and a push gateway if you are a wallet vendor, on your own
server. The procedure, the settings and their consequences are in
[`docs/operating.md`](../docs/operating.md); this page says what the files here are and
which of the three ways to run them fits.

| File | What it is |
|---|---|
| `compose.yaml` | Relay + Postgres, and the gateway under `--profile gateway`. Builds the images from this checkout. Hardened: read-only root, no capabilities, no new privileges, statement logging off in Postgres. |
| `compose.release.yaml` | Override for `compose.yaml`: the signed release images from `ghcr.io/xchonnect/` instead of a local build. |
| `example.env` | Every setting the compose files read, with the production defaults. Copy to `.env`, which is git-ignored. |
| `Dockerfile` | Compiles the relay and the gateway from source into a distroless image. For local builds and `compose.yaml`. |
| `Dockerfile.dist` | Packages the binaries a release already built and signed, so the image holds byte-for-byte the artifact in `SHA256SUMS`. The release workflow uses it; so does [reproducing a release](../docs/release.md#3-rebuilding-the-images). |

## Three ways to run it

**Release images with Compose** — a server with Docker, a relay you did not build:

```sh
cp deploy/example.env deploy/.env       # set XCHONNECT_VERSION, the password and the keys
docker compose -f deploy/compose.yaml -f deploy/compose.release.yaml \
  --env-file deploy/.env up -d
curl http://127.0.0.1:8787/readyz       # ok
```

**Build from the checkout with Compose** — the same, from source; `docker compose -f
deploy/compose.yaml --env-file deploy/.env up -d`. The relay listens on `127.0.0.1:8787`
only (`127.0.0.1:8788` for the gateway): put a TLS-terminating proxy in front
([`docs/operating.md`, TLS and edge proxies](../docs/operating.md#tls-and-edge-proxies)).

**One container on a host that provides the proxy and the database** — such as
[ONCE](../docs/operating.md#running-under-once): `once deploy
ghcr.io/xchonnect/xchonnect-relay:<version> --host relay.example.org`, then the settings.
The relay needs a Postgres it can reach; the gateway needs no database.

## The release images

| Image | Listens on | Needs |
|---|---|---|
| `ghcr.io/xchonnect/xchonnect-relay:<version>` | `0.0.0.0:80` | `XCHONNECT_DATABASE_URL` (Postgres; without it the relay refuses to start unless `XCHONNECT_STORE=memory` asks for a store in memory, gone at every restart), `XCHONNECT_POW_KEY`, `XCHONNECT_OHTTP_KEYS` or `XCHONNECT_OHTTP=false` |
| `ghcr.io/xchonnect/xchonnect-gateway:<version>` | `0.0.0.0:80` | `XCHONNECT_GATEWAY_KEYS`; APNs or FCM credentials to deliver anything |

Both run as uid 65532 on a distroless base, with no shell, and hold no setting but their
port. Started with none of their settings they wait for them instead of exiting
([waiting for settings](../docs/operating.md#waiting-for-settings)); started with some,
they exit with the error when one is wrong. `<version>` is a release tag without the
`v`, `0.1.0-rc.3` for instance; there is no `latest`. Multi-platform: `linux/amd64` and
`linux/arm64`.

Every release image is signed, keyless, by the release workflow. Verify before pulling
into production:

```sh
cosign verify ghcr.io/xchonnect/xchonnect-relay:<version> \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity "https://github.com/xchonnect/xchonnect/.github/workflows/release.yml@refs/tags/v<version>"
```

An image that verifies against any other identity is not a release of this project.
[`docs/release.md`](../docs/release.md#verifying-a-release-as-a-third-party) has the full verification,
including the binaries and the provenance attestation, and how to rebuild an image and
compare digests.

The release images listen on port 80 because that is the port a host such as ONCE
expects; the images `compose.yaml` builds listen on 8787 and 8788. `compose.release.yaml`
sets the listen address back, so the published ports are the same either way. Where the
container runtime does not let a non-root process bind port 80 (host networking, some
Kubernetes and Podman set-ups), set `XCHONNECT_LISTEN` or `XCHONNECT_GATEWAY_LISTEN` to a
high port.

## Development

For a relay on your own machine none of this is needed:
`XCHONNECT_STORE=memory XCHONNECT_OHTTP=ephemeral cargo run -p xchonnect-relay`
([`crates/relay/README.md`](../crates/relay/README.md#run-a-development-relay)), or
without a toolchain the release image with the same two settings as the
[dApp quickstart](../docs/guides/dapp-quickstart.md#1-a-first-pairing-from-npm-5-minutes).

## Upgrading

**From 0.1.0-rc.3 and earlier:** a relay without `XCHONNECT_DATABASE_URL` used to fall back
to an in-memory store without a word, and every redeploy dropped every mailbox, so every
paired wallet and dApp. It now refuses to start instead. Production: set
`XCHONNECT_DATABASE_URL` (`compose.yaml` does). A relay that really should keep everything
in memory (development, a demo) needs `XCHONNECT_STORE=memory`. The relay logs which store
it runs at start (`store: postgres` or `store: memory`).

Set the new `XCHONNECT_VERSION` and `up -d` again; the relay migrates its own database
schema at start. [`CHANGELOG.md`](../CHANGELOG.md) names the settings a release adds or
changes, and [`docs/operating.md`, Upgrades](../docs/operating.md#upgrades) the order to
follow with more than one relay node.
