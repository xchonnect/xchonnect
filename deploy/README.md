# deploy/

What it takes to run a relay, and a push gateway if you are a wallet vendor, on your own
server. The procedure, the settings and their consequences are in
[`docs/operating.md`](../docs/operating.md); this page says what the files here are and
which of the three ways to run them fits.

| File | What it is |
|---|---|
| `compose.yaml` | Relay + Postgres, and the gateway under `--profile gateway`. Builds the images from this checkout. Hardened: read-only root, no capabilities, no new privileges, statement logging off in Postgres. |
| `compose.release.yaml` | Override for `compose.yaml`: the signed release images from `ghcr.io/xchonnect/`, pinned by the digest you verified, instead of a local build. |
| `example.env` | Every setting the compose files read, with the production defaults. Copy to `.env`, which is git-ignored. |
| `Dockerfile` | Compiles the relay and the gateway from source into a distroless image. For local builds and `compose.yaml`. |
| `Dockerfile.dist` | Packages the binaries a release already built and signed, so the image holds byte-for-byte the artifact in `SHA256SUMS`. The release workflow uses it; so does [reproducing a release](../docs/release.md#3-rebuilding-the-images). |

## Three ways to run it

**Release images with Compose** — a server with Docker, a relay you did not build:

```sh
cp deploy/example.env deploy/.env       # the password, the keys, and the verified digests:
                                        # XCHONNECT_RELAY_DIGEST (below, "The release images")
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
ghcr.io/xchonnect/xchonnect-relay@sha256:<digest> --host relay.example.org` with the
digest you verified (below), then the settings.
The relay needs a Postgres it can reach; the gateway needs no database.

## The release images

| Image | Listens on | Needs |
|---|---|---|
| `ghcr.io/xchonnect/xchonnect-relay` | `0.0.0.0:80` | `XCHONNECT_DATABASE_URL` (Postgres; without it the relay refuses to start unless `XCHONNECT_STORE=memory` asks for a store in memory, gone at every restart), `XCHONNECT_POW_KEY`, `XCHONNECT_OHTTP_KEYS` or `XCHONNECT_OHTTP=false` |
| `ghcr.io/xchonnect/xchonnect-gateway` | `0.0.0.0:80` | `XCHONNECT_GATEWAY_KEYS`; APNs or FCM credentials to deliver anything |

Both run as uid 65532 on a distroless base, with no shell, and hold no setting but their
port. Started with none of their settings they wait for them instead of exiting
([waiting for settings](../docs/operating.md#waiting-for-settings)); started with some,
they exit with the error when one is wrong. Each release is tagged `<version>`, the
release tag without the `v` (`1.2.3`, `1.2.3-rc.1`); there is no `latest`.
Multi-platform: `linux/amd64` and `linux/arm64`.

**Run a release image only by its digest, and only the digest you verified.** Every
release image is signed, keyless, by the release workflow. A tag is only a name: whoever
can push to the package can point it at other bytes after you verified it (by default any
workflow run of the repository can, [`docs/release.md`, Pushing images to
ghcr.io](../docs/release.md#pushing-images-to-ghcrio)). So verify, take the digest the
verification reports, and pull and run that digest, never the tag:

```sh
gh release download v<version> --dir dl --repo xchonnect/xchonnect
./scripts/release-verify.sh --dir dl --tag v<version> \
  --image ghcr.io/xchonnect/xchonnect-relay:<version> \
  --image ghcr.io/xchonnect/xchonnect-gateway:<version>
# ends with, for deploy/.env:
#   XCHONNECT_RELAY_DIGEST=sha256:…
#   XCHONNECT_GATEWAY_DIGEST=sha256:…
```

Put those lines into `deploy/.env` (the gateway's only matters with `--profile gateway`); `compose.release.yaml` runs
`ghcr.io/xchonnect/xchonnect-relay@${XCHONNECT_RELAY_DIGEST}` and refuses to start
without it (a tag in the variable gives an invalid image name, so nothing is pulled).
Without the script, `cosign verify` alone does the same check and names the digest it
verified (`jq` reads it):

```sh
cosign verify ghcr.io/xchonnect/xchonnect-relay:<version> \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity "https://github.com/xchonnect/xchonnect/.github/workflows/release-publish.yml@refs/tags/v<version>" |
  jq -r '.[0].critical.image."docker-manifest-digest"'
# sha256:…  ->  docker pull ghcr.io/xchonnect/xchonnect-relay@sha256:…
```

cosign resolves the tag once and checks the signatures of what it resolved to, so the
digest it prints is the one whose signature it checked; a later pull by that digest gets
those bytes or nothing. An image that verifies against any other identity is not a
release of this project, including the `release.yml` identity of the tags up to
`v0.1.0-rc.4` (`docs/release.md`, "The old `release.yml`").
[`docs/release.md`](../docs/release.md#verifying-a-release-as-a-third-party) has the full
verification, including the binaries and the provenance attestation, and how to rebuild an
image and compare digests.

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

Verify the new release as above, put its digests into `deploy/.env` and `up -d` again; the relay migrates its own database
schema at start. [`CHANGELOG.md`](../CHANGELOG.md) names the settings a release adds or
changes, and [`docs/operating.md`, Upgrades](../docs/operating.md#upgrades) the order to
follow with more than one relay node.
