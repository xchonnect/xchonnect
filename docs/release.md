# Releasing Xchonnect

A release of this repository is meant to be checkable by someone who trusts nobody in
it: the binaries can be rebuilt bit-for-bit from the tagged source, every artifact has a
bill of materials, and the manifest that ties them together is signed by the release
workflow itself rather than by a key a person holds. Spec 11.4 and 16 and threat T15
(a tampered build reaching users) are what this exists for.

- Version numbers and changelog rules: [`versioning.md`](versioning.md)
- Package registries (not yet published): TASK-67
- Workflow: [`.github/workflows/release.yml`](../.github/workflows/release.yml)

## What a release contains

| Asset | Produced by |
|---|---|
| `xchonnect-relay-<version>-<triple>`, `xchonnect-gateway-<version>-<triple>` | `scripts/release-build.sh`, for `x86_64-unknown-linux-gnu` and `aarch64-unknown-linux-gnu` |
| `BUILD-INFO-<triple>.txt` | the same script: toolchain, commit, `SOURCE_DATE_EPOCH`, `RUSTFLAGS` |
| `*.cdx.json` | `scripts/sbom.sh`, CycloneDX 1.5, one per crate and one for the npm package; byte-identical on a rebuild of the same commit |
| `SHA256SUMS` | digests of every asset above |
| `SHA256SUMS.sigstore.json` | `cosign sign-blob`, Sigstore keyless (no private key exists) |
| provenance attestations | `actions/attest-build-provenance`, one per binary and SBOM |
| `ghcr.io/<owner>/xchonnect-relay:<version>`, `…-gateway:<version>` | `deploy/Dockerfile.dist`, multi-platform, signed with `cosign sign` and attested |

The images package the very binaries the release signed (`Dockerfile.dist` copies them
in, it does not compile), so verifying a binary verifies what is in the image.

## Cutting a release

1. Move the `Unreleased` section of `CHANGELOG.md` to `## [X.Y.Z] - YYYY-MM-DD`, keeping
   the `Protocol version:` and `Spec version:` lines.
2. Set the version in `Cargo.toml` (`[workspace.package]`) and `sdk-ts/package.json`, and
   refresh `Cargo.lock` (`cargo check --workspace --locked` must pass afterwards).
3. Merge that through the normal review path.
4. Dry-run the gate locally: `./scripts/release-gate.sh vX.Y.Z` (it will complain about
   the missing tag; everything else is checked).
5. Tag and push:

   ```sh
   git tag -s vX.Y.Z -m "xchonnect vX.Y.Z"
   git push origin vX.Y.Z
   ```

   The tag **must** be annotated and signed: the workflow refuses a lightweight or
   unsigned tag.
6. The run stops at the `Two-person approval` job. A second maintainer approves the
   `release` environment. Nothing is built, signed or pushed before that.
7. The run ends with a **draft** GitHub release. Check the assets, then publish it.

### The two-person rule

The wiki (`03-technical-stack-and-improvements.md` 2.7) requires signed releases with
two people. A GitHub environment only ever needs one approver, so one approval is not
two people. Both of these must hold, and the workflow checks both:

1. the tag carries a signature GitHub can verify, which attributes the contents to a
   maintainer (`scripts/release-gate.sh`);
2. the `release` environment was approved by a maintainer **other than** the person who
   started the run, checked against the run's approval list
   (`scripts/release-approval-check.sh`), with both logins in
   [`.github/release-maintainers.txt`](../.github/release-maintainers.txt).

## Verifying a release as a third party

### 1. Digests, signature and provenance

```sh
gh release download vX.Y.Z --dir dl --repo maximedogawa/xchonnect
./scripts/release-verify.sh --dir dl --tag vX.Y.Z \
  --image ghcr.io/maximedogawa/xchonnect-relay:X.Y.Z
```

That runs, and is worth understanding rather than trusting:

```sh
# the files are the files the manifest names
(cd dl && sha256sum -c SHA256SUMS)

# the manifest was signed by this repository's release workflow, on this tag.
# Keyless: the identity is the workflow, certified by Sigstore's Fulcio from the
# GitHub OIDC token. There is no long-lived signing key to steal.
cosign verify-blob --bundle dl/SHA256SUMS.sigstore.json \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity "https://github.com/maximedogawa/xchonnect/.github/workflows/release.yml@refs/tags/vX.Y.Z" \
  dl/SHA256SUMS

# GitHub attests which workflow, commit and runner produced each file
gh attestation verify dl/xchonnect-relay-X.Y.Z-x86_64-unknown-linux-gnu \
  --repo maximedogawa/xchonnect

# the image, by the same identity
cosign verify ghcr.io/maximedogawa/xchonnect-relay:X.Y.Z \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity "https://github.com/maximedogawa/xchonnect/.github/workflows/release.yml@refs/tags/vX.Y.Z"
```

A signature that verifies against any other identity — another workflow, another
repository, another ref — is not a release of this project.

### 2. Rebuilding the binaries yourself

```sh
git clone https://github.com/maximedogawa/xchonnect && cd xchonnect
git checkout vX.Y.Z
XCHONNECT_RELEASE_TARGET=x86_64-unknown-linux-gnu \
  ./scripts/release-repro-check.sh --manifest ../dl/SHA256SUMS
```

The script builds twice from cold target directories, requires the two results to be
identical, and then compares them with the published manifest. Note that `SHA256SUMS`
in a release names the assets as `xchonnect-relay-<version>-<triple>`, so compare
digests rather than file names, or point `--manifest` at the per-target `SHA256SUMS`
from the build artifacts.

What makes this work, and what you must match (all of it is set by
`scripts/release-build.sh`, so running the script is the way to match it):

| Input | Fixed how |
|---|---|
| compiler | `rust-toolchain.toml` pins the exact toolchain; rustup installs it |
| dependencies | `--locked`, so `Cargo.lock` decides every version |
| compiler flags | the script sets `RUSTFLAGS` and ignores whatever is in your environment |
| absolute paths | `--remap-path-prefix` for the checkout, `CARGO_HOME` and the sysroot |
| `OUT_DIR` paths | a fixed `--target-dir` |
| timestamps, locale | `SOURCE_DATE_EPOCH` (the commit time), `TZ=UTC`, `LC_ALL=C` |
| symbols | `-C strip=symbols`, so no local path survives in a symbol table |

**Verified reproducible** (two cold builds, digests compared):

| Target | Result |
|---|---|
| `aarch64-unknown-linux-gnu`, in `rust:1.98-bookworm` | identical digests |
| `aarch64-apple-darwin` (host build) | identical digests |
| `x86_64-unknown-linux-gnu` | gated in CI by the same script; not run on an arm64 development machine |

Cross-platform caveat: a build is reproducible for a given *target and build
environment*. The same target built with a different libc, linker or sysroot (musl
versus glibc, a different Debian release) legitimately gives a different binary, which is
why the published `BUILD-INFO.txt` names the environment and why the release builds run
on `ubuntu-24.04` images.

### 3. Rebuilding the images

```sh
SOURCE_DATE_EPOCH=$(git -c log.showsignature=false log -1 --pretty=%ct) \
docker buildx build -f deploy/Dockerfile.dist --target relay \
  --platform linux/amd64 \
  --output type=oci,dest=relay.tar,rewrite-timestamp=true \
  target/release-artifacts/x86_64-unknown-linux-gnu
```

The base image is pinned by digest, the build context holds only the binary, and
`rewrite-timestamp=true` with `SOURCE_DATE_EPOCH` clamps layer and config timestamps.
The release workflow builds each image twice and fails if the two differ, so image
reproducibility is gated on every release; it needs BuildKit (`docker buildx`), so a
Docker installation without buildx cannot check it.

## What a human must configure once

Nothing in this repository holds a key, and nothing here can create one. Before the
first release, a repository administrator sets up:

1. **The `release` environment** (Settings → Environments → `release`):
   - *Required reviewers*: at least two maintainers. Approval holds the run before any
     artifact exists.
   - *Deployment branches and tags*: restrict to tags matching `v*`.
2. **`.github/release-maintainers.txt`**: the logins allowed to start or approve a
   release, at least two, matching the reviewers above.
3. **Signing keys for tags**: each maintainer uploads a GPG or SSH signing key to their
   GitHub account, so GitHub can mark their tags verified. No signing key is used for
   artifacts — Sigstore keyless uses a short-lived certificate bound to the workflow's
   OIDC identity.
4. **Package write access** for `ghcr.io` (`packages: write` is already granted to the
   workflow; the first push also needs the package to be linked to the repository).
5. **Nothing for cosign**: there is intentionally no `COSIGN_PRIVATE_KEY`. If you ever
   introduce one, the verification identity above stops being the workflow and the
   two-person rule no longer covers the signature.
6. **Optional**: a `FUZZ_ADVISORY_TOKEN` secret for the fuzzing workflow, which is a
   separate concern — see [`fuzzing.md`](fuzzing.md).

## If something goes wrong

- *The gate fails on versions*: fix the version or the CHANGELOG on `main`, delete the
  tag, re-tag. Never re-point a tag that a run already signed.
- *The reproducibility gate fails*: do not release. A difference between two builds of
  the same source means some input is not pinned; the two artifact sets are kept in the
  job so they can be compared (`diffoscope` on the two binaries is the fastest route).
- *A release must be withdrawn*: delete the GitHub release and the image tag, publish an
  advisory per [`../SECURITY.md`](../SECURITY.md), and release a new version. Signatures
  cannot be revoked, so the withdrawal must be announced; Sigstore entries are public
  and permanent by design.
