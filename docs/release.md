# Releasing Xchonnect

A release of this repository is meant to be checkable by someone who trusts nobody in
it: the binaries can be rebuilt bit-for-bit from the tagged source, every artifact has a
bill of materials, and the manifest that ties them together is signed by the release
workflow itself rather than by a key a person holds. Spec 11.4 and 16 and threat T15
(a tampered build reaching users) are what this exists for.

- Version numbers and changelog rules: [`versioning.md`](versioning.md)
- npm (`@xchonnect/dapp`): [Publishing the TypeScript SDK to npm](#publishing-the-typescript-sdk-to-npm)
- crates.io (`xchonnect-core`, `xchonnect-wallet-kit`):
  [Publishing the Rust crates to crates.io](#publishing-the-rust-crates-to-cratesio);
  the Swift package, Maven and the remaining crates are still TASK-67
- Workflow: [`.github/workflows/release.yml`](../.github/workflows/release.yml)

## What a release contains

| Asset | Produced by |
|---|---|
| `xchonnect-relay-<version>-<triple>`, `xchonnect-gateway-<version>-<triple>` | `scripts/release-build.sh`, for `x86_64-unknown-linux-gnu` and `aarch64-unknown-linux-gnu` |
| `BUILD-INFO-<triple>.txt` | the same script: toolchain, commit, `SOURCE_DATE_EPOCH`, `RUSTFLAGS` |
| `*.cdx.json` | `scripts/sbom.sh`, CycloneDX 1.5, one per crate and one for the npm package; byte-identical on a rebuild of the same commit |
| `SHA256SUMS` | digests of every asset above |
| `SHA256SUMS.sigstore.json` | `cosign sign-blob`, Sigstore keyless (no private key exists) |
| provenance attestations | `actions/attest-build-provenance`, one per binary and SBOM; only while the repository is public (see below) |
| `ghcr.io/<owner>/xchonnect-relay:<version>`, `…-gateway:<version>` | `deploy/Dockerfile.dist`, multi-platform, signed with `cosign sign` and attested |
| `@xchonnect/dapp@<version>` on npm | the `npm` job, after everything above, with npm provenance (trusted publishing, no token) |
| `xchonnect-core` and `xchonnect-wallet-kit` `<version>` on crates.io | the `crates` job, last in the run (`scripts/release-crates.sh`; trusted publishing, no token) |

The images package the very binaries the release signed (`Dockerfile.dist` copies them
in, it does not compile), so verifying a binary verifies what is in the image.

GitHub stores build provenance attestations only for public repositories (and for private
ones on Enterprise Cloud). The workflow skips the two attestation steps when the repository
is private, so a release cut from a private repository has the Sigstore signatures but no
attestations, and `gh attestation verify` reports nothing to verify for it. Everything else
(digests, signatures, reproducibility) is unaffected.

## Cutting a release

1. Move the `Unreleased` section of `CHANGELOG.md` to `## [X.Y.Z] - YYYY-MM-DD`, keeping
   the `Protocol version:` and `Spec version:` lines.
2. Set the version in `Cargo.toml` — `[workspace.package]` and the three `"=X.Y.Z"`
   requirements under `[workspace.dependencies]` — and in `sdk-ts/package.json`, and
   refresh `Cargo.lock` (`cargo check --workspace --locked` must pass afterwards). For a
   pre-release, also set it in the dependency line of `crates/core/README.md` and
   `crates/wallet-kit/README.md`.
3. Merge that through the normal review path.
4. Dry-run the gate locally: `./scripts/release-gate.sh vX.Y.Z` (it will complain about
   the missing tag; everything else is checked), and package the crates the way the
   workflow will: `./scripts/release-crates.sh`.
5. Tag and push:

   ```sh
   git tag -s vX.Y.Z -m "xchonnect vX.Y.Z"
   git push origin vX.Y.Z
   ```

   The tag **must** be annotated and signed: the workflow refuses a lightweight or
   unsigned tag.
6. The `gate` job checks the tag, the versions (workspace, npm package and the two
   published crates), the CHANGELOG section and the tag signature; nothing is built,
   signed or pushed before it passes. There is no manual approval step: pushing the signed
   tag is the release decision.
7. The run ends with a **draft** GitHub release and, unlike the draft, an `@xchonnect/dapp`
   that is **already public on npm** and two crates that are **already public on
   crates.io** (the `npm` job runs only after everything else passed, the `crates` job
   after that). Check the assets, then publish the GitHub release.

### Who can release

The tag signature is the only sign-off: the gate requires a signature GitHub can verify,
which attributes the release to a maintainer (`scripts/release-gate.sh`). There is no
second approver while the project has a single maintainer (see the note on roles in
[`guides/incident-response.md`](guides/incident-response.md)), so tag protection (below)
is what keeps anyone else from cutting a release.

### Cutting a pre-release (`vX.Y.Z-rc.N`)

The same procedure, with these differences:

- Versions (`Cargo.toml` and `sdk-ts/package.json`) and the CHANGELOG heading carry the
  full pre-release version: `0.1.0-rc.1`, `## [0.1.0-rc.1] - YYYY-MM-DD`.
- Release notes start with the warning from the README: *pre-audit pre-release, testnet
  only, no real funds*, plus the open limitations that matter to integrators (for example,
  push delivery that is not finished yet).
- The workflow creates the draft as a GitHub **pre-release**, so it is never shown as
  the repository's latest release, and npm publishes it under the `next` dist-tag, so
  `npm install @xchonnect/dapp` does not pick it up.
- crates.io needs no such switch: Cargo selects a pre-release only for a requirement that
  names one, so `xchonnect-core = "0.1"` and `cargo update` never land on an rc. The gate
  makes sure the crate READMEs show the exact requirement (`"=0.1.0-rc.1"`) instead.

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

1. **Branch and tag protection**: only maintainers may create tags matching `v*`. With no
   approval step in the workflow, whoever can push a signed `v*` tag can cut a release,
   so this rule is what stands between a compromised contributor account and a release.
2. **Signing keys for tags**: each maintainer uploads a GPG or SSH signing key to their
   GitHub account, so GitHub can mark their tags verified. No signing key is used for
   artifacts — Sigstore keyless uses a short-lived certificate bound to the workflow's
   OIDC identity.
3. **Package write access** for `ghcr.io` (`packages: write` is already granted to the
   workflow; the first push also needs the package to be linked to the repository).
4. **Nothing for cosign**: there is intentionally no `COSIGN_PRIVATE_KEY`. If you ever
   introduce one, the verification identity above stops being the workflow, and a stolen
   key could sign artifacts no tagged commit ever produced.
5. **npm**: the `@xchonnect` scope, a first manual publish and a trusted publisher — see
   [Publishing the TypeScript SDK to npm](#publishing-the-typescript-sdk-to-npm). There is
   intentionally no `NPM_TOKEN` secret.
6. **crates.io**: a first manual publish of both crates and a trusted publisher on each —
   see [Publishing the Rust crates to crates.io](#publishing-the-rust-crates-to-cratesio).
   There is intentionally no `CARGO_REGISTRY_TOKEN` secret.
7. **Optional**: a `FUZZ_ADVISORY_TOKEN` secret for the fuzzing workflow, which is a
   separate concern — see [`fuzzing.md`](fuzzing.md).

## Publishing the TypeScript SDK to npm

`@xchonnect/dapp` is published by the `npm` job of the release workflow, from the same
signed tag and after every other job has passed. It authenticates with
npm **trusted publishing**: npm accepts the workflow's short-lived GitHub OIDC token instead
of a long-lived `NPM_TOKEN`, and attaches provenance (`publishConfig.provenance`) linking
the tarball to this repository, workflow and commit. A version containing `-`
(`1.0.0-rc.1`) is published under the `next` dist-tag, anything else under `latest`.

The gate already requires `sdk-ts/package.json` to carry the tag's version, so cutting a
release (above) is all a routine publish needs. An npm version can never be reused, even
after `npm unpublish`; a broken one is fixed with `npm deprecate` and a new version.

### Once, before the first automated publish

npm only lets a trusted publisher be configured on a package that already exists, so the
very first version goes up by hand:

1. **Own the scope.** On npmjs.com create the organisation `xchonnect` (free, public
   packages), add the maintainers, and require two-factor authentication for the org.
2. **Publish the first version manually**, from a clean checkout of a signed release tag:

   ```sh
   git checkout vX.Y.Z
   cargo install wasm-bindgen-cli --version 0.2.129 --locked   # once
   ./scripts/build-wasm.sh
   npm ci --ignore-scripts && npm run build -w @xchonnect/dapp
   (cd sdk-ts && npm pack --dry-run)       # check the file list: dist/, README.md, LICENSE
   npm login                               # a maintainer of the xchonnect org, with 2FA
   npm publish -w @xchonnect/dapp --ignore-scripts --provenance=false --tag next
   ```

   `--provenance=false` because provenance can only be generated inside CI; this one
   version therefore has none. Use `--tag latest` instead of `next` if this version is meant
   to be the default install.

3. **Register the trusted publisher.** On npmjs.com → `@xchonnect/dapp` → Settings →
   Trusted Publisher → GitHub Actions: organisation/user `maximedogawa`, repository
   `xchonnect`, workflow filename `release.yml`, environment left empty (the workflow
   uses no GitHub environment).
4. **Lock the package to the workflow.** Same page, Publishing access → *Require two-factor
   authentication and disallow tokens*. From then on only `release.yml` can publish; a
   leaked maintainer password or token cannot.
5. Verify the next release: `npm view @xchonnect/dapp dist-tags` shows the version, and
   `npm audit signatures` in a project depending on it reports a verified provenance
   attestation.

### Consuming a published version

```sh
npm install @xchonnect/dapp@X.Y.Z        # or: bun add @xchonnect/dapp@X.Y.Z
```

The WASM core ships inside the package at `@xchonnect/dapp/xchonnect_bg.wasm`
(`dist/wasm/xchonnect_bg.wasm`). An app whose bundler does not handle WebAssembly copies
that file into its static assets and passes its URL to the SDK, as Pengui does.

## Publishing the Rust crates to crates.io

Rust wallets depend on two crates: `xchonnect-core` (the protocol) and
`xchonnect-wallet-kit` (signing safety on Chia, which requires the core). The `crates` job
publishes both from the signed tag, core first, as the last step of the run. The other
crates of the workspace are not published to crates.io (TASK-67).

- **No stored token.** The job authenticates with crates.io **trusted publishing**:
  `rust-lang/crates-io-auth-action` exchanges the workflow's GitHub OIDC token for a
  crates.io token that lives for minutes and is revoked when the job ends.
- **What is uploaded was built first.** The `crates-package` job runs
  `./scripts/release-crates.sh` right after the gate: `cargo package --locked` builds each
  crate from its own tarball (wallet-kit against the packaged core), and the script checks
  that each tarball carries `LICENSE` and `README.md`, has no dependency by path, and
  requires the core at exactly the release version. The upload itself uses `--no-verify`,
  so no dependency's build script runs while the token is in the environment.
- **One version, both crates.** `[workspace.dependencies]` requires the workspace crates
  with `=`, so `xchonnect-wallet-kit X.Y.Z` resolves to `xchonnect-core X.Y.Z` and nothing
  newer. The gate refuses a tag when a crate's version, that requirement or (for a
  pre-release) the README's dependency line differs from the tag.
- **Re-runs are safe.** A version that is already on crates.io is skipped, and when
  nothing is left to publish the job does not ask for a token at all.

### Once, before the first automated publish

crates.io only lets a trusted publisher be configured on a crate that already exists, so
the first version of each crate goes up by hand. On the first release that includes the
`crates` job, that job therefore **fails at the authentication step**; everything before
it — draft release, images, npm — is complete by then. Continue from there:

1. **Have a crates.io account** (sign in with GitHub at <https://crates.io>, verify the
   e-mail address) and create an API token under Account Settings → API Tokens with the
   scope `publish-new`, an expiry of a day, and the crate pattern `xchonnect-*`.
2. **Publish the first version manually**, from a clean checkout of the signed release tag:

   ```sh
   git checkout vX.Y.Z
   ./scripts/release-gate.sh vX.Y.Z      # versions, CHANGELOG, tag signature
   ./scripts/release-crates.sh           # package, build from the tarballs, check them
   cargo login                           # paste the token
   ./scripts/release-crates.sh --publish # core, then wallet-kit
   cargo logout
   ```

   Then revoke the token on crates.io.
3. **Register the trusted publisher on both crates.** crates.io → the crate → Settings →
   Trusted Publishing → Add → GitHub: repository owner `maximedogawa`, repository name
   `xchonnect`, workflow filename `release.yml`, environment left empty (the workflow uses
   no GitHub environment).
4. **Lock both crates to the workflow.** Same settings page: turn on the option that
   requires trusted publishing, which disables publishing with API tokens. From then on
   only `release.yml` can publish; a leaked token of a crate owner cannot.
5. Re-run the failed `crates` job (Re-run failed jobs). It finds both versions on
   crates.io, skips them and passes, so the run is green. The next release publishes
   without anyone's token.

### Consuming a published version

```toml
[dependencies]
xchonnect-wallet-kit = "=X.Y.Z-rc.N"
# only when the wallet also calls the core directly; same version as the kit
xchonnect-core = "=X.Y.Z-rc.N"
```

The exact requirement is what selects a pre-release, and it keeps a later release
candidate, which may break the API, from being picked up by `cargo update`.

### Yanking a broken version

A crates.io version can never be replaced or reused. A broken one is **yanked**: projects
that already have it in their `Cargo.lock` keep building, and no new resolution selects
it.

```sh
cargo yank --version X.Y.Z xchonnect-wallet-kit
cargo yank --version X.Y.Z xchonnect-core
```

Yank both even when only one is at fault: wallet-kit requires the core at exactly its own
version, so wallet-kit without its core no longer resolves, and a core without its kit
invites mixing. Yanking needs an owner's API token with the `yank` scope (trusted
publishing only covers publishing), or the Yank button on the crate's Versions page.
`cargo yank --undo` reverses it. Then release a fixed version, and for a security problem
publish an advisory per [`../SECURITY.md`](../SECURITY.md) — a yank hides a version, it
does not warn the wallets that already ship it.

## If something goes wrong

- *The gate fails on versions*: fix the version or the CHANGELOG on `main`, delete the
  tag, re-tag. Never re-point a tag that a run already signed.
- *The reproducibility gate fails*: do not release. A difference between two builds of
  the same source means some input is not pinned; the two artifact sets are kept in the
  job so they can be compared (`diffoscope` on the two binaries is the fastest route).
- *The `npm` job fails*: everything else of the release exists. Fix the cause and re-run
  only that job (Re-run failed jobs); the version is not burned until npm accepted it. A
  `404`/`403` on publish almost always means the trusted publisher above does not match
  this repository and `release.yml` exactly.
- *The `crates-package` job fails*: nothing was published anywhere (`npm` and `crates`
  wait for it). Reproduce with `./scripts/release-crates.sh`, fix on `main` and release a
  new version; the tag of a run that already signed artifacts is not re-pointed.
- *The `crates` job fails*: everything else of the release exists, npm included. Fix the
  cause and re-run only that job; versions already uploaded are skipped. A failure in the
  authentication step means the crate does not exist yet (first publish, above) or its
  trusted publisher does not match this repository and `release.yml` exactly. If
  `xchonnect-core` went up and `xchonnect-wallet-kit` did not, re-run rather than yank.
- *A release must be withdrawn*: delete the GitHub release and the image tag,
  `npm deprecate @xchonnect/dapp@X.Y.Z "<reason>"`,
  [yank both crates](#yanking-a-broken-version), publish an
  advisory per [`../SECURITY.md`](../SECURITY.md), and release a new version. Signatures
  cannot be revoked, so the withdrawal must be announced; Sigstore entries are public
  and permanent by design.
