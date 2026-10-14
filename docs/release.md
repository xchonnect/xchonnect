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
| `@xchonnect/dapp@<version>` on npm | built and packed by the `npm-pack` job; that very tarball published by the `npm` job, after everything above, with npm provenance (trusted publishing from the `release` environment, no token) |
| `xchonnect-core` and `xchonnect-wallet-kit` `<version>` on crates.io | packaged by `crates-package`, published by the `crates` job, last in the run (`scripts/release-crates.sh`; trusted publishing from the `release` environment, no token) |

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

   The tag **must** be annotated and signed with an **SSH signing key** that a login listed
   in [`.github/release-maintainers.txt`](../.github/release-maintainers.txt) has uploaded
   to GitHub (key type *Signing Key*): the gate checks the signature against those keys
   itself, and refuses a lightweight tag, an unsigned one, a GPG signature and a key of
   anyone else, even one GitHub shows as verified. Pushing it publishes **nothing**.
6. **The verify run.** The tag push starts `release.yml` without publishing: the `gate` job
   checks the tag, the versions (workspace, npm package and the two published crates), the
   CHANGELOG section and the tag's signer, and records the commit the tag points to; every
   later job checks out that commit by SHA. Then the binaries and images are each built
   twice and compared, the SBOMs are made, the crates are packaged, the npm tarball is
   built and packed (`npm-pack`) and the release directory with `SHA256SUMS` is assembled
   (`assemble`). Nothing is signed, pushed to ghcr.io, uploaded or published, and no GitHub
   release is created or changed. Wait for it to pass (the run's page in the browser). If
   it fails, fix the cause; the tag can still be deleted and re-made, because nothing was
   signed under it.
7. **The release.** On GitHub → Releases → *Draft a new release*:
   - *Choose a tag*: the tag you pushed. Never type a new tag name there: GitHub would
     create an unsigned lightweight tag, and the gate refuses it.
   - Title `vX.Y.Z`; notes from the CHANGELOG section of the version. A pre-release's notes
     start with the warning under [Cutting a pre-release](#cutting-a-pre-release-vxyz-rcn).
   - *Set as a pre-release* for a `-rc.N` version, and only then. The gate refuses a
     release whose pre-release box does not match the version, so an rc cannot become the
     repository's latest release by mistake (and a final version cannot hide as an rc).
   - *Publish release*. Saving a draft starts nothing.
8. **The publishing run.** Publishing the release starts `release.yml` again (event
   `release`, on the tag). The gate repeats every check and also requires the release to
   be published, its pre-release box to match and the tag to still point at the commit
   the event was for; then the same builds and packages are made. Only when **all** of
   them passed do the publishing jobs start, and each of them waits for a maintainer to
   **approve the `release` environment**: on the run's page, *Review deployments* → tick
   `release` → *Approve and deploy*. GitHub asks whenever a job reaches the environment,
   so expect up to three approvals: the images and the assets together (`images-publish`,
   `sign`), then `npm`, then `crates`. Each approval is also the moment to stop: *Reject*
   ends the run with nothing further published.
   - `images-publish` pushes the images to ghcr.io and signs them;
   - `sign` signs `SHA256SUMS` and **attaches every asset to your release**
     (`gh release upload --clobber`; your title and notes are left alone);
   - `npm` publishes the tarball `npm-pack` built (digest checked, nothing built or
     installed in that job);
   - `crates` publishes the two crates, last.

   Every one of these jobs first checks again that the release is published with the
   right pre-release box, that the tag still points at the commit the gate checked
   (`scripts/release-state-check.sh`) and that a maintainer approved the environment
   (`scripts/release-approval-check.sh`). The release page shows no assets until `sign`
   finishes.
9. **Check**: the release has the binaries, `BUILD-INFO-*.txt`, the SBOMs, `SHA256SUMS`
   and `SHA256SUMS.sigstore.json`; `./scripts/release-verify.sh` passes on them
   ([below](#verifying-a-release-as-a-third-party)); `npm view @xchonnect/dapp dist-tags`
   shows the version (under `next` for an rc); `./scripts/release-crates.sh --pending`
   prints nothing.

If the publishing run fails, the GitHub release is public, possibly without assets. Fix
the cause and use *Re-run failed jobs* on that run (it keeps the `release` event, the tag
and the gate's result; the re-run jobs check the release state and the approval
themselves and ask for the approval again). A re-run is safe at every step: `sign`
replaces its assets, `npm` passes without publishing when npm already has this exact
tarball, `crates` skips versions already on crates.io. A manual run (*Run workflow*, `tag`
and `publish` set) can publish too, but only when started on the tag itself (*Use workflow
from* → the tag) and only while a published release exists for it; otherwise the gate
refuses. See [If something goes wrong](#if-something-goes-wrong) for each job.

### Who can release

[`.github/release-maintainers.txt`](../.github/release-maintainers.txt) names the GitHub
logins that may release. A release needs, in this order:

1. **a `v*` tag**, which the tag ruleset lets only repository administrators create
   ([owner checklist](#what-the-owner-configures), step 2);
2. **signed by a listed maintainer**: `scripts/release-gate.sh` fetches each listed
   login's SSH signing keys from GitHub and verifies the tag with `ssh-keygen`; GitHub's
   own "verified" mark is required too but is not enough, since it accepts anyone's key;
3. **a published GitHub release** for the tag, which needs write access;
4. **an approval of the `release` environment** on the publishing run by one of its
   required reviewers, which `scripts/release-approval-check.sh` also checks against the
   list. The environment admits only `v*` tags, and npm, crates.io trust only OIDC
   tokens from `release.yml` running in it, so a workflow changed on a branch, or run from
   anything but a release tag, gets no publishing rights.

While the list holds one login, all four are the same person (see the note on roles in
[`guides/incident-response.md`](guides/incident-response.md)): the approval is a deliberate
second step, not a second person. As soon as it holds two or more,
`release-approval-check.sh` requires the approval to come from a maintainer other than the
tag's signer: the two-person rule switches itself on. A change to the list takes effect
for tags made after it is merged, because the gate reads it from the tagged commit; keep
it in step with the environment's reviewers and the ruleset's bypass list.

### Cutting a pre-release (`vX.Y.Z-rc.N`)

The same procedure, with these differences:

- Versions (`Cargo.toml` and `sdk-ts/package.json`) and the CHANGELOG heading carry the
  full pre-release version: `0.1.0-rc.1`, `## [0.1.0-rc.1] - YYYY-MM-DD`.
- You write the release notes; the workflow does not touch them. They start with the
  warning from the README, then the open limitations that matter to integrators (for
  example, push delivery that is not finished yet):

  ```markdown
  > **Pre-audit pre-release: testnet only, no real funds.** No external security audit
  > has been completed. Do not use it to move, sign for or protect mainnet funds.
  ```
- Tick *Set as a pre-release* when creating the GitHub release, so it is never shown as
  the repository's latest release; the gate refuses to publish without it. npm publishes
  the version under the `next` dist-tag, so `npm install @xchonnect/dapp` does not pick it
  up.
- crates.io needs no such switch: Cargo selects a pre-release only for a requirement that
  names one, so `xchonnect-core = "0.1"` and `cargo update` never land on an rc. The gate
  makes sure the crate READMEs show the exact requirement (`"=0.1.0-rc.1"`) instead.

## Verifying a release as a third party

### 1. Digests, signature and provenance

```sh
gh release download vX.Y.Z --dir dl --repo xchonnect/xchonnect
./scripts/release-verify.sh --dir dl --tag vX.Y.Z \
  --image ghcr.io/xchonnect/xchonnect-relay:X.Y.Z
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
  --certificate-identity "https://github.com/xchonnect/xchonnect/.github/workflows/release.yml@refs/tags/vX.Y.Z" \
  dl/SHA256SUMS

# GitHub attests which workflow, commit and runner produced each file
gh attestation verify dl/xchonnect-relay-X.Y.Z-x86_64-unknown-linux-gnu \
  --repo xchonnect/xchonnect

# the image, by the same identity
cosign verify ghcr.io/xchonnect/xchonnect-relay:X.Y.Z \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity "https://github.com/xchonnect/xchonnect/.github/workflows/release.yml@refs/tags/vX.Y.Z"
```

A signature that verifies against any other identity — another workflow, another
repository, another ref — is not a release of this project. The `release` environment the
signing jobs run in is not part of the Sigstore certificate (Fulcio records the workflow,
ref, commit, trigger and repository, not the environment), so the identity above did not
change when the environment was introduced. To pin the commit as well, add
`--certificate-github-workflow-sha <commit the tag points to>` (and
`--certificate-github-workflow-trigger release` for a release published from the web UI).

The repository moved from `maximedogawa/xchonnect` to `xchonnect/xchonnect` after
`v0.1.0-rc.1`. That release was signed under the old path, and its images are under
`ghcr.io/maximedogawa/`: verify it with `--repo maximedogawa/xchonnect` (or the old path in
the `--certificate-identity` above). Every later release uses the path shown here.

### 2. Rebuilding the binaries yourself

```sh
git clone https://github.com/xchonnect/xchonnect && cd xchonnect
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

## What the owner configures

Nothing in this repository holds a key, and nothing here can create one or change a
repository setting. A repository administrator works through this list, in this order,
before the first release that uses the workflow with the `release` environment
(0.1.0-rc.5): first merge the workflow, then steps 1 to 4, then push the tag. Step 1 must
come before any release is published: when a job names an environment that does not
exist, GitHub creates it on the spot, without any protection rule.

1. **The `release` environment.** Settings → Environments → *New environment*, name
   `release` (exactly; the workflow and the registries name it) → *Configure environment*:
   - *Required reviewers*: tick, add every login of `.github/release-maintainers.txt`.
   - *Prevent self-review*: **off** while there is one maintainer. On, GitHub forbids the
     person who started the run (who published the release) from approving it, and with
     one maintainer nobody could. The trade-off: with it off, one person signs, publishes
     and approves, so the approval guards against mistakes and against anyone who is not
     a listed reviewer, but not against that person or their stolen credentials. With a
     second maintainer, turn it on (and
     list the second login; `release-approval-check.sh` then also requires the approver
     not to be the tag's signer).
   - *Allow administrators to bypass configured protection rules*: **off**, so an admin's
     token or session cannot skip the review.
   - *Deployment branches and tags*: *Selected branches and tags* → *Add deployment branch
     or tag rule* → *Ref type: Tag*, name pattern `v*`. Add no branch rule.
   - No wait timer, no environment secrets or variables (none are used).
2. **A tag ruleset on `v*`.** Settings → Rules → Rulesets → *New ruleset* → *New tag
   ruleset*: name `release tags`, *Enforcement status: Active*; *Bypass list* → *Add
   bypass* → *Repository admin* (*Always allow*; while maintainers are admins, that is the
   maintainers; add *Maintain* only if a maintainer has that role instead); *Target tags*
   → *Add target* → *Include by pattern* `v*`; rules: *Restrict creations*, *Restrict
   updates*, *Restrict deletions*, *Block force pushes*. Optionally *Require signed
   commits*: the commits a release tag points at are merge commits made on GitHub, which
   GitHub signs. A ruleset cannot require a signed *tag*; the gate does that.
3. **npm: bind the trusted publisher to the environment.** npmjs.com → `@xchonnect/dapp` →
   *Settings* → *Trusted Publisher*: edit the GitHub Actions entry (or remove it and add a
   new one) to Organization or user `xchonnect`, Repository `xchonnect`, Workflow filename
   `release.yml`, **Environment name `release`** → save. Keep *Publishing access* at
   *Require two-factor authentication and disallow tokens*. See
   [Publishing the TypeScript SDK to npm](#publishing-the-typescript-sdk-to-npm).
4. **crates.io: bind both trusted publishers to the environment.** For `xchonnect-core`
   and then `xchonnect-wallet-kit`: crates.io → the crate → *Settings* → *Trusted
   Publishing*: remove the existing GitHub entry, then *Add* → GitHub: Repository owner
   `xchonnect`, Repository name `xchonnect`, Workflow filename `release.yml`,
   **Environment `release`** → save. Keep the option that requires trusted publishing on.
   See [Publishing the Rust crates to crates.io](#publishing-the-rust-crates-to-cratesio).
5. **Who has write access.** Publishing a GitHub release needs write access and GitHub
   cannot restrict it further; the environment and the ruleset are what stop a writer from
   publishing. ghcr.io cannot be restricted to an environment either: any workflow run of
   this repository that asks for `packages: write`, on any branch, can push to
   `ghcr.io/xchonnect/xchonnect-*` (Package → *Package settings* → *Manage Actions access*
   grants the repository *Write*; that is all GitHub offers). So keep write access to
   maintainers, and treat an image tag as a name, not a proof: deployments pull by digest
   after `cosign verify` with the identity in
   [Verifying a release](#verifying-a-release-as-a-third-party), which a run on a branch
   cannot obtain. Leave *immutable releases* off in the repository settings: the workflow
   attaches the assets after the release is published, which an immutable release refuses.
6. **Signing keys for tags**: each maintainer uploads an SSH key to their GitHub account
   as a *Signing Key* (Settings → SSH and GPG keys → *New SSH key*, *Key type: Signing
   Key*) and signs tags with it (`git config gpg.format ssh`, `user.signingkey`). No
   signing key is used for artifacts: Sigstore keyless uses a short-lived certificate bound
   to the workflow's OIDC identity.
7. **Nothing for cosign**: there is intentionally no `COSIGN_PRIVATE_KEY`. If you ever
   introduce one, the verification identity above stops being the workflow, and a stolen
   key could sign artifacts no tagged commit ever produced.
8. **No registry secrets**: there is intentionally no `NPM_TOKEN` and no
   `CARGO_REGISTRY_TOKEN`. A new package or crate first goes up by hand, then gets a
   trusted publisher as in steps 3 and 4 (the sections on npm and crates.io below).
9. **Optional**: a token for `scripts/fuzz-crash-report.sh`, which files a draft
   advisory for a crash found by local fuzzing — see [`fuzzing.md`](fuzzing.md).

To check steps 1 and 2 without a token: `curl -s
https://api.github.com/repos/xchonnect/xchonnect/environments` lists `release` with its
protection rules, and `curl -s https://api.github.com/repos/xchonnect/xchonnect/rulesets`
lists the tag ruleset.

## Publishing the TypeScript SDK to npm

`@xchonnect/dapp` is built and packed by the `npm-pack` job, which has no OIDC token, and
that tarball (its SHA-256 checked) is published by the `npm` job, which builds and installs
nothing, from the same signed tag and after every other job has passed. It authenticates
with
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
   Trusted Publisher → GitHub Actions: organisation/user `xchonnect`, repository
   `xchonnect`, workflow filename `release.yml`, environment `release`. With the
   environment named, npm accepts only a token of a job in that environment, which runs
   only on a `v*` tag after a maintainer's approval; left empty, any run of a modified
   `release.yml` on any branch could publish.
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
  so no build script runs in the `crates` job, which holds the OIDC token: cargo packages
  the sources and uploads them, it compiles nothing.
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
it — release assets, images, npm — is complete by then. Continue from there:

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
   Trusted Publishing → Add → GitHub: repository owner `xchonnect`, repository name
   `xchonnect`, workflow filename `release.yml`, environment `release` (as for npm: only a
   job in that environment, on a `v*` tag, after approval, can publish).
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

- *The gate fails on versions* (on the tag push): fix the version or the CHANGELOG on
  `main`, delete the tag, re-tag. Nothing was signed yet. Never re-point a tag that a
  publishing run already signed.
- *The gate fails on the signer*: the tag is not signed with an SSH signing key of a
  login in `.github/release-maintainers.txt` (a GPG signature, an authentication key
  uploaded as such instead of as a signing key, or a login missing from the list at the
  tagged commit). Upload the key as a *Signing Key*, or list the login on `main`, then
  delete and re-make the tag.
- *A run stops because the tag moved* (`release-state-check.sh`, or the gate's
  commit check): someone re-pointed the tag after the run started. Stop and find out who;
  a release tag is never moved.
- *A publishing job fails at "Release state and approval"* with no approval: the job was
  started without a review (for example by an administrator bypass); re-run it and approve
  it. With two listed maintainers, the approval must come from the one who did not sign
  the tag.
- *The gate fails on the release* (pre-release box, draft): edit the GitHub release and
  use *Re-run failed jobs*. A release created with a new tag name instead of the pushed
  tag carries a lightweight tag: delete the release and that tag, push the signed tag and
  create the release from it.
- *The reproducibility gate fails*: do not release. A difference between two builds of
  the same source means some input is not pinned; the two artifact sets are kept in the
  job so they can be compared (`diffoscope` on the two binaries is the fastest route).
- *The `sign` job fails at the upload*: the release has no or partial assets. Re-run
  failed jobs; `--clobber` replaces what the failed attempt left.
- *The `npm` job fails*: everything else of the release exists. Fix the cause and re-run
  only that job (Re-run failed jobs); the version is not burned until npm accepted it, and
  if npm did accept it the re-run sees the same integrity and passes, so `crates` runs. A
  `404`/`403` on publish almost always means the trusted publisher above does not match
  this repository, `release.yml` and the environment `release` exactly. *Already on npm
  with integrity …*: npm has this version with a different tarball (published by hand, or
  rebuilt by *Re-run all jobs*); check that what npm has is what you meant to release, and
  release `crates` by hand from the tag if needed (above), or deprecate and release a new
  version.
- *The `crates-package` or `npm-pack` job fails*: nothing was pushed, signed or published
  anywhere (every publishing job waits for all build and package jobs). Reproduce with
  `./scripts/release-crates.sh` or the `npm-pack` steps, fix on `main` and release a new
  version; the tag of a run that already signed artifacts is not re-pointed.
- *The `crates` job fails*: everything else of the release exists, npm included. Fix the
  cause and re-run only that job; versions already uploaded are skipped. A failure in the
  authentication step means the crate does not exist yet (first publish, above) or its
  trusted publisher does not match this repository, `release.yml` and the environment
  `release` exactly. If
  `xchonnect-core` went up and `xchonnect-wallet-kit` did not, re-run rather than yank.
- *A release must be withdrawn*: delete the GitHub release and the image tag,
  `npm deprecate @xchonnect/dapp@X.Y.Z "<reason>"`,
  [yank both crates](#yanking-a-broken-version), publish an
  advisory per [`../SECURITY.md`](../SECURITY.md), and release a new version. Signatures
  cannot be revoked, so the withdrawal must be announced; Sigstore entries are public
  and permanent by design.
