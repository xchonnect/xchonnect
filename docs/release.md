# Releasing Xchonnect

A release of this repository is meant to be checkable by someone who trusts nobody in
it: the binaries can be rebuilt bit-for-bit from the tagged source, every artifact has a
bill of materials, and the manifest that ties them together is signed by the release
workflow itself rather than by a key a person holds. Spec 11.4 and 16 and threat T15
(a tampered build reaching users) are what this exists for.

- Version numbers and changelog rules: [`versioning.md`](versioning.md)
- npm (`@xchonnect/dapp`, `@xchonnect/mcp`): [Publishing the TypeScript SDK to npm](#publishing-the-typescript-sdk-to-npm)
- crates.io (`xchonnect-core`, `xchonnect-wallet-kit`):
  [Publishing the Rust crates to crates.io](#publishing-the-rust-crates-to-cratesio);
  the Swift package, Maven and the remaining crates are still TASK-67
- Workflow: [`.github/workflows/release-publish.yml`](../.github/workflows/release-publish.yml)

## What a release contains

| Asset | Produced by |
|---|---|
| `xchonnect-relay-<version>-<triple>`, `xchonnect-gateway-<version>-<triple>` | `scripts/release-build.sh`, for `x86_64-unknown-linux-gnu` and `aarch64-unknown-linux-gnu`; built twice in `binaries-<arch>` and a third time on another runner by `binaries-<arch>-repro`, which must arrive at the same digests |
| `BUILD-INFO-<triple>.txt` | the same script: toolchain, commit, `SOURCE_DATE_EPOCH`, `RUSTFLAGS` |
| `*.cdx.json` | `scripts/sbom.sh`, CycloneDX 1.5, one per crate and one per npm package; built by `sbom` and again on another runner by `sbom-repro`, which must arrive at the same digests. Byte-identical on a rebuild of the same commit **at the same checkout path**: the Cargo SBOMs record the absolute path of each workspace crate (`/home/runner/work/xchonnect/xchonnect/…` on GitHub's runners), so a rebuild elsewhere differs in those lines only |
| `SHA256SUMS` | digests of every asset above |
| `SHA256SUMS.sigstore.json` | `cosign sign-blob`, Sigstore keyless (no private key exists) |
| provenance attestations | `actions/attest-build-provenance`, one per binary and SBOM; only while the repository is public (see below) |
| `ghcr.io/<owner>/xchonnect-relay:<version>`, `…-gateway:<version>` | `deploy/Dockerfile.dist`, multi-platform, signed with `cosign sign` and attested |
| `@xchonnect/dapp@<version>` and `@xchonnect/mcp@<version>` on npm | built and packed twice, by `npm-pack` and independently by `npm-pack-repro` (`scripts/release-npm-pack.sh`), which must give the same SHA-256 for each; those very tarballs published by the `npm` job, after everything above, the SDK first, with npm provenance (trusted publishing from the `release` environment, no token) |
| `xchonnect-core` and `xchonnect-wallet-kit` `<version>` on crates.io | packaged by `crates-package`, published by the `crates` job, last in the run, only when it packages the same bytes again (`scripts/release-crates.sh`; trusted publishing from the `release` environment, no token) |

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
   requirements under `[workspace.dependencies]` — in `sdk-ts/package.json` and in
   `agent-mcp/package.json`, and refresh `Cargo.lock` (`cargo check --workspace --locked`
   must pass afterwards), `package-lock.json` and `agent-mcp/package-lock.json`
   (`npm install --package-lock-only --ignore-scripts`, at the root and in `agent-mcp`). For a
   pre-release, also set it in the dependency line of `crates/core/README.md` and
   `crates/wallet-kit/README.md`. The `@xchonnect/dapp` that `agent-mcp/package.json`
   requires is not the release's version: it stays an exact version already on npm
   ([below](#xchonnectmcp-and-the-sdk-it-requires)).
3. Merge that through the normal review path.
4. Dry-run the gate locally: `./scripts/release-gate.sh vX.Y.Z` (it will complain about
   the missing tag; everything else is checked), and package the crates the way the
   workflow will: `./scripts/release-crates.sh`.
5. Tag and push:

   ```sh
   git tag -s vX.Y.Z -m "xchonnect vX.Y.Z"
   git push origin vX.Y.Z
   ```

   The tag **must** be annotated, on a commit that is on `main`, and signed with an **SSH
   signing key** that a login listed in
   [`.github/release-maintainers.txt`](../.github/release-maintainers.txt) has uploaded
   to GitHub (key type *Signing Key*) and whose fingerprint that file pins for the login.
   The gate reads the file from `main`, checks the signature against those keys itself,
   and refuses a lightweight tag, an unsigned one, a GPG signature, a key that is on the
   account but not pinned, a key of anyone else (even one GitHub shows as verified) and a
   commit that only a side branch has. Pushing it publishes **nothing**.
6. **The verify run.** The tag push starts `release-publish.yml` without publishing: the `gate` job
   checks the tag, the versions (workspace, both npm packages and the two published crates), the
   CHANGELOG section and the tag's signer, and records the commit the tag points to; every
   later job checks out that commit by SHA. Then the binaries and images are each built
   twice and compared, and every binary is built once more on a separate runner
   (`binaries-<arch>-repro`); the SBOMs are made twice on separate runners (`sbom`,
   `sbom-repro`); the crates are packaged; the npm tarballs are built and packed twice on
   separate runners (`npm-pack`, `npm-pack-repro`); and the release directory with
   `SHA256SUMS` is assembled (`assemble`). Every job that uploads an
   artifact states its digests as a job output, and every job that downloads one checks it
   against that output (below, *Artifacts between jobs*). Nothing is signed, pushed to
   ghcr.io, uploaded or published, and no GitHub release is created or changed. Wait for it to pass (the run's page in the browser). If
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
8. **The publishing run.** Publishing the release starts `release-publish.yml` again (event
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
   - `npm` publishes the tarballs `npm-pack` built, `@xchonnect/dapp` then
     `@xchonnect/mcp` (digests checked, nothing built or installed in that job);
   - `crates` publishes the two crates, last.

   Every one of these jobs first checks again that the release is published with the
   right pre-release box, that the tag still points at the commit the gate checked
   (`scripts/release-state-check.sh`) and that a maintainer approved the environment
   (`scripts/release-approval-check.sh`). The release page shows no assets until `sign`
   finishes.
9. **Check**: the release has the binaries, `BUILD-INFO-*.txt`, the SBOMs, `SHA256SUMS`
   and `SHA256SUMS.sigstore.json`; `./scripts/release-verify.sh` passes on them
   ([below](#verifying-a-release-as-a-third-party)); `npm view @xchonnect/dapp dist-tags`
   and `npm view @xchonnect/mcp dist-tags` show the version (under `next` for an rc); `./scripts/release-crates.sh --pending`
   prints nothing.

If the publishing run fails, the GitHub release is public, possibly without assets. Fix
the cause and use *Re-run failed jobs* on that run (it keeps the `release` event, the tag
and the gate's result; the re-run jobs check the release state and the approval
themselves and ask for the approval again). A re-run is safe at every step: `sign`
replaces its assets, `npm` passes over a package when npm already has this exact
tarball of it, `crates` skips versions already on crates.io. A manual run (*Run workflow*, `tag`
and `publish` set) can publish too, but only when started on the tag itself (*Use workflow
from* → the tag) and only while a published release exists for it; otherwise the gate
refuses. See [If something goes wrong](#if-something-goes-wrong) for each job.

### Artifacts between jobs

Any job of a run can delete and re-upload any artifact of that run: the runtime token for
artifacts sits in the runner's memory, and hosted runners give every step passwordless
`sudo`. So a malicious dependency in a job that publishes nothing (a build script in
`crates-package` or `sbom`, a package `npm run build` loads, `cargo install` of
`wasm-bindgen-cli` or `cargo-cyclonedx`) could swap `binaries-<triple>` while `assemble`
waits, and the swapped binary would be hashed, signed and pushed under the real identity.
The workflow therefore does not trust an artifact by its name:

- every job that uploads one (`binaries-x86_64`, `binaries-aarch64`, `sbom`, `npm-pack`)
  states its SHA-256 digests as a **job output**, which only that job can set
  (`scripts/release-artifact-sums.sh --output`); `crates-package` states the digests of
  the two `.crate` files;
- `assemble`, `images` and `images-publish` download each artifact by its exact name and
  check it against that output (`--check`: same files, same bytes, nothing added); `sign`
  checks the release directory against `assemble`'s output; `npm-pack-repro` fails unless
  its tarballs have `npm-pack`'s digests, and `npm` publishes only the files with those digests;
  `crates` packages the crates again and uploads nothing unless both `.crate` files have
  `crates-package`'s digests;
- `images` builds each multi-platform image twice into a local OCI layout and outputs its
  index digest and one manifest digest per platform; `images-publish` builds it again,
  pushes only when that build has the same index digest, and signs only after the
  registry serves that index with those platform manifests.

A compromised job can still lie about what it itself built. That is what the second,
independent build is for: `binaries-<arch>-repro`, `sbom-repro` and `npm-pack-repro` each
run on a fresh runner, rebuild from the same commit and fail unless they arrive at the
digests the producing job stated, and every job that pushes, signs or publishes waits for
all three. (The images are built twice inside `images` and a third time in
`images-publish`, from binaries that the repro jobs confirmed.) Two runners agreeing does
not help against a compromised dependency or toolchain, which both builds load alike; that
is what the pinned lockfiles and the supply-chain checks are for.

### Who can release

[`.github/release-maintainers.txt`](../.github/release-maintainers.txt) names the GitHub
logins that may release. A release needs, in this order:

1. **a `v*` tag**, which the tag ruleset lets only repository administrators create
   ([owner checklist](#what-the-owner-configures), step 4);
2. **on `main` and signed by a listed maintainer**: `scripts/release-gate.sh` requires
   the tagged commit to be on `main` (the compare API reports it identical to or behind
   `main`), reads the list from `main`, fetches each listed login's SSH signing keys from
   GitHub, keeps only those whose fingerprint the list pins, and verifies the tag with
   `ssh-keygen`; GitHub's own "verified" mark is required too but is not enough, since it
   accepts anyone's key;
3. **a published GitHub release** for the tag, which needs write access;
4. **an approval of the `release` environment** on the publishing run by one of its
   required reviewers, which `scripts/release-approval-check.sh` also checks against the
   list. The environment admits only `v*` tags, and npm, crates.io trust only OIDC
   tokens from `release-publish.yml` running in it, so a workflow changed on a branch, or run from
   anything but a release tag, gets no publishing rights.

While the list holds one login, all four are the same person (see the note on roles in
[`guides/incident-response.md`](guides/incident-response.md)): the approval is a deliberate
second step, not a second person. As soon as it holds two or more,
`release-approval-check.sh` requires the approval to come from a maintainer other than the
tag's signer: the two-person rule switches itself on.

**What this does not stop while there is one maintainer.** Anyone holding that
maintainer's administrator credentials (a stolen classic token with `repo` scope, a
stolen session) can release whatever they like: push a branch with a workflow that has no
gate, push a `v*` tag on it (administrators bypass the tag ruleset), publish a GitHub
release for it, and approve the `release` deployment through the API. The workflow on
that tag is theirs, so no check inside any workflow can stop it; the environment, the
registries' trusted publishers and the Sigstore identity all accept a run of a file named
`release-publish.yml` on a `v*` tag in `release`. What is left is that every step is public
and logged (the tag, the release, the run, the Rekor entry, the registries' provenance).
The real fix is a **second maintainer** with *Prevent self-review* on (owner step 1), so
that no single account can approve its own run. Until then, keep the credentials that
could do this few and short-lived:

- no classic personal access token with `repo` scope, anywhere;
- fine-grained tokens only, scoped to the repositories they need, with short lifetimes
  (days, not the maximum), and **without** the *Administration*, *Environments*,
  *Deployments* or *Workflows* permissions, and without *Contents: write* unless the
  token's job is to push;
- two-factor authentication with a hardware security key or passkey (not SMS, not a
  TOTP seed kept beside the password), for GitHub, npm and crates.io;
- review *Settings → Sessions* and *Settings → Applications* (authorised OAuth and GitHub
  Apps) for anything not recognised, and the organisation's audit log after a release.

The same holds, with less reach, for any account with write access: it can merge its own
pull request into `main` (0 approvals) and change the maintainers file, the workflow or
the scripts every later run trusts, which is why owner step 2 leaves write access with the
owner alone.

Both scripts read the list from `main` through the contents API (`?ref=main`), never
from the checkout. A tag on a side branch that adds a signer to the list would otherwise
vouch for itself: someone holding a stolen administrator token could push such a branch,
tag it, publish a release through the API and approve the deployment. A change to the
list therefore takes effect once it is merged to `main`, for every run after that
(removing a maintainer also stops runs of tags they already made); it is only as strong
as the protection of `main` ([owner checklist](#what-the-owner-configures), steps 2 and 4). Keep
it in step with the environment's required reviewers. A maintainer's line is
`<login> SHA256:<fingerprint> …`, one fingerprint per signing key they tag with
(`ssh-keygen -lf key.pub`, second column); a new key is listed through a pull request
before its first tag.

### Cutting a pre-release (`vX.Y.Z-rc.N`)

The same procedure, with these differences:

- Versions (`Cargo.toml`, `sdk-ts/package.json` and `agent-mcp/package.json`) and the CHANGELOG heading carry the
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
  the version under the `next` dist-tag and leaves `latest` alone. That does **not** mean
  `npm install @xchonnect/dapp` never installs an rc: until a final version exists,
  `latest` is whatever it was set to, and today it is `0.1.0-rc.1`, the first version,
  published by hand without provenance (owner step 1, "npm's `latest` tag"). Install an
  exact version.
- crates.io needs no such switch: Cargo selects a pre-release only for a requirement that
  names one, so `xchonnect-core = "0.1"` and `cargo update` never land on an rc. The gate
  makes sure the crate READMEs show the exact requirement (`"=0.1.0-rc.1"`) instead.

## Verifying a release as a third party

### 1. Digests, signature and provenance

```sh
gh release download vX.Y.Z --dir dl --repo xchonnect/xchonnect
./scripts/release-verify.sh --dir dl --tag vX.Y.Z \
  --image ghcr.io/xchonnect/xchonnect-relay:X.Y.Z \
  --image ghcr.io/xchonnect/xchonnect-gateway:X.Y.Z
```

It ends by printing the digest of each image it verified (`XCHONNECT_RELAY_DIGEST=sha256:…`,
the lines `deploy/.env` takes): pull and run that digest, never the tag, which anyone who
can push to the package can re-point after you verified it
([`deploy/README.md`](../deploy/README.md#the-release-images)).

That runs, and is worth understanding rather than trusting:

```sh
# the files are the files the manifest names
(cd dl && sha256sum -c SHA256SUMS)

# the manifest was signed by this repository's release workflow, on this tag.
# Keyless: the identity is the workflow, certified by Sigstore's Fulcio from the
# GitHub OIDC token. There is no long-lived signing key to steal.
cosign verify-blob --bundle dl/SHA256SUMS.sigstore.json \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity "https://github.com/xchonnect/xchonnect/.github/workflows/release-publish.yml@refs/tags/vX.Y.Z" \
  dl/SHA256SUMS

# GitHub attests that the release workflow, on this tag, produced each binary
gh attestation verify dl/xchonnect-relay-X.Y.Z-x86_64-unknown-linux-gnu \
  --repo xchonnect/xchonnect \
  --signer-workflow xchonnect/xchonnect/.github/workflows/release-publish.yml \
  --source-ref refs/tags/vX.Y.Z

# the image, by the same identity; cosign names the digest whose signature it checked
cosign verify ghcr.io/xchonnect/xchonnect-relay:X.Y.Z \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity "https://github.com/xchonnect/xchonnect/.github/workflows/release-publish.yml@refs/tags/vX.Y.Z" |
  jq -r '.[0].critical.image."docker-manifest-digest"'
# and its attestation, for that digest; then run ghcr.io/xchonnect/xchonnect-relay@sha256:…
gh attestation verify oci://ghcr.io/xchonnect/xchonnect-relay@sha256:<digest> \
  --repo xchonnect/xchonnect \
  --signer-workflow xchonnect/xchonnect/.github/workflows/release-publish.yml \
  --source-ref refs/tags/vX.Y.Z
```

`release-verify.sh` runs the attestation check for every `xchonnect-relay-*` and
`xchonnect-gateway-*` in the directory and fails when there is none, and fails on any file
in the directory that `SHA256SUMS` does not name (as the `sign` job does), so download
into an empty directory. `--no-provenance` skips the attestations for a release made while
the repository was private (none exist); it warns loudly when the repository is public
now, because a release made while it was public has them, and advice to skip them is
then a reason for suspicion. With `--image`, an image whose attestation cannot be checked
(`--no-provenance`, or no `gh`) fails the run unless `--skip-image-attestation` accepts
that explicitly.

A signature that verifies against any other identity — another workflow, another
repository, another ref — is not a release of this project. That includes
`.github/workflows/release.yml`, the file name used up to `v0.1.0-rc.4`
([below](#the-old-releaseyml-v010-rc1-to-rc4)). The `release` environment the
signing jobs run in is not part of the Sigstore certificate (Fulcio records the workflow,
ref, commit, trigger and repository, not the environment), so the identity above did not
change when the environment was introduced. To pin the commit as well, add
`--certificate-github-workflow-sha <commit the tag points to>` (and
`--certificate-github-workflow-trigger release` for a release published from the web UI).

### The old `release.yml` (`v0.1.0-rc.1` to `rc.4`)

Up to `v0.1.0-rc.4` the release workflow was `.github/workflows/release.yml`, and every
one of those tags still carries it. Its gate checked out whatever ref its `tag` input
named, and its later jobs ran the scripts of that checkout with `id-token`, `packages`
and `contents` write and no environment, so any writer could start it by hand on an old
tag (`gh workflow run release.yml --ref v0.1.0-rc.4 -f tag=<their branch> -f publish=true`)
and have their own code signed under `release.yml@refs/tags/v0.1.0-rc.4`, replace release
assets, push signed images, and publish to the registries while their trusted publishers
still named `release.yml`. The workflow is now `release-publish.yml`; the registries trust
only that file in the `release` environment, and the owner disabled `release.yml` by its
workflow ID `375367524` (owner step 1, before this change was merged).

**Treat the identity `…/.github/workflows/release.yml@refs/tags/v0.1.0-rc.N` as
untrusted** for anything signed after it was disabled. A Sigstore bundle carries the time
Rekor logged the signature, which cosign verifies. Where that time sits depends on the
bundle's format. Both workflows install cosign v2.6.0 (`sigstore/cosign-installer`
v3.10.0's default) and call `cosign sign-blob --bundle` without `--new-bundle-format`,
which in v2.6.0 defaults to false: they write cosign's **legacy** bundle
(`base64Signature`, `cert`, `rekorBundle`), with the time at
`.rekorBundle.Payload.integratedTime` (a number). A bundle in the **new** Sigstore format
(`--new-bundle-format`, the default from cosign v3; `mediaType`
`application/vnd.dev.sigstore.bundle…`) has it at
`.verificationMaterial.tlogEntries[0].integratedTime` (a string). This reads either:

```sh
jq -r '.rekorBundle.Payload.integratedTime // .verificationMaterial.tlogEntries[0].integratedTime' \
  SHA256SUMS.sigstore.json | xargs -I{} date -u -d @{}      # macOS: date -u -r {}
```

and reject anything under the old identity logged on or after 2026-10-14 (the day this
was found; the disable came later, so this cut-off is the stricter one). For images,
`cosign verify … --output json` (cosign v2) prints each signature with the legacy bundle
under `optional.Bundle`: `jq -r '.[].optional.Bundle.Payload.integratedTime'`. Better still, check the old releases
against what they contained before 2026-10-14, as recorded here (fetched anonymously from
the GitHub, npm and crates.io APIs on 2026-10-14):

- **GitHub release assets: none.** The releases `v0.1.0-rc.1` (pre-release, published
  2026-10-06T02:48:31Z), `v0.1.0-rc.3` (2026-10-09T10:42:17Z) and `v0.1.0-rc.4`
  (2026-10-09T10:53:45Z) had **zero assets**, so no `SHA256SUMS` exists to record, and
  `v0.1.0-rc.2` has no GitHub release. Any binary, SBOM, `SHA256SUMS` or signature that
  appears on one of these releases later is not genuine. (`rc.3` and `rc.4` are not
  marked as pre-releases; the gate of `release-publish.yml` would refuse that.)
- **Images**: none of `ghcr.io/xchonnect/xchonnect-relay`, `…-gateway` (or the
  `maximedogawa` ones) could be listed anonymously; no image of these versions is
  recorded as published.
- **npm** (`@xchonnect/dapp`, immutable once published; `dist.integrity`):

  | Version | Integrity |
  |---|---|
  | `0.1.0-rc.1` | `sha512-gLDU+UGlDFmhlgBMN/xwg28xwkepqKOThgKrazMhfGk+4PgineAqNbrXlTn2QO0bUVyp61oLHt04eVKmgG41AQ==` (no provenance) |
  | `0.1.0-rc.2` | `sha512-AfLjprhpbzZHoamOBBWnlFkxu6Nw+5tkgM1liS8kVnMq2UycbiR+NDbHMjNyzC9Y8X4pJQexi8aWFgJaDI0+5g==` |
  | `0.1.0-rc.3` | `sha512-X59AmKsuNbKMKwCxSm9Jn09jBoZ/UFTsHgdfx2+Tux2Atm+9X+HjE9IbSye6dN15ujFQmYG/e/0Xj4RNDCIdlA==` |
  | `0.1.0-rc.4` | `sha512-9UjqI73H0wkxfmJd5QFxRPuJZug0ODOJXsRDauCFJOH8QveZ12P8pDZBsCnfAhZ9hlwtT/sOSvCTa//jjFb4Og==` |

- **crates.io** (immutable once published; SHA-256 of the `.crate`):

  | Crate | Version | SHA-256 |
  |---|---|---|
  | `xchonnect-core` | `0.1.0-rc.2` | `40fa28e6d6a13eb87e0cc1cfe207fd6cc80823b7fbf2ce4bcbbb04a5c251c37c` (published by hand) |
  | `xchonnect-core` | `0.1.0-rc.3` | `4226a7636c57c03e37aa3460e107c7416710702b8482422d1598a3162aa881b1` (run 37520501772) |
  | `xchonnect-core` | `0.1.0-rc.4` | `f6b8effe69e4eec93e6abeca42a065d61ee96bbc664343b506eb38abbaae218b` (run 37920202079) |
  | `xchonnect-wallet-kit` | `0.1.0-rc.2` | `89eb510edcf60242328f86ada0d37c8383d5787c3ba5a6548ea2bb5b1cdf6b47` (published by hand) |

  `xchonnect-wallet-kit` has no `rc.3` or `rc.4`: the old workflow stopped after the core.

A registry version cannot be replaced, so these can only gain siblings: a version of
either package that is not in these tables and is not a release made by
`release-publish.yml` from `v0.1.0-rc.5` on is not genuine.

The repository moved from `maximedogawa/xchonnect` to `xchonnect/xchonnect` after
`v0.1.0-rc.1`; anything of that release would be under the old path (`--repo
maximedogawa/xchonnect`, `ghcr.io/maximedogawa/`), and the same rule applies to it.

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
before the first release that uses `release-publish.yml` and the `release` environment
(0.1.0-rc.5). Step 1 does not wait for any merge, and the old workflow is disabled in it,
**before** this branch is merged; the tag is the last step.

1. **Now, independent of any merge: disable the old workflow, then the `release`
   environment, then the registries.**
   - **Disable `release.yml` first** (workflow ID `375367524`, name "Release",
     `.github/workflows/release.yml`). Every tag up to `v0.1.0-rc.4` carries it, and any
     writer can run it by hand on such a tag ([The old
     release.yml](#the-old-releaseyml-v010-rc1-to-rc4)); nothing needs it, so it goes
     before anything else, and before the merge:

     ```sh
     gh workflow disable 375367524 --repo xchonnect/xchonnect
     gh workflow list --all --repo xchonnect/xchonnect
     curl -s -A release-check https://api.github.com/repos/xchonnect/xchonnect/actions/workflows/375367524 | jq -r .state
     ```

     or Actions → *Release* (the old one, `.github/workflows/release.yml`) → *⋯* →
     *Disable workflow*. The state must be `disabled_manually`. A disabled workflow
     starts on no event: no manual run, no tag push, no published release. Disable every
     other workflow the list shows apart from *Release publish* as well (older commits
     carry `CI`, `Fuzz`, `Supply chain`; none can sign under a release identity). Never
     re-enable `release.yml`. Write down the date and time of the disable. The runs it
     already made (6 to 9 October 2026) can still be *re-run* from their pages for 30
     days after each run, until 8 November 2026: a re-run repeats that run's own commit
     and inputs, which were honest, so it can at most sign those same files again under
     the old identity, with a Rekor time after the 2026-10-14 cut-off that verifiers
     reject, and after the registry step below it can no longer publish. That is
     accepted; do not re-run them.
   - **The environment.** When a job names an environment that does not exist, GitHub
     creates it on the spot without any protection rule, so this comes before any run
     that names it. Settings → Environments → `release` if it exists (edit it; first look for
     anything you did not put there: secrets, variables, deployment branch rules, a
     wait timer, and remove it), otherwise *New environment*, name `release` (exactly;
     the workflow and the registries name it) → *Configure environment*:
     - *Required reviewers*: tick, add every login of `.github/release-maintainers.txt`.
     - *Prevent self-review*: **off** while `.github/release-maintainers.txt` lists one
       login. On, GitHub forbids the person who started the run (who published the
       release) from approving it, and with one maintainer nobody could. With it off,
       one person signs, publishes and approves, so the approval guards against mistakes
       and against anyone who is not a listed reviewer, but not against that person or
       their stolen credentials ([Who can release](#who-can-release)). With a second
       maintainer, list the login with its key fingerprints and turn it on;
       `release-approval-check.sh` then also requires the approver not to be the tag's
       signer.
     - *Allow administrators to bypass configured protection rules*: **off**, so an
       admin's token or session cannot skip the review.
     - *Deployment branches and tags*: *Selected branches and tags* → *Add deployment
       branch or tag rule* → *Ref type: Tag*, name pattern `v*`. Add no branch rule.
     - No wait timer, no variables, and **no secrets**, except the optional
       `GHCR_PUSH_TOKEN` of step 4 option (a) (with the variable `GHCR_PUSH_USER`).
   - **npm.** npmjs.com → `@xchonnect/dapp` → *Settings* → *Trusted Publisher*: edit the
     GitHub Actions entry (or remove it and add a new one) to Organization or user
     `xchonnect`, Repository `xchonnect`, Workflow filename **`release-publish.yml`**,
     **Environment name `release`** → save. Keep *Publishing access* at *Require
     two-factor authentication and disallow tokens*. The same for `@xchonnect/mcp` once
     it exists on npm ([its first version](#xchonnectmcp-and-the-sdk-it-requires)).
   - **npm's `latest` tag.** `npm view @xchonnect/dapp dist-tags` shows `latest:
     0.1.0-rc.1` (the version published by hand, without provenance; a package always
     has a `latest`, and its first version got it) and `next` at the newest rc. So
     `npm install @xchonnect/dapp`, with no version, installs that old rc today. Do not
     try to remove `latest` (npm expects every package to have one); move it. The
     workflow moves it only when it
     publishes a version without `-` (0.1.0). Decide, and do it yourself (an agent never
     runs npm): either leave it until 0.1.0, or point it now at a version you choose,
     preferably the first one `release-publish.yml` published with provenance:
     `npm dist-tag add @xchonnect/dapp@<version> latest` (as a maintainer, with 2FA), then
     `npm view @xchonnect/dapp dist-tags`.
   - **crates.io**, for `xchonnect-core` and then `xchonnect-wallet-kit`: crates.io → the
     crate → *Settings* → *Trusted Publishing*: **remove** the existing GitHub entry (it
     names `release.yml`), then *Add* → GitHub: Repository owner `xchonnect`, Repository
     name `xchonnect`, Workflow filename **`release-publish.yml`**, **Environment
     `release`** → save. Keep the option that requires trusted publishing on.

   Until this branch is merged, `main` has no `release-publish.yml`, so from this moment
   nothing can publish to npm or crates.io at all, and the old `release.yml` (on `main`
   and on every old tag) loses its publishing rights to both registries. That is the
   point: those rights do not wait for the merge. Signing and uploading release assets
   and images under the old identity is what the disable above stops.
2. **Write access: the owner only.** With *Require a pull request* and 0 approvals (step
   4), **any account that can write to the repository can open and merge its own pull
   request** that changes `.github/release-maintainers.txt`, the workflow, the
   `scripts/release-*` the workflow runs or any `build.rs`, and every later run trusts
   it. Until there is a second maintainer who reviews, nobody but the owner may have
   write access. Check, and remove what is not the owner:
   - Settings → *Collaborators and teams*: direct collaborators, outside collaborators
     and teams with *Write*, *Maintain* or *Admin*
     (`gh api 'repos/xchonnect/xchonnect/collaborators?affiliation=all' --jq '.[] | [.login, .role_name] | @tsv'`,
     `gh api repos/xchonnect/xchonnect/teams`);
   - the organisation's base permission (Organization settings → *Member privileges* →
     *Base permissions*: *No permission* or *Read*;
     `gh api orgs/xchonnect --jq .default_repository_permission`);
   - organisation owners: each is an administrator of every repository and counts as
     *Repository admin* in every bypass list (`gh api 'orgs/xchonnect/members?role=admin' --jq '.[].login'`);
   - deploy keys with write access (Settings → *Deploy keys*;
     `gh api repos/xchonnect/xchonnect/keys --jq '.[] | select(.read_only == false) | .title'`
     must print nothing);
   - GitHub Apps installed on the repository with *Contents: write*, *Workflows*,
     *Administration* or *Environments* (Organization settings → *GitHub Apps* →
     *Installed*, and each app's repository access), and fine-grained tokens the
     organisation approved (Organization settings → *Personal access tokens*).

   If the plan offers push rulesets (Settings → Rules → Rulesets → *New ruleset* shows
   *New push ruleset*; GitHub offers them only on some plans and repository
   visibilities), add one: name `release paths`, *Enforcement status: Active*, rule
   *Restrict file paths* with `.github/**` and `scripts/release-*` (add `**/build.rs` if
   accepted), *Bypass list*: *Repository admin* only. A push ruleset applies to every
   branch, so no writer's branch can even carry such a change. If the plan does not offer
   it, write it down in the release notes of the next release; the access review above is
   then the only control.
3. **Actions settings and secrets, then merge this branch.**
   - **No pull requests from Actions.** Settings → *Actions* → *General* → *Workflow
     permissions*: untick *Allow GitHub Actions to create and approve pull requests*
     (and keep *Read repository contents and packages permissions* as the default), and
     the same under Organization settings → *Actions* → *General*, so a repository cannot
     turn it back on. Otherwise a workflow's `GITHUB_TOKEN` could open a pull request and,
     once approvals are required, approve one. Check:
     `gh api repos/xchonnect/xchonnect/actions/permissions/workflow` and
     `gh api orgs/xchonnect/actions/permissions/workflow` both show
     `"can_approve_pull_request_reviews": false`.
   - **Optional: fork pull requests.** Same page, *Approval for running fork pull
     request workflows from contributors*: *Require approval for all external
     contributors*. No current workflow runs on a pull request, but a fork's pull request
     can bring its own workflow file.
   - **No Actions secrets the repository can reach**, at any level, apart from the
     optional `GHCR_PUSH_TOKEN` in the `release` environment. `fuzz.yml` at
     `v0.1.0-rc.1` reads `FUZZ_ADVISORY_TOKEN`, and any workflow on any old commit or
     branch can read whatever secret is in reach. Settings → *Secrets and variables* →
     *Actions* (repository secrets, and the organisation secrets shown there) and →
     *Dependabot*; Organization settings → *Secrets and variables* → *Actions* and
     *Dependabot* (each secret's repository access); every environment but `release`
     (Settings → *Environments*). With the owner's login each of these must print
     nothing:

     ```sh
     gh api repos/xchonnect/xchonnect/actions/secrets --jq '.secrets[].name'
     gh api repos/xchonnect/xchonnect/actions/organization-secrets --jq '.secrets[].name'
     gh api repos/xchonnect/xchonnect/dependabot/secrets --jq '.secrets[].name'
     gh api orgs/xchonnect/dependabot/secrets --jq '.secrets[] | [.name, .visibility] | @tsv'
     gh api repos/xchonnect/xchonnect/environments --jq '.environments[].name | select(. != "release")'
     ```

     (the second covers organisation secrets visible to this repository; the fourth
     lists organisation Dependabot secrets, which must not include this repository; the
     last lists other environments, whose secrets
     `gh api repos/xchonnect/xchonnect/environments/<name>/secrets` shows: remove them or
     the environment). Delete what is there, and revoke the token behind it.
   - **Merge this branch.** Then `main` has `release-publish.yml` ("Release publish")
     and no `release.yml`. A merge does not re-enable a workflow: check again that
     `gh workflow list --all --repo xchonnect/xchonnect` shows `Release` as
     `disabled_manually` (step 1).
4. **Rulesets and ghcr.io.**
   - **A tag ruleset on `v*`.** Settings → Rules → Rulesets → *New ruleset* → *New tag
     ruleset*: name `release tags`, *Enforcement status: Active*; *Bypass list* → *Add
     bypass* → *Repository admin* (*Always allow*; after step 2 that is the owner). **No
     deploy keys, GitHub Apps or integrations in the bypass list.** *Target tags* → *Add
     target* → *Include by pattern* `v*`; rules: *Restrict creations*, *Restrict
     updates*, *Restrict deletions*, *Block force pushes*. Optionally *Require signed
     commits*: the commits a release tag points at are merge commits made on GitHub, which
     GitHub signs. A ruleset cannot require a signed *tag*; the gate does that.
   - **A pull request rule on `main`.** The existing branch ruleset on `main` has only
     *Restrict deletions* and *Block force pushes*. Edit it (or *New branch ruleset*,
     target *Default branch*) and add *Require a pull request before merging*; keep an
     **empty bypass list** (no *Repository admin*, no apps, no deploy keys), so no token
     pushes straight to `main`. Required approvals 0 and no code-owner review while there
     is one maintainer (GitHub does not let an author approve their own pull request, so
     either would block every merge); once there is a second, 1 approval and *Require
     review from Code Owners*. `.github/CODEOWNERS` assigns every path to the owner
     through `*`, so `.github/`, the `build.rs` files, `scripts/`, `Cargo.toml` and the
     lockfiles are covered; if `*` is ever narrowed (a second maintainer taking general
     paths), keep `/.github/`, `/scripts/`, `**/build.rs`, `**/Cargo.toml`,
     `/Cargo.lock`, `/sdk-ts/package.json` and `/agent-mcp/package.json` with the release maintainers.
   - **The maintainers file.** The gate and the approval check trust
     `.github/release-maintainers.txt` as `main` has it. Its protection is the `main`
     ruleset above, the push ruleset of step 2 where the plan has it, and the access
     review of step 2; with one maintainer, an administrator can still merge a change to
     it or edit the rulesets ([Who can release](#who-can-release)).
   - **ghcr.io: optionally, decide how images are pushed**
     ([Pushing images to ghcr.io](#pushing-images-to-ghcrio)): option (a), a bot account's
     token in the `release` environment, or option (b), accept that any workflow run of
     the repository can push. Deployments pin the verified digest either way, so (b) is
     safe to keep; (a) only narrows who can push a misleading tag. The workflow supports
     both without a change: it uses `GHCR_PUSH_TOKEN` when the environment has it,
     `GITHUB_TOKEN` otherwise.
5. **Check before pushing a tag.** Without a token:

   ```sh
   curl -s https://api.github.com/repos/xchonnect/xchonnect/environments
   curl -s https://api.github.com/repos/xchonnect/xchonnect/rulesets
   ```

   The first must list `release` with a `required_reviewers` protection rule naming the
   maintainers, `can_admins_bypass: false` and `deployment_branch_policy` with
   `custom_branch_policies: true` (and `protected_branches: false`); the second the tag
   ruleset, the `main` ruleset and, if made, the push ruleset (bypass lists and rules need
   a token to read; check them on the settings page, and that the `main` ruleset now has
   the pull request rule). With the owner's login:

   ```sh
   gh workflow list --all --repo xchonnect/xchonnect
   ```

   shows `Release publish` active and `Release` `disabled_manually`. Then, **only once it
   shows that**, check that a manual run of the old workflow on an old tag is refused:

   ```sh
   gh workflow run release.yml --repo xchonnect/xchonnect --ref v0.1.0-rc.4 -f tag=v0.0.0-refused
   ```

   must fail (HTTP 422, the workflow is disabled) and start no run. The `tag` input names
   a tag that does not exist, so even a run that wrongly started would stop at its first
   checkout. Do not push the tag while any of this is missing.
6. **Then tag `v0.1.0-rc.5`** ([Cutting a release](#cutting-a-release)).

Standing rules, nothing to click:

- **Signing keys for tags**: each maintainer uploads an SSH key to their GitHub account
  as a *Signing Key* (Settings → SSH and GPG keys → *New SSH key*, *Key type: Signing
  Key*), signs tags with it (`git config gpg.format ssh`, `user.signingkey`) and has its
  fingerprint added to their line in `.github/release-maintainers.txt` through a pull
  request. No signing key is used for artifacts: Sigstore keyless uses a short-lived
  certificate bound to the workflow's OIDC identity.
- **Nothing for cosign**: there is intentionally no `COSIGN_PRIVATE_KEY`. If you ever
  introduce one, the verification identity above stops being the workflow, and a stolen
  key could sign artifacts no tagged commit ever produced.
- **No registry secrets** for npm and crates.io: there is intentionally no `NPM_TOKEN`
  and no `CARGO_REGISTRY_TOKEN`. A new package or crate first goes up by hand, then gets
  a trusted publisher as in step 1 (the sections on npm and crates.io below).
- **Who has write access.** Publishing a GitHub release needs write access and GitHub
  cannot restrict it further; the environment, the tag ruleset and the gate are what stop
  a writer from publishing, and a writer can still merge their own pull request into
  `main` while 0 approvals are required, which is why owner step 2 leaves write access
  with the owner alone. Leave *immutable releases* off in the repository settings: the
  workflow attaches the assets after the release is published, which an immutable
  release refuses. That also means **release assets stay mutable**: anyone with write
  access can replace or add a file on a published release. Verification covers it: an
  asset counts only when `SHA256SUMS` names its digest and `SHA256SUMS.sigstore.json`
  verifies against the workflow identity on the tag
  ([Verifying a release](#verifying-a-release-as-a-third-party)); a replaced file or a
  replaced manifest fails that check, so download and verify, never trust the release
  page alone.
- **Optional**: a token for `scripts/fuzz-crash-report.sh`, which files a draft
  advisory for a crash found by local fuzzing — see [`fuzzing.md`](fuzzing.md).

### Pushing images to ghcr.io

ghcr.io cannot be bound to an environment: by default any workflow run of this
repository that asks for `packages: write`, on any branch, can push to
`ghcr.io/xchonnect/xchonnect-*`. The owner may pick one of two options (step 4); with
either, **deployments pull and run an image only by the digest they verified**
([`deploy/README.md`](../deploy/README.md#the-release-images)):

- **(a) A bot account's token, only in the `release` environment.** Create a machine
  account (a separate GitHub user, with 2FA), give it write access to the two packages
  only (Package → *Package settings* → *Manage access*), and create for it a **classic**
  personal access token with only `write:packages` (ghcr.io accepts no fine-grained
  token for pushing). Store it as the **environment** secret `GHCR_PUSH_TOKEN` of
  `release` (not a repository secret), and the bot's login as the environment variable
  `GHCR_PUSH_USER`. Then, for each package: *Package settings* → turn **off** *Inherit
  access from source repository*, and under *Manage Actions access* **remove** the
  repository `xchonnect/xchonnect`, so `GITHUB_TOKEN` of no run can push any more. Only a
  job in `release` (a `v*` tag, after approval) gets the token; `images-publish` logs
  which credentials it pushed with. Costs: a token that expires and must be rotated, and
  one more account to secure.
- **(b) Accept the residual.** Keep `GITHUB_TOKEN`. A run on a branch can push an image
  tag, but cannot obtain a signature under the release identity, which needs a run on a
  `v*` tag. A tag pushed that way fails `cosign verify`; a tag re-pointed after you
  verified it is what digest pinning defeats. The image index digest is the one
  `images-publish` logged and checked against the `images` job.

Either way an image tag is a name, not a proof: verify, then pull and run the digest that
`cosign verify` (or `scripts/release-verify.sh --image`) reported, never the tag. Under
(a) a stolen bot token could still re-point a tag, so (a) does not make tag pulls safe.

## Publishing the TypeScript SDK to npm

`@xchonnect/dapp`, and with it the MCP plugin `@xchonnect/mcp` (`agent-mcp/`), are built
and packed by the `npm-pack` job, which has no OIDC token, and
again by `npm-pack-repro` on another runner, which must arrive at the same SHA-256 for
each. Those tarballs are published by the `npm` job, the SDK first, which builds and installs nothing, from the same
signed tag and after every other job has passed. It authenticates with
npm **trusted publishing**: npm accepts the workflow's short-lived GitHub OIDC token instead
of a long-lived `NPM_TOKEN`, and attaches provenance (`publishConfig.provenance`) linking
the tarball to this repository, workflow and commit. A version containing `-`
(`1.0.0-rc.1`) is published under the `next` dist-tag, anything else under `latest`.

The gate already requires `sdk-ts/package.json` and `agent-mcp/package.json` to carry the
tag's version, so cutting a release (above) is all a routine publish needs. An npm version
can never be reused, even after `npm unpublish`; a broken one is fixed with `npm deprecate`
and a new version.

### `@xchonnect/mcp` and the SDK it requires

`agent-mcp` is a package of its own, outside the npm workspace, with its own
`package-lock.json`: the plugin runs on the `@xchonnect/dapp` it requires from npm, while
its tests run the wallet side on this tree's SDK build (`agent-mcp/test/sdk.ts`), so the
two meet only on the relay. That requirement is one exact version (`"0.1.0-rc.5"`, no
range), and it is a version **already on npm**, not the one being released: `npm-pack`
installs the plugin's dependencies with `npm ci` from registry.npmjs.org before the
release's own SDK is published, and `npm install @xchonnect/mcp` must resolve it. The gate
requires the exact version and a lockfile that resolves it from registry.npmjs.org; the
`npm` job checks the tarball's requirement again and that npm has that SDK version. So
`@xchonnect/mcp` X.Y.Z runs on the SDK of an earlier release; to move it, after that SDK
version is on npm, set it in `agent-mcp/package.json` and run `npm install --ignore-scripts`
in `agent-mcp` (the lockfile then records its integrity), on a branch like any change.

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
   version therefore has none. Whatever `--tag` says, the first version of a package also
   becomes `latest` (that is how `0.1.0-rc.1` got it); move `latest` deliberately
   afterwards (`npm dist-tag add @xchonnect/dapp@<version> latest`).

3. **Register the trusted publisher.** On npmjs.com → `@xchonnect/dapp` → Settings →
   Trusted Publisher → GitHub Actions: organisation/user `xchonnect`, repository
   `xchonnect`, workflow filename `release-publish.yml`, environment `release`. With the
   environment named, npm accepts only a token of a job in that environment, which runs
   only on a `v*` tag after a maintainer's approval; left empty, any run of a modified
   `release-publish.yml` on any branch could publish.
4. **Lock the package to the workflow.** Same page, Publishing access → *Require two-factor
   authentication and disallow tokens*. From then on only `release-publish.yml` can publish; a
   leaked maintainer password or token cannot.
5. Verify the next release: `npm view @xchonnect/dapp dist-tags` shows the version, and
   `npm audit signatures` in a project depending on it reports a verified provenance
   attestation.

**`@xchonnect/mcp`** goes through the same steps, but its first version is the release's
own (`agent-mcp` is in no release up to `v0.1.0-rc.5`), so publish by hand exactly the
tarball the verify run of that tag built, and the publishing run then finds it on npm and
passes over it:

1. After the verify run of the tag `vX.Y.Z` passed, rebuild the tarball from a fresh clone
   of the tag and compare it with the `mcp_sha256` the `npm-pack` job printed (its log,
   "Build and pack"):

   ```sh
   git clone --branch vX.Y.Z https://github.com/xchonnect/xchonnect.git && cd xchonnect
   ./scripts/release-npm-pack.sh /tmp/npm X.Y.Z   # prints both digests last
   ```

   Or download the run's `npm-package` artifact (its page, signed in) and check
   `sha256sum xchonnect-mcp-X.Y.Z.tgz` against that digest. A different digest: stop,
   publish nothing, and find out why (as for [`npm-pack-repro`](#if-something-goes-wrong)).
2. Publish that file, as a maintainer of the `xchonnect` org with 2FA:
   `npm publish /tmp/npm/xchonnect-mcp-X.Y.Z.tgz --access public --tag next --provenance=false --ignore-scripts`
   (without `--provenance`, as for the SDK's first version; it also becomes `latest`).
   Do this **before** publishing the GitHub release: the `npm` job publishes the SDK and
   then sees this tarball's integrity on npm and goes on.
3. Steps 3 to 5 above for `@xchonnect/mcp`: the trusted publisher (`xchonnect`,
   `xchonnect`, `release-publish.yml`, environment `release`), *Require two-factor
   authentication and disallow tokens*, and `npm view @xchonnect/mcp dist-tags`.

If npm lets a trusted publisher be set up for a package that does not exist yet, skip
steps 1 and 2: register it (step 3) before publishing the GitHub release, and the `npm`
job publishes the first version with provenance.

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
   `xchonnect`, workflow filename `release-publish.yml`, environment `release` (as for npm: only a
   job in that environment, on a `v*` tag, after approval, can publish).
4. **Lock both crates to the workflow.** Same settings page: turn on the option that
   requires trusted publishing, which disables publishing with API tokens. From then on
   only `release-publish.yml` can publish; a leaked token of a crate owner cannot.
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
- *The gate fails on the signer*: the tag is not signed with a pinned SSH signing key of
  a login in `.github/release-maintainers.txt` on `main` (a GPG signature, an
  authentication key uploaded as such instead of as a signing key, a key whose
  fingerprint the list does not pin, or a login missing from the list). Upload the key as
  a *Signing Key* and add its fingerprint to the list through a pull request; once it is
  on `main`, re-run (the tag can stay, the list is read at run time).
- *The gate fails with "not on main"*: the tag points at a commit that is not on `main`.
  Releases are cut from merged commits; delete the tag and tag the merge commit.
- *A job fails with "is not what the job that made it uploaded"*
  (`release-artifact-sums.sh --check`), or `images-publish` with an image digest that
  differs from the `images` job's: an artifact or an image changed between two jobs of
  the run. **Do not release and do not re-run**: treat it as an incident (one of the
  run's dependencies or the runner may be compromised), keep the run's logs, and follow
  [`guides/incident-response.md`](guides/incident-response.md).
- *`binaries-<arch>-repro` or `sbom-repro` fails* ("do not reproduce on another
  runner"): two runners built different bytes from the same commit. Every publishing job
  waits for these, so nothing was signed or published. Compare the two jobs' logs (the
  diff of the digests is printed); if one runner's build cannot be explained by an
  unpinned input, treat it as an incident as above.
- *`npm-pack-repro` fails with "the npm tarball does not reproduce"*: the two builds made
  different tarballs (of `@xchonnect/dapp`, or of `@xchonnect/mcp` when the message names it). Every publishing job waits for that job, so nothing was published;
  rebuild locally twice from the tag (`scripts/release-npm-pack.sh`, fresh clones),
  compare (unpack both, `diff -r`), fix on `main` and release a new version.
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
  if npm did accept it the re-run sees the same integrity and passes, so `crates` runs
  (when the SDK went up and the plugin did not, the re-run passes over the SDK and
  publishes the plugin). *requires @xchonnect/dapp@…, which npm does not have*: the
  plugin's SDK pin names a version that is not on npm; fix `agent-mcp/package.json` on
  `main` and release a new version. A
  `404`/`403` on publish almost always means the trusted publisher above does not match
  this repository, `release-publish.yml` and the environment `release` exactly. *Already on npm
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
  trusted publisher does not match this repository, `release-publish.yml` and the environment
  `release` exactly. If
  `xchonnect-core` went up and `xchonnect-wallet-kit` did not, re-run rather than yank.
- *A release must be withdrawn*: delete the GitHub release and the image tag,
  `npm deprecate @xchonnect/dapp@X.Y.Z "<reason>"` (and `@xchonnect/mcp@X.Y.Z`),
  [yank both crates](#yanking-a-broken-version), publish an
  advisory per [`../SECURITY.md`](../SECURITY.md), and release a new version. Signatures
  cannot be revoked, so the withdrawal must be announced; Sigstore entries are public
  and permanent by design.
