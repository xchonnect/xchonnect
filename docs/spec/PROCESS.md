# Specification change process

1. **Normative source.** `docs/spec/xchonnect-spec.md` in this repository is the only
   normative text. The wiki and the CHIP draft link here; when they disagree, this file
   wins. The CHIP draft (`docs/chip/`) is regenerated from it before submission.
2. **Proposing a change.** Open a pull request that edits the spec, adds an entry under
   "Unreleased" in `CHANGELOG.md`, and names the affected threat IDs (T1–T2x) and
   sections. Changes to cryptography, wire formats or relay behaviour also update the
   wire definitions in `docs/spec/wire/` and the test vectors.
3. **Review.** Changes touching Sections 5–7, 13 or the wire definitions need approval
   from a CODEOWNER for `docs/spec/` and must keep the reference implementation and
   vectors consistent in the same PR (or block on a linked PR).
4. **Versioning.** The document version is `MAJOR.MINOR`. While in Draft (0.x) any
   change may be breaking. After 1.0, a change that alters bytes on the wire or
   verification rules requires a new protocol version `v` (Section 17); editorial and
   additive changes bump MINOR.
5. **Releasing.** On release, move "Unreleased" entries under the new version heading,
   update the version field in the spec header, and tag `spec-vX.Y`.
