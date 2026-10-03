# Specification changelog

All normative changes to `xchonnect-spec.md` are recorded here. Versions are tagged
`spec-vX.Y` in git.

## Unreleased (v0.2)

- **5, 5.3 (TASK-3):** session AEAD changed from ChaCha20-Poly1305 with `seq`-derived nonces to XChaCha20-Poly1305 with a random 192-bit nonce carried in the outer envelope (`n`). Outer envelope gains `kind`; AAD made byte-exact and includes `kind`. Padding now pads the *ciphertext* to exact bucket sizes. `seq` is used only for replay/ordering; senders that lose state must re-pair. T5/T20 updated.

## v0.1 — 2026-10-04

Baseline imported from the internal wiki (`00-protocol-spec.md`). Tagged `spec-v0.1`.
