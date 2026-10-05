# Wire definitions (normative)

These files are part of the specification. On conflict with prose in
`xchonnect-spec.md`, raise an issue; the files here are authoritative for byte layout.

| File | Content |
|---|---|
| [`envelope.cddl`](envelope.cddl) | CBOR structures: envelopes, inner plaintext, pairing reply, session and RPC bodies, sealed push token |
| [`pairing-uri.md`](pairing-uri.md) | Pairing URI grammar, field rules, origin signature input |
| [`xchonnect.schema.json`](xchonnect.schema.json) | `/.well-known/xchonnect.json` JSON Schema and fetch rules |
| [`relay-api.md`](relay-api.md) | Relay HTTP API, error model, token hashing, limits |
