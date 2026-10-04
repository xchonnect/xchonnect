# xchonnect-wasm

WebAssembly build of `xchonnect-core` used by `@xchonnect/dapp`. Build with
`scripts/build-wasm.sh` (output: `sdk-ts/wasm/`, gzip size budget enforced).

## Content Security Policy

The module is loaded with `WebAssembly.instantiateStreaming`. It needs **no**
`unsafe-eval`; browsers require only `script-src 'wasm-unsafe-eval'` (Chrome ≥ 95,
Firefox ≥ 102, Safari ≥ 16) in addition to serving the `.wasm` file from an allowed
origin. Recommended signing-page policy:

```
Content-Security-Policy: default-src 'self'; script-src 'self' 'wasm-unsafe-eval';
  connect-src 'self' https://<relay-host>; img-src 'self' data:; object-src 'none';
  base-uri 'none'; frame-ancestors 'none'
```

## API conventions

- Binary values are base64url strings without padding; times are unix seconds passed
  in by the caller (deterministic, testable).
- Secrets leave WASM only where JS must use them: the session's own read token and the
  peer's write token (relay authentication) and the serialised session state (to be
  stored encrypted, spec 12.1).
- Decoded messages are returned as JSON text.
- OHTTP (`OhttpClient`, `ohttpSelectKey`; rotation via `OhttpPending.decapsulateKeyRotation`): encapsulated requests,
  responses and key configurations are raw `Uint8Array`s, since they are HTTP bodies.
