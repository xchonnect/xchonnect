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

`sdk-ts/src/wasmCsp.test.ts` enforces this and runs on every `npm test`:

- the emitted glue contains no `eval`, `Function` constructor or string timer;
- Node loads and uses the module with `--disallow-code-generation-from-strings`;
- every installed browser loads it from a local server that **enforces** the policy
  above (`report-uri` collected, violation list asserted empty), with a negative control
  that drops `'wasm-unsafe-eval'` and must fail — so a green run cannot be a policy that
  was never applied.

Chrome, Chromium and Firefox are driven headless and need nothing. Safari has no
headless mode, so it is driven through `safaridriver` and is **skipped** unless a human
enables Safari Settings → Advanced → "Show features for web developers", then
Develop → "Allow Remote Automation" (`safaridriver --enable` needs an administrator
password and cannot be done from a test). With that enabled, `npm test -w @xchonnect/dapp`
covers Safari too.

## API conventions

- Binary values are base64url strings without padding; times are unix seconds passed
  in by the caller (deterministic, testable).
- Secrets leave WASM only where JS must use them: the session's own read token and the
  peer's write token (relay authentication) and the serialised session state (to be
  stored encrypted, spec 12.1).
- Decoded messages are returned as JSON text.
- OHTTP (`OhttpClient`, `ohttpSelectKey`; rotation via `OhttpPending.decapsulateKeyRotation`): encapsulated requests,
  responses and key configurations are raw `Uint8Array`s, since they are HTTP bodies.

## Licence and security

Apache-2.0 ([`LICENSE`](https://github.com/maximedogawa/xchonnect/blob/main/LICENSE)).

Report vulnerabilities privately - **not** as a public issue - per
[`SECURITY.md`](https://github.com/maximedogawa/xchonnect/blob/main/SECURITY.md).
Pre-audit software; see the browser storage requirements in spec 12.1 before shipping a
dApp with it.
