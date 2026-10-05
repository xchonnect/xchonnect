# Examples (development only)

| Example | What it is |
|---|---|
| [`dapp-web/`](dapp-web) | Minimal web dApp using `@xchonnect/dapp`: QR pairing, SAS confirmation, CHIP-0002 requests, rotation, disconnect. Its Vite dev server also acts as the dApp backend: it publishes `/.well-known/xchonnect.json` and signs pairing URIs with a generated **development** origin key (`.dev-origin-key`). |
| [`wallet-cli/`](wallet-cli) | Command-line wallet using the native Rust core: verifies the dApp origin, shows the domain and SAS, answers requests. **It holds no keys**: signing requests return the BLS identity signature `0xc000…`. |

## Run the full stack locally

```sh
./scripts/dev.sh        # builds everything, starts the relay and the dApp
```

Then open <http://localhost:5173>, click **Connect wallet**, and in another terminal:

```sh
./target/debug/xchonnect-wallet-cli pair '<URI from the page>' --dev
```

Compare the six-digit codes on both sides and confirm. `--dev` enables developer mode
(plain-HTTP loopback relay, `localhost:<port>` domain); production wallets never accept it.
Add `--auto-approve` to answer every prompt with "yes" (used by the interop test).

With `--dev-key <seed> [--network testnet11]` the CLI derives a **development** key and
answers through `xchonnect-wallet-kit`: it simulates each `signCoinSpends`, shows the real
effect, applies the signature policy and limits, and produces real BLS signatures for
its own coins (it prints its receive puzzle hash). Fund it with testnet coins only; a key
passed on the command line is never safe for real funds.

`--limit-xch-per-request <mojos>` and `--limit-xch-per-day <mojos>` set the per-dApp
spending limits a real wallet would ask the user for during pairing (spec 9.3). With a
development key the CLI also sends `session.permissions` after pairing, so the dApp can
see which methods, keys and limits it was granted instead of discovering them by being
refused.

## Conformance

The CLI wallet is the reference wallet for the wallet conformance suite
([`conformance/`](../conformance)), which drives it through pairing, the SAS, signing,
refusals, replays, limits, rotation and disconnect as a dApp would:

```sh
./scripts/wallet-conformance.sh
```

Without `--dev-key` the CLI answers signing requests with the BLS identity element and
exposes a placeholder public key, so the suite fails it on `getPublicKeys` and
`signMessage` — correctly: a wallet must not answer for a key it never exposed. That is
why the conformance run uses a development key.

Neither example contains production key handling. Real dApps sign pairing URIs with an
origin key held in an HSM or KMS; real wallets simulate every spend, show the net effect
and require biometric approval before signing (spec Section 11).
