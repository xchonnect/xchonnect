/**
 * `@xchonnect/dapp/testing` — a wallet and a relay for a dApp's tests, so pairing and
 * requests can be exercised with no wallet app, no server and no Rust toolchain.
 *
 * - {@link FakeWallet} answers as a wallet would, with the answers you give it. It holds
 *   no keys, simulates no spend and asks no user.
 * - {@link MockRelay} is the relay HTTP API in memory, as a `fetch` function.
 *
 * Neither is for production, and this entry point is not covered by semantic
 * versioning: it follows the SDK's own tests.
 */
export { FakeWallet, type FakeWalletOptions } from "./fakeWallet.js";
export { MockRelay } from "./mockRelay.js";
