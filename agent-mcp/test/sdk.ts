/**
 * The wallet side of the tests runs on this repository's SDK build (`../sdk-ts`, `npm run build`
 * there), whose test wallet can send `error.data` (an agent refusal's reason); the plugin itself
 * runs on the published `@xchonnect/dapp` it depends on. The two meet only on the relay, as a
 * real wallet and agent would.
 */
import { readFileSync } from "node:fs";
import { initXchonnect } from "../../sdk-ts/dist/src/index.js";

export const walletWasm = readFileSync(new URL("../../sdk-ts/dist/wasm/xchonnect_bg.wasm", import.meta.url));
await initXchonnect(walletWasm);

export { RelayClient } from "../../sdk-ts/dist/src/index.js";
export { FakeWallet, MockRelay } from "../../sdk-ts/dist/src/testing/index.js";
export const pluginWasm = readFileSync(new URL(import.meta.resolve("@xchonnect/dapp/xchonnect_bg.wasm")));
