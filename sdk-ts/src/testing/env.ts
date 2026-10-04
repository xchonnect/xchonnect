/** Shared fixtures for the SDK unit tests; importing this initialises the WASM core. */
import { readFileSync } from "node:fs";
import * as core from "../../wasm/xchonnect.js";
import { type ClientOptions, MemorySessionStore, XchonnectClient } from "../index.js";

export const wasm = readFileSync(new URL("../../wasm/xchonnect_bg.wasm", import.meta.url));
core.initSync({ module: wasm });

export const RELAY = "http://127.0.0.1:8787";
export const SEED = Buffer.alloc(32, 9).toString("base64url");

/** Developer-mode client for `localhost:5173` signing with {@link SEED}; `opts` override. */
export function devClient(opts: Partial<ClientOptions> = {}): Promise<XchonnectClient> {
  return XchonnectClient.create({ relay: RELAY, domain: "localhost:5173", kid: "k1", sign: async (i) => core.devSign(SEED, i), developerMode: true, storage: new MemorySessionStore(), wasm, ...opts });
}
