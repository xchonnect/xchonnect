/**
 * End-to-end interop: TypeScript SDK (WASM core) ↔ reference relay (Rust) ↔ CLI wallet
 * (Rust, native core). Requires the binaries:
 *   cargo build -p xchonnect-relay -p xchonnect-wallet-cli
 */
import type { ChildProcess } from "node:child_process";
import type { Server } from "node:http";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import * as core from "../wasm/xchonnect.js";
import { XchonnectRpcError } from "../src/index.js";
import { type Proc, sdkClient, sleep, spawnWallet, startOrigin, startRelay, wasm } from "./harness.js";

const SEED = Buffer.alloc(32, 42).toString("base64url");

let relay: ChildProcess;
let relayUrl = "";
let origin: Server;
let originPort = 0;
const wallets: Proc[] = [];

beforeAll(async () => {
  core.initSync({ module: wasm });
  ({ proc: relay, url: relayUrl } = await startRelay({ XCHONNECT_CREATION: "pow", XCHONNECT_POW_DIFFICULTY: "8", XCHONNECT_OHTTP: "ephemeral" }));
  ({ server: origin, port: originPort } = await startOrigin("Interop dApp", SEED));
}, 30_000);

afterAll(() => {
  for (const w of wallets) w.p.kill("SIGKILL");
  relay?.kill("SIGTERM");
  origin?.close();
});

/** A posted envelope with its credentials (for the replay test). */
interface Posted {
  url: string;
  body: string;
  auth: string;
}

function recordingFetch(log: Posted[]): typeof fetch {
  return async (input, init) => {
    if (init?.method === "POST" && String(input).includes("/messages") && init.body) {
      log.push({ url: String(input), body: String(init.body), auth: new Headers(init.headers).get("authorization") ?? "" });
    }
    return fetch(input, init);
  };
}

async function pairWithWallet(posted: Posted[]) {
  const client = await sdkClient(relayUrl, originPort, SEED, { fetch: recordingFetch(posted) });
  const pairing = await client.pair();
  const wallet = spawnWallet(pairing.uri, "Interop Wallet");
  wallets.push(wallet);
  const [, walletSas] = await wallet.waitFor(/SAS: (\d{3} \d{3})/);
  const { sas, walletName } = await pairing.waitForWallet();
  return { client, pairing, wallet, sas, walletSas, walletName };
}

describe("interop: SDK ↔ relay ↔ CLI wallet", () => {
  it("pairs, exchanges requests, rotates, rejects replays and expired requests, and ends", async () => {
    const posted: Posted[] = [];
    const { client, pairing, wallet, sas, walletSas, walletName } = await pairWithWallet(posted);
    expect(sas).toBe(walletSas);
    expect(walletName).toBe("Interop Wallet");
    await pairing.confirm({ timeoutSeconds: 30 });
    expect(client.status).toBe("active");
    await wallet.waitFor(/Paired\./);

    // Requests in both directions through the real relay.
    expect(await client.request("chainId")).toBe("testnet11");
    expect(await client.request("chip0002_connect", { eager: false })).toBe(true);
    const keys = await client.request<string[]>("getPublicKeys", { limit: 1 });
    expect(keys[0]).toMatch(/^0x(ab){48}$/);
    expect(await client.request("signCoinSpends", { coinSpends: [], partialSign: true })).toBe(`0xc0${"00".repeat(95)}`);
    const err = await client.request("chia_unknownMethod").catch((e: unknown) => e);
    expect(err).toBeInstanceOf(XchonnectRpcError);
    expect((err as XchonnectRpcError).code).toBe(4004);

    // Replay: re-post the last request envelope verbatim with valid credentials. The
    // relay cannot tell (it only sees ciphertext); the wallet must reject it (spec 5.3).
    const last = posted.at(-1);
    if (!last) throw new Error("no posted envelope recorded");
    const replay = await fetch(last.url, { method: "POST", headers: { "content-type": "application/json", authorization: last.auth }, body: last.body });
    expect(replay.status).toBe(202);
    for (let i = 0; i < 200 && !/replayed/.test(wallet.err); i++) await sleep(25);
    expect(wallet.err).toMatch(/ignored message: replayed or reordered message/);
    const answered = (wallet.out.match(/answered/g) ?? []).length;
    expect(answered).toBe(5);

    // Rotation: keys and mailboxes change, requests keep working.
    await client.rotate();
    await wallet.waitFor(/Rotated to epoch 1/);
    expect(await client.request("chainId")).toBe("testnet11");

    // Expiry: pause the wallet so the request expires before it is read.
    wallet.p.kill("SIGSTOP");
    const expired = client.request("chainId", {}, { ttlSeconds: 1 }).catch((e: unknown) => e);
    await sleep(2500);
    wallet.p.kill("SIGCONT");
    const e2 = await expired;
    expect(e2).toBeInstanceOf(XchonnectRpcError);
    expect((e2 as XchonnectRpcError).code).toBe(4100);
    for (let i = 0; i < 100 && !/message expired/.test(wallet.err); i++) await sleep(50);
    expect(wallet.err).toMatch(/message expired/);

    // End: the wallet process exits cleanly.
    await client.end("interop done");
    expect(await wallet.exited()).toBe(0);
    expect(wallet.out).toMatch(/Session ended by dApp \(interop done\)/);
  }, 90_000);
});
