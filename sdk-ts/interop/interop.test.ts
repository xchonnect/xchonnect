/**
 * End-to-end interop: TypeScript SDK (WASM core) ↔ reference relay (Rust) ↔ CLI wallet
 * (Rust, native core). Requires the binaries:
 *   cargo build -p xchonnect-relay -p xchonnect-wallet-cli
 */
import { type ChildProcess, spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { type AddressInfo, createServer as netServer } from "node:net";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import * as core from "../wasm/xchonnect.js";
import { MemorySessionStore, XchonnectClient, XchonnectRpcError } from "../src/index.js";

const ROOT = new URL("../../", import.meta.url).pathname;
const BIN = `${ROOT}target/debug`;
const wasm = readFileSync(new URL("../wasm/xchonnect_bg.wasm", import.meta.url));
const SEED = Buffer.from(new Uint8Array(32).fill(42)).toString("base64url");

const freePort = () =>
  new Promise<number>((resolve) => {
    const s = netServer().listen(0, "127.0.0.1", () => {
      const p = (s.address() as AddressInfo).port;
      s.close(() => resolve(p));
    });
  });

class Proc {
  out = "";
  err = "";
  constructor(readonly p: ChildProcess) {
    p.stdout?.on("data", (d: Buffer) => (this.out += d.toString()));
    p.stderr?.on("data", (d: Buffer) => (this.err += d.toString()));
  }
  async waitFor(re: RegExp, ms = 20_000): Promise<RegExpMatchArray> {
    const end = Date.now() + ms;
    while (Date.now() < end) {
      const m = re.exec(this.out);
      if (m) return m;
      await new Promise((r) => setTimeout(r, 25));
    }
    throw new Error(`timeout waiting for ${re}\nstdout:\n${this.out}\nstderr:\n${this.err}`);
  }
  exited(): Promise<number | null> {
    return new Promise((r) => (this.p.exitCode !== null ? r(this.p.exitCode) : this.p.on("exit", (c) => r(c))));
  }
}

let relay: Proc;
let relayUrl = "";
let origin: Server;
let originPort = 0;
const wallets: Proc[] = [];

beforeAll(async () => {
  core.initSync({ module: wasm });
  const port = await freePort();
  relayUrl = `http://127.0.0.1:${port}`;
  relay = new Proc(
    spawn(`${BIN}/xchonnect-relay`, [], {
      env: { ...process.env, XCHONNECT_LISTEN: `127.0.0.1:${port}`, XCHONNECT_CREATION: "pow", XCHONNECT_POW_DIFFICULTY: "8", XCHONNECT_OHTTP: "ephemeral", XCHONNECT_LOG: "warn" },
      stdio: ["ignore", "pipe", "pipe"],
    }),
  );
  for (let i = 0; i < 200; i++) {
    if (await fetch(`${relayUrl}/healthz`).then((r) => r.ok).catch(() => false)) break;
    await new Promise((r) => setTimeout(r, 50));
  }
  const doc = JSON.stringify({ v: 1, name: "Interop dApp", origin_keys: [{ kid: "k1", pk: core.devPublicKey(SEED), not_after: "2030-01-01" }] });
  origin = createServer((req, res) => {
    if (req.url === "/.well-known/xchonnect.json") {
      res.setHeader("content-type", "application/json");
      res.end(doc);
    } else {
      res.statusCode = 404;
      res.end();
    }
  });
  await new Promise<void>((r) => origin.listen(0, "127.0.0.1", () => r()));
  originPort = (origin.address() as AddressInfo).port;
}, 30_000);

afterAll(() => {
  for (const w of wallets) w.p.kill("SIGKILL");
  relay?.p.kill("SIGTERM");
  origin?.close();
});

/** Fetch wrapper that records every posted envelope (for the replay test). */
interface Posted {
  url: string;
  body: string;
  auth: string;
}

function recordingFetch(log: Posted[]): typeof fetch {
  return async (input, init) => {
    if (init?.method === "POST" && String(input).includes("/messages") && init.body) {
      const auth = new Headers(init.headers).get("authorization") ?? "";
      log.push({ url: String(input), body: String(init.body), auth });
    }
    return fetch(input, init);
  };
}

async function pairWithWallet(posted: Posted[]) {
  const client = await XchonnectClient.create({
    relay: relayUrl,
    domain: `localhost:${originPort}`,
    kid: "k1",
    sign: async (input) => core.devSign(SEED, input),
    originPublicKey: core.devPublicKey(SEED),
    developerMode: true,
    storage: new MemorySessionStore(),
    wasm,
    fetch: recordingFetch(posted),
  });
  const pairing = await client.pair();
  const wallet = new Proc(spawn(`${BIN}/xchonnect-wallet-cli`, ["pair", pairing.uri, "--dev", "--auto-approve", "--name", "Interop Wallet"], { stdio: ["ignore", "pipe", "pipe"] }));
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
    for (let i = 0; i < 200 && !/replayed/.test(wallet.err); i++) await new Promise((r) => setTimeout(r, 25));
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
    await new Promise((r) => setTimeout(r, 2500));
    wallet.p.kill("SIGCONT");
    const e2 = await expired;
    expect(e2).toBeInstanceOf(XchonnectRpcError);
    expect((e2 as XchonnectRpcError).code).toBe(4100);
    for (let i = 0; i < 100 && !/message expired/.test(wallet.err); i++) await new Promise((r) => setTimeout(r, 50));
    expect(wallet.err).toMatch(/message expired/);

    // End: the wallet process exits cleanly.
    await client.end("interop done");
    expect(await wallet.exited()).toBe(0);
    expect(wallet.out).toMatch(/Session ended by dApp \(interop done\)/);
  }, 90_000);
});
