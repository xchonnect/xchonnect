/**
 * SDK over OHTTP (TASK-53): the dApp SDK (WASM OHTTP client) talks to the reference relay
 * only through a small in-process "OHTTP relay" (a forwarder, as an independent operator
 * would run it) and the relay's gateway; the CLI wallet talks to the relay directly.
 * Covers polling without long-poll (max_wait_ohttp_s = 0), key rotation learned through
 * the gateway, OHTTP relay failure with and without the opt-in fallback, and a pinned key
 * the gateway does not have.
 *
 * Requires: cargo build -p xchonnect-relay -p xchonnect-wallet-cli, ./scripts/build-wasm.sh
 */
import { type ChildProcess, spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { type AddressInfo, createServer as netServer } from "node:net";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import * as core from "../wasm/xchonnect.js";
import { MemorySessionStore, OhttpKeyError, type PrivacyEvent, XchonnectClient, XchonnectError } from "../src/index.js";

const ROOT = new URL("../../", import.meta.url).pathname;
const BIN = `${ROOT}target/debug`;
const wasm = readFileSync(new URL("../wasm/xchonnect_bg.wasm", import.meta.url));
const SEED = Buffer.from(new Uint8Array(32).fill(43)).toString("base64url");
const NEW_KEY = Buffer.alloc(32, 0x62).toString("base64url");
const OLD_KEY = Buffer.alloc(32, 0x61).toString("base64url");

const freePort = () =>
  new Promise<number>((resolve) => {
    const s = netServer().listen(0, "127.0.0.1", () => {
      const p = (s.address() as AddressInfo).port;
      s.close(() => resolve(p));
    });
  });

let relay: ChildProcess;
let relayUrl = "";
let origin: Server;
let originPort = 0;
let forwarder: Server;
let ohttpRelayUrl = "";
const ohttpRelay = { down: false, forwarded: 0 };
const wallets: ChildProcess[] = [];
/** Key configuration list as published before the rotation (old key only). */
let shippedKeys = "";

beforeAll(async () => {
  core.initSync({ module: wasm });
  const port = await freePort();
  relayUrl = `http://127.0.0.1:${port}`;
  relay = spawn(`${BIN}/xchonnect-relay`, [], {
    env: {
      ...process.env,
      XCHONNECT_LISTEN: `127.0.0.1:${port}`,
      XCHONNECT_CREATION: "pow",
      XCHONNECT_POW_DIFFICULTY: "8",
      XCHONNECT_OHTTP_KEYS: `2:${NEW_KEY},1:${OLD_KEY}`,
      XCHONNECT_MAX_WAIT_S: "25",
      XCHONNECT_MAX_WAIT_OHTTP_S: "0",
      XCHONNECT_LOG: "warn",
    },
    stdio: "ignore",
  });
  for (let i = 0; i < 200; i++) {
    if (await fetch(`${relayUrl}/healthz`).then((r) => r.ok).catch(() => false)) break;
    await new Promise((r) => setTimeout(r, 50));
  }
  // The operator published only key 1 when the dApp was built: keep the entry with id 1.
  const list = new Uint8Array(await (await fetch(`${relayUrl}/.well-known/ohttp-keys`)).arrayBuffer());
  for (let i = 0; i < list.length; ) {
    const len = (list[i]! << 8) | list[i + 1]!;
    if (list[i + 2] === 1) shippedKeys = Buffer.from(list.subarray(i, i + 2 + len)).toString("base64url");
    i += 2 + len;
  }
  expect(shippedKeys).not.toBe("");

  const doc = JSON.stringify({ v: 1, name: "OHTTP dApp", origin_keys: [{ kid: "k1", pk: core.devPublicKey(SEED), not_after: "2030-01-01" }] });
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

  // Minimal OHTTP relay (spec 10.2): forwards message/ohttp-req bodies to the gateway,
  // adds no client-identifying headers and returns the gateway's answer.
  forwarder = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      if (ohttpRelay.down) {
        res.statusCode = 502;
        res.end();
        return;
      }
      ohttpRelay.forwarded++;
      void fetch(`${relayUrl}/.well-known/ohttp-gateway`, {
        method: "POST",
        headers: { "content-type": req.headers["content-type"] ?? "" },
        body: Buffer.concat(chunks),
      }).then(async (g) => {
        res.statusCode = g.status;
        res.setHeader("content-type", g.headers.get("content-type") ?? "application/octet-stream");
        res.end(Buffer.from(await g.arrayBuffer()));
      });
    });
  });
  await new Promise<void>((r) => forwarder.listen(0, "127.0.0.1", () => r()));
  ohttpRelayUrl = `http://127.0.0.1:${(forwarder.address() as AddressInfo).port}/`;
}, 30_000);

afterAll(() => {
  for (const w of wallets) w.kill("SIGKILL");
  relay?.kill("SIGTERM");
  origin?.close();
  forwarder?.close();
});

/** Records every URL the dApp's own fetch is asked for. */
function recording(urls: string[]): typeof fetch {
  return (input, init) => {
    urls.push(String(input));
    return fetch(input, init);
  };
}

async function client(urls: string[], ohttp: { keyConfig?: string; allowDirectFallback?: boolean } = {}) {
  return XchonnectClient.create({
    relay: relayUrl,
    domain: `localhost:${originPort}`,
    kid: "k1",
    sign: async (input) => core.devSign(SEED, input),
    originPublicKey: core.devPublicKey(SEED),
    developerMode: true,
    storage: new MemorySessionStore(),
    wasm,
    fetch: recording(urls),
    ohttp: { relayUrl: ohttpRelayUrl, keyConfig: ohttp.keyConfig ?? shippedKeys, allowDirectFallback: ohttp.allowDirectFallback ?? false },
  });
}

function waitForLine(p: ChildProcess, re: RegExp, ms = 30_000): Promise<RegExpMatchArray> {
  let out = "";
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`timeout waiting for ${re}\n${out}`)), ms);
    p.stdout?.on("data", (d: Buffer) => {
      out += d.toString();
      const m = re.exec(out);
      if (m) {
        clearTimeout(timer);
        resolve(m);
      }
    });
  });
}

describe("SDK over OHTTP", () => {
  it("pairs and exchanges requests only through the OHTTP relay, polling without long-poll, and follows a key rotation", async () => {
    const urls: string[] = [];
    const c = await client(urls);
    expect(c.privacy).toBe("ohttp");
    const rotated: number[] = [];
    const privacy: PrivacyEvent[] = [];
    c.on("ohttpKeyRotated", (k) => rotated.push(k));
    c.on("privacy", (e) => privacy.push(e));
    const waits: number[] = [];
    const orig = c.relay.fetchMessages.bind(c.relay);
    vi.spyOn(c.relay, "fetchMessages").mockImplementation((m, t, w = 0, s) => {
      waits.push(w);
      return orig(m, t, w, s);
    });

    const pairing = await c.pair();
    const wallet = spawn(`${BIN}/xchonnect-wallet-cli`, ["pair", pairing.uri, "--dev", "--auto-approve", "--name", "OHTTP Wallet"], { stdio: ["ignore", "pipe", "pipe"] });
    wallets.push(wallet);
    const sasLine = waitForLine(wallet, /SAS: (\d{3} \d{3})/);
    const paired = waitForLine(wallet, /Paired\./);
    const { sas } = await pairing.waitForWallet();
    expect(sas).toBe((await sasLine)[1]);
    await pairing.confirm({ timeoutSeconds: 30 });
    await paired;
    expect(await c.request("chainId")).toBe("testnet11");

    // Every byte the dApp sent went to the OHTTP relay; never to the Xchonnect relay.
    expect(urls.length).toBeGreaterThan(5);
    expect(urls.every((u) => u === ohttpRelayUrl)).toBe(true);
    expect(ohttpRelay.forwarded).toBeGreaterThan(5);
    // max_wait_ohttp_s = 0: no long-poll through OHTTP although max_wait_s is 25.
    expect(waits.length).toBeGreaterThan(0);
    expect(waits.every((w) => w === 0)).toBe(true);
    // The shipped pin (key 1) was rotated to key 2 through the gateway.
    expect(rotated).toEqual([2]);
    expect(privacy).toEqual([]);
    expect(c.privacy).toBe("ohttp");
    c.close();
  }, 90_000);

  it("fails closed when the OHTTP relay is down, unless direct fallback is opted in", async () => {
    ohttpRelay.down = true;
    try {
      const urls: string[] = [];
      const strict = await client(urls);
      const events: PrivacyEvent[] = [];
      strict.on("privacy", (e) => events.push(e));
      await expect(strict.pair()).rejects.toMatchObject({ code: "ohttp_failed" });
      expect(strict.privacy).toBe("ohttp");
      expect(events).toEqual([]);
      expect(urls.every((u) => u === ohttpRelayUrl)).toBe(true);

      const fallbackUrls: string[] = [];
      const lenient = await client(fallbackUrls, { allowDirectFallback: true });
      lenient.on("privacy", (e) => events.push(e));
      const pairing = await lenient.pair();
      expect(pairing.uri).toMatch(/^xchonnect:v1\?/);
      expect(lenient.privacy).toBe("direct");
      expect(events).toEqual([{ state: "direct", reason: "ohttp-failed" }]);
      expect(fallbackUrls.some((u) => u.startsWith(relayUrl))).toBe(true);
    } finally {
      ohttpRelay.down = false;
    }
  }, 30_000);

  it("treats a pinned key the gateway does not have as a hard error, even with fallback", async () => {
    // A configuration for a key the relay never had (id 9).
    const cfg = new Uint8Array([0, 41, 9, 0, 0x20, ...new Uint8Array(32).fill(7), 0, 4, 0, 1, 0, 3]);
    const urls: string[] = [];
    const c = await client(urls, { keyConfig: Buffer.from(cfg).toString("base64url"), allowDirectFallback: true });
    const err = await c.pair().catch((e: unknown) => e);
    expect(err).toBeInstanceOf(OhttpKeyError);
    expect((err as XchonnectError).code).toBe("ohttp_key_mismatch");
    expect(c.privacy).toBe("ohttp");
    expect(urls.every((u) => u === ohttpRelayUrl)).toBe(true);
  });
});
