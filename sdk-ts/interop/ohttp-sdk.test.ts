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
import type { ChildProcess } from "node:child_process";
import { createServer, type Server } from "node:http";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import * as core from "../wasm/xchonnect.js";
import { OhttpKeyError, type PrivacyEvent, pushSpendBundle, XchonnectError } from "../src/index.js";
import { listen, type Proc, sdkClient, spawnWallet, startOrigin, startRelay, wasm } from "./harness.js";

const SEED = Buffer.alloc(32, 43).toString("base64url");
const NEW_KEY = Buffer.alloc(32, 0x62).toString("base64url");
const OLD_KEY = Buffer.alloc(32, 0x61).toString("base64url");

let relay: ChildProcess;
let relayUrl = "";
let origin: Server;
let originPort = 0;
let forwarder: Server;
let ohttpRelayUrl = "";
const ohttpRelay = { down: false, forwarded: 0 };
const wallets: Proc[] = [];
/** Key configuration list as published before the rotation (old key only). */
let shippedKeys = "";

beforeAll(async () => {
  core.initSync({ module: wasm });
  ({ proc: relay, url: relayUrl } = await startRelay({ XCHONNECT_CREATION: "pow", XCHONNECT_POW_DIFFICULTY: "8", XCHONNECT_OHTTP_KEYS: `2:${NEW_KEY},1:${OLD_KEY}`, XCHONNECT_MAX_WAIT_S: "25", XCHONNECT_MAX_WAIT_OHTTP_S: "0" }));
  // The operator published only key 1 when the dApp was built: keep the entry with id 1.
  const list = new Uint8Array(await (await fetch(`${relayUrl}/.well-known/ohttp-keys`)).arrayBuffer());
  for (let i = 0; i < list.length; ) {
    const len = (list[i]! << 8) | list[i + 1]!;
    if (list[i + 2] === 1) shippedKeys = Buffer.from(list.subarray(i, i + 2 + len)).toString("base64url");
    i += 2 + len;
  }
  expect(shippedKeys).not.toBe("");
  ({ server: origin, port: originPort } = await startOrigin("OHTTP dApp", SEED));

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
  ohttpRelayUrl = `http://127.0.0.1:${await listen(forwarder)}/`;
}, 30_000);

afterAll(() => {
  for (const w of wallets) w.p.kill("SIGKILL");
  relay?.kill("SIGTERM");
  origin?.close();
  forwarder?.close();
});

/** SDK client over OHTTP whose own fetch records every URL it is asked for. */
function client(urls: string[], ohttp: { keyConfig?: string; allowDirectFallback?: boolean } = {}) {
  const recording: typeof fetch = (input, init) => {
    urls.push(String(input));
    return fetch(input, init);
  };
  return sdkClient(relayUrl, originPort, SEED, { fetch: recording, ohttp: { relayUrl: ohttpRelayUrl, keyConfig: ohttp.keyConfig ?? shippedKeys, allowDirectFallback: ohttp.allowDirectFallback ?? false } });
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
    const wallet = spawnWallet(pairing.uri, "OHTTP Wallet");
    wallets.push(wallet);
    const { sas } = await pairing.waitForWallet();
    expect(sas).toBe((await wallet.waitFor(/SAS: (\d{3} \d{3})/))[1]);
    await pairing.confirm({ timeoutSeconds: 30 });
    await wallet.waitFor(/Paired\./);
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

  // Spec 10.6 / TASK-70: a node submission through the node operator's own gateway. The
  // reference relay stands in for that gateway (same RFC 9458 implementation a node
  // operator would deploy); it has no `/push_tx`, so the inner answer is 404 — which only
  // arrives if the whole encapsulated round trip worked.
  it("sends pushSpendBundle through OHTTP to the node's own gateway", async () => {
    const urls: string[] = [];
    const recording: typeof fetch = (input, init) => {
      urls.push(String(input));
      return fetch(input, init);
    };
    const events: (PrivacyEvent & { node: string })[] = [];
    const before = ohttpRelay.forwarded;
    const node = { url: relayUrl, ohttp: { relayUrl: ohttpRelayUrl, keyConfig: shippedKeys } };
    const r = await pushSpendBundle([], `0x${"c0"}${"00".repeat(95)}`, [node], {
      fetch: recording,
      developerMode: true,
      onPrivacy: (e) => events.push(e),
    }).catch((e: unknown) => e as XchonnectError);
    expect((r as XchonnectError).message).toMatch(/no node accepted/);
    // Nothing was sent to the node directly, and the gateway really answered.
    expect(urls.length).toBeGreaterThan(0);
    expect(urls.every((u) => u === ohttpRelayUrl)).toBe(true);
    expect(ohttpRelay.forwarded).toBeGreaterThan(before);
    expect(events).toEqual([]);

    // The same submission against a node that accepts it: a direct node, for contrast,
    // is reported as `direct`.
    const accepting = createServer((req, res) => {
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify({ success: req.url === "/push_tx" }));
    });
    const port = await listen(accepting);
    try {
      const ok = await pushSpendBundle([], `0x${"c0"}${"00".repeat(95)}`, [node, `http://127.0.0.1:${port}`], { fetch: recording, developerMode: true });
      expect(ok.accepted).toEqual([`http://127.0.0.1:${port}`]);
      expect(ok.transport).toEqual([
        { node: relayUrl, state: "ohttp" },
        { node: `http://127.0.0.1:${port}`, state: "direct" },
      ]);
    } finally {
      accepting.close();
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
