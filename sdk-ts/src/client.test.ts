import { readFileSync } from "node:fs";
import { beforeAll, describe, expect, it } from "vitest";
import * as core from "../wasm/xchonnect.js";
import { createChip0002Provider, MemorySessionStore, RelayClient, XchonnectClient, XchonnectRpcError, type DeliveryEvent } from "./index.js";
import { FakeWallet } from "./testing/fakeWallet.js";
import { MockRelay } from "./testing/mockRelay.js";

const wasm = readFileSync(new URL("../wasm/xchonnect_bg.wasm", import.meta.url));
const SEED = Buffer.from(new Uint8Array(32).fill(9)).toString("base64url");
let originDocument = "";

beforeAll(() => {
  core.initSync({ module: wasm });
  originDocument = JSON.stringify({ v: 1, name: "Pengui", origin_keys: [{ kid: "k1", pk: core.devPublicKey(SEED), not_after: "2030-01-01" }] });
});

async function setup(opts: { handle?: (m: string, p: string) => string; receipts?: boolean; link?: string; opened?: string[] } = {}) {
  const relay = new MockRelay();
  const storage = new MemorySessionStore();
  const client = await XchonnectClient.create({
    relay: "http://127.0.0.1:8787",
    domain: "localhost:5173",
    kid: "k1",
    sign: async (input) => core.devSign(SEED, input),
    originPublicKey: core.devPublicKey(SEED),
    developerMode: true,
    fetch: relay.fetch,
    storage,
    wasm,
    pollIntervalMs: 2,
    openUrl: (u) => opts.opened?.push(u),
  });
  const walletRelay = new RelayClient("http://127.0.0.1:8787", { fetch: relay.fetch });
  const wallet = new FakeWallet({ relay: walletRelay, originDocument, name: "Test Wallet", ...(opts.link ? { link: opts.link } : {}), ...(opts.handle ? { handle: opts.handle } : {}), ...(opts.receipts ? { receipts: opts.receipts } : {}) });
  return { relay, storage, client, wallet };
}

async function paired(opts: Parameters<typeof setup>[0] = {}) {
  const s = await setup(opts);
  const pairing = await s.client.pair();
  await s.wallet.scan(pairing.uri);
  const { sas, walletName } = await pairing.waitForWallet();
  await s.wallet.confirm();
  await pairing.confirm();
  return { ...s, sas, walletName, pairing };
}

describe("XchonnectClient", () => {
  it("pairs with matching SAS on both sides and becomes active", async () => {
    const { client, wallet, sas, walletName, relay } = await paired();
    expect(sas).toBe(wallet.sas);
    expect(sas).toMatch(/^\d{3} \d{3}$/);
    expect(walletName).toBe("Test Wallet");
    expect(client.status).toBe("active");
    // The pairing mailbox was deleted after the first valid reply.
    expect(relay.boxes.size).toBe(2);
  });

  it("only the first wallet reply wins", async () => {
    const s = await setup();
    const pairing = await s.client.pair();
    await s.wallet.scan(pairing.uri);
    const second = new FakeWallet({ relay: new RelayClient("http://127.0.0.1:8787", { fetch: s.relay.fetch }), originDocument });
    await second.scan(pairing.uri);
    const { sas } = await pairing.waitForWallet();
    expect(sas).toBe(s.wallet.sas);
    // The second wallet cannot post to the deleted pairing mailbox any more.
    const third = new FakeWallet({ relay: new RelayClient("http://127.0.0.1:8787", { fetch: s.relay.fetch }), originDocument });
    await expect(third.scan(pairing.uri)).rejects.toThrow(/not_found/);
  });

  it("does not activate before the user confirms the SAS on the dApp", async () => {
    const s = await setup();
    const pairing = await s.client.pair();
    await s.wallet.scan(pairing.uri);
    await pairing.waitForWallet();
    await s.wallet.confirm();
    await s.client.sync();
    expect(s.client.status).toBe("awaiting-sas");
    await expect(s.client.request("chainId")).rejects.toThrow(/no active session/);
  });

  it("rejecting the SAS ends the session on both sides", async () => {
    const s = await setup();
    const pairing = await s.client.pair();
    await s.wallet.scan(pairing.uri);
    await pairing.waitForWallet();
    await s.wallet.confirm();
    await pairing.reject();
    expect(s.client.status).toBe("ended");
    expect(await s.storage.load("default")).toBeNull();
    await s.wallet.step();
    expect(s.wallet.session?.isEnded()).toBe(true);
  });

  it("sends requests and receives results with delivery events", async () => {
    const { client, wallet } = await paired({ receipts: true, handle: (m) => (m === "chainId" ? '"testnet11"' : '"0xabcdef"') });
    const events: DeliveryEvent[] = [];
    client.on("delivery", (e) => events.push(e));
    const stop = wallet.run();
    try {
      expect(await client.request("chainId")).toBe("testnet11");
      expect(await client.request("signCoinSpends", { coinSpends: [], partialSign: true })).toBe("0xabcdef");
    } finally {
      stop();
    }
    expect(wallet.requests[1]).toEqual({ method: "signCoinSpends", params: '{"coinSpends":[],"partialSign":true}' });
    expect(events.map((e) => e.state).slice(0, 3)).toEqual(["queued", "delivered", "completed"]);
  });

  it("surfaces wallet errors as XchonnectRpcError", async () => {
    const { client, wallet } = await paired({
      handle: () => {
        throw { code: 4002, message: "user rejected request" };
      },
    });
    const stop = wallet.run();
    try {
      const err = await client.request("signMessage", { message: "00", publicKey: "aa" }).catch((e: unknown) => e);
      expect(err).toBeInstanceOf(XchonnectRpcError);
      expect((err as XchonnectRpcError).code).toBe(4002);
    } finally {
      stop();
    }
  });

  it("expires requests the wallet never answers", async () => {
    const s = await setup();
    const pairing = await s.client.pair();
    await s.wallet.scan(pairing.uri);
    await pairing.waitForWallet();
    await s.wallet.confirm();
    await pairing.confirm();
    // The wallet never answers; the request expires after its 1 s TTL.
    const p = s.client.request("chainId", {}, { ttlSeconds: 1 });
    const err = await Promise.race([p.catch((e: unknown) => e), new Promise((r) => setTimeout(() => r("timeout"), 3000))]);
    expect(err).toBeInstanceOf(XchonnectRpcError);
    expect((err as XchonnectRpcError).code).toBe(4100);
  }, 10_000);

  it("restores an active session from storage", async () => {
    const { storage, relay, wallet } = await paired({ handle: () => '"mainnet"' });
    const restored = await XchonnectClient.create({
      relay: "http://127.0.0.1:8787",
      domain: "localhost:5173",
      kid: "k1",
      sign: async (i) => core.devSign(SEED, i),
      developerMode: true,
      fetch: relay.fetch,
      storage,
      wasm,
      pollIntervalMs: 2,
    });
    expect(restored.status).toBe("active");
    const stop = wallet.run();
    try {
      expect(await restored.request("chainId")).toBe("mainnet");
    } finally {
      stop();
    }
  });

  it("rotates keys and mailboxes and keeps working", async () => {
    const { client, wallet } = await paired({ handle: () => "1" });
    const stop = wallet.run();
    try {
      await client.rotate();
      for (let i = 0; i < 3; i++) expect(await client.request("chainId")).toBe(1);
      expect(wallet.session?.epoch()).toBe(1);
    } finally {
      stop();
    }
  });

  it("ending the session clears state and notifies the wallet", async () => {
    const { client, wallet, storage } = await paired();
    await client.end("logout");
    expect(client.status).toBe("ended");
    expect(await storage.load("default")).toBeNull();
    await wallet.step();
    expect(wallet.session?.isEnded()).toBe(true);
  });
});

describe("CHIP-0002 provider", () => {
  it("passes required methods through and maps errors", async () => {
    const answers: Record<string, string> = { chainId: '"mainnet"', connect: "true", getPublicKeys: '["0xaa"]', signCoinSpends: '"0xc0"', signMessage: '"0xbb"' };
    const { client, wallet } = await paired({
      handle: (m) => {
        const a = answers[m];
        if (a === undefined) throw { code: 4004, message: "method not found" };
        return a;
      },
    });
    const chia = createChip0002Provider(client);
    const stop = wallet.run();
    try {
      expect(await chia.request({ method: "chainId" })).toBe("mainnet");
      expect(await chia.request({ method: "chip0002_connect", params: { eager: true } })).toBe(true);
      expect(await chia.request({ method: "getPublicKeys", params: { limit: 1, offset: 0 } })).toEqual(["0xaa"]);
      expect(await chia.request({ method: "signCoinSpends", params: { coinSpends: [], partialSign: true } })).toBe("0xc0");
      expect(await chia.request({ method: "signMessage", params: { message: "00", publicKey: "aa" } })).toBe("0xbb");
      await expect(chia.request({ method: "chia_takeOffer" })).rejects.toEqual({ code: 4004, message: "method not found" });
    } finally {
      stop();
    }
    expect(wallet.requests.map((r) => r.method)).toEqual(["chainId", "connect", "getPublicKeys", "signCoinSpends", "signMessage", "chia_takeOffer"]);
    expect(wallet.requests[3]?.params).toBe('{"coinSpends":[],"partialSign":true}');
    await client.end();
    await expect(chia.request({ method: "chainId" })).rejects.toMatchObject({ code: 4001 });
  });
});

describe("same-device flow", () => {
  it("opens the pairing link and the wallet for requests via the fragment", async () => {
    const opened: string[] = [];
    const s = await setup({ link: "https://wallet.example/app", opened, handle: () => '"testnet11"' });
    const pairing = await s.client.pair();
    pairing.openInWallet("https://wallet.example/app/pair");
    expect(opened[0]).toMatch(/^https:\/\/wallet\.example\/app\/pair#r=/);
    await s.wallet.scan(pairing.uri);
    await pairing.waitForWallet();
    await s.wallet.confirm();
    await pairing.confirm();
    expect(s.client.walletLink).toBe("https://wallet.example/app");
    const stop = s.wallet.run();
    try {
      expect(await s.client.request("chainId", {}, { openWallet: true })).toBe("testnet11");
    } finally {
      stop();
    }
    expect(opened[1]).toMatch(/^https:\/\/wallet\.example\/app\/req#mbx=[A-Za-z0-9_-]{22}$/);
    // The link survives a reload.
    const restored = await XchonnectClient.create({ relay: "http://127.0.0.1:8787", domain: "localhost:5173", kid: "k1", sign: async (i) => core.devSign(SEED, i), developerMode: true, fetch: s.relay.fetch, storage: s.storage, wasm });
    expect(restored.walletLink).toBe("https://wallet.example/app");
  });

  it("refuses openWallet without a wallet link", async () => {
    const { client } = await paired();
    await expect(client.request("chainId", {}, { openWallet: true })).rejects.toThrow(/link/);
  });
});

describe("review regressions", () => {
  it("junk in the pairing mailbox cannot block the real reply", async () => {
    const s = await setup();
    const pairing = await s.client.pair();
    // Anyone holding the QR can post to the pairing mailbox; flood it beyond one fetch page.
    const pairingBox = [...s.relay.boxes.values()][0];
    if (!pairingBox) throw new Error("no pairing mailbox");
    for (let i = 0; i < 40; i++) pairingBox.messages.push({ msg_id: `junk${i}`, env: "AAAA" });
    await s.wallet.scan(pairing.uri);
    const { sas } = await pairing.waitForWallet();
    expect(sas).toBe(s.wallet.sas);
  });

  it("a failed /v1/info call does not break the client", async () => {
    const relay = new MockRelay();
    let fail = true;
    const flaky: typeof fetch = async (input, init) => {
      if (fail && String(input).endsWith("/v1/info")) {
        fail = false;
        throw new TypeError("network error");
      }
      return relay.fetch(input, init);
    };
    const client = await XchonnectClient.create({ relay: "http://127.0.0.1:8787", domain: "localhost:5173", kid: "k1", sign: async (i) => core.devSign(SEED, i), developerMode: true, fetch: flaky, storage: new MemorySessionStore(), wasm });
    await expect(client.pair()).rejects.toThrow(/network/);
    await expect(client.pair()).resolves.toBeDefined();
  });

  it("openWallet without a wallet link fails before anything is posted", async () => {
    const { client, relay } = await paired();
    const before = relay.posts;
    await expect(client.request("chainId", {}, { openWallet: true })).rejects.toThrow(/link/);
    expect(relay.posts).toBe(before);
  });

  it("accepts a rotation started by the wallet", async () => {
    const { client, wallet } = await paired({ handle: () => '"ok"' });
    const stop = wallet.run();
    try {
      await wallet.rotate();
      for (let i = 0; i < 200 && client.relay && wallet.session?.epoch() !== 1; i++) {
        await client.sync();
        await new Promise((r) => setTimeout(r, 5));
      }
      expect(wallet.session?.epoch()).toBe(1);
      expect(await client.request("chainId")).toBe("ok");
    } finally {
      stop();
    }
  });
});
