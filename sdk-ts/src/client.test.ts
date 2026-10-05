import { describe, expect, it } from "vitest";
import * as core from "../wasm/xchonnect.js";
import { createChip0002Provider, MemorySessionStore, RelayClient, XchonnectRpcError, type DeliveryEvent } from "./index.js";
import { devClient, RELAY, SEED } from "./testing/env.js";
import { FakeWallet, type FakeWalletOptions } from "./testing/fakeWallet.js";
import { MockRelay } from "./testing/mockRelay.js";

const originDocument = JSON.stringify({ v: 1, name: "Pengui", origin_keys: [{ kid: "k1", pk: core.devPublicKey(SEED), not_after: "2030-01-01" }] });
type WalletOpts = Omit<Partial<FakeWalletOptions>, "relay">;

const walletFor = (relay: MockRelay, opts: WalletOpts = {}) => new FakeWallet({ relay: new RelayClient(RELAY, { fetch: relay.fetch }), originDocument, ...opts });

async function setup(walletOpts: WalletOpts = {}, opened: string[] = []) {
  const relay = new MockRelay();
  const storage = new MemorySessionStore();
  const client = await devClient({ originPublicKey: core.devPublicKey(SEED), fetch: relay.fetch, storage, pollIntervalMs: 2, openUrl: (u) => opened.push(u) });
  return { relay, storage, client, wallet: walletFor(relay, { name: "Test Wallet", ...walletOpts }) };
}

/** Pair up to the SAS comparison: the wallet replied and confirmed, the dApp user has not. */
async function atSas(s: Awaited<ReturnType<typeof setup>>) {
  const pairing = await s.client.pair();
  await s.wallet.scan(pairing.uri);
  const { sas, walletName } = await pairing.waitForWallet();
  await s.wallet.confirm();
  return { pairing, sas, walletName };
}

async function paired(walletOpts: WalletOpts = {}) {
  const s = await setup(walletOpts);
  const p = await atSas(s);
  await p.pairing.confirm();
  return { ...s, ...p };
}

async function waitFor(ok: () => boolean, ms = 3000): Promise<void> {
  const end = Date.now() + ms;
  while (!ok()) {
    if (Date.now() > end) throw new Error("timed out");
    await new Promise((r) => setTimeout(r, 5));
  }
}

/** Run `f` while the wallet answers in the background. */
async function withWallet<T>(wallet: FakeWallet, f: () => Promise<T>): Promise<T> {
  const stop = wallet.run();
  try {
    return await f();
  } finally {
    stop();
  }
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
    await walletFor(s.relay).scan(pairing.uri);
    const { sas } = await pairing.waitForWallet();
    expect(sas).toBe(s.wallet.sas);
    // A later wallet cannot post to the deleted pairing mailbox any more.
    await expect(walletFor(s.relay).scan(pairing.uri)).rejects.toThrow(/not_found/);
  });

  it("does not activate before the user confirms the SAS on the dApp", async () => {
    const s = await setup();
    await atSas(s);
    await s.client.sync();
    expect(s.client.status).toBe("awaiting-sas");
    await expect(s.client.request("chainId")).rejects.toThrow(/no active session/);
  });

  it("rejecting the SAS ends the session on both sides", async () => {
    const s = await setup();
    await (await atSas(s)).pairing.reject();
    expect(s.client.status).toBe("ended");
    expect(await s.storage.load("default")).toBeNull();
    await s.wallet.step();
    expect(s.wallet.session?.isEnded()).toBe(true);
  });

  it("sends requests and receives results with delivery events", async () => {
    const { client, wallet } = await paired({ receipts: true, handle: (m) => (m === "chainId" ? '"testnet11"' : '"0xabcdef"') });
    const events: DeliveryEvent[] = [];
    client.on("delivery", (e) => events.push(e));
    await withWallet(wallet, async () => {
      expect(await client.request("chainId")).toBe("testnet11");
      expect(await client.request("signCoinSpends", { coinSpends: [], partialSign: true })).toBe("0xabcdef");
    });
    expect(wallet.requests[1]).toEqual({ method: "signCoinSpends", params: '{"coinSpends":[],"partialSign":true}' });
    expect(events.map((e) => e.state).slice(0, 3)).toEqual(["queued", "delivered", "completed"]);
  });

  it("reports shown, approved and broadcast with the transaction id (rpc.status)", async () => {
    const txId = `0x${"ab".repeat(32)}`;
    const { client, wallet } = await paired({ broadcastTxId: txId, handle: () => `{"txId":"${txId}"}` });
    const events: DeliveryEvent[] = [];
    client.on("delivery", (e) => events.push(e));
    await withWallet(wallet, () => client.request("chia_send", { address: "txch1", amount: "1", fee: "0" }));
    expect(events.map((e) => e.state)).toEqual(["queued", "shown", "approved", "broadcast", "completed"]);
    expect(events.find((e) => e.state === "broadcast")?.txId).toBe(txId);
    expect(events.find((e) => e.state === "shown")).not.toHaveProperty("txId");
  });

  it("cancel withdraws a waiting request in the wallet; the wallet answers 4102", async () => {
    const { client, wallet } = await paired({ hold: true });
    const events: DeliveryEvent[] = [];
    client.on("delivery", (e) => events.push(e));
    await withWallet(wallet, async () => {
      const p = client.request("chia_send", { address: "txch1", amount: "1", fee: "0" }).catch((e: unknown) => e);
      await waitFor(() => events.some((e) => e.state === "shown"));
      const id = events[0]!.id;
      await client.cancel(id);
      expect(await p).toMatchObject({ code: "aborted" });
      await waitFor(() => wallet.cancelled.includes(id));
    });
    expect(events.map((e) => e.state)).toEqual(["queued", "shown", "cancelled"]);
  });

  it("aborting a request's signal cancels it in the wallet too", async () => {
    const { client, wallet } = await paired({ hold: true });
    const controller = new AbortController();
    const events: DeliveryEvent[] = [];
    client.on("delivery", (e) => events.push(e));
    await withWallet(wallet, async () => {
      const p = client.request("chia_send", {}, { signal: controller.signal }).catch((e: unknown) => e);
      await waitFor(() => events.some((e) => e.state === "shown"));
      controller.abort();
      expect(await p).toMatchObject({ code: "aborted" });
      await waitFor(() => wallet.cancelled.length === 1);
    });
  });

  it("learns from a refusal when the wallet declared nothing, and remembers it", async () => {
    const { client, wallet, relay, storage } = await paired({
      handle: (m) => {
        if (m === "chainId") return '"mainnet"';
        throw { code: 4004, message: "method not found" };
      },
    });
    // Nothing declared: unknown, so the dApp may try (spec 9.3 default is a narrow grant).
    expect(client.canRequest("chia_takeOffer")).toBeUndefined();
    await withWallet(wallet, async () => {
      await expect(client.request("chia_takeOffer")).rejects.toMatchObject({ code: 4004 });
      // A user declining is not a withdrawn scope, so it must not narrow the view.
      expect(await client.request("chainId")).toBe("mainnet");
    });
    expect(client.canRequest("chia_takeOffer")).toBe(false);
    expect(client.canRequest("chainId")).toBeUndefined();
    expect(client.permissions).toMatchObject({ declared: false, refused: ["chia_takeOffer"] });
    const restored = await devClient({ fetch: relay.fetch, storage, pollIntervalMs: 2 });
    expect(restored.canRequest("chia_takeOffer")).toBe(false);
    await client.end();
    expect((await devClient({ fetch: relay.fetch, storage })).permissions.refused).toEqual([]);
  });

  it("surfaces wallet errors as XchonnectRpcError", async () => {
    const { client, wallet } = await paired({
      handle: () => {
        throw { code: 4002, message: "user rejected request" };
      },
    });
    const err = await withWallet(wallet, () => client.request("signMessage", { message: "00", publicKey: "aa" }).catch((e: unknown) => e));
    expect(err).toBeInstanceOf(XchonnectRpcError);
    expect((err as XchonnectRpcError).code).toBe(4002);
  });

  it("expires requests the wallet never answers", async () => {
    const { client } = await paired();
    // The wallet never answers; the request expires after its 1 s TTL.
    const p = client.request("chainId", {}, { ttlSeconds: 1 });
    const err = await Promise.race([p.catch((e: unknown) => e), new Promise((r) => setTimeout(() => r("timeout"), 3000))]);
    expect(err).toBeInstanceOf(XchonnectRpcError);
    expect((err as XchonnectRpcError).code).toBe(4100);
  }, 10_000);

  it("restores an active session from storage", async () => {
    const { storage, relay, wallet } = await paired({ handle: () => '"mainnet"' });
    const restored = await devClient({ fetch: relay.fetch, storage, pollIntervalMs: 2 });
    expect(restored.status).toBe("active");
    expect(await withWallet(wallet, () => restored.request("chainId"))).toBe("mainnet");
  });

  it("rotates keys and mailboxes and keeps working", async () => {
    const { client, wallet } = await paired({ handle: () => "1" });
    await withWallet(wallet, async () => {
      await client.rotate();
      for (let i = 0; i < 3; i++) expect(await client.request("chainId")).toBe(1);
      expect(wallet.session?.epoch()).toBe(1);
    });
  });

  it("accepts a rotation started by the wallet", async () => {
    const { client, wallet } = await paired({ handle: () => '"ok"' });
    await withWallet(wallet, async () => {
      await wallet.rotate();
      // The offering side can recover the mailbox it polls for the accept.
      expect(wallet.session?.pendingRotationMailbox()).toHaveLength(2);
      for (let i = 0; i < 200 && wallet.session?.epoch() !== 1; i++) {
        await client.sync();
        await new Promise((r) => setTimeout(r, 5));
      }
      expect(wallet.session?.epoch()).toBe(1);
      expect(wallet.session?.pendingRotationMailbox()).toBeUndefined();
      expect(await client.request("chainId")).toBe("ok");
    });
  });

  it("concurrent rotation offers: the wallet gets back its abandoned mailbox to delete", async () => {
    const { client, wallet, relay } = await paired({ handle: () => '"ok"' });
    await wallet.rotate();
    await client.rotate();
    await withWallet(wallet, async () => {
      for (let i = 0; i < 200 && wallet.abandoned.length === 0; i++) {
        await client.sync();
        await new Promise((r) => setTimeout(r, 5));
      }
    });
    expect(wallet.abandoned).toHaveLength(1);
    expect(relay.boxes.has(wallet.abandoned[0]!)).toBe(false);
    expect(await withWallet(wallet, () => client.request("chainId"))).toBe("ok");
  });

  it("ending the session clears state and notifies the wallet", async () => {
    const { client, wallet, storage } = await paired();
    await client.end("logout");
    expect(client.status).toBe("ended");
    expect(await storage.load("default")).toBeNull();
    await wallet.step();
    expect(wallet.session?.isEnded()).toBe(true);
  });

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
    const client = await devClient({ fetch: flaky });
    await expect(client.pair()).rejects.toThrow(/network/);
    await expect(client.pair()).resolves.toBeDefined();
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
    await withWallet(wallet, async () => {
      expect(await chia.request({ method: "chainId" })).toBe("mainnet");
      expect(await chia.request({ method: "chip0002_connect", params: { eager: true } })).toBe(true);
      expect(await chia.request({ method: "getPublicKeys", params: { limit: 1, offset: 0 } })).toEqual(["0xaa"]);
      expect(await chia.request({ method: "signCoinSpends", params: { coinSpends: [], partialSign: true } })).toBe("0xc0");
      expect(await chia.request({ method: "signMessage", params: { message: "00", publicKey: "aa" } })).toBe("0xbb");
      await expect(chia.request({ method: "chia_takeOffer" })).rejects.toEqual({ code: 4004, message: "method not found" });
    });
    expect(wallet.requests.map((r) => r.method)).toEqual(["chainId", "connect", "getPublicKeys", "signCoinSpends", "signMessage", "chia_takeOffer"]);
    expect(wallet.requests[3]?.params).toBe('{"coinSpends":[],"partialSign":true}');
    await client.end();
    await expect(chia.request({ method: "chainId" })).rejects.toMatchObject({ code: 4001 });
  });
});

describe("same-device flow", () => {
  it("opens the pairing link and the wallet for requests via the fragment", async () => {
    const opened: string[] = [];
    const s = await setup({ link: "https://wallet.example/app", handle: () => '"testnet11"' }, opened);
    const pairing = await s.client.pair();
    pairing.openInWallet("https://wallet.example/app/pair");
    expect(opened[0]).toMatch(/^https:\/\/wallet\.example\/app\/pair#r=/);
    await s.wallet.scan(pairing.uri);
    await pairing.waitForWallet();
    await s.wallet.confirm();
    await pairing.confirm();
    expect(s.client.walletLink).toBe("https://wallet.example/app");
    expect(await withWallet(s.wallet, () => s.client.request("chainId", {}, { openWallet: true }))).toBe("testnet11");
    expect(opened[1]).toMatch(/^https:\/\/wallet\.example\/app\/req#mbx=[A-Za-z0-9_-]{22}$/);
    // The link survives a reload.
    expect((await devClient({ fetch: s.relay.fetch, storage: s.storage })).walletLink).toBe("https://wallet.example/app");
  });

  it("openWallet without a wallet link fails before anything is posted", async () => {
    const { client, relay } = await paired();
    const before = relay.posts;
    await expect(client.request("chainId", {}, { openWallet: true })).rejects.toThrow(/link/);
    expect(relay.posts).toBe(before);
  });

  it("an already aborted signal rejects without posting; listeners are removed after settling", async () => {
    const { client, relay, wallet } = await paired();
    const before = relay.posts;
    await expect(client.request("chainId", {}, { signal: AbortSignal.abort() })).rejects.toMatchObject({ code: "aborted" });
    expect(relay.posts).toBe(before);
    const ac = new AbortController();
    const add = ac.signal.addEventListener.bind(ac.signal);
    let added = 0;
    let removed = 0;
    ac.signal.addEventListener = ((...a: Parameters<typeof add>) => (added++, add(...a))) as typeof add;
    const remove = ac.signal.removeEventListener.bind(ac.signal);
    ac.signal.removeEventListener = ((...a: Parameters<typeof remove>) => (removed++, remove(...a))) as typeof remove;
    await withWallet(wallet, () => client.request("chainId", {}, { signal: ac.signal }));
    expect([added, removed]).toEqual([1, 1]);
  });
});
