import { describe, expect, it, vi } from "vitest";
import * as core from "../wasm/xchonnect.js";
import { createSignClientShim, MemorySessionStore, RelayClient, XchonnectError, type ShimSession, type XchonnectClient } from "./index.js";
import { devClient, RELAY, SEED } from "./testing/env.js";
import { FakeWallet, type FakeWalletOptions } from "./testing/fakeWallet.js";
import { MockRelay } from "./testing/mockRelay.js";

const originDocument = JSON.stringify({ v: 1, name: "Pengui", origin_keys: [{ kid: "k1", pk: core.devPublicKey(SEED), not_after: "2030-01-01" }] });
const CHIA_NS = { chains: ["chia:mainnet"], methods: ["chip0002_getPublicKeys", "chip0002_signCoinSpends"], events: [] };
const KEYS = ['["0xabc"]'];

type WalletOpts = Omit<Partial<FakeWalletOptions>, "relay">;

async function setup(walletOpts: WalletOpts = {}, clientOpts: Parameters<typeof devClient>[0] = {}) {
  const relay = new MockRelay();
  const storage = new MemorySessionStore();
  const client = await devClient({ originPublicKey: core.devPublicKey(SEED), fetch: relay.fetch, storage, pollIntervalMs: 2, ...clientOpts });
  const wallet = new FakeWallet({
    relay: new RelayClient(RELAY, { fetch: relay.fetch }),
    originDocument,
    name: "Test Wallet",
    handle: (m) => (m === "getPublicKeys" ? KEYS[0]! : "null"),
    ...walletOpts,
  });
  return { relay, storage, client, wallet };
}

/** Drive the shim through a full pairing with the fake wallet; `confirmSas` decides. */
async function connect(
  s: Awaited<ReturnType<typeof setup>>,
  confirmSas: (sas: string, info: { walletName?: string }) => Promise<boolean> = async () => true,
  connectParams: Parameters<ReturnType<typeof createSignClientShim>["connect"]>[0] = { requiredNamespaces: { chia: CHIA_NS } },
) {
  const shim = createSignClientShim({ client: s.client, confirmSas });
  const { uri, approval, expiry } = await shim.connect(connectParams);
  const pending = approval();
  await s.wallet.scan(uri);
  // The wallet side runs concurrently: it waits for `session.confirm` (which
  // `waitForWallet()` posts) and answers with `session.ready`, which `approval()` awaits.
  const walletSide = s.wallet.confirm().catch(() => undefined);
  const session = await pending;
  await walletSide;
  return { shim, uri, expiry, session };
}

describe("XchonnectSignClient (WalletConnect sign-client shim)", () => {
  it("refuses to exist without a SAS screen", () => {
    // The whole reason this is not a silent drop-in: no confirmSas, no shim (spec 6.3).
    expect(() => createSignClientShim({ client: {} as XchonnectClient, confirmSas: undefined as never })).toThrow(/confirmSas is required/);
  });

  it("connect() → approval() → request() → disconnect() over an Xchonnect session", async () => {
    const s = await setup();
    const seen: { sas: string; walletName?: string }[] = [];
    const { shim, uri, session } = await connect(s, async (sas, info) => {
      seen.push({ sas, ...info });
      return true;
    });

    expect(uri).toMatch(/^xchonnect:v1\?/);
    expect(seen).toHaveLength(1);
    expect(seen[0]?.sas).toBe(s.wallet.sas);
    expect(seen[0]?.walletName).toBe("Test Wallet");
    expect(s.client.status).toBe("active");

    expect(session.topic).toMatch(/^[0-9a-f]{64}$/);
    expect(session.acknowledged).toBe(true);
    expect(session.namespaces["chia"]?.chains).toEqual(["chia:mainnet"]);
    expect(session.peer.metadata.name).toBe("Test Wallet");
    expect(shim.session.getAll()).toEqual([session]);
    expect(shim.session.length).toBe(1);
    expect(shim.session.keys).toEqual([session.topic]);
    expect(shim.session.get(session.topic)).toEqual(session);

    const stop = s.wallet.run();
    try {
      // Prefixed and bare names both work, as a WalletConnect deployment sends them.
      await expect(shim.request<string[]>({ topic: session.topic, chainId: "chia:mainnet", request: { method: "chip0002_getPublicKeys", params: {} } })).resolves.toEqual(["0xabc"]);
      await expect(shim.request<string[]>({ topic: session.topic, request: { method: "getPublicKeys" } })).resolves.toEqual(["0xabc"]);
    } finally {
      stop();
    }
    expect(s.wallet.requests.map((r) => r.method)).toEqual(["getPublicKeys", "getPublicKeys"]);

    const deleted: string[] = [];
    shim.on("session_delete", (e) => deleted.push(e.topic));
    await shim.disconnect({ topic: session.topic, reason: { code: 6000, message: "user disconnected" } });
    expect(deleted).toEqual([session.topic]);
    expect(shim.session.getAll()).toEqual([]);
    shim.close();
  });

  it("reports the granted methods once the wallet declares them, not the request", async () => {
    const s = await setup();
    const { shim, session } = await connect(s);
    // Before any declaration the struct can only echo the proposal.
    expect(session.namespaces["chia"]?.methods).toEqual(CHIA_NS.methods);

    await s.wallet.declare(["getPublicKeys"], ["0xabc"], { perDayMojos: "5" });
    await s.client.sync();
    // Narrowed to the grant, with the alias prefix stripped (spec 9.1).
    expect(shim.session.get(session.topic).namespaces["chia"]?.methods).toEqual(["getPublicKeys"]);
    // Keys stay out of `accounts`: a public key is not a CAIP-10 account.
    expect(shim.session.get(session.topic).namespaces["chia"]?.accounts).toEqual([]);
    expect(s.client.permissions.keys).toEqual(["0xabc"]);
    shim.close();
    // After close() the shim stops following the client.
    await s.wallet.declare(["signCoinSpends"], []);
    await s.client.sync();
    expect(shim.session.get(session.topic).namespaces["chia"]?.methods).toEqual(["getPublicKeys"]);
  });

  it("a rejected SAS ends the pairing instead of activating it", async () => {
    const s = await setup();
    await expect(connect(s, async () => false)).rejects.toThrow(/different codes/);
    expect(s.client.status).not.toBe("active");
  });

  it("rejects proposals it cannot honour instead of silently narrowing them", async () => {
    const s = await setup();
    const shim = createSignClientShim({ client: s.client, confirmSas: async () => true });
    await expect(shim.connect({ requiredNamespaces: { eip155: { chains: ["eip155:1"], methods: [], events: [] } } })).rejects.toThrow(/Chia only/);
    await expect(shim.connect({ requiredNamespaces: { chia: { chains: ["chia:mainnet", "chia:testnet11"], methods: [], events: [] } } })).rejects.toThrow(/bound to one network/);
    await expect(shim.connect({ requiredNamespaces: { chia: { chains: ["chia:testnet11"], methods: [], events: [] } } })).rejects.toThrow(/bound to chia:mainnet/);
    await expect(shim.connect({ optionalNamespaces: { eip155: { methods: [], events: [] } } })).rejects.toThrow(/Chia only/);
    await expect(shim.connect({ pairingTopic: "a".repeat(64) })).rejects.toThrow(/single-use/);
    await expect(shim.connect({ relays: [{ protocol: "irn" }] })).rejects.toThrow(/relay on the XchonnectClient/);
    // None of those reached the relay.
    expect(s.relay.boxes.size).toBe(0);
  });

  it("refuses a request for another chain or an unknown topic", async () => {
    const s = await setup();
    const { shim, session } = await connect(s);
    await expect(shim.request({ topic: session.topic, chainId: "chia:testnet11", request: { method: "chainId" } })).rejects.toThrow(/bound to chia:mainnet/);
    await expect(shim.request({ topic: "b".repeat(64), request: { method: "chainId" } })).rejects.toThrow(/no matching key/);
    expect(() => shim.session.get("b".repeat(64))).toThrow(/no matching key/);
    await expect(shim.disconnect({ topic: "b".repeat(64) })).rejects.toThrow(/no matching key/);
    // The wallet never saw a request for the wrong chain.
    expect(s.wallet.requests).toEqual([]);
    shim.close();
  });

  it("surfaces wallet errors as CHIP-0002 error objects", async () => {
    const s = await setup({
      handle: () => {
        throw { code: 4002, message: "user rejected request" };
      },
    });
    const { shim, session } = await connect(s);
    const stop = s.wallet.run();
    try {
      await expect(shim.request({ topic: session.topic, request: { method: "signCoinSpends", params: { coinSpends: [] } } })).rejects.toMatchObject({ code: 4002, message: "user rejected request" });
    } finally {
      stop();
    }
    shim.close();
  });

  it("throws on every unsupported sign-client call and event rather than no-opping", async () => {
    const s = await setup();
    const shim = createSignClientShim({ client: s.client, confirmSas: async () => true });
    for (const name of ["ping", "extend", "update", "pair", "approve", "reject", "respond", "emit"] as const) {
      expect(() => shim[name]()).toThrow(/not supported by the Xchonnect sign-client shim/);
    }
    expect(() => shim.core).toThrow(/WalletConnect core/);
    for (const event of ["session_update", "session_event", "session_expire", "session_proposal", "session_request", "session_ping", "proposal_expire"]) {
      expect(() => shim.on(event as "session_delete", () => undefined)).toThrow(XchonnectError);
    }
    const cb = vi.fn();
    const off = shim.on("session_delete", cb);
    off();
    shim.off("session_delete", cb);
    expect(cb).not.toHaveBeenCalled();
  });

  it("restore() re-wraps a session the client loaded from storage, with a persisted topic", async () => {
    const s = await setup();
    const { shim, session } = await connect(s);
    shim.close();

    // Same storage, new client and new shim: what a page reload looks like.
    const reloaded = await devClient({ originPublicKey: core.devPublicKey(SEED), fetch: s.relay.fetch, storage: s.storage, pollIntervalMs: 2 });
    expect(reloaded.status).toBe("active");
    const fresh = createSignClientShim({ client: reloaded, confirmSas: async () => true, topic: session.topic });
    expect(fresh.session.getAll()).toEqual([]);
    const restored = fresh.restore({ requiredNamespaces: { chia: CHIA_NS }, walletName: "Test Wallet" }) as ShimSession;
    expect(restored.topic).toBe(session.topic);
    const stop = s.wallet.run();
    try {
      await expect(fresh.request<string[]>({ topic: session.topic, request: { method: "getPublicKeys" } })).resolves.toEqual(["0xabc"]);
    } finally {
      stop();
    }
    fresh.close();
    reloaded.close();
  });

  it("restore() returns undefined when there is no active session", async () => {
    const s = await setup();
    const shim = createSignClientShim({ client: s.client, confirmSas: async () => true });
    expect(shim.restore()).toBeUndefined();
    await expect(shim.request({ topic: "c".repeat(64), request: { method: "chainId" } })).rejects.toThrow(/no active session/);
  });

  it("runs side by side with another sign-client in one dApp (AC#4)", async () => {
    // Stand-in for a real @walletconnect/sign-client: same call shape, different session.
    const wcCalls: string[] = [];
    const walletConnect = {
      session: { getAll: () => [{ topic: "wc-topic" }] },
      request: async ({ request }: { topic: string; request: { method: string } }) => {
        wcCalls.push(request.method);
        return ["0xdef"];
      },
    };

    const s = await setup();
    const { shim, session } = await connect(s);

    // One dApp-level call site, two live transports, the same CHIP-0002 method.
    const route = async (transport: "xchonnect" | "walletconnect") =>
      transport === "xchonnect"
        ? shim.request<string[]>({ topic: session.topic, request: { method: "chip0002_getPublicKeys", params: {} } })
        : walletConnect.request({ topic: walletConnect.session.getAll()[0]!.topic, request: { method: "chip0002_getPublicKeys" } });

    const stop = s.wallet.run();
    try {
      expect(await route("xchonnect")).toEqual(["0xabc"]);
      expect(await route("walletconnect")).toEqual(["0xdef"]);
    } finally {
      stop();
    }
    // Neither transport disturbed the other: separate sessions, no globals touched.
    expect(wcCalls).toEqual(["chip0002_getPublicKeys"]);
    expect(s.wallet.requests.map((r) => r.method)).toEqual(["getPublicKeys"]);
    expect(shim.session.getAll()).toHaveLength(1);
    expect(walletConnect.session.getAll()).toHaveLength(1);
    expect((globalThis as { chia?: unknown }).chia).toBeUndefined();
    shim.close();
  });
});
