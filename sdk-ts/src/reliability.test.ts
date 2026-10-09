/**
 * Phones freeze a hidden page with its fetches in flight and suspend the wallet app; IndexedDB
 * connections die with the page. These tests pin the behaviour that keeps a session working
 * through that: deadlines, restarts on resume, expiry on its own timer, no ack on a storage
 * failure, close() stopping the poll, and the polls that keep `session.permissions` and
 * `session.end` flowing with nothing pending.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import * as core from "../wasm/xchonnect.js";
import { IndexedDbSessionStore, MemorySessionStore, RelayClient, RelayError, XchonnectRpcError, type ClientOptions, type EndedEvent } from "./index.js";
import { devClient, RELAY, SEED } from "./testing/env.js";
import { FakeWallet } from "./testing/fakeWallet.js";
import { MockRelay } from "./testing/mockRelay.js";

const originDocument = JSON.stringify({ v: 1, name: "Pengui", origin_keys: [{ kid: "k1", pk: core.devPublicKey(SEED), not_after: "2030-01-01" }] });
const never = <T>() => new Promise<T>(() => undefined);
const delay = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function waitFor(ok: () => boolean, ms = 3000): Promise<void> {
  const end = Date.now() + ms;
  while (!ok()) {
    if (Date.now() > end) throw new Error("timed out");
    await delay(5);
  }
}

/** A store whose writes fail while `failing` is set (a dead IndexedDB connection). */
class FlakyStore extends MemorySessionStore {
  failing = false;
  override async save(key: string, state: string): Promise<void> {
    if (this.failing) throw new DOMException("Connection to Indexed Database server lost", "UnknownError");
    return super.save(key, state);
  }
}

/**
 * A paired client. `hang()` makes the next long poll on the session mailbox a fetch that
 * never settles and ignores its signal, as a frozen page's fetch does.
 */
async function paired(opts: Partial<ClientOptions> = {}, storage = new MemorySessionStore()) {
  const relay = new MockRelay();
  let hangNext = false;
  let gets = 0;
  const fetch: typeof globalThis.fetch = (input, init) => {
    const url = String(input);
    if ((init?.method ?? "GET") === "GET" && url.includes("/messages")) {
      gets++;
      if (hangNext) {
        hangNext = false;
        return never();
      }
    }
    return relay.fetch(input, init);
  };
  const client = await devClient({ originPublicKey: core.devPublicKey(SEED), fetch, storage, pollIntervalMs: 2, ...opts });
  const wallet = new FakeWallet({ relay: new RelayClient(RELAY, { fetch: relay.fetch }), originDocument, handle: () => '"ok"' });
  const pairing = await client.pair();
  await wallet.scan(pairing.uri);
  await pairing.waitForWallet();
  await wallet.confirm();
  await pairing.confirm();
  const queued = () => [...relay.boxes.values()].reduce((n, b) => n + b.messages.length, 0);
  return {
    relay,
    client,
    wallet,
    storage,
    queued,
    gets: () => gets,
    hang: () => {
      hangNext = true;
    },
  };
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("relay call deadlines", () => {
  it("a fetch that never settles fails at the deadline instead of hanging", async () => {
    const relay = new RelayClient(RELAY, { fetch: () => never(), timeoutMs: 30, longPollGraceMs: 30 });
    const t0 = Date.now();
    await expect(relay.fetchMessages("m", "t", 0)).rejects.toMatchObject({ code: "timeout", status: 0 });
    await expect(relay.ack("m", "t", ["x"])).rejects.toBeInstanceOf(RelayError);
    expect(Date.now() - t0).toBeLessThan(1000);
  });

  it("a long poll gets its wait plus the grace", async () => {
    const relay = new RelayClient(RELAY, { fetch: () => never(), timeoutMs: 10, longPollGraceMs: 50 });
    const t0 = Date.now();
    await expect(relay.fetchMessages("m", "t", 1)).rejects.toMatchObject({ code: "timeout" });
    expect(Date.now() - t0).toBeGreaterThanOrEqual(1000);
  });

  it("the caller's signal still ends a call", async () => {
    const relay = new RelayClient(RELAY, { fetch: () => never() });
    const ac = new AbortController();
    const p = relay.fetchMessages("m", "t", 0, ac.signal);
    ac.abort(new Error("stop"));
    await expect(p).rejects.toThrow("stop");
  });
});

describe("polling through freezes", () => {
  it("a frozen long poll does not stop polling: the deadline ends it and the answer arrives", async () => {
    const s = await paired({ timeouts: { longPollGraceMs: 50 } });
    s.hang();
    const p = s.client.request("chainId");
    await delay(20);
    await s.wallet.step();
    expect(await p).toBe("ok");
    s.client.close();
  });

  it("resume() aborts a hung poll and polls again at once", async () => {
    const s = await paired({ timeouts: { requestMs: 60_000, longPollGraceMs: 60_000 } });
    s.hang();
    const p = s.client.request("chainId");
    await delay(20);
    await s.wallet.step();
    await delay(50);
    // Still stuck on the frozen poll: the answer waits on the relay.
    expect(s.queued()).toBe(1);
    s.client.resume();
    expect(await p).toBe("ok");
    s.client.close();
  });

  it("pageshow and visibilitychange restart polling in a browser", async () => {
    const doc = Object.assign(new EventTarget(), { visibilityState: "visible" });
    const win = new EventTarget();
    vi.stubGlobal("document", doc);
    vi.stubGlobal("window", win);
    const s = await paired({ timeouts: { requestMs: 60_000, longPollGraceMs: 60_000 } });
    s.hang();
    const p = s.client.request("chainId");
    await delay(20);
    await s.wallet.step();
    await delay(50);
    expect(s.queued()).toBe(1);
    win.dispatchEvent(new Event("pageshow"));
    expect(await p).toBe("ok");
    s.client.close();
  });

  it("requests expire on time even while the poll is stuck", async () => {
    const s = await paired({ timeouts: { requestMs: 60_000, longPollGraceMs: 60_000 } });
    s.hang();
    const err = await s.client.request("chainId", {}, { ttlSeconds: 1 }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(XchonnectRpcError);
    expect((err as XchonnectRpcError).code).toBe(4100);
    s.client.close();
  }, 10_000);
});

describe("storage failures", () => {
  it("a message that cannot be persisted stays on the relay and is read on a later pass", async () => {
    const store = new FlakyStore();
    const s = await paired({}, store);
    const p = s.client.request("chainId");
    await delay(10);
    store.failing = true;
    await s.wallet.step();
    await delay(100);
    // Several passes failed to persist; none acknowledged the answer.
    expect(s.queued()).toBe(1);
    store.failing = false;
    expect(await p).toBe("ok");
    expect(s.queued()).toBe(0);
    s.client.close();
  });

  it("IndexedDB: a lost connection is opened again", async () => {
    const fake = fakeIndexedDb();
    vi.stubGlobal("indexedDB", fake);
    const store = new IndexedDbSessionStore();
    await store.save("k", "state");
    fake.loseConnection("UnknownError");
    expect(await store.load("k")).toBe("state");
    fake.closeConnection();
    await store.save("k", "state2");
    expect(await store.load("k")).toBe("state2");
    expect(fake.opens).toBe(3);
  });
});

describe("close()", () => {
  it("stops the poll in flight: what it would have fetched stays for the next client", async () => {
    const s = await paired({ timeouts: { requestMs: 60_000, longPollGraceMs: 60_000 } });
    s.hang();
    const p = s.client.request("chainId").catch((e: unknown) => e);
    await delay(20);
    s.client.close();
    expect(await p).toMatchObject({ code: "closed" });
    const before = s.gets();
    await s.wallet.step();
    await delay(100);
    expect(s.gets()).toBe(before);
    expect(s.queued()).toBe(1);
    await expect(s.client.request("chainId")).rejects.toMatchObject({ code: "closed" });
  });
});

describe("polling with nothing pending", () => {
  it("reads the wallet's session.permissions posted right after session.ready", async () => {
    const s = await paired();
    await s.wallet.declare(["chip0002_getPublicKeys"], ["0xaa"]);
    await waitFor(() => s.client.permissions.declared);
    expect(s.client.canRequest("getPublicKeys")).toBe(true);
    s.client.close();
  });

  it("keep-alive: a wallet's session.end arrives without a request", async () => {
    const s = await paired({ keepAlive: true });
    const ended: EndedEvent[] = [];
    s.client.on("ended", (e) => ended.push(e));
    await s.wallet.end("user disconnected");
    await waitFor(() => s.client.status === "ended");
    expect(ended).toEqual([{ by: "wallet", reason: "user disconnected" }]);
    s.client.close();
  });

  it("keep-alive is off by default outside browsers", async () => {
    const s = await paired();
    await delay(50);
    const before = s.gets();
    // The short after-ready window ends once permissions arrive (or after 10 s).
    await s.wallet.declare([], []);
    await waitFor(() => s.client.permissions.declared);
    await delay(50);
    const settled = s.gets();
    await delay(100);
    expect(s.gets()).toBe(settled);
    expect(settled).toBeGreaterThan(before);
    s.client.close();
  });
});

describe("review fixes", () => {
  /** A relay that offers long polls (max_wait_s 25) but answers every poll at once. */
  function eagerRelay(relay: MockRelay, junk: () => boolean, status?: () => number | undefined) {
    let gets = 0;
    const fetch: typeof globalThis.fetch = async (input, init) => {
      const url = String(input);
      if (url.endsWith("/v1/info")) {
        const res = await relay.fetch(input, init);
        const info = (await res.json()) as Record<string, unknown>;
        return new Response(JSON.stringify({ ...info, max_wait_s: 25 }), { status: 200 });
      }
      if ((init?.method ?? "GET") === "GET" && url.includes("/messages")) {
        gets++;
        const st = status?.();
        if (st !== undefined) return new Response('{"error":"rate_limited"}', { status: st, headers: { "retry-after": "1000000000000" } });
        // Junk the relay keeps returning because it ignores the acks.
        if (junk()) return new Response(JSON.stringify({ messages: [{ msg_id: "junk", env: "AAAA" }] }), { status: 200 });
      }
      return relay.fetch(input, init);
    };
    return { fetch, gets: () => gets };
  }

  async function pairedWith(fetch: typeof globalThis.fetch, relay: MockRelay, opts: Partial<ClientOptions> = {}) {
    const storage = new MemorySessionStore();
    const client = await devClient({ originPublicKey: core.devPublicKey(SEED), fetch, storage, poll: { fastMs: 50, slowMs: 50 }, ...opts });
    const wallet = new FakeWallet({ relay: new RelayClient(RELAY, { fetch: relay.fetch }), originDocument, handle: () => '"ok"' });
    const pairing = await client.pair();
    await wallet.scan(pairing.uri);
    await pairing.waitForWallet();
    await wallet.confirm();
    await pairing.confirm();
    await wallet.declare([], []); // ends the after-ready window
    await waitFor(() => client.permissions.declared);
    return { client, wallet, storage };
  }

  it("a relay that keeps returning junk at once does not make the loop spin", async () => {
    const relay = new MockRelay();
    let junk = false;
    const r = eagerRelay(relay, () => junk);
    const { client } = await pairedWith(r.fetch, relay, { keepAlive: true });
    junk = true;
    const before = r.gets();
    await delay(300);
    // About one poll per 50 ms pause; a spinning loop makes thousands.
    expect(r.gets() - before).toBeLessThan(15);
    client.close();
  });

  it("an empty long poll answered at once does not make the loop spin either", async () => {
    const relay = new MockRelay();
    const r = eagerRelay(relay, () => false);
    const { client } = await pairedWith(r.fetch, relay, { keepAlive: true });
    const before = r.gets();
    await delay(300);
    expect(r.gets() - before).toBeLessThan(15);
    client.close();
  });

  it("a huge Retry-After is clamped, not an overflowing timer", async () => {
    const relay = new MockRelay();
    let limited = false;
    const r = eagerRelay(relay, () => false, () => (limited ? 429 : undefined));
    const { client } = await pairedWith(r.fetch, relay, { keepAlive: true });
    limited = true;
    await delay(100);
    const before = r.gets();
    await delay(300);
    // Waiting (at most 300 s), not firing at once over and over.
    expect(r.gets() - before).toBeLessThanOrEqual(1);
    client.close();
  });

  it("forged or malformed messages on the tab channel are ignored", async () => {
    const s = await paired({ storageKey: "chan" });
    const ids: string[] = [];
    s.client.on("delivery", (e) => ids.push(e.id));
    const p = s.client.request("chainId");
    await waitFor(() => ids.length > 0);
    const id = ids[0]!;
    const ch = new BroadcastChannel("xchonnect:chan");
    ch.postMessage({ type: "rpc.response", requestId: id, result: '"forged"' }); // untagged
    ch.postMessage({ tag: "not-this-session", m: { type: "rpc.response", requestId: id, result: '"forged"' } });
    ch.postMessage({ tag: "x", m: { type: "rpc.response", requestId: id, result: 42 } });
    await delay(100);
    ch.close();
    await s.wallet.step();
    expect(await p).toBe("ok");
    s.client.close();
  });

  it("a session another tab ended is not brought back from memory", async () => {
    const s = await paired();
    const other = await devClient({ fetch: s.relay.fetch, storage: s.storage, storageKey: "default", pollIntervalMs: 2 });
    await other.end();
    expect(await s.storage.load("default")).toBeNull();
    await expect(s.client.request("chainId")).rejects.toMatchObject({ code: "no_session" });
    await waitFor(() => s.client.status === "ended");
    expect(await s.storage.load("default")).toBeNull();
    s.client.close();
    other.close();
  });
});

/** Just enough IndexedDB for {@link IndexedDbSessionStore}, with a connection that can die. */
function fakeIndexedDb() {
  const data = new Map<string, unknown>();
  const later = <T>(result: T) => {
    const r = { result, onsuccess: null as null | (() => void), onerror: null as null | (() => void), error: null };
    setTimeout(() => r.onsuccess?.(), 0);
    return r;
  };
  let current: { onclose: null | (() => void); dead: string | undefined } | undefined;
  const fake = {
    opens: 0,
    open() {
      fake.opens++;
      const conn = {
        dead: undefined as string | undefined,
        onclose: null as null | (() => void),
        onversionchange: null as null | (() => void),
        close() {},
        transaction() {
          if (conn.dead) throw new DOMException("Connection to Indexed Database server lost. Refresh the page to try again", conn.dead);
          return {
            objectStore: () => ({
              get: (k: string) => later(data.get(k)),
              put: (v: unknown, k: string) => (data.set(k, v), later(k)),
              delete: (k: string) => (data.delete(k), later(undefined)),
            }),
          };
        },
      };
      current = conn;
      const r = { result: conn, onsuccess: null as null | (() => void), onerror: null, onupgradeneeded: null };
      setTimeout(() => r.onsuccess?.(), 0);
      return r;
    },
    /** The connection dies without telling (iOS after a suspension). */
    loseConnection(name: string) {
      if (current) current.dead = name;
    },
    /** The browser closes the connection and says so. */
    closeConnection() {
      if (!current) return;
      current.dead = "InvalidStateError";
      current.onclose?.();
    },
  };
  return fake;
}
