import { describe, expect, it } from "vitest";
import { OhttpKeyError, OhttpTransport, pollDelayMs, type PrivacyEvent } from "./index.js";
import { devClient, RELAY } from "./testing/env.js";
import { MockRelay } from "./testing/mockRelay.js";

const OHTTP_RELAY = "https://ohttp.example/relay";
// One key configuration: id 1, X25519, HKDF-SHA256 + ChaCha20-Poly1305.
const KEYS = Buffer.from([0, 41, 1, 0, 0x20, ...new Uint8Array(32).fill(5), 0, 4, 0, 1, 0, 3]).toString("base64url");

/** Base fetch: the OHTTP relay answers with `ohttp`, everything else goes to the mock relay. */
function routes(relay: MockRelay, ohttp: () => Promise<Response>, seen: string[]): typeof fetch {
  return (input, init) => {
    const url = String(input);
    seen.push(url);
    return url === OHTTP_RELAY ? ohttp() : relay.fetch(input, init);
  };
}

/** Client over OHTTP whose base fetch routes as {@link routes}; records privacy events. */
async function client(ohttp: () => Promise<Response>, allowDirectFallback: boolean) {
  const relay = new MockRelay();
  const seen: string[] = [];
  const events: PrivacyEvent[] = [];
  const c = await devClient({ fetch: routes(relay, ohttp, seen), ohttp: { relayUrl: OHTTP_RELAY, keyConfig: KEYS, allowDirectFallback } });
  c.on("privacy", (e) => events.push(e));
  return { c, relay, seen, events };
}

/** Transport with fallback whose base fetch records URLs; the direct relay always answers 201. */
function fallbackTransport(ohttp: () => Promise<Response>) {
  const seen: string[] = [];
  const t = new OhttpTransport({ relayUrl: OHTTP_RELAY, keyConfig: KEYS, allowDirectFallback: true }, RELAY, async (input) => {
    seen.push(String(input));
    return String(input) === OHTTP_RELAY ? ohttp() : new Response("{}", { status: 201 });
  });
  return { t, seen, internals: t as unknown as { fallbackUntil: number; nextKeyCheck: number } };
}

describe("OHTTP transport", () => {
  it("polls every 2 s for 30 s after sending, then every 10 s, with ±20 % jitter (spec 10.1)", () => {
    const s = { fastMs: 2000, slowMs: 10_000, fastWindowMs: 30_000 };
    expect(pollDelayMs(0, s, () => 0.5)).toBe(2000);
    expect(pollDelayMs(29_999, s, () => 0)).toBe(1600);
    expect(pollDelayMs(29_999, s, () => 1)).toBe(2400);
    expect(pollDelayMs(30_000, s, () => 0.5)).toBe(10_000);
    expect(pollDelayMs(120_000, s, () => 0)).toBe(8000);
    expect(pollDelayMs(120_000, s, () => 1)).toBe(12_000);
    const samples = Array.from({ length: 200 }, () => pollDelayMs(0, s));
    expect(Math.min(...samples)).toBeGreaterThanOrEqual(1600);
    expect(Math.max(...samples)).toBeLessThanOrEqual(2400);
    expect(new Set(samples).size).toBeGreaterThan(10);
  });

  it("encapsulates relay requests for the configured OHTTP relay", async () => {
    let posted: RequestInit | undefined;
    const t = new OhttpTransport({ relayUrl: OHTTP_RELAY, keyConfig: KEYS }, RELAY, async (_input, init) => {
      posted = init;
      return new Response(null, { status: 502 });
    });
    expect(t.state).toBe("ohttp");
    expect(t.keyId).toBe(1);
    await expect(t.fetch(`${RELAY}/v1/info`)).rejects.toMatchObject({ code: "ohttp_failed" });
    expect(posted?.method).toBe("POST");
    expect(new Headers(posted?.headers).get("content-type")).toBe("message/ohttp-req");
    expect(posted?.credentials).toBe("omit");
    const body = posted?.body as Uint8Array;
    expect([...body.subarray(0, 7)]).toEqual([1, 0, 0x20, 0, 1, 0, 3]);
    // The relay URL must be https outside developer mode; the key config must be usable.
    expect(() => new OhttpTransport({ relayUrl: "http://ohttp.example/", keyConfig: KEYS }, RELAY, fetch)).toThrow(/https/);
    expect(() => new OhttpTransport({ relayUrl: OHTTP_RELAY, keyConfig: "AAAA" }, RELAY, fetch)).toThrow(/key configuration/);
  });

  it("OHTTP relay failure: fails closed by default and never contacts the relay directly", async () => {
    const { c, relay, seen, events } = await client(() => Promise.reject(new TypeError("network down")), false);
    await expect(c.pair()).rejects.toMatchObject({ code: "ohttp_failed" });
    expect(c.privacy).toBe("ohttp");
    expect(events).toEqual([]);
    expect(seen.length).toBeGreaterThan(0);
    expect(seen.every((u) => u === OHTTP_RELAY)).toBe(true);
    expect(relay.boxes.size).toBe(0);
  });

  it("OHTTP relay failure with opt-in fallback: goes direct and reports it", async () => {
    const { c, relay, seen, events } = await client(async () => new Response("bad gateway", { status: 502 }), true);
    const pairing = await c.pair();
    expect(pairing.uri).toMatch(/^xchonnect:v1\?/);
    expect(c.privacy).toBe("direct");
    expect(events).toEqual([{ state: "direct", reason: "ohttp-failed" }]);
    expect(relay.boxes.size).toBe(1);
    // During the cooldown requests go direct without retrying OHTTP first.
    const before = seen.filter((u) => u === OHTTP_RELAY).length;
    await c.relay.info();
    await c.pair().catch(() => undefined);
    expect(seen.filter((u) => u === OHTTP_RELAY).length).toBe(before);
  });

  it("with fallback, a non-GET the gateway may have executed is not re-sent directly", async () => {
    const { t, seen } = fallbackTransport(() => Promise.reject(new TypeError("network down")));
    // OHTTP relay unreachable: nothing left the client, so the POST may go direct.
    expect((await t.fetch(`${RELAY}/v1/mailboxes`, { method: "POST", body: "{}" })).status).toBe(201);
    expect(t.state).toBe("direct");
    expect(seen.filter((u) => u !== OHTTP_RELAY)).toHaveLength(1);
  });

  it("with fallback, an ambiguous OHTTP failure after sending a POST is surfaced, not repeated", async () => {
    const { t, seen, internals } = fallbackTransport(async () => new Response("timeout", { status: 504 }));
    // The first-use key check fails with 504 before the POST is sent, so the POST may
    // still fall back.
    expect((await t.fetch(`${RELAY}/v1/mailboxes`, { method: "POST", body: "{}" })).status).toBe(201);
    expect(seen).toHaveLength(2);
    seen.length = 0;
    // After the cooldown, with the key check done, a 504 for the POST itself is final.
    internals.fallbackUntil = 0;
    internals.nextKeyCheck = Infinity;
    await expect(t.fetch(`${RELAY}/v1/mailboxes/x/messages`, { method: "POST", body: "{}" })).rejects.toMatchObject({ code: "ohttp_failed" });
    expect(seen).toEqual([OHTTP_RELAY]);
    // A GET in the same situation may still fall back.
    internals.fallbackUntil = 0;
    expect((await t.fetch(`${RELAY}/v1/info`)).status).toBe(201);
  });

  it("with fallback, a POST whose connection drops after sending is not re-sent", async () => {
    const { t, seen, internals } = fallbackTransport(() => Promise.reject(new TypeError("connection reset")));
    internals.nextKeyCheck = Infinity;
    await expect(t.fetch(`${RELAY}/v1/mailboxes`, { method: "POST", body: "{}" })).rejects.toMatchObject({ code: "ohttp_failed" });
    expect(seen).toEqual([OHTTP_RELAY]);
  });

  it("a failed key check is retried after a short delay, not on every request", async () => {
    const { t, internals } = fallbackTransport(async () => new Response("down", { status: 502 }));
    const start = Date.now();
    await t.fetch(`${RELAY}/v1/info`);
    expect(internals.nextKeyCheck).toBeGreaterThan(start + 30_000);
    expect(internals.nextKeyCheck).toBeLessThanOrEqual(Date.now() + 60_000);
  });

  it("one caller aborting does not abort concurrent requests sharing the key check", async () => {
    let release: (r: Response) => void = () => undefined;
    const gate = new Promise<Response>((r) => (release = r));
    const t = new OhttpTransport({ relayUrl: OHTTP_RELAY, keyConfig: KEYS }, RELAY, (_input, init) =>
      new Promise<Response>((resolve, reject) => {
        init?.signal?.addEventListener("abort", () => reject(init.signal!.reason as Error), { once: true });
        void gate.then(resolve);
      }),
    );
    const ac = new AbortController();
    const a = t.fetch(`${RELAY}/v1/info`, { signal: ac.signal });
    const b = t.fetch(`${RELAY}/v1/info`);
    ac.abort(new DOMException("caller gave up", "AbortError"));
    await expect(a).rejects.toMatchObject({ name: "AbortError" });
    release(new Response(null, { status: 502 }));
    await expect(b).rejects.toMatchObject({ code: "ohttp_failed" });
  });

  it("a gateway key problem is a hard error, even with fallback", async () => {
    const problem = async () => new Response(JSON.stringify({ type: "https://iana.org/assignments/http-problem-types#ohttp-key" }), { status: 400, headers: { "content-type": "application/problem+json" } });
    const { c, seen, events } = await client(problem, true);
    await expect(c.pair()).rejects.toBeInstanceOf(OhttpKeyError);
    expect(c.privacy).toBe("ohttp");
    expect(events).toEqual([]);
    expect(seen.every((u) => u === OHTTP_RELAY)).toBe(true);
  });

  it("without OHTTP the client reports direct", async () => {
    expect((await devClient({ fetch: new MockRelay().fetch })).privacy).toBe("direct");
  });
});
