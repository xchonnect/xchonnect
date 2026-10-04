import { describe, expect, it } from "vitest";
import { aggregateSignatures, OhttpKeyError, type PrivacyEvent, pushSpendBundle } from "./index.js";
import "./testing/env.js";

const OHTTP_RELAY = "https://ohttp.example/relay";
const NODE = "https://node.example";
// The node operator's gateway key configuration: id 1, X25519, HKDF-SHA256 + ChaCha20.
const NODE_KEYS = Buffer.from([0, 41, 1, 0, 0x20, ...new Uint8Array(32).fill(7), 0, 4, 0, 1, 0, 3]).toString("base64url");
const KEY_PROBLEM = { type: "https://iana.org/assignments/http-problem-types#ohttp-key" };

// Aggregation of real signatures is checked against chia-bls in bindings/wasm
// (aggregate_tests); here: identity, encoding and error handling through the WASM API.
const INFINITY = "0xc0" + "00".repeat(95);

describe("multi-party helpers", () => {
  it("aggregates signatures and validates points", () => {
    expect(aggregateSignatures([])).toBe(INFINITY);
    expect(aggregateSignatures([INFINITY, INFINITY.slice(2)])).toBe(INFINITY);
    expect(() => aggregateSignatures(["00".repeat(96)])).toThrow(/invalid signature point/);
    expect(() => aggregateSignatures(["zz"])).toThrow(/hex/);
  });

  it("pushes to several nodes and succeeds if any accepts", async () => {
    const calls: string[] = [];
    const fake: typeof fetch = async (input) => {
      calls.push(String(input));
      return String(input).startsWith("https://a.example")
        ? new Response(JSON.stringify({ success: true }), { status: 200 })
        : new Response(JSON.stringify({ success: false, error: "mempool full" }), { status: 200 });
    };
    const r = await pushSpendBundle([], INFINITY, ["https://a.example/", "https://b.example"], fake);
    expect(calls).toEqual(["https://a.example/push_tx", "https://b.example/push_tx"]);
    expect(r.accepted).toEqual(["https://a.example/"]);
    expect(r.failed).toEqual([{ node: "https://b.example", error: "mempool full" }]);
    const down: typeof fetch = async () => new Response("", { status: 503 });
    await expect(pushSpendBundle([], INFINITY, ["https://x.example"], down)).rejects.toThrow(/no node accepted/);
    await expect(pushSpendBundle([], INFINITY, [], down)).rejects.toThrow(/at least one/);
    // A node given as a plain URL has no gateway: the node sees the submitter's IP.
    expect(r.transport).toEqual([
      { node: "https://a.example/", state: "direct" },
      { node: "https://b.example", state: "direct" },
    ]);
  });

  // Spec 10.6: node requests go through the node operator's OHTTP gateway, reached through
  // the independent OHTTP relay — never through the Xchonnect relay.
  it("sends a node request through OHTTP and never contacts the node directly", async () => {
    const seen: string[] = [];
    const posted: RequestInit[] = [];
    const base: typeof fetch = async (input, init) => {
      seen.push(String(input));
      if (String(input) !== OHTTP_RELAY) throw new Error("the node must not be contacted directly");
      posted.push(init ?? {});
      // Enough to make the first-use key check fail without falling back further.
      return new Response("gateway down", { status: 502 });
    };
    const nodes = [{ url: NODE, ohttp: { relayUrl: OHTTP_RELAY, keyConfig: NODE_KEYS } }];
    await expect(pushSpendBundle([], INFINITY, nodes, base)).rejects.toThrow(/no node accepted/);
    expect(seen).toEqual([OHTTP_RELAY]);
    expect(new Headers(posted[0]?.headers).get("content-type")).toBe("message/ohttp-req");
    // RFC 9458 header for the pinned key, then the padded body (spec 10.5: 2 KiB floor).
    const body = posted[0]?.body as Uint8Array;
    expect([...body.subarray(0, 7)]).toEqual([1, 0, 0x20, 0, 1, 0, 3]);
    expect(body.length).toBe(2048 + 7 + 32 + 16);
  });

  it("reports the transport per node and falls back only when allowed", async () => {
    const events: (PrivacyEvent & { node: string })[] = [];
    const accepted = () => new Response(JSON.stringify({ success: true }), { status: 200 });
    const base: typeof fetch = async (input) => (String(input) === OHTTP_RELAY ? new Response("down", { status: 502 }) : accepted());
    const strict = { url: NODE, ohttp: { relayUrl: OHTTP_RELAY, keyConfig: NODE_KEYS } };
    const lenient = { url: NODE, ohttp: { ...strict.ohttp, allowDirectFallback: true } };

    // Without opt-in the submission fails rather than revealing the IP to the node.
    const r = await pushSpendBundle([], INFINITY, [strict, "https://plain.example"], { fetch: base, onPrivacy: (e) => events.push(e) });
    expect(r.accepted).toEqual(["https://plain.example"]);
    expect(r.failed).toEqual([{ node: NODE, error: "OHTTP relay answered 502" }]);
    expect(r.transport).toEqual([
      { node: NODE, state: "ohttp" },
      { node: "https://plain.example", state: "direct" },
    ]);
    expect(events).toEqual([]);

    // With opt-in it goes direct and says so, per node.
    const f = await pushSpendBundle([], INFINITY, [lenient], { fetch: base, onPrivacy: (e) => events.push(e) });
    expect(f.accepted).toEqual([NODE]);
    expect(f.transport).toEqual([{ node: NODE, state: "direct" }]);
    expect(events).toEqual([{ node: NODE, state: "direct", reason: "ohttp-failed" }]);
  });

  it("a node gateway key mismatch is a hard error, even with fallback", async () => {
    const problem = new Response(JSON.stringify(KEY_PROBLEM), { status: 400, headers: { "content-type": "application/problem+json" } });
    const base: typeof fetch = async (input) => {
      if (String(input) === OHTTP_RELAY) return problem.clone();
      throw new Error("the node must not be contacted directly");
    };
    const nodes = [{ url: NODE, ohttp: { relayUrl: OHTTP_RELAY, keyConfig: NODE_KEYS, allowDirectFallback: true } }];
    const e = await pushSpendBundle([], INFINITY, nodes, base).catch((x: unknown) => x);
    expect(e).toBeInstanceOf(Error);
    expect(String(e)).toMatch(/no node accepted/);
    const out = await pushSpendBundle([], INFINITY, [...nodes, "https://plain.example"], {
      fetch: async (input, init) => (String(input) === OHTTP_RELAY ? problem.clone() : new Response(JSON.stringify({ success: true }), { status: 200, ...init })),
    });
    expect(out.failed[0]?.error).toMatch(/no longer accepts the pinned OHTTP key/);
    expect(out.transport[0]).toEqual({ node: NODE, state: "ohttp" });
    expect(new OhttpKeyError("x").code).toBe("ohttp_key_mismatch");
  });
});
