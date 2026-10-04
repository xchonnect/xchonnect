import { describe, expect, it } from "vitest";
import { aggregateSignatures, pushSpendBundle } from "./index.js";
import "./testing/env.js";

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
  });
});
