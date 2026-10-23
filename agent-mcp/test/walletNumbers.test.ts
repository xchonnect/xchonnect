/**
 * Security audit L3 (T22): amounts in the wallet's answers (rules, balances) are checked before
 * they reach `BigInt`, whose error would carry the wallet's text, unbounded, to the agent.
 */
import { describe, expect, it } from "vitest";
import { mojoText, WALLET_AMOUNT_ERROR } from "../src/amounts.js";
import { parseRules } from "../src/rules.js";
import { call, type Context } from "../src/tools.js";
import type { Wallet } from "../src/wallet.js";

const LONG = "x".repeat(10_000);

/** A context whose wallet answers every request with `result`. */
function answering(result: unknown): Context {
  const wallet = { request: async () => ({ result }) } as unknown as Wallet;
  return { wallet, maxFeeMojos: 0n, elicit: null, origin: null, offers: {} as Context["offers"], relay: "", keychain: "", openViewer: false };
}

const rules = (limit: Record<string, unknown>) => ({
  agent: { name: "agent" },
  paused: false,
  methods: ["chia_takeOffer"],
  limits: [{ assetId: "", used: "0", held: "0", remaining: "5", ...limit }],
});

describe("amounts from the wallet", () => {
  it("mojoText takes 1 to 40 digits or a safe whole number, nothing else", () => {
    expect(mojoText("0")).toBe(0n);
    expect(mojoText("9".repeat(40))).toBe(10n ** 40n - 1n);
    expect(mojoText(42)).toBe(42n);
    for (const bad of ["", "9".repeat(41), "-1", "1.5", " 1", "0x10", "1e3", LONG, -1, 1.5, 2 ** 60, null, undefined, {}]) {
      expect(() => mojoText(bad)).toThrow(WALLET_AMOUNT_ERROR);
    }
  });

  it("parseRules refuses a malformed limit amount with a fixed message", () => {
    for (const field of ["used", "held", "remaining", "perRequest", "perPeriod"]) {
      expect(() => parseRules(rules({ [field]: LONG }))).toThrow(WALLET_AMOUNT_ERROR);
    }
    expect(parseRules(rules({ perRequest: "1000", perPeriod: 5000 })).limits).toHaveLength(1);
  });

  it("get_rules and get_balances answer with a bounded, fixed error", async () => {
    const cases: [string, unknown][] = [
      ["get_rules", rules({ used: LONG })],
      ["get_balances", { spendable: LONG, confirmed: "1" }],
      ["get_balances", { spendable: "1", confirmed: `1${LONG}` }],
    ];
    for (const [tool, result] of cases) {
      const out = await call(answering(result), tool, {});
      expect(out?.["isError"]).toBe(true);
      expect(out?.["structuredContent"]).toEqual({ error: "internal", message: WALLET_AMOUNT_ERROR });
      expect(JSON.stringify(out).length).toBeLessThan(400);
      expect(JSON.stringify(out)).not.toContain("xxxx");
    }
  });

  it("well-formed balances still convert", async () => {
    const out = await call(answering({ spendable: "1500000000000", confirmed: 2000000000000, spendableCoinCount: LONG }), "get_balances", {});
    expect(out?.["structuredContent"]).toEqual({ balances: [{ asset: "xch", spendable: "1.5", confirmed: "2", spendable_coins: null }] });
  });
});
