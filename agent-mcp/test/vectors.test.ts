/** The agent-rule vectors of spec 9.4 (`docs/spec/vectors/agent.json`) against the test wallet. */
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { parseRules } from "../src/rules.js";
import { check, describe as describeRules, type Effect, type Rules, type Usage } from "./agentWallet.js";

interface Case {
  name: string;
  now: number;
  rules: Rules;
  usage: { used: Record<string, string>; held: Record<string, string> };
  effect: { method: string; leaves: { asset: string; mojos: string }[]; arrives: { asset: string; mojos: string }[]; expiresAt?: number };
  expect: { allowed: true } | { code: number; reason: string };
}

const vectors = JSON.parse(readFileSync(new URL("../../docs/spec/vectors/agent.json", import.meta.url), "utf8")) as {
  refusalReasons: string[];
  getAgentRules: { result: unknown };
  cases: Case[];
};

const usage = (u: Case["usage"]): Usage => ({
  used: new Map(Object.entries(u.used).map(([k, v]) => [k, BigInt(v)])),
  held: new Map(Object.entries(u.held).map(([k, v]) => [k, BigInt(v)])),
});

const effect = (e: Case["effect"]): Effect => ({
  method: e.method,
  leaves: e.leaves.map((a) => ({ asset: a.asset, mojos: BigInt(a.mojos) })),
  arrives: e.arrives.map((a) => ({ asset: a.asset, mojos: BigInt(a.mojos) })),
  ...(e.expiresAt !== undefined ? { expiresAt: e.expiresAt } : {}),
});

describe("spec 9.4 vectors", () => {
  for (const c of vectors.cases) {
    it(c.name, () => {
      const refusal = check(c.rules, usage(c.usage), effect(c.effect), c.now);
      if ("allowed" in c.expect) expect(refusal).toBeNull();
      else expect({ code: refusal?.code, reason: refusal?.reason }).toEqual(c.expect);
    });
  }

  it("every refusal reason has a case, and the list is the plugin's", async () => {
    const { AGENT_REASONS } = await import("../src/rules.js");
    expect(vectors.refusalReasons).toEqual([...AGENT_REASONS]);
    for (const reason of AGENT_REASONS) {
      expect(vectors.cases.some((c) => "reason" in c.expect && c.expect.reason === reason)).toBe(true);
    }
  });

  it("the rules answer parses, and the test wallet writes the same shape", () => {
    const parsed = parseRules(vectors.getAgentRules.result);
    const tdbx = parsed.limits[1];
    expect(tdbx?.remaining).toBe("150000");
    const rules = { ...parsed, limits: parsed.limits.map(({ assetId, perRequest, period, perPeriod }) => ({ assetId, perRequest: String(perRequest), ...(period ? { period } : {}), perPeriod: String(perPeriod) })) } as Rules;
    const written = describeRules(rules, usage({ used: { [tdbx?.assetId as string]: "100000" }, held: { [tdbx?.assetId as string]: "50000" } }), tdbx?.resetsAt as number);
    expect(written).toEqual(vectors.getAgentRules.result);
  });
});
