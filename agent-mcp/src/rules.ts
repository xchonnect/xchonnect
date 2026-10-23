/**
 * Agent rules and refusals (spec 9.4): what the wallet lets this agent do, as the wallet says it,
 * and the closed list of reasons it refuses with. The rules are the wallet's to keep and enforce;
 * this module only reads them and names refusals, so the agent can tell the user why and plan a
 * trade that fits.
 */

import { mojoText } from "./amounts.js";

/** Spec 9.4: the only reasons a wallet gives for a request a rule forbids. */
export const AGENT_REASONS = [
  "paused",
  "expired",
  "outside_hours",
  "action_not_allowed",
  "asset_not_allowed",
  "price_out_of_band",
  "limit_per_trade",
  "limit_per_period",
] as const;
export type AgentReason = (typeof AGENT_REASONS)[number];

export function isAgentReason(value: unknown): value is AgentReason {
  return typeof value === "string" && (AGENT_REASONS as readonly string[]).includes(value);
}

/** What each reason tells the user, and what the agent can do about it. */
export const REASON_TEXT: Record<AgentReason, string> = {
  paused: "The user paused this agent in the wallet.",
  expired: "This agent's rules in the wallet have expired (or the offer would outlive them). The user can renew them in the wallet.",
  outside_hours: "The wallet only accepts this agent's requests during its active hours.",
  action_not_allowed: "The wallet does not allow this agent to do this.",
  asset_not_allowed: "The wallet does not allow this agent to trade this asset.",
  price_out_of_band: "The price is outside the band the user set for this pair.",
  limit_per_trade: "The amount is more than the wallet allows in one trade; a smaller trade may fit (see get_rules).",
  limit_per_period: "This would go past the amount the wallet allows per period, counting open offers; see get_rules for what is left and when it resets.",
};

export interface Limit {
  assetId: string;
  perRequest?: string | number;
  period?: "day" | "week";
  perPeriod?: string | number;
  used: string | number;
  held: string | number;
  remaining: string | number;
  resetsAt?: number;
}

export interface PriceBand {
  base: string;
  quote: string;
  min?: string;
  max?: string;
}

export interface AgentRules {
  agent: { name: string };
  paused: boolean;
  expiresAt?: number;
  methods: string[];
  assets?: string[];
  hours?: { timeZone: string; from: string; to: string };
  bands?: PriceBand[];
  limits: Limit[];
}

/** What a malformed time or period in the wallet's rules gives: fixed, never the wallet's text (T22). */
export const WALLET_TIME_ERROR = "the wallet answered with a time that is not a Unix time in seconds";
export const WALLET_PERIOD_ERROR = "the wallet answered with a limit period that is not day or week";

/** The latest Unix time a date can show: 9999-12-31T23:59:59Z. */
const MAX_UNIX_S = 253_402_300_799;

/** A Unix time from the wallet as an ISO date; anything but a whole number of seconds in range is refused. */
export function walletTime(v: unknown): string {
  if (typeof v === "number" && Number.isSafeInteger(v) && v >= 0 && v <= MAX_UNIX_S) return new Date(v * 1000).toISOString();
  throw new Error(WALLET_TIME_ERROR);
}

/** The rules as the wallet sent them, checked for shape (they come off the wire). */
export function parseRules(json: unknown): AgentRules {
  const r = json as Partial<AgentRules> | null;
  if (!r || typeof r !== "object") throw new Error("the wallet's rules are not an object");
  if (!r.agent || typeof r.agent.name !== "string") throw new Error("the wallet's rules have no agent name");
  if (typeof r.paused !== "boolean") throw new Error("the wallet's rules do not say whether the agent is paused");
  if (!Array.isArray(r.methods) || !r.methods.every((m) => typeof m === "string")) throw new Error("the wallet's rules have no method list");
  if (!Array.isArray(r.limits)) throw new Error("the wallet's rules have no limits list");
  // Fixed messages on a malformed field; the wallet's text is never repeated (T22).
  if (r.expiresAt !== undefined && r.expiresAt !== null) walletTime(r.expiresAt);
  for (const l of r.limits as Partial<Limit>[]) {
    if (!l || typeof l !== "object") throw new Error("the wallet's rules have a limit that is not an object");
    for (const v of [l.used, l.held, l.remaining]) mojoText(v);
    for (const v of [l.perRequest, l.perPeriod]) if (v !== undefined) mojoText(v);
    if (l.period !== undefined && l.period !== null && l.period !== "day" && l.period !== "week") throw new Error(WALLET_PERIOD_ERROR);
    if (l.resetsAt !== undefined && l.resetsAt !== null) walletTime(l.resetsAt);
  }
  return r as AgentRules;
}
