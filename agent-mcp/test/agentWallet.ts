/**
 * A test wallet for agents: the SDK's FakeWallet (the real protocol, no keys) with the agent
 * rules of spec 9.4 in front of it. It is the reference the vectors (`docs/spec/vectors/agent.json`)
 * are checked against, and the wallet the end-to-end test and the Claude Code demo pair with.
 * It holds no keys and builds no spend: offers it "makes" are placeholders, takes are recorded.
 * Never a wallet for funds.
 */
import { FakeWallet } from "./sdk.js";
import type { RelayClient } from "./sdk.js";

export type Asset = string; // "xch" or hex

export interface Limit {
  assetId: Asset;
  perRequest?: string;
  period?: "day" | "week";
  perPeriod?: string;
}

export interface Rules {
  agent: { name: string };
  paused: boolean;
  expiresAt?: number;
  methods: string[];
  assets?: Asset[];
  hours?: { timeZone: string; from: string; to: string };
  bands?: { base: Asset; quote: Asset; min?: string; max?: string }[];
  limits: Limit[];
}

export interface AssetAmount {
  asset: Asset;
  mojos: bigint;
}

/** What a request moves, as the wallet decoded it: what leaves the user, what arrives. */
export interface Effect {
  method: string;
  leaves: AssetAmount[];
  arrives: AssetAmount[];
  expiresAt?: number;
}

export interface Usage {
  /** Spent per asset in the current period. */
  used: Map<Asset, bigint>;
  /** Held by open offers per asset. */
  held: Map<Asset, bigint>;
}

export type Refusal = { code: 4001 | 4029; reason: string; rule?: unknown };

const DECIMALS = (a: Asset) => (a === "xch" ? 12 : 3);

/** Price of a pair in quote units per base unit, from an effect with one asset each way. */
function price(effect: Effect, base: Asset, quote: Asset): number | undefined {
  const all = [...effect.leaves, ...effect.arrives];
  const b = all.find((x) => x.asset === base);
  const q = all.find((x) => x.asset === quote);
  if (!b || !q || effect.leaves.length !== 1 || effect.arrives.length !== 1) return undefined;
  return Number(q.mojos) / 10 ** DECIMALS(quote) / (Number(b.mojos) / 10 ** DECIMALS(base));
}

function minutesOf(hhmm: string): number {
  const [h, m] = hhmm.split(":").map(Number);
  return (h ?? 0) * 60 + (m ?? 0);
}

function localMinutes(now: number, timeZone: string): number {
  const parts = new Intl.DateTimeFormat("en-GB", { timeZone, hour: "2-digit", minute: "2-digit", hourCycle: "h23" }).formatToParts(new Date(now * 1000));
  const h = Number(parts.find((p) => p.type === "hour")?.value ?? 0);
  const m = Number(parts.find((p) => p.type === "minute")?.value ?? 0);
  return h * 60 + m;
}

/** Spec 9.4: the first rule a request breaks, in the order of the table, or null. */
export function check(rules: Rules, usage: Usage, effect: Effect, now: number): Refusal | null {
  if (rules.paused) return { code: 4001, reason: "paused" };
  if (rules.expiresAt !== undefined && now >= rules.expiresAt) return { code: 4001, reason: "expired" };
  if (rules.expiresAt !== undefined && effect.expiresAt !== undefined && effect.expiresAt > rules.expiresAt) return { code: 4001, reason: "expired" };
  if (rules.hours) {
    const at = localMinutes(now, rules.hours.timeZone);
    const from = minutesOf(rules.hours.from);
    const to = minutesOf(rules.hours.to);
    const inside = from <= to ? at >= from && at < to : at >= from || at < to;
    if (!inside) return { code: 4001, reason: "outside_hours" };
  }
  if (!rules.methods.includes(effect.method)) return { code: 4001, reason: "action_not_allowed" };
  if (rules.assets) {
    for (const a of [...effect.leaves, ...effect.arrives]) {
      if (!rules.assets.includes(a.asset)) return { code: 4001, reason: "asset_not_allowed" };
    }
  }
  for (const band of rules.bands ?? []) {
    const p = price(effect, band.base, band.quote);
    if (p === undefined) continue;
    if ((band.min !== undefined && p < Number(band.min)) || (band.max !== undefined && p > Number(band.max))) {
      return { code: 4001, reason: "price_out_of_band", rule: band };
    }
  }
  for (const out of effect.leaves) {
    const limit = rules.limits.find((l) => l.assetId === out.asset);
    if (!limit) continue;
    if (limit.perRequest !== undefined && out.mojos > BigInt(limit.perRequest)) return { code: 4029, reason: "limit_per_trade", rule: limit };
    if (limit.perPeriod !== undefined) {
      const total = (usage.used.get(out.asset) ?? 0n) + (usage.held.get(out.asset) ?? 0n) + out.mojos;
      if (total > BigInt(limit.perPeriod)) return { code: 4029, reason: "limit_per_period", rule: limit };
    }
  }
  return null;
}

/** `xchonnect_getAgentRules`'s answer for `rules` and `usage`. */
export function describe(rules: Rules, usage: Usage, periodEndsAt: number): unknown {
  return {
    ...rules,
    limits: rules.limits.map((l) => {
      const used = usage.used.get(l.assetId) ?? 0n;
      const held = usage.held.get(l.assetId) ?? 0n;
      const cap = l.perPeriod !== undefined ? BigInt(l.perPeriod) : l.perRequest !== undefined ? BigInt(l.perRequest) : 0n;
      const left = l.perPeriod !== undefined ? cap - used - held : cap;
      return {
        ...l,
        used: used.toString(),
        held: held.toString(),
        remaining: (left > 0n ? left : 0n).toString(),
        ...(l.period ? { resetsAt: periodEndsAt } : {}),
      };
    }),
  };
}

class RpcError extends Error {
  constructor(
    readonly code: number,
    message: string,
    readonly data?: string,
  ) {
    super(message);
  }
}

function mojosOf(v: unknown): bigint {
  if (typeof v === "number" || (typeof v === "string" && /^\d+$/.test(v))) return BigInt(v);
  throw new RpcError(4000, "an amount is not a whole number of mojos");
}

function assetOf(sage: unknown): Asset {
  if (sage === "" || sage === null || sage === undefined) return "xch";
  if (typeof sage === "string" && /^(0x)?[0-9a-fA-F]{64}$/.test(sage)) return sage.replace(/^0x/, "").toLowerCase();
  throw new RpcError(4000, "an asset id is not valid");
}

export interface AgentWalletOptions {
  relay: RelayClient | string;
  originDocument: string;
  rules: Rules;
  balances?: Record<Asset, bigint>;
  /** Decodes an offer to take: what the maker gives and asks. */
  decodeOffer?: (offer: string) => Promise<{ offered: AssetAmount[]; requested: AssetAmount[] } | null>;
  now?: () => number;
  network?: string;
}

/**
 * The wallet: `pair(uri)` scans and confirms, then it answers in the background. Requests are
 * answered synchronously (FakeWallet's `handle`), so an offer to take must have been decoded
 * before: `prepareTake(offer)` does that for the e2e, `decodeOffer` for the demo (async, so the
 * take is refused 4101 until the decode is cached; the demo decodes on the first try and the
 * agent's retry goes through).
 */
export class AgentWallet {
  readonly fake: FakeWallet;
  readonly usage: Usage = { used: new Map(), held: new Map() };
  readonly offers = new Map<string, { leaves: AssetAmount[]; open: boolean }>();
  readonly taken: string[] = [];
  readonly decoded = new Map<string, { offered: AssetAmount[]; requested: AssetAmount[] }>();
  private stop: (() => void) | undefined;
  private counter = 0;
  private readonly now: () => number;

  constructor(private readonly o: AgentWalletOptions) {
    this.now = o.now ?? (() => Math.floor(Date.now() / 1000));
    this.fake = new FakeWallet({
      relay: o.relay,
      originDocument: o.originDocument,
      name: "Test wallet (agent rules)",
      receipts: true,
      handle: (method, params) => this.answer(method, params),
      now: this.now,
    });
  }

  async pair(uri: string): Promise<string> {
    await this.fake.scan(uri);
    return this.fake.sas as string;
  }

  async confirm(): Promise<void> {
    await this.fake.confirm(true);
    await this.fake.declare(["xchonnect_getAgentRules", "getAssetBalance", "chia_takeOffer", "chia_createOffer", "chia_cancelOffer"], []);
    this.stop = this.fake.run();
  }

  async prepareTake(offer: string): Promise<void> {
    const d = await this.o.decodeOffer?.(offer);
    if (d) this.decoded.set(offer, d);
  }

  close(): void {
    this.stop?.();
  }

  private refuse(effect: Effect): void {
    const refusal = check(this.o.rules, this.usage, effect, this.now());
    if (refusal) throw new RpcError(refusal.code, `refused by the agent rules: ${refusal.reason}`, JSON.stringify({ reason: refusal.reason, ...(refusal.rule ? { rule: refusal.rule } : {}) }));
  }

  private answer(method: string, paramsJson: string): string {
    try {
      const params = JSON.parse(paramsJson || "{}") as Record<string, unknown>;
      switch (method) {
        case "chainId":
          return JSON.stringify(this.o.network ?? "testnet11");
        case "xchonnect_getAgentRules":
          return JSON.stringify(describe(this.o.rules, this.usage, this.now() + 86_400));
        case "getAssetBalance": {
          const asset = params["assetId"] ? assetOf(params["assetId"]) : "xch";
          const b = this.o.balances?.[asset] ?? 0n;
          return JSON.stringify({ confirmed: b.toString(), spendable: b.toString(), spendableCoinCount: b > 0n ? 1 : 0 });
        }
        case "chia_createOffer": {
          const give = (params["offerAssets"] as { assetId: unknown; amount: unknown }[]).map((a) => ({ asset: assetOf(a.assetId), mojos: mojosOf(a.amount) }));
          const take = (params["requestAssets"] as { assetId: unknown; amount: unknown }[]).map((a) => ({ asset: assetOf(a.assetId), mojos: mojosOf(a.amount) }));
          const expiresAt = typeof params["expiresAt"] === "number" ? params["expiresAt"] : undefined;
          this.refuse({ method, leaves: give, arrives: take, ...(expiresAt !== undefined ? { expiresAt } : {}) });
          const id = `test-offer-${++this.counter}`;
          for (const g of give) this.usage.held.set(g.asset, (this.usage.held.get(g.asset) ?? 0n) + g.mojos);
          this.offers.set(id, { leaves: give, open: true });
          return JSON.stringify({ id, offer: `offer1testplaceholder${this.counter}` });
        }
        case "chia_cancelOffer": {
          const id = String(params["id"]);
          const made = this.offers.get(id);
          if (!made || !made.open) throw new RpcError(4000, "no open offer with that id");
          this.refuse({ method, leaves: [], arrives: [] });
          made.open = false;
          for (const g of made.leaves) this.usage.held.set(g.asset, (this.usage.held.get(g.asset) ?? 0n) - g.mojos);
          return JSON.stringify({});
        }
        case "chia_takeOffer": {
          const offer = String(params["offer"]);
          const d = this.decoded.get(offer);
          if (!d) {
            void this.prepareTake(offer);
            throw new RpcError(4101, "the wallet could not decode this offer yet; retry in a moment");
          }
          // Taking: the user pays what the maker asks and gets what the maker gives.
          this.refuse({ method, leaves: d.requested, arrives: d.offered });
          for (const p of d.requested) this.usage.used.set(p.asset, (this.usage.used.get(p.asset) ?? 0n) + p.mojos);
          this.taken.push(offer);
          return JSON.stringify({ id: `take-${this.taken.length}` });
        }
        default:
          throw new RpcError(4004, "method not supported");
      }
    } catch (e) {
      if (e instanceof RpcError) throw { code: e.code, message: e.message, data: e.data };
      throw { code: 4000, message: e instanceof Error ? e.message : "bad request" };
    }
  }
}
