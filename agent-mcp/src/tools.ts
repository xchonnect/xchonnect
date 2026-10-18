/**
 * The MCP tools: pairing with the wallet, reading the agent's rules and balances, and asking the
 * wallet to take, create or cancel offers. The wallet builds and signs every spend itself
 * (`chia_*`, spec 9.1) and checks it against the user's rules (spec 9.4): this plugin builds no
 * spend and holds no wallet key. Every request that moves funds has a dry run that shows what
 * would be asked without contacting the wallet.
 */
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AmountError, assetId, feeMojos, fromMojos, toMojos, type AssetId } from "./amounts.js";
import { log } from "./log.js";
import type { OfferBook, OfferRecord } from "./offers.js";
import type { Origin } from "./origin.js";
import { matrix, showImage, text as qrText } from "./qr.js";
import { AGENT_REASONS, parseRules, REASON_TEXT } from "./rules.js";
import { ToolError, type PendingRequest, type Wallet } from "./wallet.js";

/** Asks the user (MCP elicitation): their answer, or null when the client cannot ask. */
export type Elicit = (
  message: string,
  requestedSchema: Record<string, unknown>,
) => Promise<{ action: "accept" | "decline" | "cancel"; content?: Record<string, unknown> } | null>;

export interface Context {
  wallet: Wallet | null;
  /** The largest network fee a request may carry, in mojos (XCHONNECT_MCP_MAX_FEE). */
  maxFeeMojos: bigint;
  /** Set by the server when the client can ask the user questions. */
  elicit: Elicit | null;
  /** The wallet answered `xchonnect_getAgentRules`: it enforces the agent rules (spec 9.4). */
  rulesSupported?: boolean;
  origin: Origin | null;
  offers: OfferBook;
  relay: string;
  keychain: string;
  /** Open the QR image in the system viewer (off in tests). */
  openViewer: boolean;
  /** Where the QR image is written. */
  imageDir?: string;
  /** Why the wallet is unavailable, when it is. */
  setupError?: string;
}

type Args = Record<string, unknown>;

interface ToolSpec {
  name: string;
  title: string;
  description: string;
  inputSchema: Record<string, unknown>;
  /** Changes something outside the plugin (the wallet's state, the pairing). */
  writes: boolean;
  /** Can move or lock funds. */
  destructive?: boolean;
  run(ctx: Context, args: Args): Promise<unknown>;
}

const NO_ARGS = { type: "object", properties: {}, additionalProperties: false };

const WAIT = {
  type: "integer",
  minimum: 0,
  maximum: 55,
  default: 45,
  description: "Seconds to wait for the wallet before returning; a request still waiting gets a handle for request_status",
};

const ASSET_AMOUNT = {
  type: "object",
  properties: {
    asset: { type: "string", description: '"xch" or a CAT asset id (64 hex characters)' },
    amount: { type: "string", description: 'Units as a decimal string ("0.25"): XCH has 12 decimals, a CAT 3' },
  },
  required: ["asset", "amount"],
  additionalProperties: false,
};

function wallet(ctx: Context): Wallet {
  if (ctx.wallet) return ctx.wallet;
  throw new ToolError("not_set_up", ctx.setupError ?? "The plugin has no origin to pair with.");
}

function bool(args: Args, name: string, fallback: boolean): boolean {
  const v = args[name];
  if (v === undefined || v === null) return fallback;
  if (typeof v !== "boolean") throw new ToolError("invalid_request", `${name} must be true or false`);
  return v;
}

function seconds(args: Args, name: string, fallback: number, max: number): number {
  const v = args[name];
  if (v === undefined || v === null) return fallback;
  if (typeof v !== "number" || !Number.isInteger(v) || v < 0 || v > max) throw new ToolError("invalid_request", `${name} must be a whole number from 0 to ${max}`);
  return v;
}

function str(args: Args, name: string, max: number): string {
  const v = args[name];
  if (typeof v !== "string" || v.trim() === "") throw new ToolError("invalid_request", `${name} is required`);
  if (v.length > max) throw new ToolError("invalid_request", `${name} is longer than ${max} characters`);
  return v.trim();
}

function fee(ctx: Context, args: Args): bigint {
  const mojos = feeMojos(args["fee"]);
  if (mojos > ctx.maxFeeMojos) {
    throw new ToolError(
      "invalid_request",
      `fee ${fromMojos(mojos, "xch")} XCH is above the most this plugin sends, ${fromMojos(ctx.maxFeeMojos, "xch")} XCH (XCHONNECT_MCP_MAX_FEE). Fees are in XCH, not mojos.`,
    );
  }
  return mojos;
}

/** A short string from the wallet, or undefined: what comes off the wire is bounded before it reaches the agent. */
function shortText(v: unknown, max = 200): string | undefined {
  return typeof v === "string" && v.length <= max ? v : undefined;
}

/** The largest offer text taken back from a wallet. */
const OFFER_TEXT_MAX = 128 * 1024;

/** Sage's shape of an asset in an offer request: `""` for XCH, else the asset id. */
function sageAsset(asset: AssetId): string {
  return asset === "xch" ? "" : asset;
}

/** Mojos as the wallet takes them: a number while it is exact, else a decimal string. */
function wire(mojos: bigint): number | string {
  return mojos <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(mojos) : mojos.toString();
}

function sides(list: unknown, name: string): { asset: AssetId; mojos: bigint; units: string }[] {
  if (!Array.isArray(list) || list.length === 0 || list.length > 8) throw new ToolError("invalid_request", `${name} must list 1 to 8 assets`);
  return list.map((item, i) => {
    const entry = (item ?? {}) as Args;
    const asset = assetId(entry["asset"], `${name}[${i}].asset`);
    const mojos = toMojos(entry["amount"], asset, `${name}[${i}].amount`);
    return { asset, mojos, units: fromMojos(mojos, asset) };
  });
}

/** A request that did not finish within the wait. */
function stillWaiting(p: PendingRequest): Record<string, unknown> {
  const delivered = !["waiting", "queued"].includes(p.state);
  return {
    status: delivered ? "waiting_for_user" : "wallet_unreachable",
    request_handle: p.handle,
    wallet_state: p.state,
    ...(p.txId ? { transaction_id: p.txId } : {}),
    message: delivered
      ? "The wallet has the request and is waiting for the user to decide. Check again with request_status."
      : "The wallet has not picked up the request yet (it may be closed or offline). It stays queued for up to 10 minutes; ask the user to open the wallet, then check with request_status, or withdraw it with cancel_request.",
  };
}

async function ask(
  ctx: Context,
  method: string,
  params: unknown,
  wait: number,
  onResult?: (result: unknown) => Promise<void>,
): Promise<{ result?: unknown; waiting?: Record<string, unknown> }> {
  const outcome = await wallet(ctx).request(method, params, wait, onResult);
  if ("pending" in outcome) return { waiting: stillWaiting(outcome.pending) };
  return { result: outcome.result };
}

export const TOOLS: ToolSpec[] = [
  {
    name: "pair",
    title: "Pair with the wallet",
    description:
      "Start pairing this agent with the user's Chia wallet (Klimper, or another Xchonnect wallet). Opens the pairing QR code as an image on this computer and returns it as text too: show qr_text to the user in a code block, ask them to scan it with the wallet, then call pairing_status. A pairing lasts across chats and restarts until the wallet ends it.",
    inputSchema: {
      type: "object",
      properties: {
        light_terminal: { type: "boolean", default: false, description: "Draw the text QR code for a light background" },
        open_image: { type: "boolean", default: true, description: "Open the QR code image in the system image viewer" },
      },
      additionalProperties: false,
    },
    writes: true,
    async run(ctx, args) {
      const w = wallet(ctx);
      const { uri, expiresAt } = await w.pair();
      const m = matrix(uri);
      const image = join(ctx.imageDir ?? tmpdir(), "xchonnect-pairing.png");
      const opened = await showImage(m, image, ctx.openViewer && bool(args, "open_image", true));
      return {
        qr_text: qrText(m, bool(args, "light_terminal", false)),
        pairing_string: uri,
        image,
        image_opened: opened,
        expires_at: expiresAt,
        next: "Show qr_text in a code block (or point to the opened image) and ask the user to scan it with the wallet, or paste pairing_string into it. Then call pairing_status. The code is valid for 5 minutes and whoever uses it first is paired, which the 6-digit code check then catches.",
      };
    },
  },
  {
    name: "pairing_status",
    title: "Pairing status",
    description:
      "Wait for the wallet to scan the pairing code. When it has, returns a 6-digit code: show it to the user and ask whether the wallet shows the same code. Only after the user says it matches, call confirm_pairing with codes_match true.",
    inputSchema: { type: "object", properties: { wait_seconds: { ...WAIT, default: 30 } }, additionalProperties: false },
    writes: false,
    async run(ctx, args) {
      const s = await wallet(ctx).pairingStatus(seconds(args, "wait_seconds", 30, 55));
      const next: Record<string, string> = {
        none: "Nothing is being paired. Call pair to start.",
        waiting_for_wallet: "The wallet has not scanned the code yet. Ask the user to scan it, then call pairing_status again.",
        compare_code: "Show the user this code and ask: does the wallet show the same 6 digits? If yes, call confirm_pairing with codes_match true; if not, with false.",
        active: "Paired. The wallet's rules for this agent can be read with get_rules.",
        failed: "Pairing did not complete. Call pair to start again.",
      };
      return {
        phase: s.phase,
        ...(s.code ? { code: s.code } : {}),
        ...(s.walletName ? { wallet_name: s.walletName } : {}),
        ...(s.error ? { error: s.error.code, message: s.error.message } : {}),
        next: next[s.phase],
      };
    },
  },
  {
    name: "confirm_pairing",
    title: "Confirm the pairing code",
    description:
      "Confirm the pairing once the user has compared the 6-digit code from pairing_status with the one the wallet shows. Where the client can ask the user itself, the plugin asks them directly and codes_match is not needed; otherwise pass the user's own answer, never your guess: the code check is what stops someone else's wallet from pairing.",
    inputSchema: {
      type: "object",
      properties: { codes_match: { type: "boolean", description: "The user said the wallet shows the same code (only for clients that cannot ask the user)" } },
      additionalProperties: false,
    },
    writes: true,
    async run(ctx, args) {
      const w = wallet(ctx);
      let matches: boolean;
      const status = await w.pairingStatus(0);
      const asked = status.phase === "compare_code" && status.code && ctx.elicit
        ? await ctx.elicit(
            `Pairing your Chia wallet with this agent. Does your wallet show the code ${status.code}? Answer only from what the wallet shows.`,
            {
              type: "object",
              properties: { matches: { type: "boolean", title: `The wallet shows ${status.code}`, description: "Yes only if the wallet shows exactly these 6 digits" } },
              required: ["matches"],
            },
          )
        : null;
      if (asked) {
        if (asked.action === "cancel") return { paired: false, next: "The user did not answer. Call confirm_pairing again to ask once more, or pair again." };
        matches = asked.action === "accept" && asked.content?.["matches"] === true;
      } else {
        const said = args["codes_match"];
        if (typeof said !== "boolean") throw new ToolError("invalid_request", "codes_match must be true or false: ask the user whether the wallet shows the same 6-digit code");
        matches = said;
      }
      await w.confirmPairing(matches);
      return matches
        ? { paired: true, next: "Paired. Read the wallet's rules for this agent with get_rules before trading." }
        : { paired: false, next: "Cancelled. Call pair to try again." };
    },
  },
  {
    name: "wallet_status",
    title: "Wallet status",
    description: "Whether a wallet is paired, what it declared this agent may do, and where the session is kept.",
    inputSchema: NO_ARGS,
    writes: false,
    async run(ctx) {
      if (!ctx.wallet) return { paired: false, setup_error: ctx.setupError };
      const p = ctx.wallet.permissions;
      return {
        paired: ctx.wallet.status === "active",
        status: ctx.wallet.status,
        ...(ctx.wallet.endedBy ? { ended_by: ctx.wallet.endedBy } : {}),
        declared_methods: p.declared ? p.methods : null,
        declared_limits: p.limits ?? null,
        refused_methods: p.refused,
        origin: ctx.origin ? { domain: ctx.origin.domain, developer_mode: ctx.origin.developerMode } : null,
        relay: ctx.relay,
        session_key_in: ctx.keychain,
      };
    },
  },
  {
    name: "end_session",
    title: "End the session",
    description: "Unpair: ends the session here and tells the wallet. Pairing again needs a new scan. The agent's open offers stay takeable until they are cancelled or expire.",
    inputSchema: NO_ARGS,
    writes: true,
    destructive: true,
    async run(ctx) {
      const told = await wallet(ctx).end();
      return told
        ? { ended: true, wallet_told: true }
        : { ended: true, wallet_told: false, next: "The wallet could not be told now (offline?): its pairing and rules for this agent stay until the user removes the agent in the wallet." };
    },
  },
  {
    name: "get_rules",
    title: "Agent rules",
    description:
      "The rules the user set in the wallet for this agent: allowed actions and assets, the most per trade and per day or week, what is left of each limit now (open offers count), price bands, active hours, expiry and pause. Read them before proposing a trade, and plan trades that fit.",
    inputSchema: { type: "object", properties: { wait_seconds: { ...WAIT, default: 30 } }, additionalProperties: false },
    writes: false,
    async run(ctx, args) {
      let asked: { result?: unknown; waiting?: Record<string, unknown> };
      try {
        asked = await ask(ctx, "xchonnect_getAgentRules", {}, seconds(args, "wait_seconds", 30, 55));
      } catch (e) {
        if (e instanceof ToolError && e.code === "not_supported") {
          ctx.rulesSupported = false;
          throw new ToolError(
            "not_supported",
            "This wallet has no agent rules (spec 9.4): it treats the agent like any app and asks the user for every request. Offer expiry may not be enforced by it.",
          );
        }
        throw e;
      }
      const { result, waiting } = asked;
      if (waiting) return waiting;
      const rules = parseRules(result);
      ctx.rulesSupported = true;
      const assetList = Array.isArray(rules.assets) ? rules.assets.slice(0, 64).map((a) => (a === "" ? "xch" : assetId(a, "assets"))) : null;
      return {
        agent: { name: shortText(rules.agent.name, 64) ?? "" },
        paused: rules.paused,
        expires_at: typeof rules.expiresAt === "number" ? new Date(rules.expiresAt * 1000).toISOString() : null,
        methods: rules.methods.filter((m) => typeof m === "string" && m.length <= 64).slice(0, 32),
        assets: assetList,
        hours: rules.hours
          ? { time_zone: shortText(rules.hours.timeZone, 64) ?? null, from: shortText(rules.hours.from, 5) ?? null, to: shortText(rules.hours.to, 5) ?? null }
          : null,
        bands: (Array.isArray(rules.bands) ? rules.bands.slice(0, 64) : []).map((b) => ({
          base: assetId(b.base, "band.base"),
          quote: assetId(b.quote, "band.quote"),
          min: shortText(b.min, 40) ?? null,
          max: shortText(b.max, 40) ?? null,
        })),
        limits: rules.limits.slice(0, 64).map((l) => {
          const asset = l.assetId === "" ? "xch" : assetId(l.assetId, "limit.assetId");
          const units = (v: string | number | undefined) => (v === undefined ? undefined : fromMojos(BigInt(v), asset));
          return {
            asset,
            ...(l.perRequest !== undefined ? { per_trade: units(l.perRequest) } : {}),
            ...(l.period ? { period: l.period } : {}),
            ...(l.perPeriod !== undefined ? { per_period: units(l.perPeriod) } : {}),
            used: units(l.used),
            held_by_open_offers: units(l.held),
            remaining: units(l.remaining),
            ...(l.resetsAt ? { resets_at: new Date(l.resetsAt * 1000).toISOString() } : {}),
          };
        }),
        refusal_codes: AGENT_REASONS,
      };
    },
  },
  {
    name: "get_balances",
    title: "Wallet balances",
    description: "Spendable and confirmed balances of the paired wallet, for XCH and the CATs asked for (asset ids).",
    inputSchema: {
      type: "object",
      properties: {
        assets: { type: "array", maxItems: 20, items: { type: "string" }, description: '"xch" and CAT asset ids; default ["xch"]' },
        wait_seconds: { ...WAIT, default: 30 },
      },
      additionalProperties: false,
    },
    writes: false,
    async run(ctx, args) {
      const list = args["assets"] === undefined ? ["xch"] : args["assets"];
      if (!Array.isArray(list) || list.length === 0 || list.length > 20) throw new ToolError("invalid_request", "assets must list 1 to 20 assets");
      const balances: Record<string, unknown>[] = [];
      for (const raw of list) {
        const asset = assetId(raw);
        const { result, waiting } = await ask(ctx, "getAssetBalance", asset === "xch" ? { type: null, assetId: null } : { type: "cat", assetId: asset }, seconds(args, "wait_seconds", 30, 55));
        if (waiting) return waiting;
        const b = (result ?? {}) as { confirmed?: string | number; spendable?: string | number; spendableCoinCount?: number };
        balances.push({
          asset,
          spendable: b.spendable === undefined ? null : fromMojos(BigInt(b.spendable), asset),
          confirmed: b.confirmed === undefined ? null : fromMojos(BigInt(b.confirmed), asset),
          spendable_coins: b.spendableCoinCount ?? null,
        });
      }
      return { balances };
    },
  },
  {
    name: "take_offer",
    title: "Take an offer",
    description:
      "Ask the wallet to take an offer (offer1… text, e.g. from nodexch best_offer). The wallet decodes it, checks it against the user's rules and asks the user or accepts within the rules, then signs and broadcasts. Check the amounts with the user first (nodexch decode_offer). With dry_run, nothing is sent.",
    inputSchema: {
      type: "object",
      properties: {
        offer: { type: "string", maxLength: 65536, description: "The offer text, offer1…" },
        fee: { type: "string", description: "Network fee in XCH units, default 0" },
        dry_run: { type: "boolean", default: false },
        wait_seconds: WAIT,
      },
      required: ["offer"],
      additionalProperties: false,
    },
    writes: true,
    destructive: true,
    async run(ctx, args) {
      const offer = str(args, "offer", 65536);
      if (!offer.startsWith("offer1")) throw new ToolError("invalid_request", "an offer text starts with offer1");
      const feeMojosValue = fee(ctx, args);
      const params = { offer, fee: wire(feeMojosValue) };
      if (bool(args, "dry_run", false)) {
        return { dry_run: true, would_send: { method: "chia_takeOffer", fee_xch: fromMojos(feeMojosValue, "xch"), offer_length: offer.length }, note: "The plugin does not decode offers; read the amounts with nodexch decode_offer. The wallet decodes it again itself before it signs." };
      }
      const { result, waiting } = await ask(ctx, "chia_takeOffer", params, seconds(args, "wait_seconds", 45, 55));
      if (waiting) return waiting;
      log("offer taken", { offer_length: offer.length, fee: fromMojos(feeMojosValue, "xch") });
      const id = shortText((result as { id?: unknown } | null)?.id, 200);
      return { taken: true, ...(id ? { wallet_trade_id: id } : {}) };
    },
  },
  {
    name: "create_offer",
    title: "Create an offer",
    description:
      "Ask the wallet to make an offer: give offer_assets for request_assets, optionally expiring. The wallet picks the coins, checks the user's rules (the amounts offered count against the limits while the offer is open) and returns the offer1 text to post (a marketplace, nodexch). For a price target, post a ladder of small expiring offers. With dry_run, nothing is sent.",
    inputSchema: {
      type: "object",
      properties: {
        offer_assets: { type: "array", items: ASSET_AMOUNT, minItems: 1, maxItems: 8, description: "What the user gives" },
        request_assets: { type: "array", items: ASSET_AMOUNT, minItems: 1, maxItems: 8, description: "What the user gets" },
        expires_in_minutes: { type: "integer", minimum: 1, maximum: 525600, default: 60, description: "The offer cannot be taken after this (default 60). A wallet without agent rules may ignore it: then the offer stays takeable until cancelled" },
        fee: { type: "string", description: "Network fee in XCH units, default 0" },
        dry_run: { type: "boolean", default: false },
        wait_seconds: WAIT,
      },
      required: ["offer_assets", "request_assets"],
      additionalProperties: false,
    },
    writes: true,
    destructive: true,
    async run(ctx, args) {
      const give = sides(args["offer_assets"], "offer_assets");
      const take = sides(args["request_assets"], "request_assets");
      for (const g of give) {
        if (take.some((t) => t.asset === g.asset)) throw new ToolError("invalid_request", `${g.asset} is on both sides of the offer`);
      }
      const feeValue = fee(ctx, args);
      const minutes = args["expires_in_minutes"] ?? 60;
      if (typeof minutes !== "number" || !Number.isInteger(minutes) || minutes < 1 || minutes > 525_600) {
        throw new ToolError("invalid_request", "expires_in_minutes must be a whole number of minutes from 1 to 525600");
      }
      const expiresAt = Math.floor(Date.now() / 1000) + minutes * 60;
      const enforced = ctx.rulesSupported === true;
      const params = {
        offerAssets: give.map((s) => ({ assetId: sageAsset(s.asset), amount: wire(s.mojos) })),
        requestAssets: take.map((s) => ({ assetId: sageAsset(s.asset), amount: wire(s.mojos) })),
        fee: wire(feeValue),
        expiresAt,
      };
      const summary = {
        gives: give.map((s) => ({ asset: s.asset, amount: s.units })),
        gets: take.map((s) => ({ asset: s.asset, amount: s.units })),
        fee_xch: fromMojos(feeValue, "xch"),
        expires_at: new Date(expiresAt * 1000).toISOString(),
        expiry_enforced: enforced,
      };
      if (bool(args, "dry_run", false)) return { dry_run: true, would_send: { method: "chia_createOffer", ...summary } };
      // Recorded when the wallet answers, also when that is after this call returned.
      const record = async (result: unknown): Promise<{ id: string; offer: string }> => {
        const made = (result ?? {}) as { id?: unknown; offer?: unknown };
        const id = shortText(made.id, 200);
        const offer = typeof made.offer === "string" && made.offer.startsWith("offer1") && made.offer.length <= OFFER_TEXT_MAX ? made.offer : undefined;
        if (!id || !offer) throw new ToolError("internal", "the wallet's answer has no usable offer id or offer1 text");
        await ctx.offers.add({ id, offer, gives: summary.gives, gets: summary.gets, createdAt: Math.floor(Date.now() / 1000), expiresAt, expiryEnforced: enforced, status: "open" });
        log("offer created", { id, ...summary });
        return { id, offer };
      };
      const { result, waiting } = await ask(ctx, "chia_createOffer", params, seconds(args, "wait_seconds", 45, 55), async (r) => void (await record(r)));
      if (waiting) return { ...waiting, note: "When the wallet answers, the offer is recorded; list_offers shows it." };
      const made = await record(result);
      return {
        created: true,
        offer_id: made.id,
        offer: made.offer,
        ...summary,
        next: enforced
          ? "Post the offer text where takers find it; list_offers shows the offers made through this pairing."
          : "Post the offer text where takers find it. This wallet does not report enforcing the expiry, so treat the offer as open until it is cancelled (cancel_offer) or taken.",
      };
    },
  },
  {
    name: "cancel_offer",
    title: "Cancel an offer",
    description: "Ask the wallet to cancel an offer it made for this agent (offer_id from create_offer or list_offers). The wallet cancels on chain by spending the offer's coins (a fee speeds it up), so it can no longer be taken anywhere once that is confirmed.",
    inputSchema: {
      type: "object",
      properties: {
        offer_id: { type: "string", maxLength: 200 },
        fee: { type: "string", description: "Network fee in XCH units, default 0" },
        dry_run: { type: "boolean", default: false },
        wait_seconds: WAIT,
      },
      required: ["offer_id"],
      additionalProperties: false,
    },
    writes: true,
    destructive: true,
    async run(ctx, args) {
      const id = str(args, "offer_id", 200);
      const feeValue = fee(ctx, args);
      if (bool(args, "dry_run", false)) return { dry_run: true, would_send: { method: "chia_cancelOffer", offer_id: id, fee_xch: fromMojos(feeValue, "xch") } };
      const { waiting } = await ask(ctx, "chia_cancelOffer", { id, fee: wire(feeValue) }, seconds(args, "wait_seconds", 45, 55), async () => ctx.offers.setStatus(id, "cancelled"));
      if (waiting) return waiting;
      await ctx.offers.setStatus(id, "cancelled");
      log("offer cancelled", { id });
      return { cancelled: true, offer_id: id, note: "The cancel is a transaction: the offer can still be taken until it is confirmed on chain." };
    },
  },
  {
    name: "list_offers",
    title: "Offers of this pairing",
    description: "The offers the wallet made through this pairing, newest first, with their status as far as this plugin knows (open, expired, cancelled). An open offer may have been taken since: check it on nodexch (get_offer) or Coinset. An offer is shown expired only when the wallet enforces expiry.",
    inputSchema: { type: "object", properties: { include_closed: { type: "boolean", default: false } }, additionalProperties: false },
    writes: false,
    async run(ctx, args) {
      const all = await ctx.offers.list();
      const closed = bool(args, "include_closed", false);
      return {
        offers: all
          .filter((o) => closed || o.status === "open")
          .map((o) => ({
            offer_id: o.id,
            status: o.status,
            gives: o.gives,
            gets: o.gets,
            created_at: new Date(o.createdAt * 1000).toISOString(),
            expires_at: o.expiresAt ? new Date(o.expiresAt * 1000).toISOString() : null,
            expiry_enforced: o.expiryEnforced === true,
            offer: o.offer,
          })),
      };
    },
  },
  {
    name: "request_status",
    title: "Request status",
    description: "Wait again for a request that was still waiting for the wallet (request_handle from an earlier answer).",
    inputSchema: {
      type: "object",
      properties: { request_handle: { type: "string", maxLength: 80 }, wait_seconds: WAIT },
      required: ["request_handle"],
      additionalProperties: false,
    },
    writes: false,
    async run(ctx, args) {
      const outcome = await wallet(ctx).requestStatus(str(args, "request_handle", 80), seconds(args, "wait_seconds", 45, 55));
      if ("pending" in outcome) return stillWaiting(outcome.pending);
      const text = JSON.stringify(outcome.result ?? null);
      return text.length <= OFFER_TEXT_MAX + 4096
        ? { done: true, result: outcome.result }
        : { done: true, result: null, note: "The wallet's answer was too large to show." };
    },
  },
  {
    name: "cancel_request",
    title: "Withdraw a request",
    description: "Withdraw a request that is still waiting for the wallet; the wallet drops it unless the user already approved it.",
    inputSchema: { type: "object", properties: { request_handle: { type: "string", maxLength: 80 } }, required: ["request_handle"], additionalProperties: false },
    writes: true,
    async run(ctx, args) {
      const outcome = await wallet(ctx).cancel(str(args, "request_handle", 80));
      return {
        withdrawn: outcome.withdrawn,
        message: outcome.detail,
        ...(outcome.result !== undefined ? { result: outcome.result } : {}),
        ...(outcome.error ? { error: outcome.error.code, error_message: outcome.error.message } : {}),
      };
    },
  },
  {
    name: "origin_document",
    title: "Origin document",
    description: "The /.well-known/xchonnect.json a wallet checks this agent's pairing codes against, for a user who serves it on their own domain (XCHONNECT_ORIGIN_DOMAIN).",
    inputSchema: NO_ARGS,
    writes: false,
    async run(ctx) {
      if (!ctx.origin) throw new ToolError("not_set_up", ctx.setupError ?? "no origin configured");
      return { domain: ctx.origin.domain, developer_mode: ctx.origin.developerMode, path: "/.well-known/xchonnect.json", document: JSON.parse(ctx.origin.document) as unknown };
    },
  },
];

/** What `tools/list` answers. */
export function list(): unknown[] {
  return TOOLS.map((t) => ({
    name: t.name,
    title: t.title,
    description: t.description,
    inputSchema: t.inputSchema,
    annotations: { title: t.title, readOnlyHint: !t.writes, destructiveHint: t.destructive === true, openWorldHint: true },
  }));
}

/** Runs a tool: the MCP result, or `null` for an unknown tool. */
export async function call(ctx: Context, name: string, args: unknown): Promise<Record<string, unknown> | null> {
  const tool = TOOLS.find((t) => t.name === name);
  if (!tool) return null;
  try {
    if (args !== undefined && args !== null && (typeof args !== "object" || Array.isArray(args))) throw new ToolError("invalid_request", "arguments must be an object");
    const result = (await tool.run(ctx, (args ?? {}) as Args)) as Record<string, unknown>;
    return { content: [{ type: "text", text: JSON.stringify(result) }], structuredContent: result, isError: false };
  } catch (e) {
    const err =
      e instanceof ToolError
        ? e
        : e instanceof AmountError
          ? new ToolError("invalid_request", e.message)
          : new ToolError("internal", e instanceof Error ? e.message : "something went wrong");
    const body = { error: err.code, message: err.message, ...(err.detail ?? {}) };
    if (err.code === "internal") log(`tool ${name} failed`);
    return { content: [{ type: "text", text: `${err.message} (${err.code})` }], structuredContent: body, isError: true };
  }
}

export { REASON_TEXT };
