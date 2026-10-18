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

export interface Context {
  wallet: Wallet | null;
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
  /** Moves or locks funds: not read-only. */
  writes: boolean;
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

async function ask(ctx: Context, method: string, params: unknown, wait: number): Promise<{ result?: unknown; waiting?: Record<string, unknown> }> {
  const outcome = await wallet(ctx).request(method, params, wait);
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
    writes: false,
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
        next: "Show qr_text in a code block (or point to the opened image) and ask the user to scan it with the wallet, or paste pairing_string into it. Then call pairing_status. Do not share the code with anyone else: whoever scans it first is paired.",
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
      "Tell the wallet whether the 6-digit code from pairing_status matches the one the wallet shows. Call it only with the user's answer: the codes are what stops someone else's wallet from pairing in the middle.",
    inputSchema: {
      type: "object",
      properties: { codes_match: { type: "boolean", description: "The user said the wallet shows the same code" } },
      required: ["codes_match"],
      additionalProperties: false,
    },
    writes: false,
    async run(ctx, args) {
      const matches = args["codes_match"];
      if (typeof matches !== "boolean") throw new ToolError("invalid_request", "codes_match must be true or false");
      await wallet(ctx).confirmPairing(matches);
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
    description: "Unpair: ends the session here and in the wallet. Pairing again needs a new scan.",
    inputSchema: NO_ARGS,
    writes: false,
    async run(ctx) {
      await wallet(ctx).end();
      return { ended: true };
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
      const { result, waiting } = await ask(ctx, "xchonnect_getAgentRules", {}, seconds(args, "wait_seconds", 30, 55));
      if (waiting) return waiting;
      const rules = parseRules(result);
      return {
        ...rules,
        limits: rules.limits.map((l) => {
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
    async run(ctx, args) {
      const offer = str(args, "offer", 65536);
      if (!offer.startsWith("offer1")) throw new ToolError("invalid_request", "an offer text starts with offer1");
      const fee = feeMojos(args["fee"]);
      const params = { offer, fee: wire(fee) };
      if (bool(args, "dry_run", false)) {
        return { dry_run: true, would_send: { method: "chia_takeOffer", fee_xch: fromMojos(fee, "xch"), offer_length: offer.length }, note: "The plugin does not decode offers; read the amounts with nodexch decode_offer. The wallet decodes it again itself before it signs." };
      }
      const { result, waiting } = await ask(ctx, "chia_takeOffer", params, seconds(args, "wait_seconds", 45, 55));
      if (waiting) return waiting;
      log("offer taken");
      return { taken: true, ...(result as object) };
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
        expires_in_minutes: { type: "integer", minimum: 1, maximum: 525600, description: "The offer cannot be taken after this; recommended for an agent's offers" },
        fee: { type: "string", description: "Network fee in XCH units, default 0" },
        dry_run: { type: "boolean", default: false },
        wait_seconds: WAIT,
      },
      required: ["offer_assets", "request_assets"],
      additionalProperties: false,
    },
    writes: true,
    async run(ctx, args) {
      const give = sides(args["offer_assets"], "offer_assets");
      const take = sides(args["request_assets"], "request_assets");
      const fee = feeMojos(args["fee"]);
      const minutes = args["expires_in_minutes"];
      if (minutes !== undefined && (typeof minutes !== "number" || !Number.isInteger(minutes) || minutes < 1 || minutes > 525_600)) {
        throw new ToolError("invalid_request", "expires_in_minutes must be a whole number of minutes from 1 to 525600");
      }
      const expiresAt = typeof minutes === "number" ? Math.floor(Date.now() / 1000) + minutes * 60 : undefined;
      const params = {
        offerAssets: give.map((s) => ({ assetId: sageAsset(s.asset), amount: wire(s.mojos) })),
        requestAssets: take.map((s) => ({ assetId: sageAsset(s.asset), amount: wire(s.mojos) })),
        fee: wire(fee),
        ...(expiresAt ? { expiresAt } : {}),
      };
      const summary = {
        gives: give.map((s) => ({ asset: s.asset, amount: s.units })),
        gets: take.map((s) => ({ asset: s.asset, amount: s.units })),
        fee_xch: fromMojos(fee, "xch"),
        ...(expiresAt ? { expires_at: new Date(expiresAt * 1000).toISOString() } : { expires_at: null }),
      };
      if (bool(args, "dry_run", false)) return { dry_run: true, would_send: { method: "chia_createOffer", ...summary } };
      const { result, waiting } = await ask(ctx, "chia_createOffer", params, seconds(args, "wait_seconds", 45, 55));
      if (waiting) return waiting;
      const made = (result ?? {}) as { id?: string; offer?: string };
      if (typeof made.id !== "string" || typeof made.offer !== "string") throw new ToolError("internal", "the wallet's answer has no offer id or text");
      const record: OfferRecord = {
        id: made.id,
        offer: made.offer,
        gives: summary.gives,
        gets: summary.gets,
        createdAt: Math.floor(Date.now() / 1000),
        ...(expiresAt ? { expiresAt } : {}),
        status: "open",
      };
      await ctx.offers.add(record);
      log("offer created");
      return { created: true, offer_id: made.id, offer: made.offer, ...summary, next: "Post the offer text where takers find it; list_offers shows the offers made through this pairing." };
    },
  },
  {
    name: "cancel_offer",
    title: "Cancel an offer",
    description: "Ask the wallet to cancel an offer it made for this agent (offer_id from create_offer or list_offers). With a fee the cancel happens on chain, so the offer can no longer be taken anywhere; without one the wallet only forgets it.",
    inputSchema: {
      type: "object",
      properties: {
        offer_id: { type: "string", maxLength: 200 },
        fee: { type: "string", description: "Network fee in XCH units; give one to cancel on chain" },
        dry_run: { type: "boolean", default: false },
        wait_seconds: WAIT,
      },
      required: ["offer_id"],
      additionalProperties: false,
    },
    writes: true,
    async run(ctx, args) {
      const id = str(args, "offer_id", 200);
      const fee = feeMojos(args["fee"]);
      if (bool(args, "dry_run", false)) return { dry_run: true, would_send: { method: "chia_cancelOffer", offer_id: id, fee_xch: fromMojos(fee, "xch"), on_chain: fee > 0n } };
      const { result, waiting } = await ask(ctx, "chia_cancelOffer", { id, fee: wire(fee) }, seconds(args, "wait_seconds", 45, 55));
      if (waiting) return waiting;
      await ctx.offers.setStatus(id, "cancelled");
      log("offer cancelled");
      return { cancelled: true, offer_id: id, on_chain: fee > 0n, ...(result as object) };
    },
  },
  {
    name: "list_offers",
    title: "Offers of this pairing",
    description: "The offers the wallet made through this pairing, newest first, with their status as far as this plugin knows (open, expired, cancelled). An open offer may have been taken since: check it on nodexch (get_offer) or Coinset.",
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
      return { done: true, result: outcome.result, note: "If this was create_offer, call list_offers: an offer answered late is not recorded there; post the offer text from result." };
    },
  },
  {
    name: "cancel_request",
    title: "Withdraw a request",
    description: "Withdraw a request that is still waiting for the wallet; the wallet drops it unless the user already approved it.",
    inputSchema: { type: "object", properties: { request_handle: { type: "string", maxLength: 80 } }, required: ["request_handle"], additionalProperties: false },
    writes: false,
    async run(ctx, args) {
      await wallet(ctx).cancel(str(args, "request_handle", 80));
      return { withdrawn: true };
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
    annotations: { title: t.title, readOnlyHint: !t.writes, destructiveHint: false, openWorldHint: true },
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
