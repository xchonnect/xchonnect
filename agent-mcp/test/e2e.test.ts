/**
 * The plugin end to end, through its tools, against the test wallet with agent rules, over the
 * relay API in memory: pair and compare the code, read the rules, take and create offers, a
 * refusal with its code, cancel, a wallet that is away, a restart that needs no new pairing, and
 * the wallet ending the session. `scripts/agent-demo.sh` runs the same against a real relay and
 * nodexch, with Claude Code as the agent.
 */
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { MemoryKeychain, sessionKey } from "../src/keychain.js";
import { OfferBook } from "../src/offers.js";
import { openOrigin, type Origin } from "../src/origin.js";
import { EncryptedFileStore } from "../src/store.js";
import { call, type Context } from "../src/tools.js";
import { Wallet } from "../src/wallet.js";
import { AgentWallet, type Rules } from "./agentWallet.js";
import { MockRelay, pluginWasm, RelayClient } from "./sdk.js";

const RELAY = "http://127.0.0.1:8787";
const TDBX = "d82dd03f8a9ad2f84353cd953c4de6b21dbaaf7de3ba3f4ddd9abe31ecba80ad";
const OFFER = "offer1qqr83wcuu2rykcmqvpsxygqqtest";

const rules: Rules = {
  agent: { name: "Claude Code (test)" },
  paused: false,
  expiresAt: Math.floor(Date.now() / 1000) + 7 * 86_400,
  methods: ["chia_takeOffer", "chia_createOffer", "chia_cancelOffer"],
  assets: ["xch", TDBX],
  limits: [
    { assetId: "xch", perRequest: "500000000000", period: "day", perPeriod: "2000000000000" },
    { assetId: TDBX, perRequest: "100000", period: "day", perPeriod: "300000" },
  ],
};

type Result = { isError: boolean; structuredContent: Record<string, unknown> };

async function tool(ctx: Context, name: string, args: Record<string, unknown> = {}): Promise<Result> {
  const r = (await call(ctx, name, args)) as unknown as Result | null;
  if (!r) throw new Error(`no tool ${name}`);
  return r;
}

const closers: (() => Promise<void> | void)[] = [];
afterAll(async () => {
  for (const c of closers.reverse()) await c();
});

async function plugin(relay: MockRelay, store: EncryptedFileStore, origin: Origin): Promise<Context> {
  const wallet = await Wallet.open({ relay: RELAY, origin, storage: store, wasm: pluginWasm, fetch: relay.fetch, poll: { fastMs: 50, slowMs: 100 } });
  closers.push(() => wallet.close());
  return { wallet, origin, offers: new OfferBook(store), relay: RELAY, keychain: "memory", openViewer: false, imageDir: await mkdtemp(join(tmpdir(), "xcmcp-img-")) };
}

describe("the plugin with a wallet that has agent rules", () => {
  it("pairs, trades within the rules, is refused past them, and survives a restart", async () => {
    const relay = new MockRelay();
    const dir = await mkdtemp(join(tmpdir(), "xcmcp-e2e-"));
    const store = new EncryptedFileStore(join(dir, "state.bin"), await sessionKey(new MemoryKeychain()));
    const origin = (await openOrigin({ name: "Claude Code agent", developerMode: true, port: 0 }, store)) as Origin;
    let ctx = await plugin(relay, store, origin);

    // Nothing paired yet: a fixed code, and a way forward.
    const early = await tool(ctx, "get_rules");
    expect(early.isError).toBe(true);
    expect(early.structuredContent["error"]).toBe("not_paired");

    // Pair: the QR as text and image, the wallet scans, the codes are compared, then confirmed.
    const paired = await tool(ctx, "pair");
    expect(paired.isError).toBe(false);
    const uri = paired.structuredContent["pairing_string"] as string;
    expect(uri.startsWith("xchonnect:v1?")).toBe(true);
    expect(String(paired.structuredContent["qr_text"])).toMatch(/[█▀▄]/);
    const wallet = new AgentWallet({
      relay: new RelayClient(RELAY, { fetch: relay.fetch }),
      originDocument: origin.document,
      rules,
      balances: { xch: 3_000_000_000_000n, [TDBX]: 1_000_000n },
      decodeOffer: async (text) => (text === OFFER ? { offered: [{ asset: TDBX, mojos: 20_000n }], requested: [{ asset: "xch", mojos: 100_000_000_000n }] } : null),
    });
    closers.push(() => wallet.close());
    const sas = await wallet.pair(uri);
    const status = await tool(ctx, "pairing_status", { wait_seconds: 5 });
    expect(status.structuredContent["phase"]).toBe("compare_code");
    expect(status.structuredContent["code"]).toBe(sas);
    const [confirmed] = await Promise.all([tool(ctx, "confirm_pairing", { codes_match: true }), wallet.confirm()]);
    expect(confirmed.structuredContent["paired"]).toBe(true);

    // The rules, in units, with what is left.
    const got = await tool(ctx, "get_rules");
    expect(got.isError).toBe(false);
    const limits = got.structuredContent["limits"] as { asset: string; per_trade: string; remaining: string }[];
    expect(limits.find((l) => l.asset === TDBX)).toMatchObject({ per_trade: "100", remaining: "300" });

    const balances = await tool(ctx, "get_balances", { assets: ["xch", TDBX] });
    expect(balances.structuredContent["balances"]).toEqual([
      { asset: "xch", spendable: "3", confirmed: "3", spendable_coins: 1 },
      { asset: TDBX, spendable: "1000", confirmed: "1000", spendable_coins: 1 },
    ]);

    // Take an offer (the wallet decodes it itself).
    await wallet.prepareTake(OFFER);
    const take = await tool(ctx, "take_offer", { offer: OFFER, wait_seconds: 10 });
    expect(take.structuredContent).toMatchObject({ taken: true });
    expect(wallet.taken).toEqual([OFFER]);

    // A dry run sends nothing.
    const dry = await tool(ctx, "create_offer", { offer_assets: [{ asset: TDBX, amount: "80" }], request_assets: [{ asset: "xch", amount: "0.4" }], expires_in_minutes: 60, dry_run: true });
    expect(dry.structuredContent).toMatchObject({ dry_run: true, would_send: { method: "chia_createOffer", gives: [{ asset: TDBX, amount: "80" }] } });

    // An expiring offer within the rules: held against the limit while open.
    const made = await tool(ctx, "create_offer", { offer_assets: [{ asset: TDBX, amount: "80" }], request_assets: [{ asset: "xch", amount: "0.4" }], expires_in_minutes: 60, wait_seconds: 10 });
    expect(made.isError).toBe(false);
    const offerId = made.structuredContent["offer_id"] as string;
    const after = await tool(ctx, "get_rules");
    expect((after.structuredContent["limits"] as { asset: string; held_by_open_offers: string; remaining: string }[]).find((l) => l.asset === TDBX)).toMatchObject({
      held_by_open_offers: "80",
      remaining: "220",
    });

    // Past the per-trade limit: refused by the wallet with the code, before anyone is asked.
    const big = await tool(ctx, "create_offer", { offer_assets: [{ asset: TDBX, amount: "150" }], request_assets: [{ asset: "xch", amount: "0.6" }], wait_seconds: 10 });
    expect(big.isError).toBe(true);
    expect(big.structuredContent["error"]).toBe("limit_per_trade");
    expect(big.structuredContent["rule"]).toMatchObject({ assetId: TDBX, perRequest: "100000" });
    // An asset the rules do not allow.
    const other = await tool(ctx, "create_offer", { offer_assets: [{ asset: "xch", amount: "0.1" }], request_assets: [{ asset: "a628c1c2c6fcb74d53746157e438e108eab5c0bb3e5c80ff9b1910b3e4832913", amount: "1" }], wait_seconds: 10 });
    expect(other.structuredContent["error"]).toBe("asset_not_allowed");

    const listed = await tool(ctx, "list_offers");
    expect((listed.structuredContent["offers"] as { offer_id: string }[]).map((o) => o.offer_id)).toEqual([offerId]);
    const cancel = await tool(ctx, "cancel_offer", { offer_id: offerId, wait_seconds: 10 });
    expect(cancel.structuredContent).toMatchObject({ cancelled: true });
    expect((await tool(ctx, "list_offers")).structuredContent["offers"]).toEqual([]);

    // The wallet is away: the request is queued, the tool says so with a handle, and the answer
    // comes once the wallet is back.
    wallet.close();
    const away = await tool(ctx, "get_balances", { assets: ["xch"], wait_seconds: 2 });
    expect(away.structuredContent["status"]).toBe("wallet_unreachable");
    const handle = away.structuredContent["request_handle"] as string;
    const restart = wallet.fake.run();
    closers.push(restart);
    const back = await tool(ctx, "request_status", { request_handle: handle, wait_seconds: 10 });
    expect(back.structuredContent).toMatchObject({ done: true });

    // A restart of the agent: the session comes back from the encrypted file, no new pairing.
    await ctx.wallet?.close();
    ctx = await plugin(relay, store, origin);
    const again = await tool(ctx, "get_rules", { wait_seconds: 10 });
    expect(again.isError).toBe(false);
    expect((await tool(ctx, "wallet_status")).structuredContent["paired"]).toBe(true);

    // The wallet ends the session: the next request says so, and pairing can start again.
    await wallet.fake.end("user removed the agent");
    for (let i = 0; i < 100 && ctx.wallet?.status === "active"; i++) await new Promise((r) => setTimeout(r, 50));
    const ended = await tool(ctx, "get_rules");
    expect(ended.structuredContent["error"]).toBe("session_ended");
    const anew = await tool(ctx, "pair");
    expect(anew.isError).toBe(false);
  }, 60_000);
});
