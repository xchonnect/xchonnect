/**
 * fund_channel (chia_fundChannel, spec 9.1) through the plugin's tools, against the test wallet
 * over the relay API in memory, with the requests of `docs/spec/vectors/fund_channel.json`: a dry
 * run sends nothing, malformed input never reaches the wallet, a deposit the wallet accepts
 * returns its transaction, and each refusal comes back with its reason explained.
 */
import { readFileSync } from "node:fs";
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
import { AgentWallet, type FundCase, type Rules } from "./agentWallet.js";
import { MockRelay, pluginWasm, RelayClient } from "./sdk.js";

const RELAY = "http://127.0.0.1:8787";
const vectors = JSON.parse(readFileSync(new URL("../../docs/spec/vectors/fund_channel.json", import.meta.url), "utf8")) as { cases: (FundCase & { assetId: string; timeout: number })[] };
const [testnet, mainnet] = vectors.cases as [FundCase & { assetId: string }, FundCase];

const rules: Rules = {
  agent: { name: "Nodi (test)" },
  paused: false,
  methods: [],
  assets: [],
  bands: [],
  maxOfferSeconds: 3600,
  limits: [],
};

type Result = { isError: boolean; structuredContent: Record<string, unknown> };

const closers: (() => Promise<void> | void)[] = [];
afterAll(async () => {
  for (const c of closers.reverse()) await c();
});

function request(c: FundCase, extra: Record<string, unknown> = {}): Record<string, unknown> {
  return { channel_pk: c.channelPk, refund_puzzle_hash: c.refundPuzzleHash, listing: c.listing, amount: "12.5", address: c.address, wait_seconds: 10, ...extra };
}

describe("fund_channel", () => {
  it("sends chia_fundChannel with the contract's params and explains each refusal", async () => {
    const relay = new MockRelay();
    const dir = await mkdtemp(join(tmpdir(), "xcmcp-fund-"));
    const store = new EncryptedFileStore(join(dir, "state.bin"), await sessionKey(new MemoryKeychain()));
    const origin = (await openOrigin({ name: "Nodi", developerMode: true, port: 0 }, store)) as Origin;
    const plugin = await Wallet.open({ relay: RELAY, origin, storage: store, wasm: pluginWasm, fetch: relay.fetch, poll: { fastMs: 50, slowMs: 100 } });
    closers.push(() => plugin.close());
    const ctx: Context = { wallet: plugin, origin, offers: new OfferBook(store), relay: RELAY, keychain: "memory", openViewer: false, imageDir: dir, maxFeeMojos: 10_000_000_000n, elicit: null };
    const tool = async (name: string, args: Record<string, unknown> = {}) => (await call(ctx, name, args)) as unknown as Result;

    const paired = await tool("pair");
    const wallet = new AgentWallet({
      relay: new RelayClient(RELAY, { fetch: relay.fetch }),
      originDocument: origin.document,
      rules,
      ownPuzzleHashes: [testnet.refundPuzzleHash],
      channels: vectors.cases,
    });
    closers.push(() => wallet.close());
    await wallet.pair(paired.structuredContent["pairing_string"] as string);
    await tool("pairing_status", { wait_seconds: 5 });
    await Promise.all([tool("confirm_pairing", { codes_match: true }), wallet.confirm()]);

    // A dry run shows the operator and the amount, and sends nothing.
    const dry = await tool("fund_channel", request(testnet, { dry_run: true }));
    expect(dry.structuredContent).toMatchObject({
      dry_run: true,
      would_send: { method: "chia_fundChannel", asset: testnet.assetId, amount: "12.5", address: testnet.address, operator: { endpoint: "https://operator.example/x/inference/v1", network: "testnet11" }, timeout_seconds: 604800 },
    });

    // An operator_pk written with 0x is read as the same key.
    const prefixed = { listing: testnet.listing.listing.replace('"operator_pk":"', '"operator_pk":"0x'), signature: testnet.listing.signature };
    const dry0x = await tool("fund_channel", request(testnet, { listing: prefixed, dry_run: true }));
    expect((dry0x.structuredContent["would_send"] as { operator: { operator_pk: string } }).operator.operator_pk).toBe(JSON.parse(testnet.listing.listing).operator_pk);

    // Malformed input is refused here, before the wallet sees it.
    for (const bad of [
      { channel_pk: "00" },
      { refund_puzzle_hash: "aa" },
      { amount: "0" },
      { amount: "1.2345" },
      { address: "txch1notanaddress" },
      { address: mainnet.address }, // a mainnet address for a testnet11 listing
      { listing: { listing: "not json", signature: testnet.listing.signature } },
      { listing: { listing: ` ${testnet.listing.listing}`, signature: testnet.listing.signature } },
      { fee: "1000" },
    ]) {
      const r = await tool("fund_channel", request(testnet, bad));
      expect(r.structuredContent["error"], JSON.stringify(bad)).toBe("invalid_request");
    }
    expect(wallet.funded).toEqual([]);

    // The wallet accepts it: the params of the contract, amounts in mojos.
    const funded = await tool("fund_channel", request(testnet));
    expect(funded.isError).toBe(false);
    expect(funded.structuredContent).toMatchObject({ funded: true, transaction_id: "ab".repeat(32), status: "submitted", amount: "12.5" });
    expect(wallet.funded).toEqual([
      { channelPk: `0x${testnet.channelPk}`, refundPuzzleHash: `0x${testnet.refundPuzzleHash}`, listing: { listing: testnet.listing.listing, signature: `0x${testnet.listing.signature}` }, amount: 12500, fee: 0, address: testnet.address },
    ]);

    // Refusals, each with its reason and what to do.
    const refusals: [Record<string, unknown>, string, RegExp][] = [
      [request(testnet, { listing: { listing: testnet.listing.listing, signature: mainnet.listing.signature } }), "listing_invalid", /listing/],
      [request(mainnet), "wrong_network", /network/],
      [request(testnet, { refund_puzzle_hash: mainnet.refundPuzzleHash }), "refund_not_own", /refund/],
      [request(testnet, { channel_pk: mainnet.channelPk.replace(/^.{2}/, "a1") }), "address_mismatch", /derive/],
    ];
    for (const [args, reason, text] of refusals) {
      const r = await tool("fund_channel", args);
      expect(r.isError).toBe(true);
      expect(r.structuredContent).toMatchObject({ error: "refused", reason, wallet_code: 4001 });
      expect(String(r.structuredContent["message"])).toMatch(text);
    }

    // A paused agent is refused with the rule's own code.
    rules.paused = true;
    const paused = await tool("fund_channel", request(testnet));
    expect(paused.structuredContent["error"]).toBe("paused");
    expect(wallet.funded.length).toBe(1);
  }, 60_000);
});
