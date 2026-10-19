/**
 * nodexch as the origin (NODEXCH_KEY, nodexch's TASK-176.05): the plugin reads nodexch's domain,
 * key id, public key and relay, and has each pairing signed by nodexch with the agent's key. A
 * stand-in for nodexch signs as nodexch does; the test wallet checks the pairing against nodexch's
 * origin document and pairs. A refused key and an odd origin are said plainly.
 */
import { generateKeyPairSync, sign as edSign, verify as edVerify } from "node:crypto";
import { createServer, type Server } from "node:http";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { MemoryKeychain, sessionKey } from "../src/keychain.js";
import { OfferBook } from "../src/offers.js";
import { openNodexchOrigin } from "../src/origin.js";
import { EncryptedFileStore } from "../src/store.js";
import { call, type Context } from "../src/tools.js";
import { Wallet } from "../src/wallet.js";
import { AgentWallet } from "./agentWallet.js";
import { MockRelay, pluginWasm, RelayClient } from "./sdk.js";

const RELAY = "http://127.0.0.1:8787";
const KEY = "nxs_agent_secret_key_for_the_test_0000000000";

const closers: (() => Promise<void> | void)[] = [];
afterAll(async () => {
  for (const c of closers.reverse()) await c();
});

/** nodexch as far as the plugin sees it: the origin, and one signature per pairing for `KEY`. */
async function nodexch(shape: Record<string, unknown> = {}): Promise<{ url: string; port: number; document: string; signed: string[] }> {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const pk = publicKey.export({ format: "jwk" }).x as string;
  const signed: string[] = [];
  const server: Server = createServer((req, res) => {
    const json = (status: number, body: unknown) => {
      res.writeHead(status, { "content-type": "application/json" });
      res.end(JSON.stringify(body));
    };
    if (req.method === "GET" && req.url === "/x/account/v1/xchonnect") {
      const address = server.address() as { port: number };
      return json(200, { relay: RELAY, domain: `localhost:${address.port}`, kid: "2026-10", public_key: pk, ...shape });
    }
    if (req.method === "GET" && req.url === "/.well-known/xchonnect.json") {
      if (shape["unpublished"]) return json(404, {});
      return json(200, { v: 1, name: "nodexch", origin_keys: [{ kid: "2026-10", pk, not_after: "2099-12-31" }] });
    }
    if (req.method === "POST" && req.url === "/x/account/v1/xchonnect/sign") {
      if (req.headers.authorization !== `Bearer ${KEY}`) return json(401, { success: false, error: "a secret API key that is active, or a sign-in", code: "unauthorized" });
      let body = "";
      req.on("data", (chunk) => (body += chunk));
      req.on("end", () => {
        const input = (JSON.parse(body) as { sig_input: string }).sig_input;
        signed.push(input);
        json(200, { signature: edSign(null, Buffer.from(input, "base64url"), privateKey).toString("base64url") });
      });
      return;
    }
    json(404, {});
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  closers.push(() => new Promise<void>((resolve) => server.close(() => resolve())));
  const address = server.address() as { port: number };
  const document = JSON.stringify({ v: 1, name: "nodexch", origin_keys: [{ kid: "2026-10", pk, not_after: "2099-12-31" }] });
  return { url: `http://127.0.0.1:${address.port}`, port: address.port, document, signed };
}

describe("nodexch as the plugin's origin", () => {
  it("reads nodexch's origin and has the pairing signed with the agent's key", async () => {
    const api = await nodexch();
    const origin = await openNodexchOrigin(`${api.url}/`, KEY);
    expect(origin).toMatchObject({ domain: `localhost:${api.port}`, kid: "2026-10", relay: RELAY, developerMode: true, document: "" });
    const input = Buffer.from("a pairing's signature input").toString("base64url");
    const signature = await origin.sign(input);
    const { publicKey } = { publicKey: { key: { kty: "OKP", crv: "Ed25519", x: origin.publicKey }, format: "jwk" as const } };
    expect(edVerify(null, Buffer.from(input, "base64url"), publicKey, Buffer.from(signature, "base64url"))).toBe(true);
  });

  it("pairs a wallet through the plugin's tools as nodexch's domain", async () => {
    const api = await nodexch();
    const origin = await openNodexchOrigin(api.url, KEY);
    const relay = new MockRelay();
    const dir = await mkdtemp(join(tmpdir(), "xcmcp-nodexch-"));
    const store = new EncryptedFileStore(join(dir, "state.bin"), await sessionKey(new MemoryKeychain()));
    const wallet = await Wallet.open({ relay: origin.relay, origin, storage: store, wasm: pluginWasm, fetch: relay.fetch, poll: { fastMs: 50, slowMs: 100 } });
    closers.push(() => wallet.close());
    const ctx: Context = {
      wallet,
      origin,
      offers: new OfferBook(store),
      relay: origin.relay,
      keychain: "memory",
      openViewer: false,
      imageDir: dir,
      maxFeeMojos: 10_000_000_000n,
      elicit: null,
    };
    const tool = async (name: string, args: Record<string, unknown> = {}) =>
      (await call(ctx, name, args)) as unknown as { isError: boolean; structuredContent: Record<string, unknown> };

    const paired = await tool("pair");
    expect(paired.isError).toBe(false);
    const uri = paired.structuredContent["pairing_string"] as string;
    expect(uri).toContain(`d=localhost:${api.port}&`);
    expect(api.signed).toHaveLength(1);
    // The wallet checks the pairing against nodexch's published document.
    const phone = new AgentWallet({
      relay: new RelayClient(RELAY, { fetch: relay.fetch }),
      originDocument: api.document,
      rules: { agent: { name: "test" }, paused: false, methods: [], assets: [], bands: [], limits: [], maxOfferSeconds: 60 },
      balances: {},
      decodeOffer: async () => null,
    });
    closers.push(() => phone.close());
    const sas = await phone.pair(uri);
    const status = await tool("pairing_status", { wait_seconds: 5 });
    expect(status.structuredContent["code"]).toBe(sas);
    const [confirmed] = await Promise.all([tool("confirm_pairing", { codes_match: true }), phone.confirm()]);
    expect(confirmed.structuredContent["paired"]).toBe(true);
    const doc = await tool("origin_document");
    expect(doc.structuredContent).toMatchObject({ published_by: "nodexch", domain: `localhost:${api.port}` });
  });

  it("says plainly when nodexch refuses the key or answers an odd origin", async () => {
    const api = await nodexch();
    const origin = await openNodexchOrigin(api.url, "nxs_wrong");
    await expect(origin.sign(Buffer.from("x").toString("base64url"))).rejects.toThrow(/NODEXCH_KEY must be an active secret key/);
    const odd = await nodexch({ public_key: "short" });
    await expect(openNodexchOrigin(odd.url, KEY)).rejects.toThrow(/unknown shape/);
    await expect(openNodexchOrigin("http://127.0.0.1:9", KEY)).rejects.toThrow(/cannot be reached/);
    // Plain http only on the loopback: the key travels with every pairing.
    await expect(openNodexchOrigin("http://api.nodexch.example", KEY)).rejects.toThrow(/must be https/);
    // A domain that does not publish the key nodexch names: said before any wallet refuses.
    const unpublished = await nodexch({ unpublished: true });
    await expect(openNodexchOrigin(unpublished.url, KEY)).rejects.toThrow(/does not list the key/);
    const otherDomain = await nodexch({ domain: "evil example" });
    await expect(openNodexchOrigin(otherDomain.url, KEY)).rejects.toThrow(/unknown shape/);
  });
});
