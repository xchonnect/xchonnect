// Session permissions (spec 9.3). Most of these tests build the message on the wire
// rather than through a sender: a dApp session derived from the published pairing vector,
// and an envelope sealed with that vector's wallet-to-dApp key. That keeps the decode path
// under test against the real CBOR body of wire/envelope.cddl, not a hand-copied JSON
// fixture. The last group goes the other way, through the WASM wallet sender
// (`Session.permissions`), so both halves of the feature are covered.
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import * as core from "../wasm/xchonnect.js";
import { MemorySessionStore, RelayClient, type SessionPermissions } from "./index.js";
import { PermissionsView } from "./permissions.js";
import { devClient, RELAY, SEED } from "./testing/env.js";
import { FakeWallet } from "./testing/fakeWallet.js";
import { MockRelay } from "./testing/mockRelay.js";

const hexToB64 = (hex: string) => Buffer.from(hex, "hex").toString("base64url");

// --- Canonical CBOR (spec 5.4), enough for an inner plaintext: uint, bstr, tstr, array, map.
type Cbor = number | string | Buffer | Cbor[] | Map<string, Cbor>;

function head(major: number, n: number): Buffer {
  if (n < 24) return Buffer.from([(major << 5) | n]);
  if (n < 0x100) return Buffer.from([(major << 5) | 24, n]);
  const b = Buffer.alloc(n < 0x10000 ? 3 : 5);
  b[0] = (major << 5) | (n < 0x10000 ? 25 : 26);
  if (n < 0x10000) b.writeUInt16BE(n, 1);
  else b.writeUInt32BE(n, 1);
  return b;
}

function cbor(v: Cbor): Buffer {
  if (typeof v === "number") return head(0, v);
  if (typeof v === "string") return Buffer.concat([head(3, Buffer.byteLength(v)), Buffer.from(v)]);
  if (Buffer.isBuffer(v)) return Buffer.concat([head(2, v.length), v]);
  if (Array.isArray(v)) return Buffer.concat([head(4, v.length), ...v.map(cbor)]);
  // Canonical map order: shorter key first, then bytewise.
  const keys = [...v.keys()].sort((a, b) => (a.length === b.length ? (a < b ? -1 : 1) : a.length - b.length));
  return Buffer.concat([head(5, keys.length), ...keys.flatMap((k) => [cbor(k), cbor(v.get(k) as Cbor)])]);
}

type Obj = Record<string, unknown>;
const vector = (JSON.parse(readFileSync(new URL("../../docs/spec/vectors/pairing.json", import.meta.url), "utf8")) as { cases: Obj[] }).cases[0] as {
  inputs: Record<string, string | number>;
  outputs: Record<string, string>;
};
const NOW = Number(vector.inputs["reply_at"]);
const MAILBOX_D = hexToB64("ad".repeat(16));

/** The dApp side of the published pairing vector, as a session reading `MAILBOX_D`. */
function vectorSession(readToken: string, writeToken: string): core.Session {
  const { inputs: i, outputs: o } = vector;
  const h = (src: Record<string, unknown>, k: string) => hexToB64(String(src[k]));
  const dapp = core.vectorDappPairing(
    String(i["relay"]),
    String(i["domain"]),
    h(i, "pairing_mailbox_hex"),
    h(i, "pairing_write_token_hex"),
    Number(i["lifetime_s"]),
    Number(i["created_at"]),
    String(i["kid"]),
    undefined,
    h(i, "dsk_hex"),
    h(i, "pairing_secret_hex"),
    h(o, "origin_signature_hex"),
    h(o, "origin_pk_hex"),
  );
  const accepted = dapp.onReply(NOW, hexToB64(o["envelope_hex"] as string));
  return accepted.confirm(NOW, MAILBOX_D, readToken, writeToken).takeSession();
}

/** A wallet-to-dApp envelope carrying `body` under `type`, sealed with the vector's key. */
function walletEnvelope(type: string, body: Map<string, Cbor>, seq: number): string {
  const inner = new Map<string, Cbor>([
    ["id", Buffer.alloc(16, seq)],
    ["exp", NOW + 60],
    ["iat", NOW],
    ["seq", seq],
    ["body", body],
    ["type", type],
  ]);
  const nonce = hexToB64(seq.toString(16).padStart(2, "0").repeat(24));
  return core.vectorSealSession(hexToB64(vector.outputs["k_w2d_hex"] as string), nonce, 2, MAILBOX_D, cbor(inner).toString("base64url"));
}

const declaration = (methods: string[], keys: string[], limits?: Map<string, Cbor>) =>
  new Map<string, Cbor>([
    ["methods", methods],
    ["keys", keys],
    ...(limits ? ([["limits", limits]] as [string, Cbor][]) : []),
  ]);

/** A restored client whose session is the vector session, reading a mailbox we can fill. */
async function clientOnVectorSession() {
  const relay = new MockRelay();
  const storage = new MemorySessionStore();
  const read = core.generateToken();
  const write = core.generateToken();
  const session = vectorSession(read, write);
  await storage.save("default", session.toBytes());
  relay.boxes.set(MAILBOX_D, { readHash: core.tokenHash(read), writeHash: core.tokenHash(write), messages: [] });
  const make = () => devClient({ fetch: relay.fetch, storage, now: () => NOW });
  const deliver = async (env: string) => {
    relay.boxes.get(MAILBOX_D)?.messages.push({ msg_id: `m${String(relay.boxes.get(MAILBOX_D)?.messages.length)}`, env });
  };
  return { relay, storage, client: await make(), make, deliver };
}

describe("session.permissions on the wire", () => {
  it("seeds the capability view from a wallet declaration", async () => {
    const { client, deliver } = await clientOnVectorSession();
    expect(client.permissions).toEqual({ declared: false, methods: [], keys: [], refused: [] });
    expect(client.canRequest("signCoinSpends")).toBeUndefined();

    const seen: SessionPermissions[] = [];
    client.on("permissions", (p) => seen.push(p));
    await deliver(
      walletEnvelope(
        "session.permissions",
        declaration(["signCoinSpends", "getPublicKeys"], ["0xb0b0"], new Map<string, Cbor>([["per_request_mojos", "1000000000000"]])),
        1,
      ),
    );
    await client.sync();

    expect(client.permissions).toEqual({
      declared: true,
      methods: ["signCoinSpends", "getPublicKeys"],
      keys: ["0xb0b0"],
      limits: { perRequestMojos: "1000000000000" },
      refused: [],
    });
    // Asked before sending anything: no round trip, no refusal needed.
    expect(client.canRequest("signCoinSpends")).toBe(true);
    expect(client.canRequest("chip0002_signCoinSpends")).toBe(true);
    expect(client.canRequest("sendTransaction")).toBe(false);
    expect(seen).toHaveLength(1);
  });

  it("a later declaration replaces the previous one and survives a reload", async () => {
    const { client, deliver, make } = await clientOnVectorSession();
    await deliver(walletEnvelope("session.permissions", declaration(["signCoinSpends"], ["0xaa"]), 1));
    await client.sync();
    await deliver(walletEnvelope("session.permissions", declaration(["signMessage"], ["0xbb"], new Map<string, Cbor>([["per_day_mojos", "5"]])), 2));
    await client.sync();

    const expected = { declared: true, methods: ["signMessage"], keys: ["0xbb"], limits: { perDayMojos: "5" }, refused: [] };
    expect(client.permissions).toEqual(expected);
    expect(client.canRequest("signCoinSpends")).toBe(false);
    // Spec 6.4: the dApp keeps what the wallet shared, so a page reload does not go blind.
    expect((await make()).permissions).toEqual(expected);
  });

  it("ignores a session.ready without a declaration, then reads the session.permissions", async () => {
    const { client, deliver } = await clientOnVectorSession();
    await deliver(walletEnvelope("session.ready", new Map<string, Cbor>([["meta", new Map<string, Cbor>([["name", "Test Wallet"]])]]), 1));
    await client.sync();
    expect(client.permissions.declared).toBe(false);

    // The wire grammar defines the declaration only in session.permissions, and that is
    // all a wallet can send (the core drops any unknown key in a session.ready body).
    // The client reads a declaration on either message; this is the half that exists.
    await deliver(walletEnvelope("session.permissions", declaration(["chainId"], []), 2));
    await client.sync();
    expect(client.permissions).toMatchObject({ declared: true, methods: ["chainId"] });
  });

  it("drops a malformed declaration instead of throwing", async () => {
    const { client, deliver } = await clientOnVectorSession();
    await deliver(walletEnvelope("session.permissions", new Map<string, Cbor>([["methods", [1 as unknown as Cbor]]]), 1));
    await client.sync();
    // The wallet-to-dApp body is malformed for the core too, so nothing reaches the view.
    expect(client.permissions.declared).toBe(false);
    expect(client.status).not.toBe("ended");
  });
});

describe("a wallet declaring through the WASM sender", () => {
  it("reaches the dApp's capability view", async () => {
    const relay = new MockRelay();
    const fetch = relay.fetch;
    const originDocument = JSON.stringify({ v: 1, name: "Pengui", origin_keys: [{ kid: "k1", pk: core.devPublicKey(SEED), not_after: "2030-01-01" }] });
    const client = await devClient({ originPublicKey: core.devPublicKey(SEED), fetch, pollIntervalMs: 2 });
    const wallet = new FakeWallet({ relay: new RelayClient(RELAY, { fetch }), originDocument, name: "Test Wallet" });
    const pairing = await client.pair();
    await wallet.scan(pairing.uri);
    await pairing.waitForWallet();
    await wallet.confirm();
    await pairing.confirm();

    // `Session.permissions` seals the real `session.permissions` body; the hand-built
    // envelopes above check the same decode path against the published vector's keys.
    await wallet.declare(["signCoinSpends", "chip0002_getPublicKeys"], ["0xc0ffee"], { perRequestMojos: "250" });
    await client.sync();
    expect(client.permissions).toMatchObject({
      declared: true,
      methods: ["signCoinSpends", "getPublicKeys"],
      keys: ["0xc0ffee"],
      limits: { perRequestMojos: "250" },
    });
    expect(client.canRequest("signCoinSpends")).toBe(true);
    await client.end();
  });
});

describe("PermissionsView", () => {
  const view = () => new PermissionsView();

  it("starts out knowing nothing, which is not the same as allowing nothing", () => {
    expect(view().snapshot()).toEqual({ declared: false, methods: [], keys: [], refused: [] });
    expect(view().can("signMessage")).toBeUndefined();
  });

  it("narrows on a refusal and keeps it across a reload", () => {
    const v = view();
    expect(v.declare({ methods: ["signCoinSpends", "signMessage"], keys: [] })).toBe(true);
    expect(v.can("signCoinSpends")).toBe(true);
    // The wallet may refuse what it granted (spec 9.3); its answer is the one that counts.
    expect(v.refuse("signCoinSpends", 4001)).toBe(true);
    expect(v.can("signCoinSpends")).toBe(false);
    expect(v.snapshot()).toMatchObject({ methods: ["signCoinSpends", "signMessage"], refused: ["signCoinSpends"] });
    expect(PermissionsView.fromJson(v.toJson()).can("signCoinSpends")).toBe(false);
  });

  it("records only refusals that mean a method is unavailable", () => {
    const v = view();
    for (const code of [4000, 4002, 4003, 4005, 4029, 4100, 4101]) expect(v.refuse("signCoinSpends", code)).toBe(false);
    expect(v.snapshot().refused).toEqual([]);
    // A user declining is not the wallet withdrawing a scope.
    expect(v.can("signCoinSpends")).toBeUndefined();
    expect(v.refuse("chia_takeOffer", 4004)).toBe(true);
    expect(v.refuse("chip0002_chia_takeOffer", 4004)).toBe(false);
  });

  it("a fresh declaration clears the refusals it covers", () => {
    const v = view();
    v.declare({ methods: ["signMessage"], keys: [] });
    v.refuse("signMessage", 4001);
    v.refuse("sendTransaction", 4004);
    expect(v.declare({ methods: ["signMessage"], keys: [] })).toBe(true);
    expect(v.snapshot().refused).toEqual(["sendTransaction"]);
    expect(v.can("signMessage")).toBe(true);
  });

  it("reports whether a declaration changed anything", () => {
    const v = view();
    expect(v.declare({})).toBe(false);
    expect(v.declare({ methods: ["chainId"], keys: [], limits: null })).toBe(true);
    expect(v.declare({ methods: ["chainId"], keys: [], limits: null })).toBe(false);
  });

  it("keeps what it can of a hostile declaration and drops the rest", () => {
    const v = view();
    v.declare({
      methods: ["chainId", "chainId", 7, "x".repeat(129), ""],
      keys: "not a list",
      limits: { perRequestMojos: 5, perDayMojos: "9" },
    });
    expect(v.snapshot()).toEqual({ declared: true, methods: ["chainId"], keys: [], limits: { perDayMojos: "9" }, refused: [] });
    expect(PermissionsView.fromJson("not json").snapshot().declared).toBe(false);
    expect(PermissionsView.fromJson(null).snapshot().declared).toBe(false);
  });
});
