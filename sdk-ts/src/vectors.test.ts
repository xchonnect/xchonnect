// Checks the WASM core against the published test vectors in docs/spec/vectors/
// (format: docs/spec/vectors/README.md). The `vector*` exports take keys, secrets and
// nonces explicitly; they are test-only and not part of the SDK API.
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import * as core from "../wasm/xchonnect.js";

core.initSync({ module: readFileSync(new URL("../wasm/xchonnect_bg.wasm", import.meta.url)) });

type Obj = Record<string, unknown>;
type VectorFile = { format: number; protocol_version: number; cases: Obj[] };

const load = (name: string): VectorFile =>
  JSON.parse(readFileSync(new URL(`../../docs/spec/vectors/${name}`, import.meta.url), "utf8")) as VectorFile;

const str = (o: Obj, k: string): string => {
  const v = o[k];
  if (typeof v !== "string") throw new Error(`field ${k} is not a string`);
  return v;
};
const num = (o: Obj, k: string): number => {
  const v = o[k];
  if (typeof v !== "number") throw new Error(`field ${k} is not a number`);
  return v;
};
const obj = (o: Obj, k: string): Obj => o[k] as Obj;

const hexToB64 = (hex: string) => Buffer.from(hex, "hex").toString("base64url");
const b64ToHex = (b64: string) => Buffer.from(b64, "base64url").toString("hex");
const sha256Hex = (b: Buffer) => createHash("sha256").update(b).digest("hex");

/** `<base>_hex` or `<base>_segments` (literal hex and `repeat`/`count` runs). */
function bytesOf(o: Obj, base: string): Buffer {
  const hex = o[`${base}_hex`];
  if (typeof hex === "string") return Buffer.from(hex, "hex");
  const segs = o[`${base}_segments`] as Obj[];
  return Buffer.concat(
    segs.map((s) =>
      typeof s.hex === "string" ? Buffer.from(s.hex, "hex") : Buffer.alloc(num(s, "count"), Buffer.from(str(s, "repeat"), "hex")),
    ),
  );
}

const dir = (o: Obj) => (str(o, "direction") === "dapp_to_wallet" ? 1 : 2);

/** WASM errors are the core's `Display` strings; map them back to vector error kinds. */
const KIND_MESSAGES: Record<string, RegExp> = {
  bad_signature: /^origin signature invalid$/,
  invalid_origin: /^invalid origin document/,
  uri_expired: /^pairing URI expired$/,
  decrypt: /^decryption failed$/,
  malformed: /^malformed message/,
  cbor: /^invalid CBOR/,
  unsupported_version: /^unsupported protocol version$/,
  too_large: /^message too large$/,
  replay: /^replayed or reordered message$/,
  expired: /^message expired$/,
  lifetime_too_long: /^message lifetime exceeds 7 days$/,
  clock_skew: /^message issued in the future$/,
};

const pairing = load("pairing.json");
const pairingCase = (name: string) => {
  const c = pairing.cases.find((x) => x.name === name);
  if (!c) throw new Error(`no pairing case ${name}`);
  return c;
};

function dappFromVector(c: Obj) {
  const i = obj(c, "inputs");
  const o = obj(c, "outputs");
  const ticket = i.ticket_hex;
  return core.vectorDappPairing(
    str(i, "relay"),
    str(i, "domain"),
    hexToB64(str(i, "pairing_mailbox_hex")),
    hexToB64(str(i, "pairing_write_token_hex")),
    num(i, "lifetime_s"),
    num(i, "created_at"),
    str(i, "kid"),
    typeof ticket === "string" ? hexToB64(ticket) : undefined,
    hexToB64(str(i, "dsk_hex")),
    hexToB64(str(i, "pairing_secret_hex")),
    hexToB64(str(o, "origin_signature_hex")),
    hexToB64(str(o, "origin_pk_hex")),
  );
}

describe("test vectors: pairing.json", () => {
  for (const c of pairing.cases) {
    it(`reproduces pairing case ${str(c, "name")}`, () => {
      const i = obj(c, "inputs");
      const o = obj(c, "outputs");
      const seed = hexToB64(str(i, "origin_seed_hex"));
      expect(b64ToHex(core.devPublicKey(seed))).toBe(str(o, "origin_pk_hex"));
      expect(b64ToHex(core.devSign(seed, hexToB64(str(o, "uri_sig_input_hex"))))).toBe(str(o, "origin_signature_hex"));
      expect(b64ToHex(core.sha256(hexToB64(str(o, "uri_sig_input_hex"))))).toBe(str(o, "h_uri_hex"));

      const dapp = dappFromVector(c);
      expect(dapp.uri()).toBe(str(o, "uri"));
      expect(dapp.expiresAt()).toBe(num(o, "expires_at"));
      expect(JSON.parse(core.inspectUri(str(o, "uri"), false))).toMatchObject({
        relay: str(i, "relay"),
        domain: str(i, "domain"),
        expiresAt: num(o, "expires_at"),
      });

      const name = i.wallet_name;
      const reply = core.vectorWalletReply(
        str(o, "uri"),
        str(o, "origin_document"),
        num(i, "reply_at"),
        hexToB64(str(i, "wallet_mailbox_hex")),
        core.generateToken(),
        hexToB64(str(i, "wallet_write_token_hex")),
        typeof name === "string" ? name : undefined,
        hexToB64(str(i, "ikm_e_hex")),
      );
      const out = reply.takeOutgoing();
      expect(b64ToHex(out.envelope)).toBe(str(o, "envelope_hex"));
      expect(b64ToHex(out.mailbox)).toBe(str(i, "pairing_mailbox_hex"));
      expect(reply.takePairing().sas()).toBe(str(o, "sas_display"));

      const accepted = dapp.onReply(num(i, "reply_at"), out.envelope);
      expect(accepted.sas()).toBe(str(o, "sas_display"));
      expect(accepted.walletName() ?? null).toBe(i.wallet_name);

      const keys = JSON.parse(core.vectorEpochKeys(hexToB64(str(o, "root_0_hex")))) as Record<string, string>;
      expect(b64ToHex(keys.d2w!)).toBe(str(o, "k_d2w_hex"));
      expect(b64ToHex(keys.w2d!)).toBe(str(o, "k_w2d_hex"));
      expect(b64ToHex(keys.ck!)).toBe(str(o, "ck_0_hex"));
      expect(keys.sas).toBe(str(o, "sas_digits"));
      // th = SHA-256("xchonnect v1 transcript" || h_uri || enc || ct_pair)
      const th = Buffer.concat([
        Buffer.from("xchonnect v1 transcript"),
        Buffer.from(str(o, "h_uri_hex"), "hex"),
        Buffer.from(str(o, "enc_hex"), "hex"),
        Buffer.from(str(o, "ct_pair_hex"), "hex"),
      ]);
      expect(sha256Hex(th)).toBe(str(o, "th_hex"));
    });
  }
});

describe("test vectors: envelope.json", () => {
  const envelopes = load("envelope.json");
  it("has one case per padding bucket", () => {
    expect(envelopes.cases.map((c) => num(c, "ct_len"))).toEqual([1024, 4096, 16384, 65536, 262144]);
  });
  for (const c of envelopes.cases) {
    it(`seals and opens envelope case ${str(c, "name")}`, () => {
      const inner = bytesOf(c, "inner_cbor");
      expect(inner.length).toBe(num(c, "inner_cbor_len"));
      expect(sha256Hex(inner)).toBe(str(c, "inner_cbor_sha256_hex"));
      const mbx = hexToB64(str(c, "recipient_mailbox_hex"));
      const key = hexToB64(str(c, "key_hex"));
      expect(b64ToHex(core.vectorAad(dir(c), mbx))).toBe(str(c, "aad_hex"));
      const env = Buffer.from(core.vectorSealSession(key, hexToB64(str(c, "nonce_hex")), dir(c), mbx, inner.toString("base64url")), "base64url");
      expect(env.length).toBe(num(c, "envelope_len"));
      expect(sha256Hex(env)).toBe(str(c, "envelope_sha256_hex"));
      if (typeof c.envelope_hex === "string") expect(env.toString("hex")).toBe(c.envelope_hex);
      expect(env.subarray(env.length - 16).toString("hex")).toBe(str(c, "tag_hex"));
      expect(b64ToHex(core.vectorOpenSession(key, dir(c), mbx, env.toString("base64url")))).toBe(inner.toString("hex"));
    });
  }
});

describe("test vectors: rotation.json", () => {
  const rotation = load("rotation.json");
  it("chains from pairing case basic", () => {
    expect(str(obj(rotation.cases[0]!, "inputs"), "ck_e_hex")).toBe(str(obj(pairingCase("basic"), "outputs"), "ck_0_hex"));
  });
  for (const c of rotation.cases) {
    it(`derives rotation case ${str(c, "name")}`, () => {
      const i = obj(c, "inputs");
      const o = obj(c, "outputs");
      const r = JSON.parse(
        core.vectorRotate(hexToB64(str(i, "ck_e_hex")), hexToB64(str(i, "a_hex")), hexToB64(str(i, "b_hex")), num(o, "new_epoch")),
      ) as Record<string, string>;
      expect(b64ToHex(r.aPub!)).toBe(str(o, "a_pub_hex"));
      expect(b64ToHex(r.bPub!)).toBe(str(o, "b_pub_hex"));
      expect(b64ToHex(r.root!)).toBe(str(o, "root_hex"));
      const keys = JSON.parse(core.vectorEpochKeys(r.root!)) as Record<string, string>;
      expect(b64ToHex(keys.d2w!)).toBe(str(o, "k_d2w_hex"));
      expect(b64ToHex(keys.w2d!)).toBe(str(o, "k_w2d_hex"));
      expect(b64ToHex(keys.ck!)).toBe(str(o, "ck_hex"));
      // th_r = SHA-256("xchonnect v1 rotate" || u64_be(e+1) || A || B)
      const epoch = Buffer.alloc(8);
      epoch.writeBigUInt64BE(BigInt(num(o, "new_epoch")));
      const thr = Buffer.concat([Buffer.from("xchonnect v1 rotate"), epoch, Buffer.from(str(o, "a_pub_hex"), "hex"), Buffer.from(str(o, "b_pub_hex"), "hex")]);
      expect(sha256Hex(thr)).toBe(str(o, "th_r_hex"));
    });
  }
});

describe("test vectors: negative.json", () => {
  const negative = load("negative.json");
  // session_receive needs a restored session with a given last seq; the WASM API has no
  // deterministic constructor for that, so those cases are covered by the Rust suite.
  const run: Record<string, ((c: Obj) => unknown) | undefined> = {
    verify_uri: (c) =>
      core.WalletPairing.reply(str(c, "uri"), str(c, "origin_document"), num(c, "now"), hexToB64("00".repeat(16)), core.generateToken(), core.generateToken(), undefined, false),
    dapp_on_reply: (c) => dappFromVector(pairingCase(str(c, "pairing_case"))).onReply(num(c, "now"), hexToB64(str(c, "envelope_hex"))),
    decode_envelope: (c) => core.vectorDecodeEnvelope(bytesOf(c, "envelope").toString("base64url")),
    open_session: (c) => core.vectorOpenSession(hexToB64(str(c, "key_hex")), dir(c), hexToB64(str(c, "recipient_mailbox_hex")), hexToB64(str(c, "envelope_hex"))),
    seal_session: (c) =>
      core.vectorSealSession(hexToB64(str(c, "key_hex")), hexToB64(str(c, "nonce_hex")), dir(c), hexToB64(str(c, "recipient_mailbox_hex")), bytesOf(c, "inner_cbor").toString("base64url")),
  };
  const checked = negative.cases.filter((c) => run[str(c, "check")]);
  it("covers every negative case except session_receive", () => {
    const skipped = negative.cases.filter((c) => !run[str(c, "check")]).map((c) => str(c, "check"));
    expect(new Set(skipped)).toEqual(new Set(["session_receive"]));
    expect(checked.length).toBeGreaterThan(20);
  });
  for (const c of checked) {
    it(`rejects ${str(c, "id")} (${str(c, "expected_error")})`, () => {
      const pattern = KIND_MESSAGES[str(c, "expected_error")];
      expect(pattern).toBeDefined();
      expect(() => run[str(c, "check")]!(c)).toThrow(pattern!);
    });
  }
});
