/**
 * OHTTP gateway interop with an independent client implementation (TASK-51).
 *
 * The relay's gateway uses Mozilla's Rust `ohttp`/`bhttp` crates. This test talks to the
 * relay binary (a separate process) with `ohttp-js` (Christopher Wood; TypeScript on
 * `hpke-js` and `bhttp-js`), which shares no code with the Rust stack. It covers both
 * advertised suites (AES-128-GCM and ChaCha20-Poly1305), a request body, bearer
 * authentication and the key-configuration problem response.
 *
 * Not yet covered: production OHTTP clients/relays such as Cloudflare's
 * privacy-gateway or Fastly's OHTTP relay service (spec 10.2); test against the chosen
 * partner before enabling OHTTP in a hosted tier.
 *
 * Requires: cargo build -p xchonnect-relay
 */
import type { ChildProcess } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { Client, PublicKeyConfig } from "ohttp-js";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { startRelay } from "./harness.js";

const KEY_SEED = Buffer.alloc(32, 0x51).toString("base64url");
const OLD_SEED = Buffer.alloc(32, 0x50).toString("base64url");
const AES_128_GCM = 1;
const CHACHA20_POLY1305 = 3;

let relay: ChildProcess;
let relayUrl = "";

beforeAll(async () => {
  ({ proc: relay, url: relayUrl } = await startRelay({ XCHONNECT_CREATION: "open", XCHONNECT_OHTTP_KEYS: `2:${KEY_SEED},1:${OLD_SEED}` }));
}, 30_000);

afterAll(() => {
  relay?.kill();
});

interface ParsedConfig {
  keyId: number;
  publicKey: Uint8Array;
  suites: [number, number][];
}

/** Parse an `application/ohttp-keys` list (RFC 9458 section 3). */
function parseKeyList(list: Uint8Array): ParsedConfig[] {
  const out: ParsedConfig[] = [];
  let i = 0;
  while (i < list.length) {
    const len = (list[i]! << 8) | list[i + 1]!;
    const c = list.subarray(i + 2, i + 2 + len);
    expect((c[1]! << 8) | c[2]!).toBe(0x0020); // DHKEM(X25519, HKDF-SHA256)
    const suitesLen = (c[35]! << 8) | c[36]!;
    const suites: [number, number][] = [];
    for (let j = 37; j < 37 + suitesLen; j += 4) suites.push([(c[j]! << 8) | c[j + 1]!, (c[j + 2]! << 8) | c[j + 3]!]);
    out.push({ keyId: c[0]!, publicKey: c.slice(3, 35), suites });
    i += 2 + len;
  }
  return out;
}

async function clientFor(cfg: ParsedConfig, aead: number): Promise<Client> {
  // ohttp-js does not export its config parser; build the public config directly.
  const pkc = new PublicKeyConfig(cfg.keyId, 0x0020, 1, aead, undefined);
  const kem = await pkc.suite.kemContext();
  pkc.publicKey = await kem.deserializePublicKey(cfg.publicKey.buffer.slice(cfg.publicKey.byteOffset, cfg.publicKey.byteOffset + 32) as ArrayBuffer);
  return new Client(pkc);
}

/** Encapsulate `req`; the test plays the OHTTP relay and forwards the opaque body to the gateway. */
async function forward(client: Client, req: Request) {
  const ctx = await client.encapsulateRequest(req);
  const res = await fetch(`${relayUrl}/.well-known/ohttp-gateway`, { method: "POST", headers: { "content-type": "message/ohttp-req" }, body: ctx.request.encode() });
  return { ctx, res };
}

async function viaGateway(client: Client, req: Request): Promise<Response> {
  const { ctx, res } = await forward(client, req);
  expect(res.status).toBe(200);
  return ctx.decapsulateResponse(res);
}

const tokenHash = (t: Buffer) =>
  createHash("sha256").update("xchonnect v1 token").update(t).digest().toString("base64url");

describe("relay OHTTP gateway with ohttp-js", () => {
  let configs: ParsedConfig[] = [];

  it("serves the key configuration list", async () => {
    const res = await fetch(`${relayUrl}/.well-known/ohttp-keys`);
    expect(res.headers.get("content-type")).toBe("application/ohttp-keys");
    configs = parseKeyList(new Uint8Array(await res.arrayBuffer()));
    expect(configs.map((c) => c.keyId)).toEqual([2, 1]);
    expect(configs[0]!.suites).toEqual([
      [1, AES_128_GCM],
      [1, CHACHA20_POLY1305],
    ]);
  });

  for (const [name, aead] of [
    ["AES-128-GCM", AES_128_GCM],
    ["ChaCha20-Poly1305", CHACHA20_POLY1305],
  ] as const) {
    it(`GET /v1/info with ${name} under the current and the previous key`, async () => {
      for (const cfg of configs) {
        const res = await viaGateway(await clientFor(cfg, aead), new Request("https://relay.example/v1/info"));
        expect(res.status).toBe(200);
        const info = (await res.json()) as { ohttp: boolean; max_wait_ohttp_s: number };
        expect(info.ohttp).toBe(true);
        expect(info.max_wait_ohttp_s).toBe(0);
      }
    });
  }

  it("creates, reads and deletes a mailbox through the gateway", async () => {
    const client = await clientFor(configs[0]!, AES_128_GCM);
    const read = randomBytes(32);
    const write = randomBytes(32);
    const created = await viaGateway(
      client,
      new Request("https://relay.example/v1/mailboxes", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ read_token_hash: tokenHash(read), write_token_hash: tokenHash(write) }),
      }),
    );
    expect(created.status).toBe(201);
    const { mailbox_id } = (await created.json()) as { mailbox_id: string };
    const auth = (t: Buffer) => ({ authorization: `Bearer ${t.toString("base64url")}` });
    const url = `https://relay.example/v1/mailboxes/${mailbox_id}`;

    const msgs = await viaGateway(client, new Request(`${url}/messages?wait=5`, { headers: auth(read) }));
    expect(msgs.status).toBe(200);
    expect(await msgs.json()).toEqual({ messages: [] });

    const wrong = await viaGateway(client, new Request(`${url}/messages`, { headers: auth(write) }));
    expect(wrong.status).toBe(404);
    expect(await wrong.text()).toBe('{"error":"not_found"}');

    // bhttp-js builds a WHATWG Response with an (empty) body for every status, which the
    // Response constructor rejects for 204; read the binary HTTP status directly instead.
    const { ctx, res } = await forward(client, new Request(url, { method: "DELETE", headers: auth(read) }));
    const plain = await ctx.decodeAndDecapsulate(new Uint8Array(await res.arrayBuffer()));
    // Framing indicator 1 (known-length response), status as a 2-byte varint.
    expect(plain[0]).toBe(1);
    expect(((plain[1]! & 0x3f) << 8) | plain[2]!).toBe(204);
  });

  // Spec 10.5 / TASK-69 AC #3: the gateway pads its inner responses to a size bucket, and
  // an independent implementation accepts them. bhttp-js validates RFC 9292 padding (it
  // rejects a non-zero byte after the message), so every decapsulation above is a padded
  // round trip; here the length and the padding bytes are checked explicitly. An unpadded
  // request from a generic client is accepted.
  it("pads inner responses to a size bucket and accepts unpadded requests", async () => {
    const client = await clientFor(configs[0]!, CHACHA20_POLY1305);
    for (const path of ["/v1/info", "/.well-known/ohttp-keys"]) {
      const req = new Request(`https://relay.example${path}`);
      const ctx = await client.encapsulateRequest(req);
      const encoded = ctx.request.encode();
      // ohttp-js does not pad: 7-byte header + 32-byte enc + sealed message.
      expect(encoded.length).toBeLessThan(2048);
      const res = await fetch(`${relayUrl}/.well-known/ohttp-gateway`, { method: "POST", headers: { "content-type": "message/ohttp-req" }, body: encoded });
      expect(res.status).toBe(200);
      const plain = await ctx.decodeAndDecapsulate(new Uint8Array(await res.arrayBuffer()));
      expect(plain.length).toBe(2048);
      // Framing indicator 1 (known-length response) and status 200.
      expect(plain[0]).toBe(1);
      expect(((plain[1]! & 0x3f) << 8) | plain[2]!).toBe(200);
      // Everything after the message is zero.
      expect(plain.subarray(plain.length - 512).every((b) => b === 0)).toBe(true);
    }
    // And bhttp-js itself decodes a padded response (its decoder validates the padding).
    const decoded = await viaGateway(client, new Request("https://relay.example/v1/info"));
    expect(((await decoded.json()) as { ohttp: boolean }).ohttp).toBe(true);
  });

  it("answers an unknown key with the RFC 9458 key problem", async () => {
    const stale = { ...configs[0]!, keyId: 77 };
    const { res } = await forward(await clientFor(stale, AES_128_GCM), new Request("https://relay.example/v1/info"));
    expect(res.status).toBe(400);
    expect(res.headers.get("content-type")).toBe("application/problem+json");
    expect(((await res.json()) as { type: string }).type).toBe("https://iana.org/assignments/http-problem-types#ohttp-key");
  });
});
