import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import * as core from "../wasm/xchonnect.js";

core.initSync({ module: readFileSync(new URL("../wasm/xchonnect_bg.wasm", import.meta.url)) });

const b64 = (bytes: Uint8Array) => Buffer.from(bytes).toString("base64url");

describe("wasm core", () => {
  it("generates tokens and hashes them", () => {
    const t = core.generateToken();
    expect(t).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(core.tokenHash(t)).not.toEqual(core.tokenHash(core.generateToken()));
    expect(() => core.tokenHash("short")).toThrow();
  });

  it("prepares, signs and finishes a pairing URI", () => {
    const seed = b64(new Uint8Array(32).fill(7));
    const now = Math.floor(Date.now() / 1000);
    const unsigned = core.UnsignedPairing.prepare(
      "https://relay.example",
      "pengui.xyz",
      b64(new Uint8Array(16).fill(1)),
      core.generateToken(),
      120,
      now,
      "k1",
      undefined,
      false,
    );
    const sig = core.devSign(seed, unsigned.sigInput());
    const pairing = unsigned.finish(sig, core.devPublicKey(seed));
    expect(pairing.uri()).toMatch(/^xchonnect:v1\?r=https%3A%2F%2Frelay\.example&m=/);
    expect(pairing.universalLink("https://klimper.app/pair")).toContain("https://klimper.app/pair#r=");
    expect(pairing.expiresAt()).toBe(now + 120);
    // A reply that is not a valid envelope is rejected without consuming the pairing.
    expect(() => pairing.onReply(now, "AAAA")).toThrow();
  });

  it("rejects a signature from the wrong key early", () => {
    const now = Math.floor(Date.now() / 1000);
    const unsigned = core.UnsignedPairing.prepare("https://r.example", "pengui.xyz", b64(new Uint8Array(16)), core.generateToken(), 60, now, "k1", undefined, false);
    const sig = core.devSign(b64(new Uint8Array(32).fill(1)), unsigned.sigInput());
    expect(() => unsigned.finish(sig, core.devPublicKey(b64(new Uint8Array(32).fill(2))))).toThrow(/signature/);
  });

  it("solves proof-of-work challenges", () => {
    // 42-byte challenge with difficulty 4 (MAC is irrelevant for solving).
    const c = new Uint8Array(42);
    c[0] = 1;
    c[9] = 4;
    expect(core.solvePow(b64(c))).toMatch(/^[A-Za-z0-9_-]{11}$/);
  });
});
