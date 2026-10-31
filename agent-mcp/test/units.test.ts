import { mkdtemp, readFile, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { XchonnectRpcError, XchonnectError } from "@xchonnect/dapp";
import { assetId, feeMojos, fromMojos, toMojos } from "../src/amounts.js";
import { MemoryKeychain, sessionKey } from "../src/keychain.js";
import { matrix, png, text } from "../src/qr.js";
import { AGENT_REASONS } from "../src/rules.js";
import { EncryptedFileStore } from "../src/store.js";
import { fromWalletError } from "../src/wallet.js";

const TDBX = "d82dd03f8a9ad2f84353cd953c4de6b21dbaaf7de3ba3f4ddd9abe31ecba80ad";

describe("amounts", () => {
  it("converts units to mojos exactly and refuses what an asset cannot hold", () => {
    expect(toMojos("0.25", "xch")).toBe(250_000_000_000n);
    expect(toMojos("1", TDBX)).toBe(1000n);
    expect(toMojos("12.345", TDBX)).toBe(12_345n);
    expect(() => toMojos("12.3456", TDBX)).toThrow(/3 decimals/);
    expect(toMojos("18446744.073709551615", "xch")).toBe(18_446_744_073_709_551_615n);
    expect(() => toMojos("0", "xch")).toThrow(/more than 0/);
    expect(() => toMojos("-1", "xch")).toThrow();
    expect(() => toMojos("1e3", "xch")).toThrow();
    expect(fromMojos(250_000_000_000n, "xch")).toBe("0.25");
    expect(fromMojos("12345", TDBX)).toBe("12.345");
    expect(feeMojos(undefined)).toBe(0n);
    expect(feeMojos("0.0001")).toBe(100_000_000n);
  });

  it("takes xch or an asset id, and sends a ticker to the lookup", () => {
    expect(assetId("XCH")).toBe("xch");
    expect(assetId(`0x${TDBX.toUpperCase()}`)).toBe(TDBX);
    expect(() => assetId("TDBX")).toThrow(/search_assets/);
  });
});

describe("the state file", () => {
  it("round-trips, is private to the user, and refuses another key", async () => {
    const dir = await mkdtemp(join(tmpdir(), "xcmcp-"));
    const path = join(dir, "state", "state.bin");
    const key = await sessionKey(new MemoryKeychain());
    const store = new EncryptedFileStore(path, key);
    await store.save("default", "secret session bytes");
    await store.save("offers", "[]");
    expect(await new EncryptedFileStore(path, key).load("default")).toBe("secret session bytes");
    expect((await stat(path)).mode & 0o777).toBe(0o600);
    expect((await readFile(path)).includes(Buffer.from("secret session"))).toBe(false);
    const other = new EncryptedFileStore(path, Buffer.alloc(32, 7));
    await expect(other.load("default")).rejects.toThrow(/does not decrypt/);
    await store.clear("default");
    expect(await new EncryptedFileStore(path, key).load("default")).toBeNull();
    await writeFile(path, "garbage");
    await expect(new EncryptedFileStore(path, key).load("default")).rejects.toThrow(/not a session file/);
  });

  it("keeps one key in the keychain once made", async () => {
    const keychain = new MemoryKeychain();
    const first = await sessionKey(keychain);
    expect(await sessionKey(keychain)).toEqual(first);
  });
});

describe("the pairing QR code", () => {
  it("draws text two rows per line with a quiet zone, and writes a PNG", () => {
    const m = matrix("xchonnect:v1?r=https%3A%2F%2Frelay.example&m=abc");
    const n = m.length;
    const lines = text(m).split("\n");
    expect(lines.length).toBe(Math.ceil((n + 4) / 2));
    expect(lines.every((l) => [...l].length === n + 4)).toBe(true);
    // Dark terminal: the quiet zone is drawn (light), the finder's corner is not.
    expect(lines[0]?.startsWith("████")).toBe(true);
    const image = png(m, 4);
    expect(image.subarray(1, 4).toString()).toBe("PNG");
    expect(image.readUInt32BE(16)).toBe((n + 8) * 4);
  });
});

describe("wallet errors", () => {
  it("names every agent refusal by its reason, and the rest by a fixed code", () => {
    for (const reason of AGENT_REASONS) {
      const code = reason.startsWith("limit_") ? 4029 : 4001;
      const err = fromWalletError(new XchonnectRpcError(code, "refused", JSON.stringify({ reason, rule: { assetId: "xch" } })));
      expect(err.code).toBe(reason);
      expect(err.detail).toEqual({ rule: { assetId: "xch" } });
    }
    expect(fromWalletError(new XchonnectRpcError(4002, "no")).code).toBe("user_rejected");
    expect(fromWalletError(new XchonnectRpcError(4004, "no")).code).toBe("not_supported");
    expect(fromWalletError(new XchonnectRpcError(4101, "cannot decode")).code).toBe("cannot_decode");
    expect(fromWalletError(new XchonnectRpcError(4001, "no", '{"reason":"agg_sig_unsafe"}')).code).toBe("refused");
    // A reason outside the closed list is not taken for one of it.
    expect(fromWalletError(new XchonnectRpcError(4001, "no", '{"reason":"made_up"}')).code).toBe("refused");
    expect(fromWalletError(new XchonnectError("not_active", "x")).code).toBe("not_paired");
    expect(fromWalletError(new XchonnectError("session_ended", "x")).code).toBe("session_ended");
    expect(fromWalletError(new TypeError("fetch failed")).code).toBe("relay_unreachable");
  });
});
