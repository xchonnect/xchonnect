/**
 * What the review and the audit of TASK-80.1 found, held in place: one process per state
 * directory, offer records that survive concurrent answers, a server that malformed input
 * cannot stop, and a pairing code the user confirms, not the model.
 */
import { spawn } from "node:child_process";
import { mkdtemp, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { toMojos } from "../src/amounts.js";
import { MemoryKeychain, sessionKey } from "../src/keychain.js";
import { OfferBook, type OfferRecord } from "../src/offers.js";
import { Server } from "../src/server.js";
import { EncryptedFileStore, lockDirectory, privateDirectory } from "../src/store.js";
import { list, type Context } from "../src/tools.js";
import type { Wallet } from "../src/wallet.js";

function record(id: string, extra: Partial<OfferRecord> = {}): OfferRecord {
  return { id, offer: "offer1x", gives: [], gets: [], createdAt: 1, status: "open", ...extra };
}

function context(wallet: Partial<Wallet> | null): Context {
  return {
    wallet: wallet as Wallet | null,
    origin: null,
    offers: new OfferBook({ load: async () => null, update: async () => {} }),
    relay: "http://127.0.0.1:8787",
    keychain: "memory",
    openViewer: false,
    maxFeeMojos: 10_000_000_000n,
    elicit: null,
  };
}

describe("one process per state directory", () => {
  it("refuses a second live holder and takes over a lock left by a dead one", async () => {
    const dir = await mkdtemp(join(tmpdir(), "xcmcp-lock-"));
    // Another live process holds it.
    const other = spawn(process.execPath, ["-e", "setTimeout(() => {}, 20000)"], { stdio: "ignore" });
    try {
      await writeFile(join(dir, "state.lock"), String(other.pid));
      await expect(lockDirectory(dir)).rejects.toThrow(/another session of the plugin/);
    } finally {
      other.kill();
    }
    // A lock whose process is gone is taken over.
    await writeFile(join(dir, "state.lock"), "999999");
    await expect(lockDirectory(dir)).resolves.toBeUndefined();
  });

  it("makes the directory private", async () => {
    const dir = join(await mkdtemp(join(tmpdir(), "xcmcp-dir-")), "state");
    await privateDirectory(dir);
    expect((await stat(dir)).mode & 0o777).toBe(0o700);
  });
});

describe("offer records", () => {
  it("keep every record when answers arrive together", async () => {
    const dir = await mkdtemp(join(tmpdir(), "xcmcp-offers-"));
    const store = new EncryptedFileStore(join(dir, "state.bin"), await sessionKey(new MemoryKeychain()));
    const book = new OfferBook(store);
    await Promise.all(["a", "b", "c"].map((id) => book.add(record(id))));
    expect((await book.list()).map((o) => o.id).sort()).toEqual(["a", "b", "c"]);
  });

  it("show an offer as expired only when the wallet enforces its expiry", async () => {
    const dir = await mkdtemp(join(tmpdir(), "xcmcp-expiry-"));
    const book = new OfferBook(new EncryptedFileStore(join(dir, "state.bin"), await sessionKey(new MemoryKeychain())));
    await book.add(record("enforced", { expiresAt: 10, expiryEnforced: true }));
    await book.add(record("asked", { expiresAt: 10 }));
    const byId = Object.fromEntries((await book.list(100)).map((o) => [o.id, o.status]));
    expect(byId).toEqual({ enforced: "expired", asked: "open" });
  });
});

describe("the stdio server", () => {
  it("answers malformed messages instead of stopping", async () => {
    const server = new Server(context(null), "xchonnect", "test", () => {});
    expect(await server.handle(null)).toMatchObject({ id: null, error: { code: -32600 } });
    expect(await server.handle([1])).toMatchObject({ error: { code: -32600 } });
    expect(await server.handle({ jsonrpc: "2.0", id: 4, method: 7 })).toMatchObject({ id: 4, error: { code: -32600 } });
    expect(await server.handle({ jsonrpc: "2.0", method: "notifications/initialized" })).toBeUndefined();
  });

  it("asks the user to compare the pairing code when the client can, whatever the agent says", async () => {
    const confirmed: boolean[] = [];
    const wallet = {
      pairingStatus: async () => ({ phase: "compare_code" as const, code: "123 456" }),
      confirmPairing: async (m: boolean) => void confirmed.push(m),
    };
    const sent: Record<string, unknown>[] = [];
    const server = new Server(context(wallet), "xchonnect", "test", (m) => sent.push(m as Record<string, unknown>));
    await server.handle({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: { elicitation: {} } } });

    // The agent says yes; the user says no: the user decides.
    const call = server.handle({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "confirm_pairing", arguments: { codes_match: true } } });
    await new Promise((r) => setTimeout(r, 10));
    const question = sent.find((m) => m["method"] === "elicitation/create") as { id: string; params: { message: string } };
    expect(question.params.message).toContain("123 456");
    await server.handle({ jsonrpc: "2.0", id: question.id, result: { action: "accept", content: { matches: false } } });
    expect(await call).toMatchObject({ id: 2, result: { structuredContent: { paired: false } } });
    expect(confirmed).toEqual([false]);
  });

  it("falls back to the agent's answer for a client that cannot ask", async () => {
    const confirmed: boolean[] = [];
    const wallet = {
      pairingStatus: async () => ({ phase: "compare_code" as const, code: "123 456" }),
      confirmPairing: async (m: boolean) => void confirmed.push(m),
    };
    const server = new Server(context(wallet), "xchonnect", "test", () => {});
    await server.handle({ jsonrpc: "2.0", id: 1, method: "initialize", params: { capabilities: {} } });
    const answer = (await server.handle({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "confirm_pairing", arguments: {} } })) as { result: { isError: boolean } };
    expect(answer.result.isError).toBe(true);
    await server.handle({ jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "confirm_pairing", arguments: { codes_match: true } } });
    expect(confirmed).toEqual([true]);
  });
});

describe("tool hints and amounts", () => {
  it("marks what changes the pairing or moves funds", () => {
    const hints = Object.fromEntries((list() as { name: string; annotations: { readOnlyHint: boolean; destructiveHint: boolean } }[]).map((t) => [t.name, t.annotations]));
    for (const name of ["take_offer", "create_offer", "cancel_offer"]) expect(hints[name]).toMatchObject({ readOnlyHint: false, destructiveHint: true });
    for (const name of ["pair", "confirm_pairing", "end_session", "cancel_request"]) expect(hints[name]?.readOnlyHint).toBe(false);
    for (const name of ["get_rules", "get_balances", "list_offers", "wallet_status"]) expect(hints[name]?.readOnlyHint).toBe(true);
  });

  it("refuses a JSON number that has already lost digits", () => {
    expect(() => toMojos(123456789012345678, "xch")).toThrow(/as a string/);
    expect(toMojos(2, "xch")).toBe(2_000_000_000_000n);
    expect(toMojos("123456789012345678", "d82dd03f8a9ad2f84353cd953c4de6b21dbaaf7de3ba3f4ddd9abe31ecba80ad")).toBe(123456789012345678000n);
  });
});
