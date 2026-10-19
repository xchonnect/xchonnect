/**
 * The plugin as a library (nodexch's one install, nodexch TASK-176.04): another MCP server serves
 * the plugin's wallet tools with its own next to them, through one `Server`: one list, calls
 * routed to whoever has the tool, the instructions of both, its own title.
 */
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import * as lib from "../src/lib.js";
import { NO_RECORDS, OfferBook } from "../src/offers.js";
import { Server, type ToolProvider } from "../src/server.js";
import type { Context } from "../src/tools.js";

function context(): Context {
  return { wallet: null, origin: null, offers: new OfferBook(NO_RECORDS), relay: "https://relay.example", keychain: "none", openViewer: false, maxFeeMojos: 0n, elicit: null, setupError: "not set up in this test" };
}

const extra: ToolProvider = {
  title: "nodexch: offers and your wallet",
  instructions: "Offer data comes from nodexch.",
  list: async () => [{ name: "offer_book", title: "Offer book", description: "The open offers of a pair", inputSchema: { type: "object" } }],
  call: async (name) => (name === "offer_book" ? { content: [{ type: "text", text: "{}" }], structuredContent: { offers: [] }, isError: false } : null),
};

afterEach(() => {
  vi.restoreAllMocks();
});

describe("the plugin as a library", () => {
  it("serves its wallet tools and another server's tools as one", async () => {
    const server = new Server(context(), "nodexch", "test", () => {}, extra);
    const init = (await server.handle({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {} } })) as { result: { serverInfo: { title: string }; instructions: string } };
    expect(init.result.serverInfo.title).toBe("nodexch: offers and your wallet");
    expect(init.result.instructions).toMatch(/^Offer data comes from nodexch\. Xchonnect connects/);
    const listed = (await server.handle({ jsonrpc: "2.0", id: 2, method: "tools/list" })) as { result: { tools: { name: string }[] } };
    const names = listed.result.tools.map((t) => t.name);
    expect(names).toContain("pair");
    expect(names).toContain("create_offer");
    expect(names.at(-1)).toBe("offer_book");
    expect(new Set(names).size).toBe(names.length);
    // The other server's tool, and the plugin's own (not set up here: a fixed code, not a crash).
    const book = (await server.handle({ jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "offer_book", arguments: {} } })) as { result: { structuredContent: unknown } };
    expect(book.result.structuredContent).toEqual({ offers: [] });
    const pair = (await server.handle({ jsonrpc: "2.0", id: 4, method: "tools/call", params: { name: "pair", arguments: {} } })) as { result: { structuredContent: { error: string } } };
    expect(pair.result.structuredContent.error).toBe("not_set_up");
    const unknown = await server.handle({ jsonrpc: "2.0", id: 5, method: "tools/call", params: { name: "nothing", arguments: {} } });
    expect(unknown).toMatchObject({ error: { code: -32602 } });
  });

  it("leaves out another server's tool named as one of the plugin's, and says when its list changed", async () => {
    let changed: () => void = () => {};
    const sent: unknown[] = [];
    const shadowing: ToolProvider = {
      list: async () => [{ name: "pair", inputSchema: { type: "object" } }, { name: "offer_book", inputSchema: { type: "object" } }],
      call: async () => null,
      onListChanged: (notify) => {
        changed = notify;
      },
    };
    const server = new Server(context(), "nodexch", "test", (m) => sent.push(m), shadowing);
    const init = (await server.handle({ jsonrpc: "2.0", id: 1, method: "initialize", params: { capabilities: {} } })) as { result: { capabilities: { tools: { listChanged: boolean } } } };
    expect(init.result.capabilities.tools.listChanged).toBe(true);
    const listed = (await server.handle({ jsonrpc: "2.0", id: 2, method: "tools/list" })) as { result: { tools: { name: string }[] } };
    const names = listed.result.tools.map((t) => t.name);
    expect(names.filter((n) => n === "pair")).toHaveLength(1);
    expect(names).toContain("offer_book");
    changed();
    expect(sent).toContainEqual({ jsonrpc: "2.0", method: "notifications/tools/list_changed" });
    // Without onListChanged the list is said to be fixed.
    const fixed = new Server(context(), "nodexch", "test", () => {}, extra);
    const plain = (await fixed.handle({ jsonrpc: "2.0", id: 1, method: "initialize", params: { capabilities: {} } })) as { result: { capabilities: { tools: { listChanged: boolean } } } };
    expect(plain.result.capabilities.tools.listChanged).toBe(false);
  });

  it("answers at once while nodexch is unreachable, and tries the setup again on a later call", async () => {
    const dir = await mkdtemp(join(tmpdir(), "xcmcp-lib-"));
    const fetches = vi.spyOn(globalThis, "fetch").mockRejectedValue(new Error("offline"));
    const started = Date.now();
    const { ctx, close } = await lib.openContext({
      XCHONNECT_MCP_DIR: join(dir, "state"),
      XCHONNECT_MCP_KEY_FILE: join(dir, "key"),
      XCHONNECT_MCP_NO_VIEWER: "1",
      NODEXCH_KEY: "nxs_test",
      NODEXCH_URL: "https://nodexch.example",
    });
    expect(Date.now() - started).toBeLessThan(2_000);
    const pair = (await lib.call(ctx, "pair", {})) as { structuredContent: { error: string; message: string } };
    expect(pair.structuredContent.error).toBe("not_set_up");
    expect(pair.structuredContent.message).toMatch(/cannot be reached/);
    const tries = fetches.mock.calls.length;
    // Within RETRY_MS a call does not ask again; after it, it does.
    await lib.call(ctx, "pair", {});
    expect(fetches.mock.calls.length).toBe(tries);
    vi.spyOn(Date, "now").mockReturnValue(Date.now() + 16_000);
    await lib.call(ctx, "pair", {});
    expect(fetches.mock.calls.length).toBeGreaterThan(tries);
    await close();
  });

  it("exports what an embedding server needs", () => {
    expect(typeof lib.openContext).toBe("function");
    expect(typeof lib.serve).toBe("function");
    expect(typeof lib.Server).toBe("function");
    expect(typeof lib.call).toBe("function");
    expect(lib.list().length).toBeGreaterThan(5);
  });
});
