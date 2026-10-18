/**
 * The plugin as a library (nodexch's one install, nodexch TASK-176.04): another MCP server serves
 * the plugin's wallet tools with its own next to them, through one `Server`: one list, calls
 * routed to whoever has the tool, the instructions of both, its own title.
 */
import { describe, expect, it } from "vitest";
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

  it("exports what an embedding server needs", () => {
    expect(typeof lib.openContext).toBe("function");
    expect(typeof lib.serve).toBe("function");
    expect(typeof lib.Server).toBe("function");
    expect(typeof lib.call).toBe("function");
    expect(lib.list().length).toBeGreaterThan(5);
  });
});
