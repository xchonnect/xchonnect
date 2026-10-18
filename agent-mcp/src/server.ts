/**
 * The Model Context Protocol over stdio: one JSON-RPC message per line on stdin, answers on
 * stdout (nothing else may be written there), logs on stderr. Tool calls run concurrently; a
 * notification gets no answer.
 */
import { createInterface } from "node:readline";
import { call, list, type Context } from "./tools.js";

const VERSIONS = ["2025-06-18", "2025-03-26", "2024-11-05"];

const INSTRUCTIONS =
  "Xchonnect connects this agent to the user's Chia wallet over an end-to-end encrypted session. " +
  "The wallet holds the keys and the user's rules for this agent; this plugin holds neither and builds no spend. " +
  "Pair once (pair, pairing_status, confirm_pairing after the user compares the code), then read get_rules before proposing trades. " +
  "take_offer, create_offer and cancel_offer ask the wallet, which decides within the user's rules or asks the user; " +
  "a refusal comes with a fixed code (limit_per_trade, limit_per_period, asset_not_allowed, action_not_allowed, price_out_of_band, outside_hours, expired, paused) to explain and plan around. " +
  "For market data (offer book, prices, loans) use the nodexch MCP server; to read an offer's amounts, nodexch decode_offer.";

type Message = { jsonrpc?: unknown; id?: unknown; method?: unknown; params?: unknown };

export async function handle(ctx: Context, message: Message, name: string, version: string): Promise<unknown | undefined> {
  const id = message.id;
  if (id === undefined || id === null || typeof message.method !== "string") return undefined;
  const ok = (result: unknown) => ({ jsonrpc: "2.0", id, result });
  const fail = (code: number, text: string) => ({ jsonrpc: "2.0", id, error: { code, message: text } });
  const params = (message.params ?? {}) as Record<string, unknown>;
  switch (message.method) {
    case "initialize": {
      const asked = typeof params["protocolVersion"] === "string" ? params["protocolVersion"] : "";
      return ok({
        protocolVersion: VERSIONS.includes(asked) ? asked : VERSIONS[0],
        capabilities: { tools: { listChanged: false } },
        serverInfo: { name, title: "Xchonnect: your Chia wallet for agents", version },
        instructions: INSTRUCTIONS,
      });
    }
    case "ping":
      return ok({});
    case "tools/list":
      return ok({ tools: list() });
    case "tools/call": {
      if (typeof params["name"] !== "string") return fail(-32602, "tools/call needs a name");
      const result = await call(ctx, params["name"], params["arguments"]);
      return result ? ok(result) : fail(-32602, `unknown tool: ${params["name"]}`);
    }
    case "resources/list":
      return ok({ resources: [] });
    case "prompts/list":
      return ok({ prompts: [] });
    default:
      return fail(-32601, `method not found: ${message.method}`);
  }
}

/** Serves `ctx` on stdin/stdout until stdin closes. */
export function serve(ctx: Context, name: string, version: string, onClose: () => Promise<void>): void {
  const out = (message: unknown) => process.stdout.write(`${JSON.stringify(message)}\n`);
  const lines = createInterface({ input: process.stdin, crlfDelay: Infinity });
  lines.on("line", (line) => {
    if (!line.trim()) return;
    let message: Message;
    try {
      message = JSON.parse(line) as Message;
    } catch {
      out({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "parse error" } });
      return;
    }
    if (Array.isArray(message)) {
      out({ jsonrpc: "2.0", id: null, error: { code: -32600, message: "one message per line" } });
      return;
    }
    void handle(ctx, message, name, version).then(
      (answer) => {
        if (answer !== undefined) out(answer);
      },
      () => out({ jsonrpc: "2.0", id: message.id ?? null, error: { code: -32603, message: "internal error" } }),
    );
  });
  lines.on("close", () => {
    void onClose().finally(() => process.exit(0));
  });
}
