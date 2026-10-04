/**
 * Multi-party spends (spec 8.3, 9.1, 11.2): collect `partialSign` signatures from several
 * wallets, aggregate them, and submit the completed spend bundle to more than one node.
 *
 * Flow for e.g. an options or lending trade:
 * 1. Build one spend bundle in which every party's spend is **bound** to the payment it
 *    expects (assert the counterparty's settlement-payment announcement). Wallets refuse
 *    unbound partial requests (`4001`, reason `unbound_partial`).
 * 2. Ask each party's wallet with {@link requestPartialSignature}.
 * 3. {@link aggregateSignatures} and {@link pushSpendBundle} to at least two independent
 *    nodes, so a single node cannot withhold the transaction.
 */
import * as core from "../wasm/xchonnect.js";
import type { XchonnectClient } from "./client.js";
import { XchonnectError } from "./errors.js";

/** CHIP-0002 coin spend (snake_case fields, hex byte strings). */
export interface CoinSpendJson {
  coin: { parent_coin_info: string; puzzle_hash: string; amount: number | string };
  puzzle_reveal: string;
  solution: string;
}

/** Ask the paired wallet for its partial signature over `coinSpends`. */
export function requestPartialSignature(client: XchonnectClient, coinSpends: CoinSpendJson[], opts: { ttlSeconds?: number } = {}): Promise<string> {
  const reqOpts = opts.ttlSeconds === undefined ? {} : { ttlSeconds: opts.ttlSeconds };
  return client.request<string>("signCoinSpends", { coinSpends, partialSign: true }, reqOpts);
}

/** Aggregate BLS signatures (hex) from several wallets into one (hex, `0x`-prefixed). */
export function aggregateSignatures(signatures: string[]): string {
  return core.aggregateSignatures(signatures);
}

/** Result of {@link pushSpendBundle}. */
export interface PushResult {
  accepted: string[];
  failed: { node: string; error: string }[];
}

/**
 * Submit a spend bundle to several full nodes (`POST <node>/push_tx`, the Chia full-node
 * RPC and coinset-style APIs). Resolves when at least one node accepted it; rejects if all
 * failed. Pass two or more independent nodes (spec 8.3).
 */
export async function pushSpendBundle(coinSpends: CoinSpendJson[], aggregatedSignature: string, nodes: string[], fetchFn: typeof fetch = (i, init) => globalThis.fetch(i, init)): Promise<PushResult> {
  if (nodes.length === 0) throw new XchonnectError("no_nodes", "at least one node URL is required");
  const body = JSON.stringify({ spend_bundle: { coin_spends: coinSpends, aggregated_signature: aggregatedSignature } });
  const results = await Promise.allSettled(
    nodes.map(async (node) => {
      const res = await fetchFn(`${node.replace(/\/+$/, "")}/push_tx`, { method: "POST", headers: { "content-type": "application/json" }, body });
      const json = (await res.json().catch(() => ({}))) as { success?: boolean; error?: string };
      if (!res.ok || json.success === false) throw new Error(json.error ?? `HTTP ${res.status}`);
      return node;
    }),
  );
  const out: PushResult = { accepted: [], failed: [] };
  results.forEach((r, i) => {
    const node = nodes[i] ?? "";
    if (r.status === "fulfilled") out.accepted.push(node);
    else out.failed.push({ node, error: String((r.reason as Error)?.message ?? r.reason) });
  });
  if (out.accepted.length === 0) throw new XchonnectError("push_failed", `no node accepted the spend bundle: ${out.failed.map((f) => f.error).join("; ")}`);
  return out;
}
