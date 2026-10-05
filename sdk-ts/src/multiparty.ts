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
 *
 * Node submissions reveal the submitter's IP to the node, so spec 10.6 routes them through
 * OHTTP as well — through the same independent OHTTP relay, but to a gateway run by the
 * **node operator**. They are never routed through the Xchonnect relay's gateway: the relay
 * would then see plaintext spend bundles (T7, T10). Give a node an `ohttp` configuration
 * ({@link NodeTarget}) to use it; a node without one is submitted to directly and reported
 * as `direct` in {@link PushResult.transport}.
 */
import * as core from "../wasm/xchonnect.js";
import type { XchonnectClient } from "./client.js";
import { XchonnectError } from "./errors.js";
import { type OhttpOptions, OhttpTransport, type PrivacyEvent, type PrivacyState } from "./ohttp.js";

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

/** A full node to submit to, with the OHTTP gateway its operator runs (spec 10.6). */
export interface NodeTarget {
  /** Base URL of the node RPC; `/push_tx` is appended. */
  url: string;
  /**
   * OHTTP transport for this node. `keyConfig` is the **node operator's** gateway key
   * configuration (pinned, shipped with the app), `relayUrl` the independent OHTTP relay.
   * Without it the node sees the submitter's IP.
   */
  ohttp?: OhttpOptions;
}

/** Options of {@link pushSpendBundle}. */
export interface PushOptions {
  /** `fetch` for direct submissions and for reaching the OHTTP relay. */
  fetch?: typeof fetch;
  /** Called whenever a node's transport changes (spec 10.6 fallback state). */
  onPrivacy?: (event: PrivacyEvent & { node: string }) => void;
  /** Allow a loopback `http:` OHTTP relay URL. Local development only. */
  developerMode?: boolean;
}

/** Result of {@link pushSpendBundle}. */
export interface PushResult {
  accepted: string[];
  failed: { node: string; error: string }[];
  /** Transport used per node; `direct` means that node learned the submitter's IP. */
  transport: { node: string; state: PrivacyState }[];
}

/**
 * Submit a spend bundle to several full nodes (`POST <node>/push_tx`, the Chia full-node
 * RPC and coinset-style APIs). Resolves when at least one node accepted it; rejects if all
 * failed. Pass two or more independent nodes (spec 8.3).
 *
 * A node given as a {@link NodeTarget} with `ohttp` is reached through its operator's OHTTP
 * gateway (spec 10.6) with the fallback rules of spec 10: a key-configuration mismatch is a
 * hard error, and a submission the gateway may already have forwarded is never re-sent
 * directly. The transport actually used is reported per node in {@link PushResult.transport}
 * and through `onPrivacy`. The request carries only the spend bundle — no relay credential,
 * mailbox id or session material.
 */
export async function pushSpendBundle(coinSpends: CoinSpendJson[], aggregatedSignature: string, nodes: (string | NodeTarget)[], options: typeof fetch | PushOptions = {}): Promise<PushResult> {
  if (nodes.length === 0) throw new XchonnectError("no_nodes", "at least one node URL is required");
  const opts: PushOptions = typeof options === "function" ? { fetch: options } : options;
  const baseFetch = opts.fetch ?? ((i: RequestInfo | URL, init?: RequestInit) => globalThis.fetch(i, init));
  const targets: NodeTarget[] = nodes.map((n) => (typeof n === "string" ? { url: n } : n));
  const transports = targets.map((t) => {
    if (!t.ohttp) return undefined;
    const transport = new OhttpTransport(t.ohttp, t.url, baseFetch, opts.developerMode ?? false);
    const { onPrivacy } = opts;
    if (onPrivacy) transport.onPrivacy((e) => onPrivacy({ ...e, node: t.url }));
    return transport;
  });
  const body = JSON.stringify({ spend_bundle: { coin_spends: coinSpends, aggregated_signature: aggregatedSignature } });
  const results = await Promise.allSettled(
    targets.map(async ({ url }, i) => {
      const send = transports[i]?.fetch ?? baseFetch;
      const res = await send(`${url.replace(/\/+$/, "")}/push_tx`, { method: "POST", headers: { "content-type": "application/json" }, body });
      const json = (await res.json().catch(() => ({}))) as { success?: boolean; error?: string };
      if (!res.ok || json.success === false) throw new Error(json.error ?? `HTTP ${res.status}`);
      return url;
    }),
  );
  const out: PushResult = { accepted: [], failed: [], transport: [] };
  results.forEach((r, i) => {
    const node = targets[i]?.url ?? "";
    const transport = transports[i];
    out.transport.push({ node, state: transport ? transport.state : "direct" });
    if (r.status === "fulfilled") out.accepted.push(node);
    else out.failed.push({ node, error: String((r.reason as Error)?.message ?? r.reason) });
  });
  if (out.accepted.length === 0) throw new XchonnectError("push_failed", `no node accepted the spend bundle: ${out.failed.map((f) => f.error).join("; ")}`);
  return out;
}
