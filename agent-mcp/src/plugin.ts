/**
 * The plugin's state, opened from the environment: the wallet session, the origin it pairs as,
 * the offers it made. `index.ts` serves it on stdio; another MCP server (nodexch's one install,
 * nodexch TASK-176.04) opens it the same way and serves its tools next to its own (`lib.ts`).
 * Settings: see `index.ts`.
 */
import { readFile } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";
import { feeMojos } from "./amounts.js";
import { sessionKey, systemKeychain } from "./keychain.js";
import { log } from "./log.js";
import { NO_RECORDS, OfferBook } from "./offers.js";
import { openNodexchOrigin, openOrigin, type Origin } from "./origin.js";
import { EncryptedFileStore, lockDirectory, privateDirectory } from "./store.js";
import type { Context } from "./tools.js";
import { Wallet } from "./wallet.js";

const DEFAULT_MAX_FEE = "0.01";

/** How soon a wallet setup that failed (nodexch or the relay unreachable) is tried again, on the
 * next tool call. */
const RETRY_MS = 15_000;

/** The plugin's context from `env`, and what closes it. It returns at once, so the server answers
 * `initialize` while the wallet session is still being set up (nodexch and the relay are asked
 * over the network): every tool call waits for that first attempt (`ctx.ready`), and one after a
 * failed attempt tries again, at most every `RETRY_MS`. A setup that fails leaves the context
 * without a wallet and says why in `setupError`: the tools then answer `not_set_up`. */
export async function openContext(env: NodeJS.ProcessEnv): Promise<{ ctx: Context; close: () => Promise<void> }> {
  const dir = env["XCHONNECT_MCP_DIR"] ?? join(homedir(), ".xchonnect-mcp");
  const developerMode = env["XCHONNECT_DEV"] === "1";
  let relay = env["XCHONNECT_RELAY"] ?? (developerMode ? "http://127.0.0.1:8787" : "https://relay.nodexch.com");
  // nodexch signs the pairing when the agent has its key and no domain of its own is set.
  const nodexchKey = env["NODEXCH_KEY"] && !env["XCHONNECT_ORIGIN_DOMAIN"] && !developerMode ? env["NODEXCH_KEY"] : undefined;
  if (env["NODEXCH_KEY"] && !nodexchKey) {
    log(`NODEXCH_KEY is not used for pairing: ${developerMode ? "XCHONNECT_DEV" : "XCHONNECT_ORIGIN_DOMAIN"} is set and takes precedence`);
  }
  const ctx: Context = {
    wallet: null,
    origin: null,
    offers: new OfferBook(NO_RECORDS),
    relay,
    keychain: "none",
    openViewer: env["XCHONNECT_MCP_NO_VIEWER"] !== "1",
    imageDir: dir,
    maxFeeMojos: 0n,
    elicit: null,
  };
  // What is on this computer, once: a failure here is the setup's, and is not tried again.
  let store: EncryptedFileStore;
  let keychainKind: string;
  try {
    ctx.maxFeeMojos = feeMojos(env["XCHONNECT_MCP_MAX_FEE"] ?? DEFAULT_MAX_FEE);
    const keychain = systemKeychain("default", env);
    keychainKind = ctx.keychain = keychain.kind;
    await privateDirectory(dir);
    await lockDirectory(dir);
    store = new EncryptedFileStore(join(dir, "state.bin"), await sessionKey(keychain));
    ctx.offers = new OfferBook(store);
  } catch (e) {
    ctx.setupError = `The plugin could not start its wallet session: ${e instanceof Error ? e.message : String(e)}`;
    log("setup failed");
    return { ctx, close: async () => undefined };
  }
  // The origin, then the wallet session: over the network, tried again after a failure. An origin
  // found is kept (a developer-mode origin serves a port), so a retry only opens the session.
  const connect = async (): Promise<void> => {
    try {
      if (!ctx.origin) {
        let origin: Origin | null;
        if (nodexchKey) {
          const nodexch = await openNodexchOrigin(env["NODEXCH_URL"] ?? "https://api.nodexch.com", nodexchKey);
          if (env["XCHONNECT_RELAY"] && env["XCHONNECT_RELAY"].replace(/\/+$/, "") !== nodexch.relay) {
            throw new Error(`XCHONNECT_RELAY (${env["XCHONNECT_RELAY"]}) is not the relay nodexch signs pairings for (${nodexch.relay}); leave it unset`);
          }
          relay = nodexch.relay;
          ctx.relay = relay;
          origin = nodexch;
        } else origin = await openOrigin(
          {
            name: env["XCHONNECT_AGENT_NAME"] ?? "Claude Code agent",
            ...(env["XCHONNECT_ORIGIN_DOMAIN"] ? { domain: env["XCHONNECT_ORIGIN_DOMAIN"] } : {}),
            ...(env["XCHONNECT_ORIGIN_KID"] ? { kid: env["XCHONNECT_ORIGIN_KID"] } : {}),
            developerMode,
            port: Number(env["XCHONNECT_DEV_PORT"] ?? 8797),
          },
          store,
        );
        if (!origin) {
          ctx.setupError =
            "No origin to sign pairing codes with. Set NODEXCH_KEY (your agent's secret nodexch key: nodexch signs the pairing), or XCHONNECT_ORIGIN_DOMAIN to a domain where you serve the document from origin_document, or XCHONNECT_DEV=1 to try it with a wallet in developer mode.";
          return;
        }
        ctx.origin = origin;
      }
      const origin = ctx.origin;
      const wasm = await readFile(new URL(import.meta.resolve("@xchonnect/dapp/xchonnect_bg.wasm")));
      ctx.wallet = await Wallet.open({ relay, origin, storage: store, wasm });
      delete ctx.setupError;
      log(`ready (${origin.developerMode ? "developer mode" : "origin " + origin.domain}${nodexchKey ? " via nodexch" : ""}, session key in ${keychainKind}, ${ctx.wallet.status})`);
    } catch (e) {
      ctx.setupError = `The plugin could not start its wallet session: ${e instanceof Error ? e.message : String(e)}`;
      log(`setup failed; tried again on the next tool call after ${RETRY_MS / 1000} s`);
    }
  };
  let running: Promise<void> | null = null;
  let tried = 0;
  const attempt = (): Promise<void> => {
    tried = Date.now();
    running = connect().finally(() => {
      running = null;
    });
    return running;
  };
  ctx.ready = async () => {
    if (ctx.wallet) return;
    if (running) return running;
    if (Date.now() - tried >= RETRY_MS) return attempt();
  };
  void attempt();
  return {
    ctx,
    close: async () => {
      await running;
      await ctx.wallet?.close();
    },
  };
}
