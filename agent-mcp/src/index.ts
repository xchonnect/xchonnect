#!/usr/bin/env node
/**
 * `xchonnect-mcp`: the Xchonnect MCP plugin over stdio. Install in Claude Code with
 *
 *   claude mcp add xchonnect -- npx -y @xchonnect/mcp
 *
 * Settings, all optional, from the environment:
 *   XCHONNECT_RELAY            the relay (default https://relay.nodexch.space)
 *   XCHONNECT_AGENT_NAME       how the wallet names this agent (default "Claude Code agent")
 *   XCHONNECT_ORIGIN_DOMAIN    a domain of yours serving the origin document (origin_document)
 *   XCHONNECT_ORIGIN_KID       its key id (default agent-1)
 *   NODEXCH_KEY                the agent's secret nodexch API key: nodexch signs the pairing as its
 *                              own domain, and its relay is used (no domain of your own needed)
 *   NODEXCH_URL                nodexch's API (default https://api.nodexch.space)
 *   XCHONNECT_DEV=1            developer mode: serve the origin on localhost, accept an http relay
 *   XCHONNECT_DEV_PORT         developer mode: the origin's port (default 8797)
 *   XCHONNECT_MCP_DIR          where the encrypted state lives (default ~/.xchonnect-mcp)
 *   XCHONNECT_MCP_KEY_FILE     keep the state key in this file instead of the system keychain
 *   XCHONNECT_MCP_MAX_FEE      the largest network fee a request may carry, in XCH (default 0.01)
 *   XCHONNECT_MCP_NO_VIEWER=1  never open the QR image
 *   XCHONNECT_MCP_DEBUG=1      log amounts, assets and offers too (off by default)
 */
import { readFile } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";
import { feeMojos } from "./amounts.js";
import { sessionKey, systemKeychain } from "./keychain.js";
import { log } from "./log.js";
import { NO_RECORDS, OfferBook } from "./offers.js";
import { openNodexchOrigin, openOrigin, type Origin } from "./origin.js";
import { serve } from "./server.js";
import { EncryptedFileStore, lockDirectory, privateDirectory } from "./store.js";
import type { Context } from "./tools.js";
import { Wallet } from "./wallet.js";

const NAME = "xchonnect";
const VERSION = "0.1.0-rc.1";
const DEFAULT_MAX_FEE = "0.01";

async function main(): Promise<void> {
  const env = process.env;
  const dir = env["XCHONNECT_MCP_DIR"] ?? join(homedir(), ".xchonnect-mcp");
  const developerMode = env["XCHONNECT_DEV"] === "1";
  let relay = env["XCHONNECT_RELAY"] ?? (developerMode ? "http://127.0.0.1:8787" : "https://relay.nodexch.space");
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
  try {
    ctx.maxFeeMojos = feeMojos(env["XCHONNECT_MCP_MAX_FEE"] ?? DEFAULT_MAX_FEE);
    const keychain = systemKeychain("default", env);
    ctx.keychain = keychain.kind;
    await privateDirectory(dir);
    await lockDirectory(dir);
    const store = new EncryptedFileStore(join(dir, "state.bin"), await sessionKey(keychain));
    ctx.offers = new OfferBook(store);
    let origin: Origin | null;
    if (nodexchKey) {
      const nodexch = await openNodexchOrigin(env["NODEXCH_URL"] ?? "https://api.nodexch.space", nodexchKey);
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
    } else {
      ctx.origin = origin;
      const wasm = await readFile(new URL(import.meta.resolve("@xchonnect/dapp/xchonnect_bg.wasm")));
      ctx.wallet = await Wallet.open({ relay, origin, storage: store, wasm });
      log(`ready (${origin.developerMode ? "developer mode" : "origin " + origin.domain}${nodexchKey ? " via nodexch" : ""}, session key in ${keychain.kind}, ${ctx.wallet.status})`);
    }
  } catch (e) {
    ctx.setupError = `The plugin could not start its wallet session: ${e instanceof Error ? e.message : String(e)}`;
    log("setup failed");
  }
  serve(ctx, NAME, VERSION, async () => {
    await ctx.wallet?.close();
  });
}

void main();
