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
 *   XCHONNECT_DEV=1            developer mode: serve the origin on localhost, accept an http relay
 *   XCHONNECT_DEV_PORT         developer mode: the origin's port (default 8797)
 *   XCHONNECT_MCP_DIR          where the encrypted state lives (default ~/.xchonnect-mcp)
 *   XCHONNECT_MCP_KEY_FILE     keep the state key in this file instead of the system keychain
 *   XCHONNECT_MCP_NO_VIEWER=1  never open the QR image
 *   XCHONNECT_MCP_DEBUG=1      log amounts, assets and offers too (off by default)
 */
import { readFile } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";
import { sessionKey, systemKeychain } from "./keychain.js";
import { log } from "./log.js";
import { OfferBook } from "./offers.js";
import { openOrigin } from "./origin.js";
import { serve } from "./server.js";
import { EncryptedFileStore } from "./store.js";
import type { Context } from "./tools.js";
import { Wallet } from "./wallet.js";

const NAME = "xchonnect";
const VERSION = "0.1.0-rc.1";

async function main(): Promise<void> {
  const env = process.env;
  const dir = env["XCHONNECT_MCP_DIR"] ?? join(homedir(), ".xchonnect-mcp");
  const developerMode = env["XCHONNECT_DEV"] === "1";
  const relay = env["XCHONNECT_RELAY"] ?? (developerMode ? "http://127.0.0.1:8787" : "https://relay.nodexch.space");
  const keychain = systemKeychain("default", env);
  const ctx: Context = {
    wallet: null,
    origin: null,
    offers: new OfferBook({ load: async () => null, save: async () => {}, clear: async () => {} }),
    relay,
    keychain: keychain.kind,
    openViewer: env["XCHONNECT_MCP_NO_VIEWER"] !== "1",
    imageDir: dir,
  };
  try {
    const store = new EncryptedFileStore(join(dir, "state.bin"), await sessionKey(keychain));
    ctx.offers = new OfferBook(store);
    const origin = await openOrigin(
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
        "No origin to sign pairing codes with. Set XCHONNECT_ORIGIN_DOMAIN to a domain where you serve the document from origin_document, or XCHONNECT_DEV=1 to try it with a wallet in developer mode.";
    } else {
      ctx.origin = origin;
      const wasm = await readFile(new URL(import.meta.resolve("@xchonnect/dapp/xchonnect_bg.wasm")));
      ctx.wallet = await Wallet.open({ relay, origin, storage: store, wasm });
      log(`ready (${developerMode ? "developer mode" : "origin " + origin.domain}, session key in ${keychain.kind}, ${ctx.wallet.status})`);
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
