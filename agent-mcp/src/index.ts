#!/usr/bin/env node
/**
 * `xchonnect-mcp`: the Xchonnect MCP plugin over stdio. Install in Claude Code with
 *
 *   claude mcp add xchonnect -- npx -y @xchonnect/mcp
 *
 * Settings, all optional, from the environment:
 *   XCHONNECT_RELAY            the relay (default https://relay.nodexch.com)
 *   XCHONNECT_AGENT_NAME       how the wallet names this agent (default "Claude Code agent")
 *   XCHONNECT_ORIGIN_DOMAIN    a domain of yours serving the origin document (origin_document)
 *   XCHONNECT_ORIGIN_KID       its key id (default agent-1)
 *   NODEXCH_KEY                the agent's secret nodexch API key: nodexch signs the pairing as its
 *                              own domain, and its relay is used (no domain of your own needed)
 *   NODEXCH_URL                nodexch's API (default https://api.nodexch.com)
 *   XCHONNECT_DEV=1            developer mode: serve the origin on localhost, accept an http relay
 *   XCHONNECT_DEV_PORT         developer mode: the origin's port (default 8797)
 *   XCHONNECT_MCP_DIR          where the encrypted state lives (default ~/.xchonnect-mcp)
 *   XCHONNECT_MCP_KEY_FILE     keep the state key in this file instead of the system keychain
 *   XCHONNECT_MCP_MAX_FEE      the largest network fee a request may carry, in XCH (default 0.01)
 *   XCHONNECT_MCP_NO_VIEWER=1  never open the QR image
 *   XCHONNECT_MCP_DEBUG=1      log amounts, assets and offers too (off by default)
 */
import { openContext } from "./plugin.js";
import { serve } from "./server.js";

const NAME = "xchonnect";
const VERSION = "0.1.0-rc.2";

async function main(): Promise<void> {
  const { ctx, close } = await openContext(process.env);
  serve(ctx, NAME, VERSION, close);
}

void main();
