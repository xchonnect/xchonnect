/**
 * The plugin's own log, on stderr (stdout carries the protocol). It says what happened, never
 * with what: no amounts, assets, addresses, offers or pairing strings, unless the user turns
 * debug logging on (`XCHONNECT_MCP_DEBUG=1`), and then only in `detail`.
 */

const debug = process.env["XCHONNECT_MCP_DEBUG"] === "1";

export function log(event: string, detail?: Record<string, unknown>): void {
  const line = debug && detail ? `${event} ${JSON.stringify(detail)}` : event;
  process.stderr.write(`[xchonnect-mcp] ${line}\n`);
}

export function debugEnabled(): boolean {
  return debug;
}
