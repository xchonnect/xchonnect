/**
 * `@xchonnect/mcp` as a library, for an MCP server that serves the plugin's wallet tools next to
 * its own in one process (nodexch's one install, nodexch TASK-176.04). The wallet session, the
 * pairing and every request stay in that process, on the user's computer. The `xchonnect-mcp`
 * program (`index.ts`) is the same code served alone.
 */
export { openContext } from "./plugin.js";
export { serve, Server, type ToolProvider } from "./server.js";
export { call, list, type Context } from "./tools.js";
