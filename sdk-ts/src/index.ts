/** @xchonnect/dapp — pair with mobile wallets and send CHIP-0002 requests over Xchonnect. */
export const PROTOCOL_VERSION = 1;
export { XchonnectClient, Pairing, initXchonnect } from "./client.js";
export type { ClientOptions, ClientStatus, DeliveryEvent, DeliveryState, WasmSource } from "./client.js";
export { RelayClient } from "./relay.js";
export type { RelayInfo, RelayMessage, RelayClientOptions } from "./relay.js";
export { MemorySessionStore, IndexedDbSessionStore, defaultSessionStore } from "./storage.js";
export type { SessionStore } from "./storage.js";
export { XchonnectError, RelayError, XchonnectRpcError, RpcErrorCode } from "./errors.js";
