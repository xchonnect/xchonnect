/** @xchonnect/dapp — pair with mobile wallets and send CHIP-0002 requests over Xchonnect. */
export const PROTOCOL_VERSION = 1;
export { XchonnectClient, Pairing, initXchonnect, isLikelyMobile } from "./client.js";
export type { ClientOptions, ClientStatus, DeliveryEvent, DeliveryState, RequestOptions, WasmSource } from "./client.js";
export { RelayClient } from "./relay.js";
export type { RelayInfo, RelayMessage, RelayClientOptions } from "./relay.js";
export { MemorySessionStore, IndexedDbSessionStore, defaultSessionStore } from "./storage.js";
export type { SessionStore } from "./storage.js";
export { XchonnectError, RelayError, XchonnectRpcError, RpcErrorCode } from "./errors.js";
export { createChip0002Provider, CHIP0002_METHODS } from "./chip0002.js";
export type { Chip0002Provider, Chip0002Error, Chip0002RequestArgs } from "./chip0002.js";
export { requestPartialSignature, aggregateSignatures, pushSpendBundle } from "./multiparty.js";
export type { CoinSpendJson, PushResult } from "./multiparty.js";
