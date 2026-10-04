/**
 * CHIP-0002 provider adapter: the `window.chia.request({ method, params })` surface over an
 * Xchonnect session, so existing CHIP-0002 code paths work unchanged (spec 9.1).
 */
import type { XchonnectClient } from "./client.js";
import { RelayError, RpcErrorCode, XchonnectError, XchonnectRpcError } from "./errors.js";

/** CHIP-0002 error object. */
export interface Chip0002Error {
  code: number;
  message: string;
  data?: unknown;
}

export interface Chip0002RequestArgs {
  method: string;
  params?: unknown;
}

export interface Chip0002Provider {
  /** Identifies the transport for dApps that support several providers. */
  readonly isXchonnect: true;
  request<T = unknown>(args: Chip0002RequestArgs): Promise<T>;
}

/** Methods defined by CHIP-0002 (Final, apiVersion 1.0.0). */
export const CHIP0002_METHODS = [
  "chainId",
  "connect",
  "walletSwitchChain",
  "getPublicKeys",
  "filterUnlockedCoins",
  "getAssetCoins",
  "getAssetBalance",
  "signCoinSpends",
  "signMessage",
  "sendTransaction",
] as const;

function toChipError(e: unknown): Chip0002Error {
  if (e instanceof XchonnectRpcError) return e.data === undefined ? { code: e.code, message: e.message } : { code: e.code, message: e.message, data: e.data };
  if (e instanceof XchonnectError && e.code === "not_active") return { code: RpcErrorCode.Unauthorized, message: "unauthorized", data: { reason: "no active session" } };
  if (e instanceof RelayError) return { code: e.status === 429 ? RpcErrorCode.LimitExceeded : RpcErrorCode.Unauthorized, message: "transport error", data: { relay: e.code } };
  return { code: RpcErrorCode.Unauthorized, message: (e as Error)?.message ?? "transport error" };
}

/** Create a CHIP-0002 provider backed by an Xchonnect client. */
export function createChip0002Provider(client: XchonnectClient, opts: { ttlSeconds?: number } = {}): Chip0002Provider {
  return {
    isXchonnect: true,
    async request<T = unknown>({ method, params }: Chip0002RequestArgs): Promise<T> {
      const name = method.startsWith("chip0002_") ? method.slice("chip0002_".length) : method;
      if (!name) throw { code: RpcErrorCode.MethodNotFound, message: "method not found" } satisfies Chip0002Error;
      try {
        const reqOpts = opts.ttlSeconds === undefined ? {} : { ttlSeconds: opts.ttlSeconds };
        return await client.request<T>(name, params ?? {}, reqOpts);
      } catch (e) {
        throw toChipError(e);
      }
    },
  };
}
