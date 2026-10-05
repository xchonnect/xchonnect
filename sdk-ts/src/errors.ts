/** Base class for SDK errors. `code` is a stable machine-readable identifier. */
export class XchonnectError extends Error {
  constructor(
    readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = "XchonnectError";
  }
}

/** The relay answered with an error from the spec's error table. */
export class RelayError extends XchonnectError {
  constructor(
    readonly status: number,
    code: string,
    readonly retryAfter?: number,
  ) {
    super(code, `relay error ${status} ${code}`);
    this.name = "RelayError";
  }
}

/** The wallet answered a request with a CHIP-0002 / Xchonnect error (spec 9.1). */
export class XchonnectRpcError extends Error {
  constructor(
    readonly code: number,
    message: string,
    readonly data?: unknown,
  ) {
    super(message);
    this.name = "XchonnectRpcError";
  }
}

/** CHIP-0002 and Xchonnect error codes. */
export const RpcErrorCode = {
  InvalidParams: 4000,
  Unauthorized: 4001,
  UserRejected: 4002,
  SpendableBalanceExceeded: 4003,
  MethodNotFound: 4004,
  NoSecretKey: 4005,
  LimitExceeded: 4029,
  RequestExpired: 4100,
  UnsupportedContent: 4101,
  /** The request was withdrawn by the dApp or the user before it was answered (spec 9.1). */
  RequestCancelled: 4102,
} as const;
