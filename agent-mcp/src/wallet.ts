/**
 * The agent's end of the xchonnect session: pairing, the SAS check, and requests to the wallet.
 * It holds the session secrets (encrypted on disk, `store.ts`), never a wallet key; every answer
 * that moves funds is the wallet's, decided by the user or by the rules the user set there.
 *
 * Every failure becomes one code from a fixed list (`ErrorCode`), so the agent can tell the
 * user what happened and what to do: pair again, open the wallet, wait, or change the trade.
 */
import { XchonnectClient, XchonnectError, XchonnectRpcError, RelayError, type Pairing, type SessionStore, type DeliveryState } from "@xchonnect/dapp";
import { log } from "./log.js";
import type { Origin } from "./origin.js";
import { REASON_TEXT, isAgentReason, type AgentReason } from "./rules.js";

/** Codes for a request that did not get a result. Spec 9.4 reasons, then the plugin's own. */
export type ErrorCode =
  | AgentReason
  | "not_paired"
  | "pairing_expired"
  | "pairing_rejected"
  | "session_ended"
  | "wallet_unreachable"
  | "relay_unreachable"
  | "user_rejected"
  | "insufficient_balance"
  | "not_supported"
  | "refused"
  | "invalid_request"
  | "cannot_decode"
  | "no_key"
  | "request_expired"
  | "cancelled"
  | "not_set_up"
  | "internal";

export class ToolError extends Error {
  constructor(
    readonly code: ErrorCode,
    message: string,
    readonly detail?: Record<string, unknown>,
  ) {
    super(message);
    this.name = "ToolError";
  }
}

const SESSION_TEXT: Partial<Record<ErrorCode, string>> = {
  not_paired: "No wallet is paired. Start with the pair tool.",
  session_ended: "The wallet ended the session (or it was ended here). Pair again with the pair tool.",
  wallet_unreachable: "The wallet has not picked up the request yet: it may be closed or offline. The request stays queued; ask the user to open the wallet, then check with request_status.",
  relay_unreachable: "The relay cannot be reached right now; retry in a moment.",
  user_rejected: "The user declined the request in the wallet.",
  insufficient_balance: "The wallet does not have enough spendable balance for this.",
  not_supported: "The wallet does not offer this.",
  request_expired: "The request expired in the wallet before anyone decided.",
  cannot_decode: "The wallet could not decode this request, so it did not show or sign it (for an offer: an asset or contract it does not know, or it is still reading it; retrying once in a moment can help). Nobody declined it.",
  no_key: "The wallet does not hold the key this request needs.",
  cancelled: "The request was withdrawn.",
};

/** The rule a refusal names, reduced to the fields of spec 9.4 with bounded values: it comes from the wallet and goes to the agent. */
function safeRule(rule: unknown): Record<string, string | number> | undefined {
  if (typeof rule !== "object" || rule === null) return undefined;
  const fields = ["assetId", "perRequest", "period", "perPeriod", "base", "quote", "min", "max"];
  const out: Record<string, string | number> = {};
  for (const name of fields) {
    const v = (rule as Record<string, unknown>)[name];
    if ((typeof v === "string" && v.length <= 80 && /^[0-9a-zA-Z._-]*$/.test(v)) || (typeof v === "number" && Number.isFinite(v))) out[name] = v;
  }
  return Object.keys(out).length ? out : undefined;
}

/** A wallet's error as a fixed code (spec 9.1, 9.4). */
export function fromWalletError(e: unknown): ToolError {
  if (e instanceof ToolError) return e;
  if (e instanceof XchonnectRpcError) {
    let data: unknown = e.data;
    if (typeof data === "string") {
      try {
        data = JSON.parse(data);
      } catch {
        // a bare reason string
      }
    }
    const reason = typeof data === "object" && data !== null ? (data as { reason?: unknown }).reason : data;
    if ((e.code === 4001 || e.code === 4029) && isAgentReason(reason)) {
      const rule = typeof data === "object" && data !== null ? safeRule((data as { rule?: unknown }).rule) : undefined;
      return new ToolError(reason, REASON_TEXT[reason], rule === undefined ? undefined : { rule });
    }
    const byCode: Record<number, ErrorCode> = {
      4000: "invalid_request",
      4001: "refused",
      4002: "user_rejected",
      4003: "insufficient_balance",
      4004: "not_supported",
      4005: "no_key",
      4029: "refused",
      4101: "cannot_decode",
      4100: "request_expired",
      4102: "cancelled",
    };
    const code = byCode[e.code] ?? "refused";
    const why = typeof reason === "string" ? reason.slice(0, 64) : undefined;
    return new ToolError(code, SESSION_TEXT[code] ?? `The wallet refused the request (${e.code}${why ? `, ${why}` : ""}).`, why ? { reason: why, wallet_code: e.code } : { wallet_code: e.code });
  }
  if (e instanceof RelayError) {
    if (e.status === 404 || e.status === 410) return new ToolError("session_ended", SESSION_TEXT.session_ended as string);
    return new ToolError("relay_unreachable", SESSION_TEXT.relay_unreachable as string);
  }
  if (e instanceof XchonnectError) {
    const map: Record<string, ErrorCode> = {
      not_active: "not_paired",
      no_session: "not_paired",
      session_ended: "session_ended",
      pairing_expired: "pairing_expired",
      ready_timeout: "pairing_expired",
      already_paired: "invalid_request",
      lock_timeout: "relay_unreachable",
      interrupted: "relay_unreachable",
      closed: "session_ended",
      aborted: "cancelled",
    };
    const code = map[e.code] ?? "internal";
    return new ToolError(code, SESSION_TEXT[code] ?? e.message);
  }
  if (e instanceof TypeError) return new ToolError("relay_unreachable", SESSION_TEXT.relay_unreachable as string);
  return new ToolError("internal", e instanceof Error ? e.message : "something went wrong");
}

export type PairingPhase = "none" | "waiting_for_wallet" | "compare_code" | "active" | "failed";

interface PairingState {
  phase: PairingPhase;
  pairing?: Pairing;
  uri?: string;
  expiresAt?: number;
  sas?: string;
  walletName?: string;
  error?: ToolError;
  changed: Promise<void>;
  notify: () => void;
}

function freshState(phase: PairingPhase): PairingState {
  let notify = () => {};
  const changed = new Promise<void>((resolve) => (notify = resolve));
  return { phase, changed, notify };
}

/** A request that outlived the tool call that sent it: kept so `request_status` can wait on. */
export interface PendingRequest {
  handle: string;
  method: string;
  /** The relay took it (`queued`): the wallet can get it, and `rpc.cancel` can name it. */
  posted: boolean;
  state: DeliveryState | "waiting";
  txId?: string;
  done: Promise<{ ok: true; result: unknown } | { ok: false; error: ToolError }>;
  settled?: { ok: true; result: unknown } | { ok: false; error: ToolError };
}

export interface WalletOptions {
  relay: string;
  origin: Origin;
  storage: SessionStore;
  wasm: Uint8Array;
  fetch?: typeof fetch;
  /** Pairing URI lifetime, at most 300 s. */
  pairingLifetimeSeconds?: number;
  /** Polling when the relay offers no long poll (the SDK's defaults otherwise; tests go faster). */
  poll?: { fastMs?: number; slowMs?: number; fastWindowMs?: number };
}

export class Wallet {
  private client!: XchonnectClient;
  private pairingState: PairingState = freshState("none");
  private readonly pending = new Map<string, PendingRequest>();
  private counter = 0;
  private serial: Promise<unknown> = Promise.resolve();
  endedBy: "wallet" | "dapp" | undefined;

  private constructor(private readonly o: WalletOptions) {}

  static async open(o: WalletOptions): Promise<Wallet> {
    const w = new Wallet(o);
    w.client = await XchonnectClient.create({
      relay: o.relay,
      domain: o.origin.domain,
      kid: o.origin.kid,
      sign: o.origin.sign,
      originPublicKey: o.origin.publicKey,
      developerMode: o.origin.developerMode,
      storage: o.storage,
      wasm: o.wasm,
      // A long-running plugin listens, so a wallet's session.end arrives within seconds.
      keepAlive: true,
      ...(o.fetch ? { fetch: o.fetch } : {}),
      ...(o.pairingLifetimeSeconds ? { pairingLifetimeSeconds: o.pairingLifetimeSeconds } : {}),
      ...(o.poll ? { poll: o.poll } : {}),
    });
    w.client.on("ended", (e) => {
      w.endedBy = e.by;
      const state = w.pairingState;
      if (state.phase !== "failed" && state.phase !== "none") {
        state.error = new ToolError("session_ended", SESSION_TEXT.session_ended as string);
        w.move(state, "failed");
      }
      log(`session ended by the ${e.by}`);
    });
    w.client.on("delivery", (d) => {
      for (const p of w.pending.values()) {
        if (p.handle === `req-${d.id}`) {
          p.state = d.state;
          if (d.txId) p.txId = d.txId;
        }
      }
    });
    if (w.client.status === "active") w.pairingState = freshState("active");
    return w;
  }

  get status(): string {
    return this.client.status;
  }

  get permissions() {
    return this.client.permissions;
  }

  /** Starts pairing: the URI to show; the wallet's reply is awaited in the background. */
  async pair(): Promise<{ uri: string; expiresAt: number }> {
    if (this.client.status === "active") throw new ToolError("invalid_request", "A wallet is already paired. End the session first (end_session) to pair another.");
    if (this.pairingState.pairing && this.pairingState.phase === "waiting_for_wallet" && (this.pairingState.expiresAt ?? 0) > Date.now() / 1000 + 30) {
      return { uri: this.pairingState.uri as string, expiresAt: this.pairingState.expiresAt as number };
    }
    if (this.client.status === "ended" || this.client.status === "awaiting-sas") await this.client.end().catch(() => undefined);
    let pairing: Pairing;
    try {
      pairing = await this.client.pair();
    } catch (e) {
      throw fromWalletError(e);
    }
    const state = freshState("waiting_for_wallet");
    state.pairing = pairing;
    state.uri = pairing.uri;
    state.expiresAt = pairing.expiresAt;
    this.pairingState = state;
    this.endedBy = undefined;
    log("pairing started");
    pairing.waitForWallet().then(
      ({ sas, walletName }) => {
        if (this.pairingState !== state) return;
        state.sas = sas;
        // The wallet's own text, shown to the agent: a short name or nothing (T22).
        if (typeof walletName === "string" && walletName.length <= 64) state.walletName = walletName;
        this.move(state, "compare_code");
        log("wallet replied; waiting for the user to compare the code");
      },
      (e: unknown) => {
        if (this.pairingState !== state) return;
        state.error = fromWalletError(e);
        this.move(state, "failed");
        log(`pairing failed: ${state.error.code}`);
      },
    );
    return { uri: pairing.uri, expiresAt: pairing.expiresAt };
  }

  /** @internal */
  move(state: PairingState, phase: PairingPhase): void {
    const notify = state.notify;
    state.phase = phase;
    state.changed = new Promise<void>((resolve) => (state.notify = resolve));
    notify();
  }

  /** Where pairing is, after waiting up to `waitSeconds` for it to move. */
  async pairingStatus(waitSeconds: number): Promise<{ phase: PairingPhase; code?: string; walletName?: string; expiresAt?: number; error?: ToolError }> {
    const state = this.pairingState;
    if (state.phase === "waiting_for_wallet" && waitSeconds > 0) {
      await Promise.race([state.changed, new Promise((r) => setTimeout(r, waitSeconds * 1000))]);
    }
    if (this.client.status === "ended" && state.phase !== "failed") {
      return { phase: "failed", error: new ToolError("session_ended", SESSION_TEXT.session_ended as string) };
    }
    if (this.client.status === "active" && state.phase !== "compare_code") return { phase: "active", ...(state.walletName ? { walletName: state.walletName } : {}) };
    return {
      phase: state.phase,
      ...(state.sas ? { code: state.sas } : {}),
      ...(state.walletName ? { walletName: state.walletName } : {}),
      ...(state.expiresAt ? { expiresAt: state.expiresAt } : {}),
      ...(state.error ? { error: state.error } : {}),
    };
  }

  /** The user compared the codes: confirm (the session becomes usable) or reject. */
  async confirmPairing(matches: boolean): Promise<void> {
    const state = this.pairingState;
    if (state.phase !== "compare_code" || !state.pairing) {
      throw new ToolError("invalid_request", state.phase === "waiting_for_wallet" ? "The wallet has not scanned the code yet; check pairing_status first." : "There is no code to confirm; start with the pair tool.");
    }
    if (!matches) {
      await state.pairing.reject().catch(() => undefined);
      state.error = new ToolError("pairing_rejected", "The codes did not match, so the pairing was cancelled. Pair again, and check that the wallet scanned this code.");
      this.move(state, "failed");
      log("pairing rejected: codes differ");
      return;
    }
    try {
      await state.pairing.confirm({ timeoutSeconds: 120 });
    } catch (e) {
      state.error = fromWalletError(e);
      this.move(state, "failed");
      throw state.error;
    }
    this.move(state, "active");
    log("paired");
  }

  /** Ends the session; whether the wallet was told (it may not be reachable now). */
  async end(): Promise<boolean> {
    const told = await this.client.end("ended by the user from the agent").then(
      () => true,
      () => false,
    );
    this.pairingState = freshState("none");
    return told;
  }

  private requireActive(): void {
    if (this.client.status === "active") return;
    if (this.client.status === "ended" || this.endedBy) throw new ToolError("session_ended", SESSION_TEXT.session_ended as string);
    throw new ToolError("not_paired", SESSION_TEXT.not_paired as string);
  }

  /**
   * Sends a request and waits up to `waitSeconds` for the answer. If the wallet has not answered
   * by then, the request stays pending: the answer says so with a handle for `request_status`
   * (`wallet_unreachable` while it was not even delivered).
   */
  async request(
    method: string,
    params: unknown,
    waitSeconds: number,
    onResult?: (result: unknown) => Promise<void>,
  ): Promise<{ result: unknown } | { pending: PendingRequest }> {
    this.requireActive();
    // One request at a time: the delivery event that follows a send belongs to it.
    const send = async (): Promise<PendingRequest> => {
      const local = `local-${++this.counter}`;
      const entry: PendingRequest = { handle: local, method, posted: false, state: "waiting", done: Promise.resolve({ ok: false, error: new ToolError("internal", "not sent") }) };
      // Requests go one at a time until the relay has taken this one (its `queued` event, or a
      // failure to post), so the first `queued` of this method after the send is this request's.
      let off = () => {};
      const first = new Promise<void>((resolve) => {
        off = this.client.on("delivery", (d) => {
          if (d.method === method && d.state === "queued" && !entry.posted) {
            entry.handle = `req-${d.id}`;
            entry.state = "queued";
            entry.posted = true;
            off();
            resolve();
          }
        });
      });
      entry.done = this.client.requestRaw(method, JSON.stringify(params), { ttlSeconds: 600 }).then(
        async (json) => {
          const settled = { ok: true as const, result: JSON.parse(json) as unknown };
          if (onResult) await onResult(settled.result).catch(() => undefined);
          entry.settled = settled;
          entry.state = "completed";
          return settled;
        },
        (e: unknown) => {
          const settled = { ok: false as const, error: fromWalletError(e) };
          entry.settled = settled;
          return settled;
        },
      );
      await Promise.race([first, entry.done]);
      off();
      return entry;
    };
    const run = this.serial.then(send, send);
    this.serial = run.catch(() => undefined);
    const entry = await run;
    this.pending.set(entry.handle, entry);
    return this.wait(entry, waitSeconds);
  }

  private async wait(entry: PendingRequest, waitSeconds: number): Promise<{ result: unknown } | { pending: PendingRequest }> {
    const outcome = await Promise.race([entry.done, new Promise<null>((r) => setTimeout(() => r(null), Math.max(0, waitSeconds) * 1000))]);
    if (outcome === null) return { pending: entry };
    this.pending.delete(entry.handle);
    if (outcome.ok) return { result: outcome.result };
    throw outcome.error;
  }

  /** A request that was still pending, waited on again. */
  async requestStatus(handle: string, waitSeconds: number): Promise<{ result: unknown } | { pending: PendingRequest }> {
    const entry = this.pending.get(handle);
    if (!entry) throw new ToolError("invalid_request", "No pending request with that handle (it was answered already, or the plugin restarted).");
    return this.wait(entry, waitSeconds);
  }

  /**
   * Asks the wallet to withdraw a pending request. Says honestly what is known: a request that
   * was answered meanwhile returns its outcome; one the user already approved may have happened.
   */
  async cancel(handle: string): Promise<{ withdrawn: "requested" | "answered" | "unknown"; detail: string; result?: unknown; error?: ToolError }> {
    const entry = this.pending.get(handle);
    if (!entry) throw new ToolError("invalid_request", "No pending request with that handle.");
    if (entry.settled) {
      this.pending.delete(handle);
      return entry.settled.ok
        ? { withdrawn: "answered", detail: "The wallet had already answered it; nothing was withdrawn.", result: entry.settled.result }
        : { withdrawn: "answered", detail: "The wallet had already answered it with an error; nothing was withdrawn.", error: entry.settled.error };
    }
    if (!entry.posted) {
      return { withdrawn: "unknown", detail: "The request has not reached the relay yet, so it cannot be named for the wallet. Check again with request_status." };
    }
    const late = ["approved", "broadcast"].includes(entry.state);
    try {
      await this.client.cancel(handle.slice(4));
    } catch {
      return { withdrawn: "unknown", detail: "The withdrawal could not be sent (the relay may be unreachable). The request may still be answered; check with request_status." };
    }
    return late
      ? { withdrawn: "unknown", detail: "The wallet had already approved it, so it was probably carried out; the wallet answers an approved request normally. Check with request_status." }
      : { withdrawn: "requested", detail: "The wallet drops it unless the user approved it in the meantime; request_status shows the final answer (cancelled, or the result)." };
  }

  async close(): Promise<void> {
    this.client.close();
    await this.o.origin.close();
  }
}

export { SESSION_TEXT };
