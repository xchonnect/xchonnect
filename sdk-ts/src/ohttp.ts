/**
 * OHTTP transport (spec 10, RFC 9458): relay requests are encrypted to the Xchonnect
 * relay's gateway key and sent through an independent OHTTP relay, so the Xchonnect
 * relay does not see the user's IP address and the OHTTP relay does not see the request.
 *
 * - Key pinning: the dApp ships the relay's key configuration. Rotations are learned by
 *   fetching `/.well-known/ohttp-keys` through the gateway under the pinned key (on first
 *   use and every `keyRefreshMs`); only an answer that decrypts under the pinned key is
 *   accepted, and the list must still contain the pinned key, otherwise requests fail
 *   with {@link OhttpKeyError}. Rotated pins live in memory only, so update
 *   the shipped configuration during the operator's overlap period.
 * - Fallback to direct HTTPS happens only with `allowDirectFallback` and is reported via
 *   the client's `privacy` state and event. A request is re-sent directly only when the
 *   OHTTP relay could not be reached or the request is a `GET`, so a request the gateway
 *   may already have executed (mailbox creation, posts, single-use proofs) is never
 *   sent twice.
 * - Polling: through OHTTP the client never asks for a `wait` above `max_wait_ohttp_s`
 *   (default 0) and polls on the spec 10.1 schedule while the page is visible.
 */
import * as core from "../wasm/xchonnect.js";
import { XchonnectError } from "./errors.js";

/** Whether the Xchonnect relay can see the user's IP address. */
export type PrivacyState = "ohttp" | "direct";

/** Emitted when the transport changes. */
export interface PrivacyEvent {
  state: PrivacyState;
  /** Why: `ohttp-failed` (fallback to direct HTTPS), `ohttp-restored`. */
  reason: "ohttp-failed" | "ohttp-restored";
}

export interface OhttpOptions {
  /**
   * URL of the independent OHTTP relay (spec 10.2) that forwards to the Xchonnect relay's
   * gateway (`<relay>/.well-known/ohttp-gateway`).
   */
  relayUrl: string;
  /**
   * Pinned gateway key configuration: the relay's `/.well-known/ohttp-keys` response
   * (base64url or bytes), published by the relay operator and shipped with the dApp.
   * Never fetched directly at runtime.
   */
  keyConfig: string | Uint8Array;
  /**
   * When the OHTTP relay fails, send requests directly over HTTPS instead of failing.
   * Off by default: the Xchonnect relay then sees the user's IP. Every switch emits a
   * `privacy` event; a key configuration mismatch never falls back.
   */
  allowDirectFallback?: boolean;
  /** How often to check for a rotated gateway key, in ms (default 6 h). */
  keyRefreshMs?: number;
}

/** After a fallback, requests go direct for this long before OHTTP is retried. */
const FALLBACK_COOLDOWN_MS = 60_000;
/** Upper bound for the shared key check (independent of any caller's signal). */
const KEY_CHECK_TIMEOUT_MS = 15_000;

/** The OHTTP relay could not be reached: the request did not leave this client. */
class OhttpUnreachable extends XchonnectError {
  constructor() {
    super("ohttp_failed", "OHTTP relay unreachable");
  }
}
const KEY_PROBLEM = "https://iana.org/assignments/http-problem-types#ohttp-key";

function bytes(v: string | Uint8Array): Uint8Array {
  if (typeof v !== "string") return v;
  const b64 = v.replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(b64 + "=".repeat((4 - (b64.length % 4)) % 4));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

/** OHTTP failed in a way that must not fall back to direct requests. */
export class OhttpKeyError extends XchonnectError {
  constructor(message: string) {
    super("ohttp_key_mismatch", message);
    this.name = "OhttpKeyError";
  }
}

/**
 * A `fetch`-compatible function that sends each relay request through OHTTP.
 * Used by {@link RelayClient} via its `fetch` option.
 */
export class OhttpTransport {
  private client: core.OhttpClient;
  private pin: Uint8Array;
  private state_: PrivacyState = "ohttp";
  private fallbackUntil = 0;
  private lastKeyCheck = -Infinity;
  private keyCheck: Promise<void> | undefined;
  private readonly listeners = new Set<(e: PrivacyEvent) => void>();
  private readonly keyListeners = new Set<(keyId: number) => void>();

  /**
   * @param relayBase base URL of the Xchonnect relay (target of the inner requests)
   * @param baseFetch the host's `fetch`, used for the OHTTP relay and for opt-in fallback
   */
  constructor(
    private readonly opts: OhttpOptions,
    private readonly relayBase: string,
    private readonly baseFetch: typeof fetch,
    developerMode = false,
  ) {
    const u = new URL(opts.relayUrl);
    const loopback = u.hostname === "localhost" || u.hostname === "127.0.0.1" || u.hostname === "[::1]";
    if (u.protocol !== "https:" && !(developerMode && u.protocol === "http:" && loopback)) {
      throw new XchonnectError("invalid_ohttp_relay", "the OHTTP relay URL must use https");
    }
    try {
      this.pin = core.ohttpSelectKey(bytes(opts.keyConfig));
      this.client = new core.OhttpClient(this.pin);
    } catch (e) {
      throw new XchonnectError("invalid_ohttp_key_config", `invalid OHTTP key configuration: ${(e as Error).message}`);
    }
  }

  /** Transport used for the latest relay request. */
  get state(): PrivacyState {
    return this.state_;
  }

  /** Transport the next request will try first. */
  get nextRoute(): PrivacyState {
    return this.opts.allowDirectFallback && Date.now() < this.fallbackUntil ? "direct" : "ohttp";
  }

  /** Key id of the gateway key currently in use. */
  get keyId(): number {
    return this.client.keyId;
  }

  /** Subscribe to transport changes. */
  onPrivacy(cb: (e: PrivacyEvent) => void): () => void {
    this.listeners.add(cb);
    return () => this.listeners.delete(cb);
  }

  /** Subscribe to gateway key rotations (new key id). */
  onKeyRotated(cb: (keyId: number) => void): () => void {
    this.keyListeners.add(cb);
    return () => this.keyListeners.delete(cb);
  }

  private setState(state: PrivacyState, reason: PrivacyEvent["reason"]) {
    if (state === this.state_) return;
    this.state_ = state;
    for (const l of this.listeners) l({ state, reason });
  }

  /** The `fetch` to give to {@link RelayClient}. */
  readonly fetch: typeof fetch = async (input, init) => {
    const url = new URL(typeof input === "string" ? input : input instanceof URL ? input.href : input.url);
    if (this.opts.allowDirectFallback && Date.now() < this.fallbackUntil) return this.baseFetch(input, init);
    let sent = false;
    try {
      await abortable(this.refreshKeys(), init?.signal ?? undefined);
      sent = true;
      const res = await this.send(url, init);
      this.setState("ohttp", "ohttp-restored");
      return res;
    } catch (e) {
      if (e instanceof OhttpKeyError || (e as Error)?.name === "AbortError" || !this.opts.allowDirectFallback) throw e;
      // Re-send directly only if the gateway cannot have executed this request.
      const method = (init?.method ?? "GET").toUpperCase();
      if (sent && !(e instanceof OhttpUnreachable) && method !== "GET") throw e;
      this.fallbackUntil = Date.now() + FALLBACK_COOLDOWN_MS;
      this.setState("direct", "ohttp-failed");
      return this.baseFetch(input, init);
    }
  };

  /**
   * Check for a rotated key at most every `keyRefreshMs`, through the gateway itself. The
   * check is shared by concurrent requests, so it runs on its own timeout rather than on
   * one caller's signal.
   */
  private refreshKeys(): Promise<void> {
    if (Date.now() - this.lastKeyCheck < (this.opts.keyRefreshMs ?? 6 * 3600_000)) return Promise.resolve();
    this.keyCheck ??= (async () => {
      try {
        const { pending, raw } = await this.exchange(new URL("/.well-known/ohttp-keys", this.relayBase), { signal: AbortSignal.timeout(KEY_CHECK_TIMEOUT_MS) });
        let next: Uint8Array;
        try {
          // Only an answer produced under the pinned key can yield a new pin.
          next = pending.decapsulateKeyRotation(raw);
        } catch (e) {
          throw new OhttpKeyError(`OHTTP key configuration rejected: ${(e as Error).message}`);
        }
        this.lastKeyCheck = Date.now();
        const client = new core.OhttpClient(next);
        if (client.keyId !== this.client.keyId || !equal(next, this.pin)) {
          this.pin = next;
          this.client = client;
          for (const l of this.keyListeners) l(client.keyId);
        }
      } finally {
        this.keyCheck = undefined;
      }
    })();
    return this.keyCheck;
  }

  private async send(url: URL, init: RequestInit | undefined): Promise<Response> {
    const { pending, raw } = await this.exchange(url, init);
    let inner: core.OhttpResponse;
    try {
      inner = pending.decapsulate(raw);
    } catch {
      throw new XchonnectError("ohttp_failed", "invalid OHTTP response");
    }
    const nullBody = inner.status === 204 || inner.status === 205 || inner.status === 304;
    return new Response(nullBody ? null : (inner.body as Uint8Array<ArrayBuffer>), {
      status: inner.status,
      headers: JSON.parse(inner.headers) as [string, string][],
    });
  }

  /** Encapsulate `url`, post it to the OHTTP relay and return the `message/ohttp-res` body. */
  private async exchange(url: URL, init: RequestInit | undefined): Promise<{ pending: core.OhttpPending; raw: Uint8Array }> {
    let body: Uint8Array | undefined;
    if (init?.body !== undefined && init.body !== null) {
      if (typeof init.body !== "string") throw new XchonnectError("ohttp_failed", "only string bodies are supported");
      body = new TextEncoder().encode(init.body);
    }
    const pending = this.client.encapsulate(init?.method ?? "GET", url.protocol.replace(/:$/, ""), url.host, url.pathname + url.search, JSON.stringify([...new Headers(init?.headers)]), body);
    const outer: RequestInit = {
      method: "POST",
      headers: { "content-type": "message/ohttp-req" },
      body: pending.request as Uint8Array<ArrayBuffer>,
      credentials: "omit",
      cache: "no-store",
      referrerPolicy: "no-referrer",
    };
    if (init?.signal) outer.signal = init.signal;
    let res: Response;
    try {
      res = await this.baseFetch(this.opts.relayUrl, outer);
    } catch (e) {
      if ((e as Error)?.name === "AbortError") throw e;
      throw new OhttpUnreachable();
    }
    const type = res.headers.get("content-type") ?? "";
    if (res.status === 400 && type.startsWith("application/problem+json")) {
      const problem = (await res.json().catch(() => ({}))) as { type?: string };
      if (problem.type === KEY_PROBLEM) throw new OhttpKeyError("the gateway no longer accepts the pinned OHTTP key; update the dApp's key configuration");
    }
    if (res.status !== 200 || !type.startsWith("message/ohttp-res")) {
      throw new XchonnectError("ohttp_failed", `OHTTP relay answered ${res.status}`);
    }
    return { pending, raw: new Uint8Array(await res.arrayBuffer()) };
  }
}

/** Wait for `p`, but reject as soon as `signal` aborts (without cancelling `p`). */
function abortable<T>(p: Promise<T>, signal: AbortSignal | undefined): Promise<T> {
  if (!signal) return p;
  if (signal.aborted) return Promise.reject(signal.reason as Error);
  return new Promise<T>((resolve, reject) => {
    const onAbort = () => reject(signal.reason as Error);
    signal.addEventListener("abort", onAbort, { once: true });
    p.then(resolve, reject).finally(() => signal.removeEventListener("abort", onAbort));
  });
}

function equal(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((v, i) => v === b[i]);
}

/**
 * Polling schedule of spec 10.1 for when the effective long-poll wait is 0: every
 * `fastMs` for the first `fastWindowMs` after sending, then every `slowMs`, with ±20 %
 * random jitter.
 */
export function pollDelayMs(sinceSendMs: number, schedule: { fastMs: number; slowMs: number; fastWindowMs: number }, random: () => number = Math.random): number {
  const base = sinceSendMs < schedule.fastWindowMs ? schedule.fastMs : schedule.slowMs;
  return Math.round(base * (0.8 + 0.4 * random()));
}
