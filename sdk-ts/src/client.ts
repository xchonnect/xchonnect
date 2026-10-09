import * as core from "../wasm/xchonnect.js";
import { RelayError, RpcErrorCode, XchonnectError, XchonnectRpcError } from "./errors.js";
import { OhttpTransport, pollDelayMs, type OhttpOptions, type PrivacyEvent, type PrivacyState } from "./ohttp.js";
import { PermissionsView, type SessionPermissions } from "./permissions.js";
import { RelayClient, type RelayInfo, type RelayMessage } from "./relay.js";
import { defaultSessionStore, type SessionStore } from "./storage.js";

/** Source of the WASM module: URL, bytes or compiled module. Defaults to the bundled file. */
export type WasmSource = core.InitInput;

let wasmReady: Promise<void> | undefined;

/** Initialise the WASM core once. In Node pass the `.wasm` bytes. */
export function initXchonnect(source?: WasmSource): Promise<void> {
  wasmReady ??= (async () => {
    if (source instanceof Uint8Array || source instanceof ArrayBuffer || source instanceof WebAssembly.Module) {
      core.initSync({ module: source });
    } else {
      await core.default(source === undefined ? undefined : { module_or_path: source });
    }
  })();
  return wasmReady;
}

export interface ClientOptions {
  /** Relay base URL, e.g. `https://relay.example.org`. */
  relay: string;
  /** This dApp's domain (A-label), as published in `/.well-known/xchonnect.json`. */
  domain: string;
  /** Origin key id. */
  kid: string;
  /** Signs `uri_sig_input` (base64url) with the origin key — normally a call to the dApp backend/KMS. */
  sign: (sigInputB64: string) => Promise<string>;
  /** Origin public key (base64url) to verify signatures early. */
  originPublicKey?: string;
  /** Publishable relay API key. */
  apiKey?: string;
  /** Session storage; default: encrypted IndexedDB in browsers, memory elsewhere. */
  storage?: SessionStore;
  /** Storage key (one session per key). */
  storageKey?: string;
  /** Allow `http://localhost` relays and `localhost:<port>` domains. Development only. */
  developerMode?: boolean;
  /** Custom fetch. */
  fetch?: typeof fetch;
  /**
   * Send relay requests through Oblivious HTTP (spec 10), so the relay does not see the
   * user's IP address. Check {@link XchonnectClient.privacy} and the `privacy` event to
   * tell users truthfully which transport is in use.
   */
  ohttp?: OhttpOptions;
  /** WASM source; see {@link initXchonnect}. */
  wasm?: WasmSource;
  /** Clock in unix seconds. */
  now?: () => number;
  /**
   * Polling when the relay offers no long-poll for the current transport (spec 10.1):
   * every `fastMs` (default 2000) for `fastWindowMs` (default 30000) after sending, then
   * every `slowMs` (default 10000), each with ±20 % jitter, only while the page is visible.
   */
  poll?: { fastMs?: number; slowMs?: number; fastWindowMs?: number };
  /** @deprecated Use `poll.fastMs`. */
  pollIntervalMs?: number;
  /** Pairing URI lifetime (s), at most 300. */
  pairingLifetimeSeconds?: number;
  /** Opens URLs for the same-device flow (default: `window.location.assign`). */
  openUrl?: (url: string) => void;
  /**
   * Keep one long poll open on the session mailbox while the page is visible, even with
   * no request pending, so a wallet's `session.end` or new `session.permissions` arrives
   * within seconds (one request per `max_wait_s`). Default: on where `document` exists
   * (browsers), off elsewhere, so a Node process can still exit. Call {@link
   * XchonnectClient.close} when the client is no longer needed.
   */
  keepAlive?: boolean;
  /**
   * Client-side deadlines for relay calls (spec 10.1): `requestMs` for calls that do not
   * long-poll (default 15000), `longPollGraceMs` added to a long poll's `wait` (default
   * 10000). A phone may freeze a page with a request in flight; a deadline ends it.
   */
  timeouts?: { requestMs?: number; longPollGraceMs?: number };
}

/** How the session ended: `by` the wallet (`session.end`) or this dApp. */
export interface EndedEvent {
  by: "wallet" | "dapp";
  reason?: string;
}

/** Whether the page probably runs in a mobile browser (same-device flow, spec 8.2). */
export function isLikelyMobile(): boolean {
  const nav = globalThis.navigator as (Navigator & { userAgentData?: { mobile?: boolean } }) | undefined;
  return nav?.userAgentData?.mobile ?? (nav !== undefined && /Android|iPhone|iPad|iPod|Mobile/i.test(nav.userAgent));
}

export interface RequestOptions {
  ttlSeconds?: number;
  signal?: AbortSignal;
  /** Same-device flow: open the wallet app after posting (needs a known wallet link). */
  openWallet?: boolean;
}

export type ClientStatus = "unpaired" | "pairing" | "awaiting-sas" | "active" | "ended";
/**
 * Where a request is. `shown`, `approved` and `broadcast` come from the wallet's `rpc.status`
 * (spec 9.1); `cancelled` is either side withdrawing it (`rpc.cancel`, error 4102).
 */
export type DeliveryState =
  | "queued"
  | "delivered"
  | "shown"
  | "approved"
  | "broadcast"
  | "completed"
  | "cancelled"
  | "failed"
  | "expired";

export interface DeliveryEvent {
  id: string;
  method: string;
  state: DeliveryState;
  /** The transaction id (`0x…`), once the wallet has broadcast it. */
  txId?: string;
}

interface Pending {
  method: string;
  exp: number;
  resolve: (json: string) => void;
  reject: (e: unknown) => void;
}

interface DecodedMessage {
  type: string;
  id: string;
  seq: number;
  requestId?: string;
  result?: string;
  error?: { code: number; message: string; data?: string | null };
  walletName?: string | null;
  reason?: string | null;
  phase?: string;
  /** `rpc.status` */
  state?: string;
  txId?: string;
  epoch?: number;
  epk?: string;
  mailbox?: string;
  writeToken?: string;
  /** `session.permissions` (spec 9.3), and a `session.ready` that carries a declaration. */
  methods?: unknown;
  keys?: unknown;
  limits?: unknown;
  permissions?: unknown;
}

type Listener<T> = (v: T) => void;

/** How long to wait for the cross-tab session lock before giving up (ms). */
const LOCK_TIMEOUT_MS = 10_000;
/** While hidden with work pending, how often to look again (ms); resume wakes it at once. */
const HIDDEN_CHECK_MS = 1_000;
/** How long to keep polling after `session.ready` for the wallet's `session.permissions` (ms). */
const AFTER_READY_MS = 10_000;
/** How often pending requests are checked for expiry (ms). */
const EXPIRY_TICK_MS = 1_000;
/** Resume events closer together than this restart polling once (ms). */
const RESUME_DEBOUNCE_MS = 300;

/** The poll was cut short on purpose (resume or close), not by a failure. */
function isInterrupt(e: unknown): boolean {
  return e instanceof XchonnectError && e.code === "interrupted";
}

/**
 * Whether a failed relay call is worth retrying: a deadline, a dropped connection, a
 * busy or failing relay. A 4xx other than 408/429 is a real answer and is not retried.
 */
function isTransient(e: unknown): boolean {
  if (e instanceof RelayError) return e.status === 0 || e.status === 408 || e.status === 429 || e.status >= 500;
  if (e instanceof XchonnectError) return isInterrupt(e) || e.code === "lock_timeout";
  return e instanceof TypeError || (e instanceof DOMException && (e.name === "AbortError" || e.name === "TimeoutError"));
}

/** `retry-after` of a relay error, in ms (spec 10.1: honour it). */
function retryAfterMs(e: unknown): number | undefined {
  if (!(e instanceof RelayError) || e.retryAfter === undefined || !Number.isFinite(e.retryAfter)) return undefined;
  // Clamped: a huge value would overflow setTimeout (and fire at once) or stall the
  // client for good; a tiny one would spin.
  return Math.min(MAX_RETRY_AFTER_S, Math.max(1, e.retryAfter)) * 1000;
}

/** Longest `Retry-After` the client honours (s). */
const MAX_RETRY_AFTER_S = 300;

const RPC_TYPES = new Set(["rpc.response", "rpc.status", "rpc.received"]);
const STATUS_STATES = new Set(["shown", "approved", "broadcast"]);

/**
 * Whether a message from another tab has the shape {@link XchonnectClient.handle} relies
 * on. The channel is same-origin, but its messages are not authenticated: anything that
 * fails this is dropped.
 */
function wellFormedPeerMessage(m: unknown): m is DecodedMessage {
  if (!m || typeof m !== "object") return false;
  const o = m as Record<string, unknown>;
  const optStr = (v: unknown) => v === undefined || v === null || typeof v === "string";
  switch (o["type"]) {
    case "session.end":
      return optStr(o["reason"]);
    case "session.permissions":
      return true; // PermissionsView.declare validates every field
    case "rpc.response": {
      if (typeof o["requestId"] !== "string") return false;
      if (o["error"] === undefined || o["error"] === null) return typeof o["result"] === "string";
      const err = o["error"] as Record<string, unknown>;
      return typeof err === "object" && typeof err["code"] === "number" && typeof err["message"] === "string" && optStr(err["data"]);
    }
    case "rpc.status":
      return typeof o["requestId"] === "string" && STATUS_STATES.has(o["state"] as string) && optStr(o["txId"]);
    case "rpc.received":
      return typeof o["requestId"] === "string";
    default:
      return false;
  }
}

/** base64url of UTF-8 text. */
function b64url(text: string): string {
  let bin = "";
  for (const b of new TextEncoder().encode(text)) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Serialises session mutations across tabs (Web Locks) or within one context. */
class SessionLock {
  private chain: Promise<unknown> = Promise.resolve();
  constructor(private readonly name: string) {}
  run<T>(f: () => Promise<T>): Promise<T> {
    const locks = (globalThis.navigator as Navigator | undefined)?.locks;
    if (locks) {
      // A frozen tab holding the lock must not stall this one forever: give up after a
      // while and let the caller retry (the message stays on the relay).
      const ctrl = new AbortController();
      const timer = setTimeout(() => ctrl.abort(new XchonnectError("lock_timeout", "the session lock is held by another tab")), LOCK_TIMEOUT_MS);
      return (
        locks.request(this.name, { signal: ctrl.signal }, () => {
          clearTimeout(timer);
          return f();
        }) as Promise<T>
      ).finally(() => clearTimeout(timer));
    }
    const next = this.chain.then(f, f);
    this.chain = next.catch(() => undefined);
    return next;
  }
}

/** A pairing in progress. */
export class Pairing {
  /** `xchonnect:v1?…` — show as QR code to the logged-in user only. */
  readonly uri: string;
  /** URI expiry (unix seconds). */
  readonly expiresAt: number;

  /** @internal */
  constructor(
    private readonly client: XchonnectClient,
    private readonly dapp: core.DappPairing,
    private readonly mailbox: string,
    private readonly readToken: string,
  ) {
    this.uri = dapp.uri();
    this.expiresAt = dapp.expiresAt();
  }

  /** Universal-link form for a wallet link base (same-device flow). */
  universalLink(base: string): string {
    return this.dapp.universalLink(base);
  }

  /** Same-device flow: open the wallet's pairing link (parameters stay in the fragment). */
  openInWallet(base: string): void {
    this.client._open(this.dapp.universalLink(base));
  }

  /** Wait for the first valid wallet reply. Resolves with the SAS to display. */
  waitForWallet(opts: { signal?: AbortSignal } = {}): Promise<{ sas: string; walletName?: string }> {
    return this.client._awaitPairingReply(this.dapp, this.mailbox, this.readToken, this.expiresAt, opts.signal);
  }

  /** The user confirmed that the wallet shows the same code. Resolves once the session is active. */
  confirm(opts: { timeoutSeconds?: number } = {}): Promise<void> {
    return this.client._confirmSas(opts.timeoutSeconds ?? 300);
  }

  /** The user reported different codes: end the session. */
  reject(): Promise<void> {
    return this.client._rejectSas();
  }
}

/** Xchonnect dApp client (spec Sections 6, 8, 9, 12). */
export class XchonnectClient {
  readonly relay: RelayClient;
  private readonly store: SessionStore;
  private readonly key: string;
  private readonly lock: SessionLock;
  private readonly now: () => number;
  private session: core.Session | undefined;
  private status_: ClientStatus = "unpaired";
  private walletLink_: string | undefined;
  private readonly pending = new Map<string, Pending>();
  /** Requests this side withdrew; the wallet's 4102 for them is expected, not an orphan. */
  private readonly withdrawn = new Set<string>();
  private waitingForReady = false;
  private permissions_ = new PermissionsView();
  private readonly listeners = {
    status: new Set<Listener<ClientStatus>>(),
    delivery: new Set<Listener<DeliveryEvent>>(),
    orphan: new Set<Listener<string>>(),
    permissions: new Set<Listener<SessionPermissions>>(),
    ended: new Set<Listener<EndedEvent>>(),
  };
  /** Resume listeners on `document`/`window`, removed by {@link close}. */
  private detach: (() => void) | undefined;
  private readonly transport: OhttpTransport | undefined;
  /** `Date.now()` of the last message sent; drives the polling schedule (spec 10.1). */
  private lastSendMs = 0;
  private readonly keepAlive: boolean;
  private closed = false;
  /** The poll loop: one at a time; a restart bumps the generation and the old loop exits. */
  private loopGen = 0;
  private loopRunning = false;
  /** Polls that a resume or close aborts. */
  private readonly inflight = new Set<AbortController>();
  /** Sleeps that a resume or close cuts short. */
  private readonly wakers = new Set<() => void>();
  private expiryTimer: ReturnType<typeof setInterval> | undefined;
  /** Keep polling until then (`Date.now()`) after `session.ready`, for `session.permissions`. */
  private afterReadyUntil = 0;
  private lastResumeMs = 0;
  /** Other clients of this session in this origin (tabs): see {@link share}. */
  private channel: BroadcastChannel | undefined;

  private constructor(private readonly opts: ClientOptions) {
    this.store = opts.storage ?? defaultSessionStore();
    this.key = opts.storageKey ?? "default";
    this.lock = new SessionLock(`xchonnect:${this.key}`);
    this.now = opts.now ?? (() => Math.floor(Date.now() / 1000));
    this.keepAlive = opts.keepAlive ?? typeof document !== "undefined";
    const relayOpts: ConstructorParameters<typeof RelayClient>[1] = { solvePow: (c) => core.solvePow(c) };
    if (opts.apiKey !== undefined) relayOpts.apiKey = opts.apiKey;
    if (opts.timeouts?.requestMs !== undefined) relayOpts.timeoutMs = opts.timeouts.requestMs;
    if (opts.timeouts?.longPollGraceMs !== undefined) relayOpts.longPollGraceMs = opts.timeouts.longPollGraceMs;
    const base = opts.relay.replace(/\/+$/, "");
    if (opts.ohttp) {
      const baseFetch: typeof fetch = opts.fetch ?? ((input, init) => globalThis.fetch(input, init));
      this.transport = new OhttpTransport(opts.ohttp, base, baseFetch, opts.developerMode ?? false);
      relayOpts.fetch = this.transport.fetch;
    } else if (opts.fetch !== undefined) {
      relayOpts.fetch = opts.fetch;
    }
    this.relay = new RelayClient(base, relayOpts);
  }

  /**
   * Whether the relay can see the user's IP address: `ohttp` (requests go through the
   * OHTTP relay) or `direct` (no OHTTP configured, or the opt-in fallback is active).
   */
  get privacy(): PrivacyState {
    return this.transport?.state ?? "direct";
  }

  /** Long-poll limit for the current transport (spec 10.1). */
  private maxWait(info: RelayInfo): number {
    return this.transport?.nextRoute === "ohttp" ? Math.min(info.max_wait_ohttp_s, info.max_wait_s) : info.max_wait_s;
  }

  /** Delay before the next poll when the effective wait is 0 (spec 10.1). */
  private pollDelay(): number {
    const p = this.opts.poll ?? {};
    return pollDelayMs(Date.now() - this.lastSendMs, {
      fastMs: p.fastMs ?? this.opts.pollIntervalMs ?? 2000,
      slowMs: p.slowMs ?? 10_000,
      fastWindowMs: p.fastWindowMs ?? 30_000,
    });
  }

  private markSent(): void {
    this.lastSendMs = Date.now();
  }

  /** Post an outgoing envelope and restart the polling schedule. */
  private async post(out: core.Outgoing, ttlSeconds?: number): Promise<void> {
    await this.relay.post(out.mailbox, out.writeToken, out.envelope, ttlSeconds);
    this.markSent();
  }

  /** Fresh tokens and a mailbox created with their hashes. */
  private async newMailbox(): Promise<{ mailbox: string; read: string; write: string }> {
    const read = core.generateToken();
    const write = core.generateToken();
    return { mailbox: await this.relay.createMailbox(core.tokenHash(read), core.tokenHash(write)), read, write };
  }

  /** Initialise WASM and restore a stored session. */
  static async create(opts: ClientOptions): Promise<XchonnectClient> {
    await initXchonnect(opts.wasm);
    const c = new XchonnectClient(opts);
    const state = await c.store.load(c.key);
    c.walletLink_ = (await c.store.load(`${c.key}:wallet-link`)) ?? undefined;
    if (state) {
      c.session = core.Session.fromBytes(state);
      c.permissions_ = PermissionsView.fromJson(await c.store.load(`${c.key}:permissions`));
      c.setStatus(c.session.isEnded() ? "ended" : c.session.isActive() ? "active" : "awaiting-sas");
    }
    c.attachResumeListeners();
    c.openChannel();
    // After a reload: pick up where the last page left off (answers, a drain, a rotation).
    c.ensurePolling();
    return c;
  }

  /**
   * Phones freeze a hidden page with its long poll in flight, and the poll may never
   * settle. Coming back (visible, `pageshow` from the back-forward cache, focus, back
   * online) restarts polling at once (spec 10.1).
   */
  private attachResumeListeners(): void {
    const onResume = () => this.resume();
    const onVisibility = () => {
      if (typeof document !== "undefined" && document.visibilityState === "visible") this.resume();
    };
    const doc = typeof document !== "undefined" ? document : undefined;
    const win = typeof window !== "undefined" ? window : undefined;
    doc?.addEventListener("visibilitychange", onVisibility);
    win?.addEventListener("pageshow", onResume);
    win?.addEventListener("focus", onResume);
    win?.addEventListener("online", onResume);
    this.detach = () => {
      doc?.removeEventListener("visibilitychange", onVisibility);
      win?.removeEventListener("pageshow", onResume);
      win?.removeEventListener("focus", onResume);
      win?.removeEventListener("online", onResume);
    };
  }

  /**
   * The page is back (or the network): abort whatever poll is in flight, cut sleeps
   * short and poll again now. Called by the SDK on `visibilitychange`, `pageshow`,
   * `focus` and `online`; call it yourself where the host has other signals (a native
   * shell's resume event).
   */
  resume(): void {
    if (this.closed) return;
    const now = Date.now();
    if (now - this.lastResumeMs < RESUME_DEBOUNCE_MS) return;
    this.lastResumeMs = now;
    this.abortInflight();
    this.wakeSleepers();
    if (this.pollWanted()) {
      // A loop stuck elsewhere (storage, a lock) is left behind: it exits on its next step.
      this.loopGen++;
      this.loopRunning = false;
      this.ensurePolling();
    } else if (this.session) {
      void this.sync().catch(() => undefined);
    }
  }

  /**
   * Tabs share one session and one mailbox, and whichever polls first opens a message.
   * Each forwarded message is tagged with {@link sessionTag} and checked for shape; the
   * channel is not authenticated, so the SDK must not run on an origin shared with
   * untrusted pages (docs/guides/security-and-privacy.md).
   * A tab that opens an answer, a status or a receipt for a request it did not send
   * passes it on, and the tab that sent it settles it; `session.end` and
   * `session.permissions` reach every tab. Same origin only (BroadcastChannel), and only
   * what this origin may read from its own storage anyway.
   */
  private openChannel(): void {
    if (typeof BroadcastChannel === "undefined") return;
    const ch = new BroadcastChannel(`xchonnect:${this.key}`);
    (ch as { unref?: () => void }).unref?.();
    ch.onmessage = (e: MessageEvent) => {
      const d = e.data as { tag?: unknown; m?: unknown } | undefined;
      if (this.closed || !d || typeof d !== "object") return;
      // Only for this session (same mailbox, same epoch), and only well-formed messages.
      const tag = this.sessionTag();
      if (tag === undefined || d.tag !== tag || !wellFormedPeerMessage(d.m)) return;
      const m = d.m;
      if (m.type === "session.end" || m.type === "session.permissions") this.handle(m, true);
      else if (RPC_TYPES.has(m.type) && m.requestId && this.pending.has(m.requestId)) this.handle(m, true);
    };
    this.channel = ch;
  }

  /** Identifies the session a forwarded message belongs to: a hash of own mailbox and epoch. */
  private sessionTag(): string | undefined {
    const s = this.session;
    if (!s) return undefined;
    try {
      return core.sha256(b64url(`xchonnect tab channel|${s.ownMailbox()}|${s.epoch()}`));
    } catch {
      return undefined;
    }
  }

  private share(m: DecodedMessage): void {
    const tag = this.sessionTag();
    if (tag === undefined) return;
    try {
      this.channel?.postMessage({ tag, m });
    } catch {
      /* closed channel: nobody to tell */
    }
  }

  /** Sleep for `ms`; {@link resume} and {@link close} cut it short. */
  private nap(ms: number): Promise<void> {
    if (this.closed) return Promise.resolve();
    return new Promise((resolve) => {
      const done = () => {
        clearTimeout(t);
        this.wakers.delete(done);
        resolve();
      };
      const t = setTimeout(done, ms);
      this.wakers.add(done);
    });
  }

  private wakeSleepers(): void {
    for (const w of [...this.wakers]) w();
  }

  /** Run a poll that {@link resume} and {@link close} may abort, and `signal` too. */
  private async interruptible<T>(signal: AbortSignal | undefined, f: (s: AbortSignal) => Promise<T>): Promise<T> {
    const ctrl = new AbortController();
    const onAbort = () => ctrl.abort(signal?.reason);
    if (signal?.aborted) onAbort();
    else signal?.addEventListener("abort", onAbort, { once: true });
    this.inflight.add(ctrl);
    try {
      return await f(ctrl.signal);
    } finally {
      this.inflight.delete(ctrl);
      signal?.removeEventListener("abort", onAbort);
    }
  }

  private abortInflight(): void {
    for (const c of this.inflight) c.abort(new XchonnectError("interrupted", "poll restarted"));
    this.inflight.clear();
  }

  /** Current status. */
  get status(): ClientStatus {
    return this.status_;
  }

  /**
   * What the wallet says this session may do: declared methods, exposed keys and spending
   * limits (spec 9.3), narrowed by anything the wallet has since refused. Ask before
   * sending, so the UI can label what is on offer and show the limits.
   *
   * **A hint for the UI, never an authorisation decision.** The wallet holds the
   * permissions and the wallet enforces them (spec 9.3, 11.1); this is a copy of what it
   * said, and it may refuse something it declared. Keep handling refusals on every
   * request — do not treat this as a security boundary.
   *
   * Empty with `declared: false` until the wallet declares anything, which means *nothing
   * is known*, not that nothing is allowed.
   */
  get permissions(): SessionPermissions {
    return this.permissions_.snapshot();
  }

  /**
   * Whether the wallet is expected to accept `method` (bare or `chip0002_`-prefixed):
   * `true` if it declared it, `false` if it declared others or has refused this one,
   * `undefined` while nothing is known.
   *
   * Only an explicit `false` is a reason not to offer something; on `undefined` go ahead
   * and send. As with {@link permissions}, this answers "what is worth showing", never
   * "what is allowed" — the wallet decides that when the request arrives.
   */
  canRequest(method: string): boolean | undefined {
    return this.permissions_.can(method);
  }

  /** Subscribe to events; returns an unsubscribe function. */
  on(event: "status", cb: Listener<ClientStatus>): () => void;
  on(event: "delivery", cb: Listener<DeliveryEvent>): () => void;
  on(event: "orphanResponse", cb: Listener<string>): () => void;
  /** The wallet declared or refused scopes: re-read {@link permissions} (spec 9.3). */
  on(event: "permissions", cb: Listener<SessionPermissions>): () => void;
  /** Transport changes (OHTTP fallback to direct HTTPS and back). Only with `ohttp` configured. */
  on(event: "privacy", cb: Listener<PrivacyEvent>): () => void;
  /** The gateway key rotated (new key id), learned through OHTTP. */
  on(event: "ohttpKeyRotated", cb: Listener<number>): () => void;
  /**
   * The session ended: the wallet sent `session.end`, or this dApp ended it or rejected
   * the SAS. `status` turns `ended` at the same time; this event says who and why.
   */
  on(event: "ended", cb: Listener<EndedEvent>): () => void;
  on(event: "status" | "delivery" | "orphanResponse" | "permissions" | "privacy" | "ohttpKeyRotated" | "ended", cb: Listener<never>): () => void {
    if (event === "privacy") return this.transport?.onPrivacy(cb as Listener<PrivacyEvent>) ?? (() => undefined);
    if (event === "ohttpKeyRotated") return this.transport?.onKeyRotated(cb as Listener<number>) ?? (() => undefined);
    const set = (event === "orphanResponse" ? this.listeners.orphan : this.listeners[event]) as Set<Listener<never>>;
    set.add(cb);
    return () => set.delete(cb);
  }

  private setStatus(s: ClientStatus) {
    if (s === this.status_) return;
    this.status_ = s;
    for (const l of this.listeners.status) l(s);
  }

  private emitDelivery(id: string, method: string, state: DeliveryState, txId?: string) {
    const event: DeliveryEvent = txId ? { id, method, state, txId } : { id, method, state };
    for (const l of this.listeners.delivery) l(event);
  }

  /** Persist the permission view and announce it, after a declaration or a refusal. */
  private async savePermissions(): Promise<void> {
    const snapshot = this.permissions_.snapshot();
    for (const l of this.listeners.permissions) l(snapshot);
    if (this.session) await this.store.save(`${this.key}:permissions`, this.permissions_.toJson());
  }

  /** Seed the view from the wallet's declaration (spec 9.3), replacing any earlier one. */
  private applyPermissions(m: DecodedMessage): void {
    if (!this.permissions_.declare(m)) return;
    void this.savePermissions().catch(() => undefined);
  }

  /**
   * A refusal narrows the view: the wallet may refuse a scope it declared, and its answer
   * is the one that counts (spec 9.3). Learning this way is the fallback, not the source.
   */
  private notePermissionRefusal(method: string, code: number): void {
    if (!this.permissions_.refuse(method, code)) return;
    void this.savePermissions().catch(() => undefined);
  }

  private visible(): boolean {
    return typeof document === "undefined" || document.visibilityState !== "hidden";
  }

  /** Start pairing: creates the single-use pairing mailbox and the signed URI. */
  async pair(): Promise<Pairing> {
    if (this.session && !this.session.isEnded()) throw new XchonnectError("already_paired", "end the current session before pairing again");
    const { mailbox, read, write } = await this.newMailbox();
    const ticket = await this.relay.ticket().catch(() => undefined);
    const lifetime = Math.min(300, this.opts.pairingLifetimeSeconds ?? 300);
    const unsigned = core.UnsignedPairing.prepare(this.relay.baseUrl, this.opts.domain, mailbox, write, lifetime, this.now(), this.opts.kid, ticket, this.opts.developerMode ?? false);
    const signature = await this.opts.sign(unsigned.sigInput());
    const dapp = unsigned.finish(signature, this.opts.originPublicKey);
    this.setStatus("pairing");
    this.markSent();
    return new Pairing(this, dapp, mailbox, read);
  }

  /** @internal */
  async _awaitPairingReply(dapp: core.DappPairing, mailbox: string, readToken: string, expiresAt: number, signal?: AbortSignal): Promise<{ sas: string; walletName?: string }> {
    const info = await this.relay.info();
    while (this.now() <= expiresAt) {
      if (signal?.aborted) throw new XchonnectError("aborted", "pairing aborted");
      if (this.closed) throw new XchonnectError("closed", "client closed");
      if (!this.visible()) {
        await this.nap(Math.min(this.pollDelay(), HIDDEN_CHECK_MS));
        continue;
      }
      const maxWait = this.maxWait(info);
      const wait = Math.min(maxWait, Math.max(0, expiresAt - this.now()));
      let msgs: RelayMessage[];
      try {
        msgs = await this.interruptible(signal, (s) => this.relay.fetchMessages(mailbox, readToken, wait, s));
      } catch (e) {
        // A frozen poll, a resume or a dropped connection: poll again (the user's abort
        // and a real error from the relay end the wait).
        if (signal?.aborted || !isTransient(e)) throw e;
        if (!isInterrupt(e)) await this.nap(retryAfterMs(e) ?? this.pollDelay());
        continue;
      }
      const invalid: string[] = [];
      for (const m of msgs) {
        let accepted: core.AcceptedPairing;
        try {
          accepted = dapp.onReply(this.now(), m.env);
        } catch {
          // Not a valid reply for this pairing: ignore it (spec 6.3 step 5) and remove it,
          // so junk posted by anyone holding the QR cannot crowd out the real reply.
          invalid.push(m.msg_id);
          continue;
        }
        // First valid reply wins: delete P immediately so later replies get not_found.
        await this.relay.deleteMailbox(mailbox, readToken).catch(() => undefined);
        const sas = accepted.sas();
        const walletName = accepted.walletName();
        const walletLink = accepted.walletLink();
        const d = await this.newMailbox();
        const confirmed = accepted.confirm(this.now(), d.mailbox, d.read, d.write);
        const out = confirmed.takeOutgoing();
        await this.lock.run(async () => {
          this.session = confirmed.takeSession();
          await this.persist();
        });
        this.walletLink_ = walletLink && /^https:\/\//.test(walletLink) ? walletLink.replace(/\/+$/, "") : undefined;
        if (this.walletLink_) await this.store.save(`${this.key}:wallet-link`, this.walletLink_);
        else await this.store.clear(`${this.key}:wallet-link`);
        await this.post(out, 300);
        this.setStatus("awaiting-sas");
        return walletName ? { sas, walletName } : { sas };
      }
      await this.relay.ack(mailbox, readToken, invalid).catch(() => undefined);
      // Pause unless a long-poll just waited: without long-polls, or when the relay
      // returned only junk at once, back off instead of spinning.
      if (wait === 0 || msgs.length > 0) await this.nap(this.pollDelay());
    }
    this.setStatus("unpaired");
    throw new XchonnectError("pairing_expired", "the pairing code expired before a wallet replied");
  }

  /** @internal */
  async _confirmSas(timeoutSeconds: number): Promise<void> {
    await this.mutate((s) => s.confirmSas(this.now()));
    this.markSent();
    const deadline = this.now() + timeoutSeconds;
    this.waitingForReady = true;
    try {
      while (!this.session?.isActive()) {
        if (this.session?.isEnded()) throw new XchonnectError("session_ended", "the wallet ended the session");
        if (this.now() > deadline) throw new XchonnectError("ready_timeout", "the wallet did not confirm the pairing in time");
        if (this.closed) throw new XchonnectError("closed", "client closed");
        if (!this.visible()) {
          await this.nap(Math.min(this.pollDelay(), HIDDEN_CHECK_MS));
          continue;
        }
        try {
          await this.syncOnce(true);
        } catch (e) {
          // A frozen poll, a resume or a dropped connection: poll again until the deadline.
          if (!isTransient(e)) throw e;
          if (!isInterrupt(e)) await this.nap(retryAfterMs(e) ?? this.pollDelay());
        }
      }
    } finally {
      this.waitingForReady = false;
    }
    this.setStatus("active");
    // The wallet posts its `session.permissions` right after `session.ready` (spec 6.3,
    // 9.3): keep polling a little so it is read now, not with the first request.
    if (!this.permissions_.snapshot().declared) {
      this.afterReadyUntil = Date.now() + AFTER_READY_MS;
      this.ensurePolling();
    }
  }

  /** @internal */
  async _rejectSas(): Promise<void> {
    const out = await this.mutate((s) => s.rejectSas(this.now()));
    await this.relay.post(out.mailbox, out.writeToken, out.envelope).catch(() => undefined);
    await this.forget({ by: "dapp", reason: "sas_mismatch" });
  }

  /** Send a CHIP-0002 request; resolves with the parsed JSON result. */
  async request<T = unknown>(method: string, params: unknown = {}, opts: RequestOptions = {}): Promise<T> {
    const json = await this.requestRaw(method, JSON.stringify(params), opts);
    return JSON.parse(json) as T;
  }

  /** Send a request with JSON-text params; resolves with the JSON-text result (exact numbers). */
  async requestRaw(method: string, paramsJson: string, opts: RequestOptions = {}): Promise<string> {
    if (this.closed) throw new XchonnectError("closed", "client closed");
    if (!this.session?.isActive()) throw new XchonnectError("not_active", "no active session");
    // Check before posting: failing afterwards would leave a request the wallet may still sign.
    if (opts.openWallet && !this.walletLink_) throw new XchonnectError("no_wallet_link", "the wallet did not provide a link for same-device requests");
    const { signal } = opts;
    const aborted = () => new XchonnectError("aborted", "request aborted");
    if (signal?.aborted) throw aborted();
    const ttl = opts.ttlSeconds ?? 600;
    const out = await this.mutate((s) => s.request(this.now(), method, paramsJson, ttl));
    if (signal?.aborted) throw aborted();
    let onAbort = () => {};
    const result = new Promise<string>((resolve, reject) => {
      this.pending.set(out.id, { method, exp: this.now() + ttl, resolve, reject });
      onAbort = () => {
        // Withdraw it in the wallet as well, so it stops waiting for the user there.
        if (this.pending.has(out.id)) void this.cancel(out.id).catch(() => {});
        else reject(aborted());
      };
      signal?.addEventListener("abort", onAbort, { once: true });
    }).finally(() => signal?.removeEventListener("abort", onAbort));
    try {
      await this.post(out, ttl);
    } catch (e) {
      this.pending.delete(out.id);
      this.emitDelivery(out.id, method, "failed");
      throw e;
    }
    this.emitDelivery(out.id, method, "queued");
    this.armExpiry();
    // The wallet mailbox id in the fragment is a fetch hint; fragments never reach servers.
    if (opts.openWallet && this.walletLink_) this._open(`${this.walletLink_}/req#mbx=${out.mailbox}`);
    this.ensurePolling();
    return result;
  }

  /** Rotate session keys and mailboxes (spec 9.2.1). */
  rotate(): Promise<void> {
    return this.rotateWith((s, n) => s.beginRotation(this.now(), n.mailbox, n.read, n.write));
  }

  private async acceptRotation(m: DecodedMessage): Promise<void> {
    const { epoch, epk, mailbox, writeToken } = m;
    if (epoch === undefined || !epk || !mailbox || !writeToken) return;
    await this.rotateWith((s, n) => s.acceptRotation(this.now(), epoch, epk, mailbox, writeToken, n.mailbox, n.read, n.write));
  }

  /** Create our next mailbox, apply the rotation step to the session and post its message. */
  private async rotateWith(step: (s: core.Session, next: { mailbox: string; read: string; write: string }) => core.Outgoing): Promise<void> {
    const next = await this.newMailbox();
    await this.post(await this.mutate((s) => step(s, next)));
    this.ensurePolling();
  }

  /**
   * Withdraw a request (spec 9.1). The wallet removes it from its queue and answers 4102;
   * the pending call rejects with `aborted` here at once. A request the wallet already
   * signed and broadcast cannot be withdrawn — the cancel then changes nothing.
   */
  async cancel(requestId: string): Promise<void> {
    const p = this.pending.get(requestId);
    if (!p) return;
    this.pending.delete(requestId);
    this.withdrawn.add(requestId);
    this.emitDelivery(requestId, p.method, "cancelled");
    p.reject(new XchonnectError("aborted", "request cancelled"));
    if (!this.session?.isActive()) return;
    await this.post(await this.mutate((s) => s.cancel(this.now(), requestId)));
  }

  private async sendPing(): Promise<void> {
    const out = await this.mutate((s) => s.ping(this.now()));
    await this.relay.post(out.mailbox, out.writeToken, out.envelope, 300).catch(() => undefined);
  }

  /** End the session and delete local state. */
  async end(reason?: string): Promise<void> {
    if (!this.session) return;
    const out = await this.mutate((s) => s.end(this.now(), reason));
    await this.relay.post(out.mailbox, out.writeToken, out.envelope).catch(() => undefined);
    await this.relay.deleteMailbox(this.session.ownMailbox(), this.session.ownReadToken()).catch(() => undefined);
    await this.forget(reason === undefined ? { by: "dapp" } : { by: "dapp", reason });
  }

  /** Fetch and process the session mailbox once (call on app resume). */
  async sync(): Promise<void> {
    await this.syncOnce(false);
  }

  /**
   * Stop this client: remove its listeners, stop polling (the poll in flight is aborted
   * and nothing it returns is processed or acknowledged, so a new client on the same
   * session gets every message) and reject pending requests with `closed`. The session
   * stays stored; a new client picks it up.
   */
  close(): void {
    if (this.closed) return;
    this.closed = true;
    this.loopGen++;
    this.loopRunning = false;
    this.detach?.();
    this.channel?.close();
    this.channel = undefined;
    this.abortInflight();
    this.wakeSleepers();
    this.rejectPending(new XchonnectError("closed", "client closed"));
  }

  /** @internal */
  _open(url: string): void {
    if (this.opts.openUrl) this.opts.openUrl(url);
    else if (typeof window !== "undefined") window.location.assign(url);
    else throw new XchonnectError("no_browser", "openUrl is required outside browsers");
  }

  /** Wallet universal-link base learned at pairing (same-device flow), if any. */
  get walletLink(): string | undefined {
    return this.walletLink_;
  }

  private async forget(ended: EndedEvent): Promise<void> {
    this.session = undefined;
    this.walletLink_ = undefined;
    this.permissions_ = new PermissionsView();
    await this.store.clear(this.key);
    await this.store.clear(`${this.key}:wallet-link`);
    await this.store.clear(`${this.key}:permissions`);
    this.rejectPending(new XchonnectError("session_ended", "session ended"));
    this.setStatus("ended");
    for (const l of this.listeners.ended) l(ended);
  }

  private rejectPending(e: XchonnectError): void {
    for (const p of this.pending.values()) p.reject(e);
    this.pending.clear();
    this.disarmExpiry();
  }

  /**
   * Expiry runs on its own timer, not only inside the poll loop: a loop stuck on a frozen
   * fetch or a lock must not keep a request's promise pending past its TTL.
   */
  private armExpiry(): void {
    if (this.expiryTimer !== undefined || this.closed) return;
    const t = setInterval(() => this.expireRequests(), EXPIRY_TICK_MS);
    (t as { unref?: () => void }).unref?.();
    this.expiryTimer = t;
  }

  private disarmExpiry(): void {
    if (this.expiryTimer === undefined) return;
    clearInterval(this.expiryTimer);
    this.expiryTimer = undefined;
  }

  private async persist(): Promise<void> {
    if (this.session) await this.store.save(this.key, this.session.toBytes());
  }

  /** Run a session mutation under the cross-tab lock: reload, mutate, persist (spec 12.1). */
  private async mutate<T>(f: (s: core.Session) => T): Promise<T> {
    return this.lock.run(async () => {
      const state = await this.store.load(this.key);
      if (state) this.session = core.Session.fromBytes(state);
      else if (this.session) {
        // Another tab ended the session and deleted it: it is over here too. Persisting
        // the copy held in memory would bring an ended session back.
        void this.forget({ by: "dapp", reason: "ended in another tab" }).catch(() => undefined);
      }
      if (!this.session) throw new XchonnectError("no_session", "no session");
      const r = f(this.session);
      await this.persist();
      return r;
    });
  }

  /**
   * Whether the session mailbox needs a poll: answers are due, a drain or rotation is
   * open, the wallet's permissions are due after `session.ready`, or (keep-alive) the
   * page is visible with an active session, so a `session.end` arrives within seconds.
   */
  private pollWanted(): boolean {
    const s = this.session;
    if (this.closed || !s) return false;
    if (this.pending.size > 0 || s.drainingMailbox() || s.rotationPending()) return true;
    if (!s.isActive() || !this.visible()) return false;
    return this.keepAlive || Date.now() < this.afterReadyUntil;
  }

  /**
   * Start the poll loop unless one runs. One loop at a time: {@link resume} starts a new
   * generation and the old loop, if stuck, exits as soon as it wakes. Errors back off
   * (`retry-after` first) and never end the loop; only {@link close}, the end of the
   * session or nothing left to wait for do.
   */
  private ensurePolling(): void {
    if (this.loopRunning || !this.pollWanted()) return;
    this.loopRunning = true;
    const gen = ++this.loopGen;
    void (async () => {
      try {
        while (gen === this.loopGen && this.pollWanted()) {
          if (!this.visible()) {
            await this.nap(Math.min(this.pollDelay(), HIDDEN_CHECK_MS));
            continue;
          }
          this.expireRequests();
          try {
            await this.syncOnce(true);
          } catch (e) {
            if (gen !== this.loopGen) break;
            if (!isInterrupt(e)) await this.nap(retryAfterMs(e) ?? this.pollDelay());
          }
        }
      } finally {
        if (gen === this.loopGen) this.loopRunning = false;
      }
    })();
  }

  private expireRequests(): void {
    const now = this.now();
    for (const [id, p] of this.pending) {
      if (p.exp < now) {
        this.pending.delete(id);
        this.emitDelivery(id, p.method, "expired");
        p.reject(new XchonnectRpcError(4100, "request expired"));
      }
    }
    if (this.pending.size === 0) this.disarmExpiry();
  }

  private async syncOnce(longPoll: boolean): Promise<void> {
    if (!this.session) return;
    const info = await this.relay.info();
    const draining = this.session.drainingMailbox();
    if (draining) {
      const [m, t] = draining as [string, string];
      const msgs = await this.relay.fetchMessages(m, t, 0);
      await this.process(m, t, msgs);
      if (msgs.length === 0) {
        const retired = await this.mutate((s) => s.finishDrain());
        if (retired) await this.relay.deleteMailbox(retired[0] as string, retired[1] as string).catch(() => undefined);
      }
    }
    if (!this.session) return;
    const own = this.session.ownMailbox();
    const read = this.session.ownReadToken();
    // Through OHTTP the wait is capped at max_wait_ohttp_s (default 0: poll, spec 10.1).
    const wait = longPoll ? this.maxWait(info) : 0;
    // A long poll is the one a frozen page leaves hanging: resume and close abort it.
    const started = Date.now();
    const msgs = longPoll ? await this.interruptible(undefined, (sig) => this.relay.fetchMessages(own, read, wait, sig)) : await this.relay.fetchMessages(own, read, wait);
    const opened = await this.process(own, read, msgs);
    // Pause unless this pass brought something new or the relay held the poll: a relay
    // that keeps returning junk, unacknowledged or not-yet-readable messages, or that
    // answers a long poll at once, must not make the loop spin.
    const held = wait > 0 && msgs.length === 0 && Date.now() - started >= (wait * 1000) / 2;
    if (longPoll && opened === 0 && !held) await this.nap(this.pollDelay());
  }

  /**
   * Open, handle and acknowledge fetched messages. Only messages that are really invalid
   * (replayed, wrong tag, wrong epoch, expired) are acknowledged unread. A storage or
   * lock failure leaves the message and those after it on the relay for the next pass:
   * acknowledging it would delete an answer nobody has read. After {@link close} nothing
   * more is opened. Returns how many new, valid messages were opened.
   */
  private async process(mailbox: string, readToken: string, msgs: RelayMessage[]): Promise<number> {
    let fresh = 0;
    const ack: string[] = [];
    let failure: unknown;
    for (const m of msgs) {
      if (this.closed) break;
      let opened: { msg: DecodedMessage } | { invalid: string };
      try {
        opened = await this.mutate((s) => {
          try {
            return { msg: JSON.parse(s.open(this.now(), mailbox, m.env)) as DecodedMessage };
          } catch (e) {
            return { invalid: String((e as Error)?.message ?? e) };
          }
        });
      } catch (e) {
        failure = e;
        break;
      }
      if ("invalid" in opened) {
        if (opened.invalid.includes("rotation pending")) continue; // retry later, keep in mailbox
        ack.push(m.msg_id); // invalid, replayed or expired: drop
        continue;
      }
      ack.push(m.msg_id);
      fresh++;
      this.handle(opened.msg);
    }
    await this.relay.ack(mailbox, readToken, ack).catch((e: unknown) => {
      if (!(e instanceof RelayError && e.code === "not_found")) throw e;
    });
    // The session ending part-way (a `session.end` in this batch) is not a failure.
    if (failure !== undefined && this.session) throw failure;
    return fresh;
  }

  /** Act on an opened message; `fromPeer`: another tab opened it ({@link share}). */
  private handle(m: DecodedMessage, fromPeer = false): void {
    switch (m.type) {
      case "rpc.response": {
        const p = m.requestId ? this.pending.get(m.requestId) : undefined;
        if (m.requestId && this.withdrawn.delete(m.requestId)) return;
        if (!p || !m.requestId) {
          if (!fromPeer) this.share(m);
          for (const l of this.listeners.orphan) l(JSON.stringify(m));
          return;
        }
        this.pending.delete(m.requestId);
        this.emitDelivery(m.requestId, p.method, m.error?.code === RpcErrorCode.RequestCancelled ? "cancelled" : "completed");
        if (!m.error) return p.resolve(m.result ?? "null");
        this.notePermissionRefusal(p.method, m.error.code);
        let data: unknown;
        try {
          data = m.error.data ? JSON.parse(m.error.data) : undefined;
        } catch {
          data = m.error.data;
        }
        p.reject(new XchonnectRpcError(m.error.code, m.error.message, data));
        return;
      }
      case "rpc.status": {
        const p = m.requestId ? this.pending.get(m.requestId) : undefined;
        const state = m.state;
        if (p && m.requestId && (state === "shown" || state === "approved" || state === "broadcast")) {
          this.emitDelivery(m.requestId, p.method, state, m.txId);
        } else if (!p && !fromPeer) this.share(m);
        return;
      }
      // `rpc.cancel` from the wallet needs nothing here: its 4102 response, which follows,
      // settles the request as "cancelled".
      case "rpc.received": {
        const p = m.requestId ? this.pending.get(m.requestId) : undefined;
        if (p && m.requestId) this.emitDelivery(m.requestId, p.method, "delivered");
        else if (!fromPeer) this.share(m);
        return;
      }
      case "session.ready":
        // The declaration is its own `session.permissions` message (spec 6.3, 9.3,
        // wire/envelope.cddl); a `session.ready` body carries only wallet metadata. We
        // still read a declaration out of a `session.ready` if some wallet puts one
        // there, rather than depending on which message it arrives in.
        this.applyPermissions(m);
        if (this.session?.isActive() && !this.waitingForReady) this.setStatus("active");
        return;
      case "session.permissions":
        this.afterReadyUntil = 0;
        this.applyPermissions(m);
        if (!fromPeer) this.share(m);
        return;
      case "session.end":
        if (!fromPeer) this.share(m);
        if (!this.session) return;
        void this.forget(m.reason ? { by: "wallet", reason: m.reason } : { by: "wallet" }).catch(() => undefined);
        return;
      case "session.rotate":
        // We are the initiator and just switched: prove it on the new mailbox so the
        // wallet can retire its previous mailbox (spec 9.2.1 step 4).
        if (m.phase === "accept") void this.sendPing();
        // The wallet may initiate rotation too (spec 9.2.1): accept it.
        else if (m.phase === "offer") void this.acceptRotation(m).catch(() => undefined);
        return;
      default:
        return;
    }
  }
}
