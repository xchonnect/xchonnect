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

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** Serialises session mutations across tabs (Web Locks) or within one context. */
class SessionLock {
  private chain: Promise<unknown> = Promise.resolve();
  constructor(private readonly name: string) {}
  run<T>(f: () => Promise<T>): Promise<T> {
    const locks = (globalThis.navigator as Navigator | undefined)?.locks;
    if (locks) return locks.request(this.name, f) as Promise<T>;
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
  private polling = false;
  private waitingForReady = false;
  private permissions_ = new PermissionsView();
  private readonly listeners = {
    status: new Set<Listener<ClientStatus>>(),
    delivery: new Set<Listener<DeliveryEvent>>(),
    orphan: new Set<Listener<string>>(),
    permissions: new Set<Listener<SessionPermissions>>(),
  };
  private visibilityHandler?: () => void;
  private readonly transport: OhttpTransport | undefined;
  /** `Date.now()` of the last message sent; drives the polling schedule (spec 10.1). */
  private lastSendMs = 0;

  private constructor(private readonly opts: ClientOptions) {
    this.store = opts.storage ?? defaultSessionStore();
    this.key = opts.storageKey ?? "default";
    this.lock = new SessionLock(`xchonnect:${this.key}`);
    this.now = opts.now ?? (() => Math.floor(Date.now() / 1000));
    const relayOpts: ConstructorParameters<typeof RelayClient>[1] = { solvePow: (c) => core.solvePow(c) };
    if (opts.apiKey !== undefined) relayOpts.apiKey = opts.apiKey;
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
    if (typeof document !== "undefined") {
      c.visibilityHandler = () => {
        if (document.visibilityState === "visible") void c.sync().catch(() => undefined);
      };
      document.addEventListener("visibilitychange", c.visibilityHandler);
    }
    return c;
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
  on(event: "status" | "delivery" | "orphanResponse" | "permissions" | "privacy" | "ohttpKeyRotated", cb: Listener<never>): () => void {
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
      if (!this.visible()) {
        await sleep(this.pollDelay());
        continue;
      }
      const maxWait = this.maxWait(info);
      const wait = Math.min(maxWait, Math.max(0, expiresAt - this.now()));
      const msgs = await this.relay.fetchMessages(mailbox, readToken, wait, signal);
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
      if (wait === 0 || msgs.length > 0) await sleep(this.pollDelay());
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
        if (!this.visible()) await sleep(this.pollDelay());
        else await this.syncOnce(true);
      }
    } finally {
      this.waitingForReady = false;
    }
    this.setStatus("active");
  }

  /** @internal */
  async _rejectSas(): Promise<void> {
    const out = await this.mutate((s) => s.rejectSas(this.now()));
    await this.relay.post(out.mailbox, out.writeToken, out.envelope).catch(() => undefined);
    await this.forget();
  }

  /** Send a CHIP-0002 request; resolves with the parsed JSON result. */
  async request<T = unknown>(method: string, params: unknown = {}, opts: RequestOptions = {}): Promise<T> {
    const json = await this.requestRaw(method, JSON.stringify(params), opts);
    return JSON.parse(json) as T;
  }

  /** Send a request with JSON-text params; resolves with the JSON-text result (exact numbers). */
  async requestRaw(method: string, paramsJson: string, opts: RequestOptions = {}): Promise<string> {
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
    await this.forget();
  }

  /** Fetch and process the session mailbox once (call on app resume). */
  async sync(): Promise<void> {
    await this.syncOnce(false);
  }

  /** Stop listeners. */
  close(): void {
    if (this.visibilityHandler && typeof document !== "undefined") document.removeEventListener("visibilitychange", this.visibilityHandler);
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

  private async forget(): Promise<void> {
    this.session = undefined;
    this.walletLink_ = undefined;
    this.permissions_ = new PermissionsView();
    await this.store.clear(this.key);
    await this.store.clear(`${this.key}:wallet-link`);
    await this.store.clear(`${this.key}:permissions`);
    this.rejectPending(new XchonnectError("session_ended", "session ended"));
    this.setStatus("ended");
  }

  private rejectPending(e: XchonnectError): void {
    for (const p of this.pending.values()) p.reject(e);
    this.pending.clear();
  }

  private async persist(): Promise<void> {
    if (this.session) await this.store.save(this.key, this.session.toBytes());
  }

  /** Run a session mutation under the cross-tab lock: reload, mutate, persist (spec 12.1). */
  private async mutate<T>(f: (s: core.Session) => T): Promise<T> {
    return this.lock.run(async () => {
      const state = await this.store.load(this.key);
      if (state) this.session = core.Session.fromBytes(state);
      if (!this.session) throw new XchonnectError("no_session", "no session");
      const r = f(this.session);
      await this.persist();
      return r;
    });
  }

  private ensurePolling(): void {
    if (this.polling) return;
    this.polling = true;
    void (async () => {
      try {
        while (this.session && (this.pending.size > 0 || this.session.drainingMailbox() || this.session.rotationPending())) {
          if (!this.visible()) {
            await sleep(this.pollDelay());
            continue;
          }
          this.expireRequests();
          await this.syncOnce(true).catch(async () => sleep(this.pollDelay()));
        }
      } finally {
        this.polling = false;
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
    const msgs = await this.relay.fetchMessages(own, read, wait);
    await this.process(own, read, msgs);
    if (longPoll && wait === 0) await sleep(this.pollDelay());
  }

  private async process(mailbox: string, readToken: string, msgs: RelayMessage[]): Promise<void> {
    const ack: string[] = [];
    for (const m of msgs) {
      let decoded: DecodedMessage | undefined;
      try {
        decoded = await this.mutate((s) => JSON.parse(s.open(this.now(), mailbox, m.env)) as DecodedMessage);
      } catch (e) {
        if (String((e as Error)?.message).includes("rotation pending")) continue; // retry later, keep in mailbox
        ack.push(m.msg_id); // invalid, replayed or expired: drop
        continue;
      }
      ack.push(m.msg_id);
      this.handle(decoded);
    }
    await this.relay.ack(mailbox, readToken, ack).catch((e: unknown) => {
      if (!(e instanceof RelayError && e.code === "not_found")) throw e;
    });
  }

  private handle(m: DecodedMessage): void {
    switch (m.type) {
      case "rpc.response": {
        const p = m.requestId ? this.pending.get(m.requestId) : undefined;
        if (m.requestId && this.withdrawn.delete(m.requestId)) return;
        if (!p || !m.requestId) {
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
        }
        return;
      }
      // `rpc.cancel` from the wallet needs nothing here: its 4102 response, which follows,
      // settles the request as "cancelled".
      case "rpc.received": {
        const p = m.requestId ? this.pending.get(m.requestId) : undefined;
        if (p && m.requestId) this.emitDelivery(m.requestId, p.method, "delivered");
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
        this.applyPermissions(m);
        return;
      case "session.end":
        void this.forget();
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
