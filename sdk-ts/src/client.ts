import * as core from "../wasm/xchonnect.js";
import { RelayError, XchonnectError, XchonnectRpcError } from "./errors.js";
import { RelayClient, type RelayMessage } from "./relay.js";
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
  /** WASM source; see {@link initXchonnect}. */
  wasm?: WasmSource;
  /** Clock in unix seconds. */
  now?: () => number;
  /** Poll interval when the relay offers no long-poll (ms). */
  pollIntervalMs?: number;
  /** Pairing URI lifetime (s), at most 300. */
  pairingLifetimeSeconds?: number;
  /** Opens URLs for the same-device flow (default: `window.location.assign`). */
  openUrl?: (url: string) => void;
}

/** Whether the page probably runs in a mobile browser (same-device flow, spec 8.2). */
export function isLikelyMobile(): boolean {
  const nav = globalThis.navigator as (Navigator & { userAgentData?: { mobile?: boolean } }) | undefined;
  if (!nav) return false;
  if (nav.userAgentData?.mobile !== undefined) return nav.userAgentData.mobile;
  return /Android|iPhone|iPad|iPod|Mobile/i.test(nav.userAgent);
}

export interface RequestOptions {
  ttlSeconds?: number;
  signal?: AbortSignal;
  /** Same-device flow: open the wallet app after posting (needs a known wallet link). */
  openWallet?: boolean;
}

export type ClientStatus = "unpaired" | "pairing" | "awaiting-sas" | "active" | "ended";
export type DeliveryState = "queued" | "delivered" | "completed" | "failed" | "expired";

export interface DeliveryEvent {
  id: string;
  method: string;
  state: DeliveryState;
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
  private polling = false;
  private waitingForReady = false;
  private readonly listeners = { status: new Set<Listener<ClientStatus>>(), delivery: new Set<Listener<DeliveryEvent>>(), orphan: new Set<Listener<string>>() };
  private visibilityHandler?: () => void;

  private constructor(private readonly opts: ClientOptions) {
    this.store = opts.storage ?? defaultSessionStore();
    this.key = opts.storageKey ?? "default";
    this.lock = new SessionLock(`xchonnect:${this.key}`);
    this.now = opts.now ?? (() => Math.floor(Date.now() / 1000));
    const relayOpts: ConstructorParameters<typeof RelayClient>[1] = { solvePow: (c) => core.solvePow(c) };
    if (opts.apiKey !== undefined) relayOpts.apiKey = opts.apiKey;
    if (opts.fetch !== undefined) relayOpts.fetch = opts.fetch;
    this.relay = new RelayClient(opts.relay.replace(/\/+$/, ""), relayOpts);
  }

  /** Initialise WASM and restore a stored session. */
  static async create(opts: ClientOptions): Promise<XchonnectClient> {
    await initXchonnect(opts.wasm);
    const c = new XchonnectClient(opts);
    const state = await c.store.load(c.key);
    c.walletLink_ = (await c.store.load(`${c.key}:wallet-link`)) ?? undefined;
    if (state) {
      c.session = core.Session.fromBytes(state);
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

  /** Subscribe to events; returns an unsubscribe function. */
  on(event: "status", cb: Listener<ClientStatus>): () => void;
  on(event: "delivery", cb: Listener<DeliveryEvent>): () => void;
  on(event: "orphanResponse", cb: Listener<string>): () => void;
  on(event: "status" | "delivery" | "orphanResponse", cb: Listener<never>): () => void {
    const set = (event === "orphanResponse" ? this.listeners.orphan : this.listeners[event]) as Set<Listener<never>>;
    set.add(cb);
    return () => set.delete(cb);
  }

  private setStatus(s: ClientStatus) {
    if (s === this.status_) return;
    this.status_ = s;
    for (const l of this.listeners.status) l(s);
  }

  private emitDelivery(id: string, method: string, state: DeliveryState) {
    for (const l of this.listeners.delivery) l({ id, method, state });
  }

  private visible(): boolean {
    return typeof document === "undefined" || document.visibilityState !== "hidden";
  }

  // -------------------------------------------------------------------------
  // Pairing
  // -------------------------------------------------------------------------

  /** Start pairing: creates the single-use pairing mailbox and the signed URI. */
  async pair(): Promise<Pairing> {
    if (this.session && !this.session.isEnded()) throw new XchonnectError("already_paired", "end the current session before pairing again");
    const read = core.generateToken();
    const write = core.generateToken();
    const mailbox = await this.relay.createMailbox(core.tokenHash(read), core.tokenHash(write));
    const ticket = await this.relay.ticket().catch(() => undefined);
    const lifetime = Math.min(300, this.opts.pairingLifetimeSeconds ?? 300);
    const unsigned = core.UnsignedPairing.prepare(this.relay.baseUrl, this.opts.domain, mailbox, write, lifetime, this.now(), this.opts.kid, ticket, this.opts.developerMode ?? false);
    const signature = await this.opts.sign(unsigned.sigInput());
    const dapp = unsigned.finish(signature, this.opts.originPublicKey);
    this.setStatus("pairing");
    return new Pairing(this, dapp, mailbox, read);
  }

  /** @internal */
  async _awaitPairingReply(dapp: core.DappPairing, mailbox: string, readToken: string, expiresAt: number, signal?: AbortSignal): Promise<{ sas: string; walletName?: string }> {
    const info = await this.relay.info();
    while (this.now() <= expiresAt) {
      if (signal?.aborted) throw new XchonnectError("aborted", "pairing aborted");
      const wait = Math.min(info.max_wait_s, Math.max(0, expiresAt - this.now()));
      const msgs = await this.relay.fetchMessages(mailbox, readToken, wait, signal);
      for (const m of msgs) {
        let accepted: core.AcceptedPairing;
        try {
          accepted = dapp.onReply(this.now(), m.env);
        } catch {
          continue; // not a valid reply for this pairing: ignore (spec 6.3 step 5)
        }
        // First valid reply wins: delete P immediately so later replies get not_found.
        await this.relay.deleteMailbox(mailbox, readToken).catch(() => undefined);
        const sas = accepted.sas();
        const walletName = accepted.walletName();
        const walletLink = accepted.walletLink();
        const dRead = core.generateToken();
        const dWrite = core.generateToken();
        const dMailbox = await this.relay.createMailbox(core.tokenHash(dRead), core.tokenHash(dWrite));
        const confirmed = accepted.confirm(this.now(), dMailbox, dRead, dWrite);
        const out = confirmed.takeOutgoing();
        await this.lock.run(async () => {
          this.session = confirmed.takeSession();
          await this.persist();
        });
        this.walletLink_ = walletLink && /^https:\/\//.test(walletLink) ? walletLink.replace(/\/+$/, "") : undefined;
        if (this.walletLink_) await this.store.save(`${this.key}:wallet-link`, this.walletLink_);
        else await this.store.clear(`${this.key}:wallet-link`);
        await this.relay.post(out.mailbox, out.writeToken, out.envelope, 300);
        this.setStatus("awaiting-sas");
        return walletName ? { sas, walletName } : { sas };
      }
      if (info.max_wait_s === 0 || msgs.length === 0) await sleep(this.opts.pollIntervalMs ?? 2000);
    }
    this.setStatus("unpaired");
    throw new XchonnectError("pairing_expired", "the pairing code expired before a wallet replied");
  }

  /** @internal */
  async _confirmSas(timeoutSeconds: number): Promise<void> {
    await this.mutate((s) => {
      s.confirmSas(this.now());
    });
    const deadline = this.now() + timeoutSeconds;
    this.waitingForReady = true;
    try {
      while (!this.session?.isActive()) {
        if (this.session?.isEnded()) throw new XchonnectError("session_ended", "the wallet ended the session");
        if (this.now() > deadline) throw new XchonnectError("ready_timeout", "the wallet did not confirm the pairing in time");
        await this.syncOnce(true);
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

  // -------------------------------------------------------------------------
  // Requests
  // -------------------------------------------------------------------------

  /** Send a CHIP-0002 request; resolves with the parsed JSON result. */
  async request<T = unknown>(method: string, params: unknown = {}, opts: RequestOptions = {}): Promise<T> {
    const json = await this.requestRaw(method, JSON.stringify(params), opts);
    return JSON.parse(json) as T;
  }

  /** Send a request with JSON-text params; resolves with the JSON-text result (exact numbers). */
  async requestRaw(method: string, paramsJson: string, opts: RequestOptions = {}): Promise<string> {
    if (!this.session?.isActive()) throw new XchonnectError("not_active", "no active session");
    const ttl = opts.ttlSeconds ?? 600;
    const out = await this.mutate((s) => s.request(this.now(), method, paramsJson, ttl));
    const result = new Promise<string>((resolve, reject) => {
      this.pending.set(out.id, { method, exp: this.now() + ttl, resolve, reject });
      opts.signal?.addEventListener("abort", () => {
        this.pending.delete(out.id);
        reject(new XchonnectError("aborted", "request aborted"));
      });
    });
    try {
      await this.relay.post(out.mailbox, out.writeToken, out.envelope, ttl);
    } catch (e) {
      this.pending.delete(out.id);
      this.emitDelivery(out.id, method, "failed");
      throw e;
    }
    this.emitDelivery(out.id, method, "queued");
    if (opts.openWallet) {
      if (!this.walletLink_) throw new XchonnectError("no_wallet_link", "the wallet did not provide a link for same-device requests");
      // The wallet mailbox id in the fragment is a fetch hint; fragments never reach servers.
      this._open(`${this.walletLink_}/req#mbx=${out.mailbox}`);
    }
    this.ensurePolling();
    return result;
  }

  // -------------------------------------------------------------------------
  // Lifecycle
  // -------------------------------------------------------------------------

  /** Rotate session keys and mailboxes (spec 9.2.1). */
  async rotate(): Promise<void> {
    const read = core.generateToken();
    const write = core.generateToken();
    const mailbox = await this.relay.createMailbox(core.tokenHash(read), core.tokenHash(write));
    const out = await this.mutate((s) => s.beginRotation(this.now(), mailbox, read, write));
    await this.relay.post(out.mailbox, out.writeToken, out.envelope);
    this.ensurePolling();
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
    const own = this.session.ownMailbox();
    const read = this.session.ownReadToken();
    await this.relay.deleteMailbox(own, read).catch(() => undefined);
    await this.forget();
  }

  /** Fetch and process the session mailbox once (call on app resume). */
  async sync(): Promise<void> {
    await this.syncOnce(false);
  }

  /** Stop listeners. */
  close(): void {
    if (this.visibilityHandler && typeof document !== "undefined") document.removeEventListener("visibilitychange", this.visibilityHandler);
    for (const [, p] of this.pending) p.reject(new XchonnectError("closed", "client closed"));
    this.pending.clear();
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
    await this.store.clear(this.key);
    await this.store.clear(`${this.key}:wallet-link`);
    for (const [, p] of this.pending) p.reject(new XchonnectError("session_ended", "session ended"));
    this.pending.clear();
    this.setStatus("ended");
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
            await sleep(this.opts.pollIntervalMs ?? 2000);
            continue;
          }
          this.expireRequests();
          await this.syncOnce(true).catch(async () => sleep(this.opts.pollIntervalMs ?? 2000));
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
    const wait = longPoll ? info.max_wait_s : 0;
    const msgs = await this.relay.fetchMessages(own, read, wait);
    await this.process(own, read, msgs);
    if (longPoll && (wait === 0 || msgs.length === 0) && wait === 0) await sleep(this.opts.pollIntervalMs ?? 2000);
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
        if (!p || !m.requestId) {
          for (const l of this.listeners.orphan) l(JSON.stringify(m));
          return;
        }
        this.pending.delete(m.requestId);
        if (m.error) {
          let data: unknown;
          try {
            data = m.error.data ? JSON.parse(m.error.data) : undefined;
          } catch {
            data = m.error.data;
          }
          this.emitDelivery(m.requestId, p.method, "completed");
          p.reject(new XchonnectRpcError(m.error.code, m.error.message, data));
        } else {
          this.emitDelivery(m.requestId, p.method, "completed");
          p.resolve(m.result ?? "null");
        }
        return;
      }
      case "rpc.received": {
        const p = m.requestId ? this.pending.get(m.requestId) : undefined;
        if (p && m.requestId) this.emitDelivery(m.requestId, p.method, "delivered");
        return;
      }
      case "session.ready":
        if (this.session?.isActive() && !this.waitingForReady) this.setStatus("active");
        return;
      case "session.end":
        void this.forget();
        return;
      case "session.rotate":
        // We are the initiator and just switched: prove it on the new mailbox so the
        // wallet can retire its previous mailbox (spec 9.2.1 step 4).
        if (m.phase === "accept") void this.sendPing();
        return;
      default:
        return;
    }
  }
}
