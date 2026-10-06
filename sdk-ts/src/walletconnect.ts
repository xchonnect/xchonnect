/**
 * WalletConnect `sign-client` compatibility shim.
 *
 * Existing Chia dApps drive `@walletconnect/sign-client` through a small slice of its API:
 * `connect()` → QR → `approval()`, then `request()`, `disconnect()` and
 * `session.getAll()`. {@link XchonnectSignClient} offers that same call shape over an
 * Xchonnect session, so migrating is a dependency swap plus the pairing-UI change below.
 *
 * **It is not a drop-in replacement, by design.** Two things cannot be papered over:
 *
 * 1. **The SAS comparison is mandatory** (spec 6.3). WalletConnect has no step where the
 *    user compares a code, so {@link SignClientShimOptions.confirmSas} is a *required*
 *    option: the shim cannot be constructed without a screen that shows the six digits and
 *    asks the user. Hiding it would remove the defence against a relayed pairing code.
 * 2. **Anything that cannot be honoured throws** rather than silently behaving
 *    differently: other CAIP namespaces, multi-chain proposals, a `chainId` that is not
 *    the session's, pairing-topic reuse, custom relays, and the wallet-side and
 *    connection-oriented parts of the API. A shim that looks like WalletConnect and
 *    quietly does something else is worse than no shim.
 *
 * Nothing here touches globals, so a dApp can run this and a real `SignClient` side by
 * side and route the same CHIP-0002 calls through whichever the user picked.
 *
 * See [`docs/guides/walletconnect-comparison.md`](../../docs/guides/walletconnect-comparison.md)
 * for the supported surface, the differences and a sample migration.
 */
import { createChip0002Provider } from "./chip0002.js";
import type { ClientStatus, XchonnectClient } from "./client.js";
import { XchonnectError } from "./errors.js";
import type { SessionPermissions } from "./permissions.js";

/** The `chia` CAIP-2 chain the session is bound to when none is configured. */
export const DEFAULT_CHAIN_ID = "chia:mainnet";

/**
 * Structural stand-in for `ProposalTypes.RequiredNamespace`.
 *
 * Declared locally on purpose: `@maximedogawa/xchonnect` ships no runtime npm dependencies
 * (`docs/dependency-policy.md` rule 7), and mirroring three fields does not justify
 * pulling in `@walletconnect/types`. A real `SignClient` proposal structurally satisfies
 * these types, so code that already builds one compiles unchanged.
 */
export interface ProposalNamespace {
  chains?: string[];
  methods: string[];
  events: string[];
}

/** Structural stand-in for `SessionTypes.Namespace`. */
export interface SessionNamespace {
  chains: string[];
  accounts: string[];
  methods: string[];
  events: string[];
}

/** Peer metadata, as `SessionTypes.Struct["peer"]["metadata"]`. */
export interface PeerMetadata {
  name: string;
  description: string;
  url: string;
  icons: string[];
}

/**
 * The fields of `SessionTypes.Struct` this shim can fill honestly. Fields of the real
 * struct that describe WalletConnect's own plumbing (`pairingTopic`, `self`, `controller`,
 * `relay`, `sessionProperties`) are absent rather than faked.
 */
export interface ShimSession {
  /** Identifies this session in `request()` and `disconnect()`. See {@link XchonnectSignClient.session}. */
  topic: string;
  /**
   * Always one entry, `chia`: `methods` is what the wallet declared it granted
   * (spec 9.3) once it has said, and the dApp's request until then. `accounts` is empty —
   * see the note on {@link SessionNamespace}.
   */
  namespaces: Record<string, SessionNamespace>;
  /** The methods the dApp asked for, echoed back; the wallet decides what it grants. */
  requiredNamespaces: Record<string, ProposalNamespace>;
  optionalNamespaces: Record<string, ProposalNamespace>;
  /** Wallet name reported at pairing, if any. */
  peer: { metadata: PeerMetadata };
  /** Pairing URI expiry (unix seconds). Xchonnect sessions do not expire on a timer. */
  expiry: number;
  acknowledged: true;
}

/** Subset of `SignClient["connect"]` parameters. */
export interface ShimConnectParams {
  requiredNamespaces?: Record<string, ProposalNamespace>;
  optionalNamespaces?: Record<string, ProposalNamespace>;
  /** Rejected: Xchonnect has no reusable pairing topic. */
  pairingTopic?: string;
  /** Rejected: the relay is configured on the {@link XchonnectClient}. */
  relays?: unknown;
}

/** Subset of `SignClient["request"]` parameters. */
export interface ShimRequestParams {
  topic: string;
  /** Checked against the session's chain when given; a mismatch throws. */
  chainId?: string;
  request: { method: string; params?: unknown };
  expiry?: number;
}

export interface ShimDisconnectParams {
  topic: string;
  reason?: { code: number; message: string };
}

/** What `connect()` resolves with: `{ uri, approval }` as WalletConnect returns it. */
export interface ShimConnectResult {
  /** `xchonnect:v1?…` — render as a QR code for the logged-in user only. */
  uri: string;
  /**
   * Resolves once the wallet has replied **and** the user has confirmed the SAS through
   * {@link SignClientShimOptions.confirmSas}. Rejects if the user reports a mismatch, if
   * the pairing code expires, or if the wallet never replies.
   */
  approval: () => Promise<ShimSession>;
  /** Additional to WalletConnect: when `uri` stops being valid (unix seconds). */
  expiry: number;
}

/** The only event this shim can emit. */
export interface SessionDeleteEvent {
  topic: string;
}

export interface SignClientShimOptions {
  /** An Xchonnect client; pairing, requests and storage all go through it. */
  client: XchonnectClient;
  /**
   * **Required.** Show `sas` (six digits, formatted `"042 917"`) next to the wallet name
   * and resolve `true` only when the user confirms the wallet shows the same code. The
   * session does not become active until then (spec 6.3), and `false` ends it.
   */
  confirmSas: (sas: string, info: { walletName?: string }) => Promise<boolean>;
  /** CAIP-2 id of the chain the wallet is on. Default {@link DEFAULT_CHAIN_ID}. */
  chainId?: string;
  /** Request TTL in seconds, passed through to {@link XchonnectClient.request}. */
  ttlSeconds?: number;
  /** How long to wait for `session.ready` after the SAS is confirmed. Default 300 s. */
  readyTimeoutSeconds?: number;
  /** Override the random topic (e.g. to restore one your dApp persisted). */
  topic?: string;
}

/** Sign-client surface this shim deliberately does not provide, and what to use instead. */
const UNSUPPORTED: Record<string, string> = {
  approve: "wallet-side API; wallets use the UniFFI bindings, see docs/wallet-integration.md",
  reject: "wallet-side API; wallets use the UniFFI bindings, see docs/wallet-integration.md",
  respond: "wallet-side API; wallets use the UniFFI bindings, see docs/wallet-integration.md",
  pair: "there is no reusable pairing topic: call connect() for each new session",
  extend: "Xchonnect sessions have no expiry to extend; rotate keys with client.rotate()",
  update: "namespaces cannot be renegotiated; end the session and pair again",
  emit: "wallet-side API",
  ping: "there is no connection to ping; read client.status and the 'delivery' event instead",
  core: "WalletConnect core (relayer, crypto, pairing store) has no Xchonnect analogue",
};

/** Events a real sign-client emits that Xchonnect has no analogue for. */
const UNEMITTED: Record<string, string> = {
  session_update: "namespaces are never renegotiated",
  session_event: "wallets emit no chain events over Xchonnect",
  session_expire: "Xchonnect sessions do not expire on a timer",
  session_proposal: "wallet-side event",
  session_request: "wallet-side event",
  session_ping: "there is no connection to ping",
  proposal_expire: "pairing expiry is reported by connect().approval() rejecting",
};

function unsupported(name: string): never {
  const why = UNSUPPORTED[name] ?? "not part of the supported subset";
  throw new XchonnectError("wc_unsupported", `${name}() is not supported by the Xchonnect sign-client shim: ${why}`);
}

/** 32 random bytes as hex, the shape of a WalletConnect topic. */
function randomTopic(): string {
  const b = new Uint8Array(32);
  crypto.getRandomValues(b);
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}

/**
 * Check a proposal: Chia only, and at most the session's own chain.
 *
 * WalletConnect would negotiate this with the wallet; an Xchonnect session is bound to one
 * network before any method call, so a proposal that asks for anything else can never be
 * satisfied and is refused here rather than at signing time.
 */
function checkNamespaces(ns: Record<string, ProposalNamespace> | undefined, chainId: string, which: string): void {
  for (const [key, value] of Object.entries(ns ?? {})) {
    if (key !== "chia") {
      throw new XchonnectError("wc_unsupported_namespace", `${which}.${key}: Xchonnect carries CHIP-0002 on Chia only (spec 9.1); drop the namespace or keep WalletConnect for it`);
    }
    const chains = value.chains ?? [];
    if (chains.length > 1) {
      throw new XchonnectError("wc_multi_chain", `${which}.chia.chains: one Xchonnect session is bound to one network; asked for ${chains.length}`);
    }
    if (chains.length === 1 && chains[0] !== chainId) {
      throw new XchonnectError("wc_chain_mismatch", `${which}.chia.chains: this client is bound to ${chainId}, not ${String(chains[0])}`);
    }
  }
}

/**
 * A WalletConnect-shaped façade over an Xchonnect session.
 *
 * Supported: {@link connect}, {@link request}, {@link disconnect}, {@link session},
 * and `on("session_delete")`. Everything else throws — see {@link UNSUPPORTED}.
 */
export class XchonnectSignClient {
  /** Lets code that supports several providers tell the transports apart. */
  readonly isXchonnect = true;
  /** CAIP-2 chain this instance is bound to. */
  readonly chainId: string;
  private readonly provider: ReturnType<typeof createChip0002Provider>;
  private readonly topic: string;
  private current: ShimSession | undefined;
  private readonly deleteListeners = new Set<(e: SessionDeleteEvent) => void>();
  private readonly offStatus: () => void;
  private readonly offPermissions: () => void;

  constructor(private readonly opts: SignClientShimOptions) {
    if (typeof opts.confirmSas !== "function") {
      throw new XchonnectError("sas_required", "confirmSas is required: the user must compare the six-digit code before the session becomes active (spec 6.3)");
    }
    this.chainId = opts.chainId ?? DEFAULT_CHAIN_ID;
    this.topic = opts.topic ?? randomTopic();
    const providerOpts = opts.ttlSeconds === undefined ? {} : { ttlSeconds: opts.ttlSeconds };
    this.provider = createChip0002Provider(opts.client, providerOpts);
    this.offStatus = opts.client.on("status", (s: ClientStatus) => {
      if (s !== "ended" || !this.current) return;
      const { topic } = this.current;
      this.current = undefined;
      for (const l of this.deleteListeners) l({ topic });
    });
    // A wallet's `session.permissions` (spec 9.3) usually arrives just after the session
    // becomes active, i.e. after `buildSession` ran. Narrow the cached struct to what was
    // granted rather than leaving the request echoed in it.
    this.offPermissions = opts.client.on("permissions", (p: SessionPermissions) => {
      const ns = this.current?.namespaces["chia"];
      if (ns && p.declared) ns.methods = [...p.methods];
    });
  }

  /**
   * Adopt a session the {@link XchonnectClient} restored from storage, so
   * {@link session} and {@link request} work after a page reload.
   *
   * WalletConnect restores sessions from its own store; here the Xchonnect client owns
   * the state and the shim only needs the WalletConnect-shaped wrapper. Pass the `topic`
   * your dApp persisted as {@link SignClientShimOptions.topic}, or read the new one from
   * `session.getAll()`.
   */
  restore(params: { requiredNamespaces?: Record<string, ProposalNamespace>; walletName?: string } = {}): ShimSession | undefined {
    if (this.opts.client.status !== "active") return undefined;
    checkNamespaces(params.requiredNamespaces, this.chainId, "requiredNamespaces");
    this.current = this.buildSession(params.requiredNamespaces, {}, params.walletName, 0);
    return this.current;
  }

  /**
   * Start pairing. Returns the URI to show as a QR code and `approval()`, which resolves
   * after the wallet replies *and* the user confirms the SAS.
   *
   * Differences from `SignClient.connect()`: `uri` is always present (there is no pairing
   * to reuse), `pairingTopic` and `relays` are refused, the namespaces are checked against
   * this client's chain, and `approval()` additionally runs
   * {@link SignClientShimOptions.confirmSas}.
   */
  async connect(params: ShimConnectParams = {}): Promise<ShimConnectResult> {
    if (params.pairingTopic !== undefined) {
      throw new XchonnectError("wc_unsupported", "pairingTopic: Xchonnect pairing codes are single-use (spec 6.3), so there is no pairing to reuse");
    }
    if (params.relays !== undefined) {
      throw new XchonnectError("wc_unsupported", "relays: set the relay on the XchonnectClient instead");
    }
    checkNamespaces(params.requiredNamespaces, this.chainId, "requiredNamespaces");
    checkNamespaces(params.optionalNamespaces, this.chainId, "optionalNamespaces");
    const pairing = await this.opts.client.pair();
    const approval = async (): Promise<ShimSession> => {
      const { sas, walletName } = await pairing.waitForWallet();
      // The one step WalletConnect has no equivalent for, and the reason this shim is not
      // a silent drop-in: without it a relayed pairing code is undetectable (spec 6.3).
      const ok = await this.opts.confirmSas(sas, walletName === undefined ? {} : { walletName });
      if (!ok) {
        await pairing.reject();
        throw new XchonnectError("sas_rejected", "the user reported different codes: pairing aborted");
      }
      const confirmOpts = this.opts.readyTimeoutSeconds === undefined ? {} : { timeoutSeconds: this.opts.readyTimeoutSeconds };
      await pairing.confirm(confirmOpts);
      this.current = this.buildSession(params.requiredNamespaces, params.optionalNamespaces, walletName, pairing.expiresAt);
      return this.current;
    };
    return { uri: pairing.uri, approval, expiry: pairing.expiresAt };
  }

  /**
   * Send a CHIP-0002 request, as `SignClient.request()`.
   *
   * Rejects with a CHIP-0002 error object (`{ code, message, data? }`), the same shape a
   * WalletConnect dApp already handles. `method` may be bare or `chip0002_`-prefixed
   * (spec 9.1).
   */
  async request<T = unknown>(params: ShimRequestParams): Promise<T> {
    this.requireTopic(params.topic);
    if (params.chainId !== undefined && params.chainId !== this.chainId) {
      // Never silently sign on a chain the caller did not mean: the wallet refuses
      // other networks anyway (spec 9.1, error 4001 `wrong_network`), but failing here
      // keeps a mistyped chain id out of the user's approval prompt.
      throw new XchonnectError("wc_chain_mismatch", `chainId ${params.chainId}: this session is bound to ${this.chainId}`);
    }
    const { method, params: args } = params.request;
    return this.provider.request<T>(args === undefined ? { method } : { method, params: args });
  }

  /** End the session, as `SignClient.disconnect()`. */
  async disconnect(params: ShimDisconnectParams): Promise<void> {
    this.requireTopic(params.topic);
    await this.opts.client.end(params.reason?.message);
  }

  /**
   * The session store, as `SignClient.session`.
   *
   * Read `getAll()[0].topic` after construction: topics are random per instance and are
   * not derived from session state, so a topic your dApp persisted across a reload is
   * rejected unless you pass it as {@link SignClientShimOptions.topic}.
   */
  get session(): { get: (topic: string) => ShimSession; getAll: () => ShimSession[]; keys: string[]; length: number } {
    const all = (): ShimSession[] => (this.current ? [this.current] : []);
    return {
      get: (topic: string) => {
        this.requireTopic(topic);
        if (!this.current) throw new XchonnectError("no_session", "no active session");
        return this.current;
      },
      getAll: all,
      get keys() {
        return all().map((s) => s.topic);
      },
      get length() {
        return all().length;
      },
    };
  }

  /**
   * Subscribe to `session_delete`, the only sign-client event with an Xchonnect analogue.
   *
   * Every other sign-client event throws instead of never firing: silence would look
   * like a working subscription. Use `client.on("status" | "delivery" | "privacy" | …)`.
   */
  on(event: "session_delete", cb: (e: SessionDeleteEvent) => void): () => void {
    if (event !== "session_delete") {
      const why = UNEMITTED[event as string] ?? "no Xchonnect analogue";
      throw new XchonnectError("wc_unsupported_event", `on("${String(event)}"): ${why}; use client.on("status" | "delivery" | "privacy" | "ohttpKeyRotated") instead`);
    }
    this.deleteListeners.add(cb);
    return () => this.deleteListeners.delete(cb);
  }

  /** Unsubscribe a {@link on} listener. */
  off(event: "session_delete", cb: (e: SessionDeleteEvent) => void): void {
    if (event === "session_delete") this.deleteListeners.delete(cb);
  }

  /** Stop listening to the underlying client. Does not end the session. */
  close(): void {
    this.offStatus();
    this.offPermissions();
    this.deleteListeners.clear();
  }

  // --- Refused surface: loud, with the Xchonnect equivalent in the message. ---

  /** @throws always — see {@link UNSUPPORTED}. */
  ping(): never {
    return unsupported("ping");
  }
  /** @throws always — see {@link UNSUPPORTED}. */
  extend(): never {
    return unsupported("extend");
  }
  /** @throws always — see {@link UNSUPPORTED}. */
  update(): never {
    return unsupported("update");
  }
  /** @throws always — see {@link UNSUPPORTED}. */
  pair(): never {
    return unsupported("pair");
  }
  /** @throws always — wallet-side API. */
  approve(): never {
    return unsupported("approve");
  }
  /** @throws always — wallet-side API. */
  reject(): never {
    return unsupported("reject");
  }
  /** @throws always — wallet-side API. */
  respond(): never {
    return unsupported("respond");
  }
  /** @throws always — wallet-side API. */
  emit(): never {
    return unsupported("emit");
  }
  /** @throws always — WalletConnect core has no analogue. */
  get core(): never {
    return unsupported("core");
  }

  private requireTopic(topic: string): void {
    if (this.current && topic === this.current.topic) return;
    if (!this.current) throw new XchonnectError("no_session", "no active session: call connect() (or restore() after a reload)");
    throw new XchonnectError("wc_unknown_topic", `no matching key: ${topic}; read the current topic from session.getAll()`);
  }

  private buildSession(
    required: Record<string, ProposalNamespace> | undefined,
    optional: Record<string, ProposalNamespace> | undefined,
    walletName: string | undefined,
    expiry: number,
  ): ShimSession {
    // What the wallet granted if it has said (spec 9.3), else what the dApp asked for.
    const declared = this.opts.client.permissions;
    const methods = declared.declared ? [...declared.methods] : (required?.["chia"]?.methods ?? []);
    return {
      topic: this.topic,
      namespaces: {
        chia: {
          chains: [this.chainId],
          // Empty on purpose: pairing discloses no address. A wallet's declaration names
          // public keys, and a CAIP-10 account is an address, so putting them here would
          // misreport them; read them from `client.permissions.keys`, or call
          // `getPublicKeys` (which the wallet prompts for).
          accounts: [],
          methods,
          events: [],
        },
      },
      requiredNamespaces: required ?? {},
      optionalNamespaces: optional ?? {},
      peer: { metadata: { name: walletName ?? "", description: "", url: "", icons: [] } },
      expiry,
      acknowledged: true,
    };
  }
}

/** Create a {@link XchonnectSignClient}. Mirrors `SignClient.init()`. */
export function createSignClientShim(opts: SignClientShimOptions): XchonnectSignClient {
  return new XchonnectSignClient(opts);
}
