/**
 * Session permissions (spec 9.3): the scopes a wallet declares for a paired session, so a
 * dApp can tell the user what it may do *before* it sends a request.
 *
 * **This is a UI hint, never an authorisation decision.** Permissions are the wallet's to
 * keep and the wallet's to enforce (spec 9.3, 11.1); what arrives here is a copy of what
 * the wallet said, not a promise. A wallet may refuse something it declared a moment ago —
 * the user revoked it, a daily limit filled up, a key moved — and it is the wallet's
 * refusal, not this view, that decides the outcome. So use it to label buttons, pre-fill
 * amounts and show limits, and never as a check that guards anything: every request still
 * has to handle a refusal (`4001`, `4002`, `4004`, `4029`).
 */

/** Spending limits a wallet declared for the session: decimal strings of mojos (spec 9.3). */
export interface SpendingLimits {
  /** Most the wallet will sign for in a single request. */
  perRequestMojos?: string;
  /** Most the wallet will sign for in a day. */
  perDayMojos?: string;
}

/** What the wallet says this session may do (spec 9.3). See the module note: a UI hint only. */
export interface SessionPermissions {
  /**
   * Whether the wallet has declared anything yet. While `false` the other fields are
   * empty because **nothing is known** — not because nothing is allowed.
   */
  declared: boolean;
  /** Declared CHIP-0002 method names, bare (no `chip0002_` prefix, spec 9.1). */
  methods: readonly string[];
  /** Public keys the wallet exposed to this session, as it sent them (lowercase hex). */
  keys: readonly string[];
  /** Declared limits, if the wallet sent any. */
  limits?: SpendingLimits;
  /** Methods this session has seen refused with `4004` or `4001`, in the order refused. */
  refused: readonly string[];
}

/**
 * The permission fields of a decoded `session.permissions` (or of a `session.ready` that
 * carries them anyway, which the grammar does not define). Everything is `unknown`: it
 * comes off the wire, so it is validated here rather than trusted.
 */
export interface DeclaredPermissions {
  methods?: unknown;
  keys?: unknown;
  limits?: unknown;
  /** A nested object, should a message carry the declaration under its own key. */
  permissions?: unknown;
}

/**
 * Bounds on a stored view. The envelope size caps what a wallet can send in one message;
 * these cap what is kept and persisted from it. Entries beyond them are dropped, which can
 * only ever understate what the wallet declared (a hint, as above).
 */
const MAX_ENTRIES = 128;
const MAX_LEN = 128;

/** Strip the `chip0002_` alias accepted by spec 9.1, so both spellings compare equal. */
function bare(method: string): string {
  return method.startsWith("chip0002_") ? method.slice("chip0002_".length) : method;
}

/** Keep the usable strings of a wire list and drop the rest; never throws. */
function strings(v: unknown): string[] {
  if (!Array.isArray(v)) return [];
  const out: string[] = [];
  for (const x of v) {
    if (typeof x !== "string" || x.length === 0 || x.length > MAX_LEN) continue;
    if (!out.includes(x)) out.push(x);
    if (out.length === MAX_ENTRIES) break;
  }
  return out;
}

function limitString(v: unknown): string | undefined {
  return typeof v === "string" && v.length > 0 && v.length <= 40 ? v : undefined;
}

/** Read the optional `limits` map; absent, null or malformed all mean "no limits declared". */
function limitsOf(v: unknown): SpendingLimits | undefined {
  if (typeof v !== "object" || v === null) return undefined;
  const o = v as Record<string, unknown>;
  const perRequestMojos = limitString(o["perRequestMojos"]);
  const perDayMojos = limitString(o["perDayMojos"]);
  if (perRequestMojos === undefined && perDayMojos === undefined) return undefined;
  return {
    ...(perRequestMojos === undefined ? {} : { perRequestMojos }),
    ...(perDayMojos === undefined ? {} : { perDayMojos }),
  };
}

/** Error codes that tell us a method is not available after all (spec 9.1). */
const REFUSAL_CODES = new Set([4001, 4004]);

/**
 * The dApp's view of a session's permissions: seeded from what the wallet declares,
 * narrowed by what it refuses.
 *
 * @internal Reachable through {@link XchonnectClient.permissions} and
 * {@link XchonnectClient.canRequest}; the class itself is not part of the public API.
 */
export class PermissionsView {
  private declared = false;
  private methods: string[] = [];
  private keys: string[] = [];
  private limits: SpendingLimits | undefined;
  private readonly refused: string[] = [];

  /** Whether `code` is a refusal that narrows the view. */
  static isRefusal(code: number): boolean {
    return REFUSAL_CODES.has(code);
  }

  /** A copy for callers; mutating it changes nothing here. */
  snapshot(): SessionPermissions {
    return {
      declared: this.declared,
      methods: [...this.methods],
      keys: [...this.keys],
      ...(this.limits === undefined ? {} : { limits: { ...this.limits } }),
      refused: [...this.refused],
    };
  }

  /**
   * Whether the wallet is expected to accept `method`: `true` if it declared it, `false`
   * if it declared others or has refused this one, `undefined` while nothing is known.
   * Only `false` means "do not offer it"; see the module note before gating on any of it.
   */
  can(method: string): boolean | undefined {
    const name = bare(method);
    if (this.refused.includes(name)) return false;
    if (!this.declared) return undefined;
    return this.methods.includes(name);
  }

  /**
   * Apply a declaration from the wallet, replacing any earlier one. Returns whether the
   * view changed, so callers only announce real news.
   *
   * A declaration also clears the refusals it covers: the wallet has just said those
   * methods are allowed again, and the dApp's older observation is the stale one.
   */
  declare(m: DeclaredPermissions): boolean {
    const src: DeclaredPermissions = typeof m.permissions === "object" && m.permissions !== null ? (m.permissions as DeclaredPermissions) : m;
    if (src.methods === undefined && src.keys === undefined && src.limits === undefined) return false;
    const before = JSON.stringify(this.snapshot());
    this.methods = strings(src.methods).map(bare);
    this.keys = strings(src.keys);
    this.limits = limitsOf(src.limits);
    this.declared = true;
    for (const name of [...this.refused]) {
      if (this.methods.includes(name)) this.refused.splice(this.refused.indexOf(name), 1);
    }
    return before !== JSON.stringify(this.snapshot());
  }

  /**
   * Record that the wallet refused `method` with `code`. Declared scopes are kept as the
   * wallet sent them; the refusal is remembered separately, because a wallet may refuse
   * what it granted (spec 9.3) and the dApp must not argue with it.
   */
  refuse(method: string, code: number): boolean {
    if (!PermissionsView.isRefusal(code)) return false;
    const name = bare(method);
    if (name.length === 0 || name.length > MAX_LEN || this.refused.includes(name)) return false;
    if (this.refused.length >= MAX_ENTRIES) this.refused.shift();
    this.refused.push(name);
    return true;
  }

  /** Serialise for session storage (spec 6.4: the dApp keeps what the wallet shared). */
  toJson(): string {
    return JSON.stringify(this.snapshot());
  }

  /** Restore from {@link toJson}; anything unreadable restores an empty view. */
  static fromJson(json: string | null): PermissionsView {
    const v = new PermissionsView();
    let parsed: unknown;
    try {
      parsed = json === null ? undefined : JSON.parse(json);
    } catch {
      return v;
    }
    if (typeof parsed !== "object" || parsed === null) return v;
    const o = parsed as Record<string, unknown>;
    if (o["declared"] === true) v.declare({ methods: o["methods"], keys: o["keys"], limits: o["limits"] });
    for (const name of strings(o["refused"])) v.refuse(name, 4004);
    return v;
  }
}
