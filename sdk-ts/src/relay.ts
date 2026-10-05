import { RelayError } from "./errors.js";

/** `GET /v1/info` (docs/spec/wire/relay-api.md). */
export interface RelayInfo {
  protocol: number;
  max_wait_s: number;
  max_wait_ohttp_s: number;
  default_ttl_s: number;
  max_ttl_s: number;
  max_envelope_bytes: number;
  mailbox_creation: string[];
  pow_difficulty?: number;
  gateway_policy: "allowlist" | "open";
  gateway_allowlist?: string[];
  ohttp: boolean;
}

/** A message returned by the relay. */
export interface RelayMessage {
  msg_id: string;
  env: string;
}

/** Proof-of-work solver (WASM-backed in the SDK). */
export type PowSolver = (challengeB64: string) => string;

export interface RelayClientOptions {
  /** Business API key (publishable; spec 7.2). */
  apiKey?: string;
  /** Custom fetch (tests, OHTTP transport). */
  fetch?: typeof fetch;
  /** Proof-of-work solver for keyless relays. */
  solvePow?: PowSolver;
}

/** Thin client for the Xchonnect relay HTTP API. */
export class RelayClient {
  private info_: Promise<RelayInfo> | undefined;
  private readonly fetchFn: typeof fetch;

  constructor(
    readonly baseUrl: string,
    private readonly opts: RelayClientOptions = {},
  ) {
    this.fetchFn = opts.fetch ?? ((input, init) => globalThis.fetch(input, init));
  }

  private async call(method: string, path: string, opts: { token?: string; body?: unknown; apiKey?: boolean; signal?: AbortSignal | undefined } = {}): Promise<unknown> {
    const headers: Record<string, string> = {};
    if (opts.token) headers["authorization"] = `Bearer ${opts.token}`;
    if (opts.body !== undefined) headers["content-type"] = "application/json";
    if (opts.apiKey && this.opts.apiKey) headers["xchonnect-api-key"] = this.opts.apiKey;
    const init: RequestInit = { method, headers, credentials: "omit", cache: "no-store", referrerPolicy: "no-referrer" };
    if (opts.body !== undefined) init.body = JSON.stringify(opts.body);
    if (opts.signal) init.signal = opts.signal;
    const res = await this.fetchFn(`${this.baseUrl}${path}`, init);
    const text = await res.text();
    if (!res.ok) {
      let code = "unavailable";
      try {
        code = (JSON.parse(text) as { error?: string }).error ?? code;
      } catch {
        /* non-JSON error body */
      }
      const retry = Number(res.headers.get("retry-after"));
      throw new RelayError(res.status, code, Number.isFinite(retry) && retry > 0 ? retry : undefined);
    }
    return text ? (JSON.parse(text) as unknown) : undefined;
  }

  /** Relay limits and policies (cached). */
  info(): Promise<RelayInfo> {
    // Cache successes only: a transient failure must not break the client for good.
    this.info_ ??= this.call("GET", "/v1/info").then(
      (v) => v as RelayInfo,
      (e: unknown) => {
        this.info_ = undefined;
        throw e;
      },
    );
    return this.info_;
  }

  /** Create a mailbox using the best available method: API key, ticket, PoW or open. */
  async createMailbox(readTokenHash: string, writeTokenHash: string, opts: { ticket?: string | undefined } = {}): Promise<string> {
    const info = await this.info();
    const body: Record<string, unknown> = { read_token_hash: readTokenHash, write_token_hash: writeTokenHash };
    let useKey = false;
    if (this.opts.apiKey && info.mailbox_creation.includes("api_key")) {
      useKey = true;
    } else if (opts.ticket && info.mailbox_creation.includes("ticket")) {
      body["ticket"] = opts.ticket;
    } else if (info.mailbox_creation.includes("pow") && this.opts.solvePow) {
      const c = (await this.call("POST", "/v1/challenge")) as { challenge: string };
      body["pow"] = { challenge: c.challenge, nonce: this.opts.solvePow(c.challenge) };
    }
    const res = (await this.call("POST", "/v1/mailboxes", { body, apiKey: useKey })) as { mailbox_id: string };
    return res.mailbox_id;
  }

  /** Sponsorship ticket for the wallet's mailbox (requires an API key). */
  async ticket(): Promise<string | undefined> {
    const info = await this.info();
    if (!this.opts.apiKey || !info.mailbox_creation.includes("ticket")) return undefined;
    const res = (await this.call("POST", "/v1/tickets", { apiKey: true })) as { ticket: string };
    return res.ticket;
  }

  /** Post an envelope. */
  async post(mailbox: string, writeToken: string, env: string, ttlSeconds?: number): Promise<string> {
    const body: Record<string, unknown> = { env };
    if (ttlSeconds !== undefined) body["ttl_s"] = ttlSeconds;
    const res = (await this.call("POST", `/v1/mailboxes/${mailbox}/messages`, { token: writeToken, body })) as { msg_id: string };
    return res.msg_id;
  }

  /** Fetch pending messages, waiting up to `waitSeconds` for the first one. */
  async fetchMessages(mailbox: string, readToken: string, waitSeconds = 0, signal?: AbortSignal): Promise<RelayMessage[]> {
    const res = (await this.call("GET", `/v1/mailboxes/${mailbox}/messages?wait=${Math.max(0, Math.floor(waitSeconds))}`, { token: readToken, signal })) as { messages: RelayMessage[] };
    return res.messages;
  }

  /** Acknowledge (delete) messages. */
  async ack(mailbox: string, readToken: string, msgIds: string[]): Promise<void> {
    if (msgIds.length === 0) return;
    await this.call("POST", `/v1/mailboxes/${mailbox}/ack`, { token: readToken, body: { msg_ids: msgIds } });
  }

  /** Delete a mailbox. */
  async deleteMailbox(mailbox: string, readToken: string): Promise<void> {
    await this.call("DELETE", `/v1/mailboxes/${mailbox}`, { token: readToken });
  }
}
