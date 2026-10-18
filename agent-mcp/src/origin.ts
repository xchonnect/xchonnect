/**
 * Who the agent is to the wallet. A pairing URI is signed with an origin key, and the wallet
 * checks the signature against the key published at `https://<domain>/.well-known/xchonnect.json`
 * (spec 6.1). A local agent has no domain of its own, so there are two ways:
 *
 * - **Own domain** (`XCHONNECT_ORIGIN_DOMAIN`, `XCHONNECT_ORIGIN_KID`): the user publishes the
 *   origin document this plugin prints (`origin_document` tool) on a domain they control. The
 *   key is made on first use and kept in the encrypted state file.
 * - **Developer mode** (`XCHONNECT_DEV=1`): the plugin serves the document itself on
 *   `http://localhost:<port>` and signs as `localhost:<port>`; only wallets in developer mode
 *   accept that (the CLI wallet, the test wallet). For trying it out, never for funds.
 * - **nodexch** (`NODEXCH_KEY`, the agent's secret API key; `NODEXCH_URL`, default
 *   `https://api.nodexch.space`): nodexch signs the pairing as its own domain (nodexch's
 *   TASK-176.05). The plugin reads the domain, key id, public key and relay there
 *   (`GET /x/account/v1/xchonnect`) and asks for one signature per pairing (`POST …/sign`, the key
 *   as `Authorization: Bearer`). nodexch signs only a pairing on its relay and its domain that
 *   expires within minutes, sees no pairing secret, and nothing of the session after it.
 *
 * A wallet that pairs agents without a domain, by the name the user gives at pairing and the
 * SAS alone, is not specified yet (spec 9.4 is the rules; pairing stays 6.1).
 */
import { createPrivateKey, createPublicKey, randomBytes, sign as edSign } from "node:crypto";
import { createServer, type Server } from "node:http";
import type { EncryptedFileStore } from "./store.js";

const SEED_KEY = "origin-key";
const PKCS8_ED25519 = Buffer.from("302e020100300506032b657004220420", "hex");

export interface Origin {
  domain: string;
  kid: string;
  developerMode: boolean;
  /** Signs `uri_sig_input` (base64url) with the origin key. */
  sign(input: string): Promise<string>;
  /** The public key, base64url. */
  publicKey: string;
  /** The `/.well-known/xchonnect.json` this origin needs published. */
  document: string;
  close(): Promise<void>;
}

function keys(seed: Buffer) {
  const privateKey = createPrivateKey({ key: Buffer.concat([PKCS8_ED25519, seed]), format: "der", type: "pkcs8" });
  const publicKey = createPublicKey(privateKey).export({ format: "der", type: "spki" }).subarray(-32).toString("base64url");
  return { privateKey, publicKey };
}

function document(name: string, kid: string, publicKey: string): string {
  const notAfter = new Date(Date.now() + 365 * 86_400_000).toISOString().slice(0, 10);
  return JSON.stringify({ v: 1, name, origin_keys: [{ kid, pk: publicKey, not_after: notAfter }] });
}

export interface OriginSettings {
  name: string;
  domain?: string;
  kid?: string;
  developerMode: boolean;
  /** Developer mode: the port the document is served on (0: any free port). */
  port: number;
}

/** What nodexch publishes as its origin (`GET /x/account/v1/xchonnect`). */
interface NodexchOrigin {
  relay: string;
  domain: string;
  kid: string;
  public_key: string;
}

/** How long one call to nodexch may take. */
const NODEXCH_TIMEOUT_MS = 10_000;

/** A host name with an optional port, as a pairing's `d` is written. */
const DOMAIN = /^(?=.{1,253}$)[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*(:\d{1,5})?$/;

function loopbackHost(host: string): boolean {
  return host === "localhost" || host === "127.0.0.1" || host === "[::1]" || host === "::1";
}

/**
 * nodexch as the origin: its domain, key id and public key, and its relay, which the pairing must
 * name. The API must be https (http only on the loopback, for a local nodexch): the agent's key
 * travels with every signature, and the answer decides whom the wallet sees. The domain's own
 * `/.well-known/xchonnect.json` must list the key nodexch named, so a wrong `NODEXCH_URL` cannot
 * make the plugin pair as another domain, and a site that has not published its key yet is said
 * plainly instead of a wallet refusing every code. Every signature is checked by the SDK against
 * that key before it shows a code.
 */
export async function openNodexchOrigin(api: string, key: string, fetchImpl: typeof fetch = fetch): Promise<Origin & { relay: string }> {
  let base: URL;
  try {
    base = new URL(api);
  } catch {
    throw new Error(`NODEXCH_URL (${api}) is not a URL`);
  }
  if (base.protocol !== "https:" && !(base.protocol === "http:" && loopbackHost(base.hostname))) {
    throw new Error(`NODEXCH_URL must be https (${base.origin}): the agent's key is sent with every pairing`);
  }
  const root = base.href.replace(/\/+$/, "");
  const timed = () => AbortSignal.timeout(NODEXCH_TIMEOUT_MS);
  let answer: Response;
  try {
    answer = await fetchImpl(`${root}/x/account/v1/xchonnect`, { headers: { accept: "application/json" }, signal: timed() });
  } catch {
    throw new Error(`nodexch (${base.origin}) cannot be reached to read its pairing origin`);
  }
  if (!answer.ok) throw new Error(`nodexch (${base.origin}) does not sign pairings (HTTP ${answer.status})`);
  const found = (await answer.json()) as Partial<NodexchOrigin>;
  const text = (v: unknown, max: number) => typeof v === "string" && v.length > 0 && v.length <= max;
  if (
    !text(found.relay, 200) ||
    !DOMAIN.test(String(found.domain)) ||
    !/^[A-Za-z0-9._-]{1,64}$/.test(String(found.kid)) ||
    !/^[A-Za-z0-9_-]{43}$/.test(String(found.public_key))
  ) {
    throw new Error(`nodexch (${base.origin}) answered an origin of an unknown shape`);
  }
  const origin = found as NodexchOrigin;
  // A local nodexch names `localhost:<port>`: only a wallet in developer mode takes that.
  const developerMode = loopbackHost(origin.domain.replace(/:\d+$/, ""));
  const documentUrl = `${developerMode ? "http" : "https"}://${origin.domain}/.well-known/xchonnect.json`;
  let listed = false;
  try {
    const published = await fetchImpl(documentUrl, { headers: { accept: "application/json" }, signal: timed() });
    const doc = (await published.json()) as { origin_keys?: { kid?: unknown; pk?: unknown }[] };
    listed = published.ok && (doc.origin_keys ?? []).some((k) => k.kid === origin.kid && k.pk === origin.public_key);
  } catch {
    listed = false;
  }
  if (!listed) throw new Error(`${documentUrl} does not list the key nodexch signs with (${origin.kid}): wallets would refuse the pairing`);
  const sign = async (input: string): Promise<string> => {
    let signed: Response;
    try {
      signed = await fetchImpl(`${root}/x/account/v1/xchonnect/sign`, {
        method: "POST",
        headers: { "content-type": "application/json", authorization: `Bearer ${key}` },
        body: JSON.stringify({ sig_input: input }),
        signal: timed(),
      });
    } catch {
      throw new Error("nodexch cannot be reached to sign the pairing; try again in a moment");
    }
    if (signed.status === 401) throw new Error("nodexch refused the key: NODEXCH_KEY must be an active secret key (nxs_…)");
    if (signed.status === 429) {
      const body = (await signed.json().catch(() => ({}))) as { error?: unknown };
      const why = typeof body.error === "string" ? body.error.slice(0, 200) : "too many pairings";
      throw new Error(`nodexch did not sign the pairing now: ${why}`);
    }
    if (!signed.ok) throw new Error(`nodexch did not sign the pairing (HTTP ${signed.status})`);
    const { signature } = (await signed.json()) as { signature?: unknown };
    if (typeof signature !== "string") throw new Error("nodexch answered without a signature");
    return signature;
  };
  return {
    domain: origin.domain,
    kid: origin.kid,
    developerMode,
    sign,
    publicKey: origin.public_key,
    // nodexch publishes it at https://<domain>/.well-known/xchonnect.json; nothing to serve here.
    document: "",
    relay: origin.relay,
    close: async () => {},
  };
}

/** The origin from the settings, its key from the store (made on first use). */
export async function openOrigin(settings: OriginSettings, store: EncryptedFileStore): Promise<Origin | null> {
  if (!settings.developerMode && !settings.domain) return null;
  let seedText = await store.load(SEED_KEY);
  if (!seedText) {
    seedText = randomBytes(32).toString("base64url");
    await store.save(SEED_KEY, seedText);
  }
  const { privateKey, publicKey } = keys(Buffer.from(seedText, "base64url"));
  const kid = settings.kid ?? "agent-1";
  const sign = async (input: string) => edSign(null, Buffer.from(input, "base64url"), privateKey).toString("base64url");
  if (!settings.developerMode) {
    const domain = settings.domain as string;
    return { domain, kid, developerMode: false, sign, publicKey, document: document(settings.name, kid, publicKey), close: async () => {} };
  }
  const doc = document(`${settings.name} (local agent, developer mode)`, kid, publicKey);
  const server: Server = createServer((req, res) => {
    if (req.method === "GET" && req.url === "/.well-known/xchonnect.json") {
      res.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" });
      res.end(doc);
      return;
    }
    res.writeHead(404).end();
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(settings.port, "127.0.0.1", () => resolve());
  });
  const address = server.address();
  const port = typeof address === "object" && address ? address.port : settings.port;
  server.unref();
  // `localhost` may resolve to ::1 first: hold that address too, so no other local process can
  // serve its own origin key under this name. Where IPv6 is off there is nothing to hold.
  const server6: Server = createServer((req, res) => server.emit("request", req, res));
  const held6 = await new Promise<boolean>((resolve, reject) => {
    server6.once("error", (e: NodeJS.ErrnoException) => (e.code === "EADDRNOTAVAIL" || e.code === "EAFNOSUPPORT" ? resolve(false) : reject(e)));
    server6.listen(port, "::1", () => resolve(true));
  });
  if (held6) server6.unref();
  return {
    domain: `localhost:${port}`,
    kid,
    developerMode: true,
    sign,
    publicKey,
    document: doc,
    close: async () => {
      await new Promise<void>((resolve) => server.close(() => resolve()));
      if (held6) await new Promise<void>((resolve) => server6.close(() => resolve()));
    },
  };
}
