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
