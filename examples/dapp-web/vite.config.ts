/**
 * Development server for the example dApp. It also plays the role of the dApp
 * backend: it publishes /.well-known/xchonnect.json and signs pairing URIs with the
 * origin key (POST /api/sign), so the key never reaches the browser.
 *
 * DEVELOPMENT ONLY: the origin key is generated into .dev-origin-key and must never
 * be used in production (production keys live in an HSM/KMS, spec 12).
 */
import { createPrivateKey, createPublicKey, randomBytes, sign } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import type { IncomingMessage } from "node:http";
import { defineConfig, type Plugin } from "vite";

const KEY_FILE = new URL("./.dev-origin-key", import.meta.url);
const KID = "dev-1";

function originKey() {
  if (!existsSync(KEY_FILE)) writeFileSync(KEY_FILE, randomBytes(32).toString("base64url"), { mode: 0o600 });
  const seed = Buffer.from(readFileSync(KEY_FILE, "utf8").trim(), "base64url");
  // PKCS#8 wrapper for a raw Ed25519 seed (RFC 8410).
  const der = Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]);
  const privateKey = createPrivateKey({ key: der, format: "der", type: "pkcs8" });
  const spki = createPublicKey(privateKey).export({ format: "der", type: "spki" });
  return { privateKey, publicKey: spki.subarray(spki.length - 32).toString("base64url") };
}

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    let data = "";
    req.on("data", (c: Buffer) => {
      data += c.toString();
      if (data.length > 4096) reject(new Error("too large"));
    });
    req.on("end", () => resolve(data));
    req.on("error", reject);
  });
}

function dappBackend(): Plugin {
  const key = originKey();
  return {
    name: "xchonnect-dapp-backend",
    configureServer(server) {
      server.middlewares.use("/.well-known/xchonnect.json", (_req, res) => {
        res.setHeader("content-type", "application/json");
        res.setHeader("access-control-allow-origin", "*");
        res.end(JSON.stringify({ v: 1, name: "Xchonnect Example dApp", origin_keys: [{ kid: KID, pk: key.publicKey, not_after: "2030-12-31" }] }));
      });
      server.middlewares.use("/api/origin", (_req, res) => {
        res.setHeader("content-type", "application/json");
        res.end(JSON.stringify({ kid: KID, publicKey: key.publicKey }));
      });
      server.middlewares.use("/api/sign", async (req, res) => {
        // A real backend authenticates the logged-in user before signing (spec 12).
        if (req.method !== "POST") {
          res.statusCode = 405;
          res.end();
          return;
        }
        const { sigInput } = JSON.parse(await readBody(req)) as { sigInput: string };
        const signature = sign(null, Buffer.from(sigInput, "base64url"), key.privateKey).toString("base64url");
        res.setHeader("content-type", "application/json");
        res.end(JSON.stringify({ signature }));
      });
    },
  };
}

export default defineConfig({
  plugins: [dappBackend()],
  server: { port: 5173, strictPort: true, host: "localhost" },
  optimizeDeps: { exclude: ["@maximedogawa/xchonnect"] },
});
