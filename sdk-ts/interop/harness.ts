/** Shared setup for the interop tests: the relay and wallet binaries, a dApp origin, SDK clients. */
import { type ChildProcess, spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import * as core from "../wasm/xchonnect.js";
import { type ClientOptions, MemorySessionStore, XchonnectClient } from "../src/index.js";

const BIN = new URL("../../target/debug/", import.meta.url).pathname;
export const wasm = readFileSync(new URL("../wasm/xchonnect_bg.wasm", import.meta.url));
export const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** Listen on a free loopback port; resolves with the port. */
export async function listen(server: Server): Promise<number> {
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  return (server.address() as AddressInfo).port;
}

/** A child process with its output collected. */
export class Proc {
  out = "";
  err = "";
  constructor(readonly p: ChildProcess) {
    p.stdout?.on("data", (d: Buffer) => (this.out += d.toString()));
    p.stderr?.on("data", (d: Buffer) => (this.err += d.toString()));
  }
  async waitFor(re: RegExp, ms = 30_000): Promise<RegExpMatchArray> {
    const end = Date.now() + ms;
    while (Date.now() < end) {
      const m = re.exec(this.out);
      if (m) return m;
      await sleep(25);
    }
    throw new Error(`timeout waiting for ${re}\nstdout:\n${this.out}\nstderr:\n${this.err}`);
  }
  exited(): Promise<number | null> {
    return new Promise((r) => (this.p.exitCode !== null ? r(this.p.exitCode) : this.p.on("exit", (c) => r(c))));
  }
}

/** Start the reference relay on a free port with extra `env` and wait until it is healthy. */
export async function startRelay(env: Record<string, string>): Promise<{ proc: ChildProcess; url: string }> {
  const probe = createServer();
  const port = await listen(probe);
  await new Promise((r) => probe.close(r));
  const url = `http://127.0.0.1:${port}`;
  const proc = spawn(`${BIN}xchonnect-relay`, [], { env: { ...process.env, XCHONNECT_LISTEN: `127.0.0.1:${port}`, XCHONNECT_LOG: "warn", XCHONNECT_STORE: "memory", ...env }, stdio: "ignore" });
  for (let i = 0; i < 200; i++) {
    if (await fetch(`${url}/healthz`).then((r) => r.ok).catch(() => false)) return { proc, url };
    await sleep(50);
  }
  throw new Error("relay did not start");
}

/** Serve `/.well-known/xchonnect.json` for a dApp with origin key `k1` = dev key of `seed`. */
export async function startOrigin(name: string, seed: string): Promise<{ server: Server; port: number }> {
  const doc = JSON.stringify({ v: 1, name, origin_keys: [{ kid: "k1", pk: core.devPublicKey(seed), not_after: "2030-01-01" }] });
  const server = createServer((req, res) => {
    if (req.url === "/.well-known/xchonnect.json") {
      res.setHeader("content-type", "application/json");
      res.end(doc);
    } else {
      res.statusCode = 404;
      res.end();
    }
  });
  return { server, port: await listen(server) };
}

/** Developer-mode SDK client for the origin on `originPort`; `opts` override. */
export function sdkClient(relay: string, originPort: number, seed: string, opts: Partial<ClientOptions> = {}): Promise<XchonnectClient> {
  return XchonnectClient.create({
    relay,
    domain: `localhost:${originPort}`,
    kid: "k1",
    sign: async (input) => core.devSign(seed, input),
    originPublicKey: core.devPublicKey(seed),
    developerMode: true,
    storage: new MemorySessionStore(),
    wasm,
    ...opts,
  });
}

/** Run the CLI wallet (auto-approving) on a pairing URI. */
export function spawnWallet(uri: string, name: string): Proc {
  return new Proc(spawn(`${BIN}xchonnect-wallet-cli`, ["pair", uri, "--dev", "--auto-approve", "--name", name], { stdio: ["ignore", "pipe", "pipe"] }));
}
