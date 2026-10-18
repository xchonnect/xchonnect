/**
 * The key that encrypts the session file, kept in the system keychain: the macOS Keychain
 * (`security`), the Linux Secret Service (`secret-tool`). The key never appears on a command
 * line (it would show in the process list): it goes to `security` and `secret-tool` on stdin.
 *
 * The keychain item is readable by `security`/`secret-tool` run as the same user without a
 * prompt (that is how this plugin reads it), so against malware running as the user it is
 * about as strong as a file; it keeps the key out of backups and synced copies of the home
 * directory.
 *
 * `XCHONNECT_MCP_KEY_FILE=<path>` keeps it in a file of its own instead (mode 0600), for a
 * machine without a keychain (a server, a container, Windows for now). That is weaker: anyone
 * who can read both files can read the session.
 */
import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { chmod, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { dirname } from "node:path";

const SERVICE = "xchonnect-mcp";

export interface Keychain {
  /** Where the key lives, for the docs and the status tool. */
  readonly kind: string;
  get(): Promise<Buffer | null>;
  set(key: Buffer): Promise<void>;
  delete(): Promise<void>;
}

function run(command: string, args: string[], input?: string): Promise<{ code: number; out: string; err: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { stdio: ["pipe", "pipe", "pipe"] });
    let out = "";
    let err = "";
    child.stdout.on("data", (d: Buffer) => (out += d.toString()));
    child.stderr.on("data", (d: Buffer) => (err += d.toString()));
    child.on("error", reject);
    child.on("close", (code) => resolve({ code: code ?? 1, out, err }));
    child.stdin.end(input ?? "");
  });
}

/** A stored key, or an error: a stored value that is not one must never be replaced silently. */
function parseKey(text: string, where: string): Buffer {
  const hex = text.trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(hex)) throw new Error(`the session key in the ${where} is not 32 bytes of hex; remove it (and the state file) to start over`);
  return Buffer.from(hex, "hex");
}

/** `security`'s exit status for "the specified item could not be found". */
const MAC_NOT_FOUND = 44;

class MacKeychain implements Keychain {
  readonly kind = "macOS Keychain";
  constructor(private readonly account: string) {}
  async get(): Promise<Buffer | null> {
    const { code, out } = await run("security", ["find-generic-password", "-a", this.account, "-s", SERVICE, "-w"]);
    if (code === 0) return parseKey(out, this.kind);
    if (code === MAC_NOT_FOUND) return null;
    // Locked, no keychain in this session, access refused: never treated as "no key yet".
    throw new Error("could not read the session key from the macOS Keychain (is the login keychain locked, or is this a session without one, such as SSH?). Unlock it, or set XCHONNECT_MCP_KEY_FILE to keep the key in a file");
  }
  async set(key: Buffer): Promise<void> {
    // `security -i` reads its commands from stdin: the key stays off the command line.
    const { code } = await run("security", ["-i"], `add-generic-password -U -a ${this.account} -s ${SERVICE} -l ${SERVICE} -w ${key.toString("hex")}\n`);
    if (code !== 0) {
      throw new Error(
        "could not store the session key in the macOS Keychain (is the login keychain locked, or is this a session without one, such as SSH?). Unlock it, or set XCHONNECT_MCP_KEY_FILE to keep the key in a file",
      );
    }
  }
  async delete(): Promise<void> {
    await run("security", ["delete-generic-password", "-a", this.account, "-s", SERVICE]);
  }
}

class SecretService implements Keychain {
  readonly kind = "Secret Service";
  constructor(private readonly account: string) {}
  async get(): Promise<Buffer | null> {
    const { code, out, err } = await run("secret-tool", ["lookup", "service", SERVICE, "account", this.account]);
    if (code === 0) return parseKey(out, this.kind);
    // `secret-tool lookup` exits 1 without a word when nothing matches; anything said is an error.
    if (code === 1 && out.trim() === "" && err.trim() === "") return null;
    throw new Error("could not read the session key with secret-tool (is a Secret Service running and unlocked?); or set XCHONNECT_MCP_KEY_FILE to keep the key in a file");
  }
  async set(key: Buffer): Promise<void> {
    const { code } = await run("secret-tool", ["store", "--label=Xchonnect MCP session key", "service", SERVICE, "account", this.account], key.toString("hex"));
    if (code !== 0) throw new Error("could not store the session key with secret-tool (is a Secret Service running and unlocked?); or set XCHONNECT_MCP_KEY_FILE to keep the key in a file");
  }
  async delete(): Promise<void> {
    await run("secret-tool", ["clear", "service", SERVICE, "account", this.account]);
  }
}

class KeyFile implements Keychain {
  readonly kind = "key file";
  constructor(private readonly path: string) {}
  async get(): Promise<Buffer | null> {
    let text: string;
    try {
      text = await readFile(this.path, "utf8");
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code === "ENOENT") return null;
      throw e;
    }
    return parseKey(text, this.kind);
  }
  async set(key: Buffer): Promise<void> {
    await mkdir(dirname(this.path), { recursive: true, mode: 0o700 });
    // A new file only (`wx`): never through a symlink, never over a key that exists.
    await writeFile(this.path, key.toString("hex"), { mode: 0o600, flag: "wx" });
    await chmod(this.path, 0o600);
  }
  async delete(): Promise<void> {
    await rm(this.path, { force: true });
  }
}

/** The keychain of this machine, or the key file the environment names. */
export function systemKeychain(account: string, env: NodeJS.ProcessEnv = process.env): Keychain {
  const file = env["XCHONNECT_MCP_KEY_FILE"];
  if (file) return new KeyFile(file);
  if (process.platform === "darwin") return new MacKeychain(account);
  if (process.platform === "linux") return new SecretService(account);
  throw new Error("no system keychain support on this platform yet: set XCHONNECT_MCP_KEY_FILE to keep the session key in a file");
}

/** The key, made and stored on first use. */
export async function sessionKey(keychain: Keychain): Promise<Buffer> {
  const found = await keychain.get();
  if (found) return found;
  const key = randomBytes(32);
  await keychain.set(key);
  const back = await keychain.get();
  if (!back || !back.equals(key)) throw new Error(`the session key could not be read back from the ${keychain.kind}`);
  return key;
}

/** For tests: a keychain in memory. */
export class MemoryKeychain implements Keychain {
  readonly kind = "memory";
  private key: Buffer | null = null;
  async get(): Promise<Buffer | null> {
    return this.key;
  }
  async set(key: Buffer): Promise<void> {
    this.key = Buffer.from(key);
  }
  async delete(): Promise<void> {
    this.key = null;
  }
}
