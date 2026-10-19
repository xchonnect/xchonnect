/**
 * The plugin's state on disk, one file encrypted with AES-256-GCM under the key in the system
 * keychain (`keychain.ts`): the xchonnect session (its secrets: spec 12.1), the origin key, and
 * the offers made through the pairing. Written atomically (a new temporary file, never one that
 * exists, then a rename), mode 0600, in a directory of mode 0700 owned by the user. A file that
 * does not decrypt (another key, tampered with) is refused, never overwritten silently: the user
 * removes it to start over.
 *
 * **One process at a time.** Each Claude Code session starts its own plugin; two on one file
 * would reuse message counters, eat each other's answers on the relay and write back stale
 * state. `lockDirectory` takes `state.lock` for the life of the process, and a second process
 * refuses to open the session (`index.ts`).
 */
import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { chmod, lstat, mkdir, open, readFile, rename, rm, writeFile } from "node:fs/promises";
import { unlinkSync } from "node:fs";
import { dirname, join } from "node:path";
import type { SessionStore } from "@xchonnect/dapp";

const MAGIC = Buffer.from("XCMCP1");

/** The state directory, made private: mode 0700, owned by this user, not a symlink. */
export async function privateDirectory(dir: string): Promise<void> {
  await mkdir(dir, { recursive: true, mode: 0o700 });
  const info = await lstat(dir);
  if (info.isSymbolicLink() || !info.isDirectory()) throw new Error(`${dir} is not a directory of its own (a symlink?)`);
  if (typeof process.getuid === "function" && info.uid !== process.getuid()) throw new Error(`${dir} belongs to another user`);
  if ((info.mode & 0o077) !== 0) await chmod(dir, 0o700);
}

/**
 * Takes `state.lock` in `dir` for this process; a lock left by a process that is gone is taken
 * over. Throws when another live process holds it.
 */
export async function lockDirectory(dir: string): Promise<void> {
  const path = join(dir, "state.lock");
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      const handle = await open(path, "wx", 0o600);
      await handle.writeFile(String(process.pid));
      await handle.close();
      process.once("exit", () => {
        try {
          unlinkSync(path);
        } catch {
          // already gone
        }
      });
      return;
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== "EEXIST") throw e;
      const pid = Number((await readFile(path, "utf8").catch(() => "")).trim());
      let alive = false;
      if (Number.isInteger(pid) && pid > 0 && pid !== process.pid) {
        try {
          process.kill(pid, 0);
          alive = true;
        } catch (err) {
          alive = (err as NodeJS.ErrnoException).code === "EPERM";
        }
      }
      if (alive) {
        throw new Error(
          `another session of the plugin (process ${pid}) holds the wallet session in ${dir}; one session at a time can use it. Close the other Claude Code session, or give this one its own XCHONNECT_MCP_DIR (it then pairs on its own)`,
        );
      }
      await rm(path, { force: true });
    }
  }
  throw new Error(`could not take the lock ${path}`);
}

/** Writes `data` to `path` through a fresh temporary file (never one that exists) and a rename. */
export async function writeAtomically(path: string, data: Buffer): Promise<void> {
  const tmp = `${path}.${process.pid}.${randomBytes(6).toString("hex")}.tmp`;
  await writeFile(tmp, data, { mode: 0o600, flag: "wx" });
  try {
    await rename(tmp, path);
  } catch (e) {
    await rm(tmp, { force: true });
    throw e;
  }
}

export class EncryptedFileStore implements SessionStore {
  private cache: Map<string, string> | undefined;
  private chain: Promise<unknown> = Promise.resolve();

  constructor(
    private readonly path: string,
    private readonly key: Buffer,
  ) {
    if (key.length !== 32) throw new Error("the session key must be 32 bytes");
  }

  private async read(): Promise<Map<string, string>> {
    if (this.cache) return this.cache;
    let blob: Buffer;
    try {
      blob = await readFile(this.path);
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code === "ENOENT") return (this.cache = new Map());
      throw e;
    }
    if (blob.length < MAGIC.length + 12 + 16 || !blob.subarray(0, MAGIC.length).equals(MAGIC)) {
      throw new Error(`${this.path} is not a session file of this plugin; remove it to pair again`);
    }
    const iv = blob.subarray(MAGIC.length, MAGIC.length + 12);
    const tag = blob.subarray(blob.length - 16);
    const body = blob.subarray(MAGIC.length + 12, blob.length - 16);
    const decipher = createDecipheriv("aes-256-gcm", this.key, iv);
    decipher.setAAD(MAGIC);
    decipher.setAuthTag(tag);
    let text: string;
    try {
      text = Buffer.concat([decipher.update(body), decipher.final()]).toString("utf8");
    } catch {
      throw new Error(`${this.path} does not decrypt with the key in the keychain; remove it to pair again`);
    }
    const entries = JSON.parse(text) as Record<string, string>;
    return (this.cache = new Map(Object.entries(entries)));
  }

  private async write(map: Map<string, string>): Promise<void> {
    const iv = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", this.key, iv);
    cipher.setAAD(MAGIC);
    const body = Buffer.concat([cipher.update(JSON.stringify(Object.fromEntries(map)), "utf8"), cipher.final()]);
    await mkdir(dirname(this.path), { recursive: true, mode: 0o700 });
    await writeAtomically(this.path, Buffer.concat([MAGIC, iv, body, cipher.getAuthTag()]));
  }

  /** One change at a time, read-modify-write. */
  private serial<T>(f: () => Promise<T>): Promise<T> {
    const next = this.chain.then(f, f);
    this.chain = next.catch(() => undefined);
    return next;
  }

  load(key: string): Promise<string | null> {
    return this.serial(async () => (await this.read()).get(key) ?? null);
  }

  save(key: string, state: string): Promise<void> {
    return this.update(key, () => state);
  }

  /** Reads `key`, computes its new value and writes it, with nothing in between. `null` removes it. */
  update(key: string, change: (current: string | null) => string | null): Promise<void> {
    return this.serial(async () => {
      const map = new Map(await this.read());
      const next = change(map.get(key) ?? null);
      if (next === null) {
        if (!map.delete(key)) return;
      } else {
        map.set(key, next);
      }
      await this.write(map);
      this.cache = map;
    });
  }

  clear(key: string): Promise<void> {
    return this.update(key, () => null);
  }

  /** Removes the file: every session and record of this plugin. */
  destroy(): Promise<void> {
    return this.serial(async () => {
      await rm(this.path, { force: true });
      this.cache = new Map();
    });
  }
}
