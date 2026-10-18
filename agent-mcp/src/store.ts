/**
 * The plugin's state on disk, one file encrypted with AES-256-GCM under the key in the system
 * keychain (`keychain.ts`): the xchonnect session (its secrets: spec 12.1), the origin key, and
 * the offers made through the pairing. Written atomically (a temporary file, then a rename),
 * mode 0600 in a directory of mode 0700. A file that does not decrypt (another key, tampered
 * with) is refused, never overwritten silently: the user removes it to start over.
 */
import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { chmod, mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import type { SessionStore } from "@xchonnect/dapp";

const MAGIC = Buffer.from("XCMCP1");

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
    const blob = Buffer.concat([MAGIC, iv, body, cipher.getAuthTag()]);
    await mkdir(dirname(this.path), { recursive: true, mode: 0o700 });
    const tmp = `${this.path}.${process.pid}.tmp`;
    await writeFile(tmp, blob, { mode: 0o600 });
    await rename(tmp, this.path);
    await chmod(this.path, 0o600);
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
    return this.serial(async () => {
      const map = new Map(await this.read());
      map.set(key, state);
      await this.write(map);
      this.cache = map;
    });
  }

  clear(key: string): Promise<void> {
    return this.serial(async () => {
      const map = new Map(await this.read());
      if (!map.delete(key)) return;
      await this.write(map);
      this.cache = map;
    });
  }

  /** Removes the file: every session and record of this plugin. */
  destroy(): Promise<void> {
    return this.serial(async () => {
      await rm(this.path, { force: true });
      this.cache = new Map();
    });
  }
}
