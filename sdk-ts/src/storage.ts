/**
 * Session state storage (spec 12.1). State contains secrets; browser storage keeps it
 * in IndexedDB encrypted with a non-extractable AES-GCM key, never in localStorage.
 */
export interface SessionStore {
  load(key: string): Promise<string | null>;
  save(key: string, state: string): Promise<void>;
  clear(key: string): Promise<void>;
}

/** In-memory store (Node, tests, or callers that persist elsewhere). */
export class MemorySessionStore implements SessionStore {
  private readonly map = new Map<string, string>();
  async load(key: string): Promise<string | null> {
    return this.map.get(key) ?? null;
  }
  async save(key: string, state: string): Promise<void> {
    this.map.set(key, state);
  }
  async clear(key: string): Promise<void> {
    this.map.delete(key);
  }
}

const DB = "xchonnect";
const STORE = "kv";
const WRAP_KEY = "wrap-key";

function req<T>(r: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    r.onsuccess = () => resolve(r.result);
    r.onerror = () => reject(r.error ?? new Error("IndexedDB error"));
  });
}

/** IndexedDB store with a non-extractable WebCrypto wrapping key. */
export class IndexedDbSessionStore implements SessionStore {
  private db?: Promise<IDBDatabase>;
  private wrapKey: Promise<CryptoKey> | undefined;

  private open(): Promise<IDBDatabase> {
    this.db ??= new Promise((resolve, reject) => {
      const r = indexedDB.open(DB, 1);
      r.onupgradeneeded = () => r.result.createObjectStore(STORE);
      r.onsuccess = () => resolve(r.result);
      r.onerror = () => reject(r.error ?? new Error("IndexedDB open failed"));
    });
    return this.db;
  }

  private async tx<T>(mode: IDBTransactionMode, f: (s: IDBObjectStore) => IDBRequest<T>): Promise<T> {
    const db = await this.open();
    return req(f(db.transaction(STORE, mode).objectStore(STORE)));
  }

  /**
   * The wrapping key, created once. A candidate key is generated first, then a single
   * readwrite transaction keeps an existing key or stores the candidate, so concurrent
   * first uses (also from other tabs) all end up with the same persisted key.
   */
  private key(): Promise<CryptoKey> {
    this.wrapKey ??= (async () => {
      const candidate = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
      const db = await this.open();
      return new Promise<CryptoKey>((resolve, reject) => {
        const s = db.transaction(STORE, "readwrite").objectStore(STORE);
        const get = s.get(WRAP_KEY) as IDBRequest<CryptoKey | undefined>;
        get.onerror = () => reject(get.error ?? new Error("IndexedDB error"));
        get.onsuccess = () => {
          if (get.result) return resolve(get.result);
          const put = s.put(candidate, WRAP_KEY);
          put.onerror = () => reject(put.error ?? new Error("IndexedDB error"));
          put.onsuccess = () => resolve(candidate);
        };
      });
    })().catch((e: unknown) => {
      this.wrapKey = undefined;
      throw e;
    });
    return this.wrapKey;
  }

  async load(key: string): Promise<string | null> {
    const rec = await this.tx("readonly", (s) => s.get(`session:${key}`) as IDBRequest<{ iv: Uint8Array; ct: ArrayBuffer } | undefined>);
    if (!rec) return null;
    const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: rec.iv as Uint8Array<ArrayBuffer> }, await this.key(), rec.ct);
    return new TextDecoder().decode(pt);
  }

  async save(key: string, state: string): Promise<void> {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, await this.key(), new TextEncoder().encode(state));
    await this.tx("readwrite", (s) => s.put({ iv, ct }, `session:${key}`));
  }

  async clear(key: string): Promise<void> {
    await this.tx("readwrite", (s) => s.delete(`session:${key}`));
  }
}

/** Default store for the environment. */
export function defaultSessionStore(): SessionStore {
  return typeof indexedDB !== "undefined" && typeof crypto?.subtle !== "undefined" ? new IndexedDbSessionStore() : new MemorySessionStore();
}
