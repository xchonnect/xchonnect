/**
 * The offers the wallet made through this pairing, kept in the encrypted state file so the agent
 * can list and cancel them in a later chat. A record says what this plugin knows: made, cancelled
 * through it, and its expiry when the wallet enforces it. A wallet without agent rules (spec 9.4)
 * may ignore the requested expiry (Klimper today does), so such an offer is never shown as
 * expired from this machine's clock: it stays open until it is cancelled or taken on chain.
 */

const KEY = "offers";
/** Records kept, newest first: an agent posting ladders makes many. */
const MAX = 500;

/** Where the records live: a store with an atomic read-modify-write. */
export interface RecordStore {
  load(key: string): Promise<string | null>;
  update(key: string, change: (current: string | null) => string | null): Promise<void>;
}

export interface OfferRecord {
  id: string;
  offer: string;
  gives: { asset: string; amount: string }[];
  gets: { asset: string; amount: string }[];
  createdAt: number;
  /** The expiry asked for. */
  expiresAt?: number;
  /** The wallet enforces `expiresAt` (it implements spec 9.4); otherwise it may not. */
  expiryEnforced?: boolean;
  status: "open" | "expired" | "cancelled";
}

function parse(text: string | null): OfferRecord[] {
  if (!text) return [];
  try {
    const list = JSON.parse(text) as OfferRecord[];
    return Array.isArray(list) ? list : [];
  } catch {
    return [];
  }
}

export class OfferBook {
  constructor(private readonly store: RecordStore) {}

  add(record: OfferRecord): Promise<void> {
    return this.store.update(KEY, (current) => {
      const list = parse(current).filter((o) => o.id !== record.id);
      list.unshift(record);
      return JSON.stringify(list.slice(0, MAX));
    });
  }

  setStatus(id: string, status: OfferRecord["status"]): Promise<void> {
    return this.store.update(KEY, (current) => {
      const list = parse(current);
      const found = list.find((o) => o.id === id);
      if (found) found.status = status;
      return JSON.stringify(list);
    });
  }

  /** Newest first; an enforced expiry that passed shows as expired. */
  async list(now = Math.floor(Date.now() / 1000)): Promise<OfferRecord[]> {
    return parse(await this.store.load(KEY)).map((o) =>
      o.status === "open" && o.expiryEnforced === true && o.expiresAt !== undefined && o.expiresAt <= now ? { ...o, status: "expired" } : o,
    );
  }
}

/** For a plugin that could not open its state: records are not kept. */
export const NO_RECORDS: RecordStore = { load: async () => null, update: async () => {} };
