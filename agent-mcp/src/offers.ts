/**
 * The offers the wallet made through this pairing, kept in the encrypted state file so the agent
 * can list and cancel them in a later chat. A record says what this plugin knows: made, expired
 * (its expiry passed), cancelled through it. Whether an open one was taken is the chain's to say.
 */
import type { SessionStore } from "@xchonnect/dapp";

const KEY = "offers";
/** Records kept, newest first: an agent posting ladders makes many. */
const MAX = 500;

export interface OfferRecord {
  id: string;
  offer: string;
  gives: { asset: string; amount: string }[];
  gets: { asset: string; amount: string }[];
  createdAt: number;
  expiresAt?: number;
  status: "open" | "expired" | "cancelled";
}

export class OfferBook {
  constructor(private readonly store: SessionStore) {}

  private async read(): Promise<OfferRecord[]> {
    const text = await this.store.load(KEY);
    if (!text) return [];
    try {
      const list = JSON.parse(text) as OfferRecord[];
      return Array.isArray(list) ? list : [];
    } catch {
      return [];
    }
  }

  async add(record: OfferRecord): Promise<void> {
    const list = (await this.read()).filter((o) => o.id !== record.id);
    list.unshift(record);
    await this.store.save(KEY, JSON.stringify(list.slice(0, MAX)));
  }

  async setStatus(id: string, status: OfferRecord["status"]): Promise<void> {
    const list = await this.read();
    const found = list.find((o) => o.id === id);
    if (!found) return;
    found.status = status;
    await this.store.save(KEY, JSON.stringify(list));
  }

  /** Newest first, with expiry applied. */
  async list(now = Math.floor(Date.now() / 1000)): Promise<OfferRecord[]> {
    return (await this.read()).map((o) => (o.status === "open" && o.expiresAt !== undefined && o.expiresAt <= now ? { ...o, status: "expired" } : o));
  }
}
