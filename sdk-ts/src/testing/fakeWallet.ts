/** Wallet built on the WASM wallet API, for SDK tests. Real wallets use the native bindings. */
import * as core from "../../wasm/xchonnect.js";
import { RelayClient } from "../relay.js";

export interface FakeWalletOptions {
  relay: RelayClient;
  originDocument: string;
  name?: string;
  /** Universal-link base announced for same-device requests. */
  link?: string;
  now?: () => number;
  /** Answer requests; return JSON text or throw `{ code, message }`. */
  handle?: (method: string, params: string) => string;
  /** Send `rpc.received` before answering. */
  receipts?: boolean;
}

export class FakeWallet {
  session: core.Session | undefined;
  sas?: string;
  private pairing?: core.WalletPairing;
  private mailbox = "";
  private read = "";
  private readonly now: () => number;
  readonly requests: { method: string; params: string }[] = [];
  /** Own rotation mailboxes abandoned (and deleted) on concurrent rotation offers. */
  readonly abandoned: string[] = [];

  constructor(private readonly o: FakeWalletOptions) {
    this.now = o.now ?? (() => Math.floor(Date.now() / 1000));
  }

  /** Scan the QR: verify, create mailbox W, post the pairing reply. */
  async scan(uri: string): Promise<void> {
    const { mailbox, read, write } = await this.newMailbox();
    [this.mailbox, this.read] = [mailbox, read];
    const reply = core.WalletPairing.reply(uri, this.o.originDocument, this.now(), mailbox, read, write, this.o.name, true, this.o.link);
    this.pairing = reply.takePairing();
    this.sas = this.pairing.sas();
    await this.post(reply.takeOutgoing(), 300);
  }

  /** Wait for session.confirm and confirm the SAS (posts session.ready). */
  async confirm(accept = true): Promise<void> {
    for (let i = 0; i < 200 && !this.session; i++) {
      const msgs = await this.o.relay.fetchMessages(this.mailbox, this.read);
      for (const m of msgs) {
        this.session = this.pairing?.onConfirm(this.now(), m.env);
        await this.o.relay.ack(this.mailbox, this.read, [m.msg_id]);
      }
      if (!this.session) await new Promise((r) => setTimeout(r, 5));
    }
    if (!this.session) throw new Error("no session.confirm");
    const out = accept ? this.session.confirmSas(this.now()) : this.session.rejectSas(this.now());
    if (out) await this.post(out);
  }

  /** Process the mailbox once: answer requests, follow rotations. Returns decoded messages. */
  async step(): Promise<Record<string, unknown>[]> {
    const s = this.session;
    if (!s) return [];
    const out: Record<string, unknown>[] = [];
    const boxes: [string, string][] = [];
    const d = s.drainingMailbox();
    if (d) boxes.push([d[0] as string, d[1] as string]);
    boxes.push([s.ownMailbox(), s.ownReadToken()]);
    for (const [mbx, read] of boxes) {
      const msgs = await this.o.relay.fetchMessages(mbx, read);
      for (const m of msgs) {
        let msg: Record<string, unknown> | undefined;
        try {
          msg = JSON.parse(s.open(this.now(), mbx, m.env)) as Record<string, unknown>;
        } catch {
          // Invalid, replayed or expired: drop it.
        }
        await this.o.relay.ack(mbx, read, [m.msg_id]);
        if (!msg) continue;
        out.push(msg);
        if (msg["type"] === "rpc.request") {
          const method = String(msg["method"]);
          const params = String(msg["params"]);
          this.requests.push({ method, params });
          if (this.o.receipts) {
            await this.post(s.received(this.now(), String(msg["id"])));
          }
          let reply: core.Outgoing;
          try {
            reply = s.respond(this.now(), String(msg["id"]), this.o.handle ? this.o.handle(method, params) : "null");
          } catch (e) {
            const err = e as { code?: number; message?: string };
            reply = s.respondError(this.now(), String(msg["id"]), err.code ?? 4002, err.message ?? "user rejected request");
          }
          await this.post(reply);
        } else if (msg["type"] === "session.rotate" && msg["phase"] === "offer") {
          const n = await this.newMailbox();
          await this.post(s.acceptRotation(this.now(), Number(msg["epoch"]), String(msg["epk"]), String(msg["mailbox"]), String(msg["writeToken"]), n.mailbox, n.read, n.write));
          const gone = s.takeAbandonedMailbox();
          if (gone) {
            await this.o.relay.deleteMailbox(gone[0]!, gone[1]!);
            this.abandoned.push(gone[0]!);
          }
        }
      }
      if (mbx === d?.[0] && msgs.length === 0) s.finishDrain();
    }
    return out;
  }

  /** Declare the granted scopes (`session.permissions`, spec 9.3). */
  async declare(methods: string[], keys: string[], limits?: { perRequestMojos?: string; perDayMojos?: string }): Promise<void> {
    const s = this.session;
    if (!s) throw new Error("not paired");
    await this.post(s.permissions(this.now(), methods, keys, limits?.perRequestMojos, limits?.perDayMojos));
  }

  /** Start a wallet-initiated rotation. */
  async rotate(): Promise<void> {
    const s = this.session;
    if (!s) throw new Error("not paired");
    const n = await this.newMailbox();
    await this.post(s.beginRotation(this.now(), n.mailbox, n.read, n.write));
  }

  private async newMailbox() {
    const read = core.generateToken();
    const write = core.generateToken();
    return { mailbox: await this.o.relay.createMailbox(core.tokenHash(read), core.tokenHash(write)), read, write };
  }

  private async post(out: core.Outgoing, ttlSeconds?: number): Promise<void> {
    await this.o.relay.post(out.mailbox, out.writeToken, out.envelope, ttlSeconds);
  }

  /** Keep answering in the background until stopped. */
  run(): () => void {
    let stop = false;
    void (async () => {
      while (!stop) {
        await this.step().catch(() => undefined);
        await new Promise((r) => setTimeout(r, 5));
      }
    })();
    return () => {
      stop = true;
    };
  }
}
