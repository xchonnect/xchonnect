/** Wallet built on the WASM wallet API, for SDK tests. Real wallets use the native bindings. */
import * as core from "../../wasm/xchonnect.js";
import { RelayClient } from "../relay.js";

export interface FakeWalletOptions {
  relay: RelayClient;
  originDocument: string;
  name?: string;
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

  constructor(private readonly o: FakeWalletOptions) {
    this.now = o.now ?? (() => Math.floor(Date.now() / 1000));
  }

  /** Scan the QR: verify, create mailbox W, post the pairing reply. Returns the post result. */
  async scan(uri: string): Promise<void> {
    this.read = core.generateToken();
    const write = core.generateToken();
    this.mailbox = await this.o.relay.createMailbox(core.tokenHash(this.read), core.tokenHash(write));
    const reply = core.WalletPairing.reply(uri, this.o.originDocument, this.now(), this.mailbox, this.read, write, this.o.name, true);
    this.pairing = reply.takePairing();
    this.sas = this.pairing.sas();
    const out = reply.takeOutgoing();
    await this.o.relay.post(out.mailbox, out.writeToken, out.envelope, 300);
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
    if (out) await this.o.relay.post(out.mailbox, out.writeToken, out.envelope);
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
        let msg: Record<string, unknown>;
        try {
          msg = JSON.parse(s.open(this.now(), mbx, m.env)) as Record<string, unknown>;
        } catch {
          await this.o.relay.ack(mbx, read, [m.msg_id]);
          continue;
        }
        await this.o.relay.ack(mbx, read, [m.msg_id]);
        out.push(msg);
        if (msg["type"] === "rpc.request") {
          const method = String(msg["method"]);
          const params = String(msg["params"]);
          this.requests.push({ method, params });
          if (this.o.receipts) {
            const r = s.received(this.now(), String(msg["id"]));
            await this.o.relay.post(r.mailbox, r.writeToken, r.envelope);
          }
          let reply: core.Outgoing;
          try {
            reply = s.respond(this.now(), String(msg["id"]), this.o.handle ? this.o.handle(method, params) : "null");
          } catch (e) {
            const err = e as { code?: number; message?: string };
            reply = s.respondError(this.now(), String(msg["id"]), err.code ?? 4002, err.message ?? "user rejected request");
          }
          await this.o.relay.post(reply.mailbox, reply.writeToken, reply.envelope);
        } else if (msg["type"] === "session.rotate" && msg["phase"] === "offer") {
          const r = core.generateToken();
          const w = core.generateToken();
          const nm = await this.o.relay.createMailbox(core.tokenHash(r), core.tokenHash(w));
          const acc = s.acceptRotation(this.now(), Number(msg["epoch"]), String(msg["epk"]), String(msg["mailbox"]), String(msg["writeToken"]), nm, r, w);
          await this.o.relay.post(acc.mailbox, acc.writeToken, acc.envelope);
        }
      }
      if (mbx === d?.[0] && msgs.length === 0) s.finishDrain();
    }
    return out;
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
