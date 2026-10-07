/** In-memory relay implementing the HTTP API for SDK tests (no long-poll). */
import * as core from "../../wasm/xchonnect.js";

/** Random base64url id of `n` bytes; `first` fixes the first byte. */
function randomId(n: number, first?: number): string {
  const bytes = Uint8Array.from({ length: n }, (_, i) => (i === 0 && first !== undefined ? first : Math.floor(Math.random() * 256)));
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

interface Box {
  readHash: string;
  writeHash: string;
  messages: { msg_id: string; env: string }[];
}

export class MockRelay {
  readonly boxes = new Map<string, Box>();
  posts = 0;
  private counter = 0;

  readonly fetch: typeof fetch = async (input, init) => {
    const url = new URL(typeof input === "string" ? input : input instanceof URL ? input.href : input.url);
    const method = init?.method ?? "GET";
    const headers = new Headers(init?.headers);
    const body = init?.body ? (JSON.parse(String(init.body)) as Record<string, unknown>) : {};
    const json = (status: number, v: unknown) => new Response(v === undefined ? null : JSON.stringify(v), { status, headers: { "content-type": "application/json" } });
    const notFound = () => json(404, { error: "not_found" });
    const p = url.pathname;
    if (p === "/v1/info") {
      return json(200, { protocol: 1, max_wait_s: 0, max_wait_ohttp_s: 0, default_ttl_s: 86400, max_ttl_s: 604800, max_envelope_bytes: 262400, mailbox_creation: ["open"], gateway_policy: "open", ohttp: false });
    }
    if (p === "/v1/mailboxes" && method === "POST") {
      const id = randomId(16, ++this.counter);
      this.boxes.set(id, { readHash: String(body["read_token_hash"]), writeHash: String(body["write_token_hash"]), messages: [] });
      return json(201, { mailbox_id: id });
    }
    const m = /^\/v1\/mailboxes\/([^/]+)(\/messages|\/ack)?$/.exec(p);
    if (!m) return notFound();
    const box = this.boxes.get(m[1] as string);
    const token = headers.get("authorization")?.replace("Bearer ", "") ?? "";
    let hash = "";
    try {
      hash = core.tokenHash(token);
    } catch {
      return notFound();
    }
    const sub = m[2];
    if (!box) return notFound();
    if (sub === "/messages" && method === "POST") {
      if (hash !== box.writeHash) return notFound();
      const msg_id = randomId(16);
      box.messages.push({ msg_id, env: String(body["env"]) });
      this.posts++;
      return json(202, { msg_id });
    }
    if (hash !== box.readHash) return notFound();
    if (sub === "/messages") return json(200, { messages: box.messages.slice(0, 32) });
    if (sub === "/ack") {
      const ids = new Set(body["msg_ids"] as string[]);
      box.messages = box.messages.filter((x) => !ids.has(x.msg_id));
      return new Response(null, { status: 204 });
    }
    if (method === "DELETE") {
      this.boxes.delete(m[1] as string);
      return new Response(null, { status: 204 });
    }
    return notFound();
  };
}
