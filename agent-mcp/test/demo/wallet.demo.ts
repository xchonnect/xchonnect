/**
 * The test wallet as a process, for trying the plugin in Claude Code without a phone
 * (`scripts/agent-demo.sh`). Not part of `npm test`; run by the script as
 *
 *   DEMO_URI='xchonnect:v1?…' DEMO_DIR=<dir> npx vitest run --config test/demo/vitest.demo.ts
 *
 * It fetches the origin document from the plugin (developer mode, `http://localhost:<port>`),
 * pairs, writes the 6-digit code to `$DEMO_DIR/sas` (compare it with the one Claude shows),
 * confirms, and answers with the rules in `$DEMO_DIR/rules.json` until `$DEMO_DIR/stop` exists.
 * Offers to take are read with nodexch's decode route when NODEXCH_URL and NODEXCH_KEY are set.
 * It holds no keys: offers it makes are placeholders, takes are only recorded.
 */
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { it } from "vitest";
import { AgentWallet, type AssetAmount, type Rules } from "../agentWallet.js";

const env = process.env;
const dir = env["DEMO_DIR"] as string;

async function decode(offer: string): Promise<{ offered: AssetAmount[]; requested: AssetAmount[] } | null> {
  const url = env["NODEXCH_URL"];
  const key = env["NODEXCH_KEY"];
  if (!url || !key) return null;
  const response = await fetch(`${url}/x/offers/v1/decode`, {
    method: "POST",
    headers: { authorization: `Bearer ${key}`, "content-type": "application/json" },
    body: JSON.stringify({ offer }),
  });
  if (!response.ok) return null;
  const body = (await response.json()) as { offered: { kind: string; id?: string; mojos: number }[]; requested: { kind: string; id?: string; mojos: number }[] };
  const side = (list: { kind: string; id?: string; mojos: number }[]) => list.map((a) => ({ asset: a.kind === "xch" ? "xch" : (a.id as string), mojos: BigInt(a.mojos) }));
  return { offered: side(body.offered), requested: side(body.requested) };
}

it("runs the demo wallet", async () => {
  const uri = env["DEMO_URI"] as string;
  const domain = decodeURIComponent(/[?&]d=([^&]+)/.exec(uri)?.[1] ?? "");
  const originDocument = await (await fetch(`http://${domain}/.well-known/xchonnect.json`)).text();
  const rules = JSON.parse(readFileSync(join(dir, "rules.json"), "utf8")) as Rules;
  const wallet = new AgentWallet({
    relay: env["DEMO_RELAY"] ?? "http://127.0.0.1:8787",
    originDocument,
    rules,
    balances: { xch: 5_000_000_000_000n, d82dd03f8a9ad2f84353cd953c4de6b21dbaaf7de3ba3f4ddd9abe31ecba80ad: 2_000_000n },
    decodeOffer: decode,
  });
  const sas = await wallet.pair(uri);
  writeFileSync(join(dir, "sas"), sas);
  console.log(`paired, code ${sas}`);
  await wallet.confirm();
  console.log("confirmed");
  while (!existsSync(join(dir, "stop"))) {
    await new Promise((r) => setTimeout(r, 500));
    writeFileSync(
      join(dir, "wallet-state.json"),
      JSON.stringify(
        {
          taken: wallet.taken,
          offers: [...wallet.offers.entries()].map(([id, o]) => ({ id, open: o.open })),
          used: Object.fromEntries([...wallet.usage.used].map(([k, v]) => [k, v.toString()])),
          held: Object.fromEntries([...wallet.usage.held].map(([k, v]) => [k, v.toString()])),
          requests: wallet.fake.requests.map((r) => r.method),
        },
        null,
        2,
      ),
    );
  }
  wallet.close();
}, 0);
