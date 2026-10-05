import { RelayError, XchonnectClient, XchonnectRpcError, type Pairing } from "@xchonnect/dapp";
import wasmUrl from "@xchonnect/dapp/xchonnect_bg.wasm?url";
import QRCode from "qrcode";

const RELAY = (import.meta.env["VITE_RELAY"] as string | undefined) ?? "http://127.0.0.1:8787";
const $ = <T extends HTMLElement>(id: string) => document.getElementById(id) as T;
const log = (msg: string) => {
  $("log").textContent = `${new Date().toLocaleTimeString()}  ${msg}\n` + ($("log").textContent ?? "");
};
const show = (section: "unpaired" | "pairing" | "sas" | "active" | "none") => {
  for (const id of ["unpaired", "pairing", "sas", "active"]) $(id).hidden = id !== section;
};

const origin = (await (await fetch("/api/origin")).json()) as { kid: string; publicKey: string };
const client = await XchonnectClient.create({
  relay: RELAY,
  domain: location.host, // "localhost:5173" (developer mode)
  kid: origin.kid,
  originPublicKey: origin.publicKey,
  developerMode: true,
  wasm: wasmUrl,
  // Production: hide the user's IP from the relay (spec 10) by routing through an
  // independent OHTTP relay with the relay's published key configuration (pinned here),
  // and show `client.privacy` ("ohttp" | "direct") and `client.on("privacy", …)` to users.
  // ohttp: { relayUrl: "https://ohttp-relay.example/", keyConfig: "<base64url of /.well-known/ohttp-keys>" },
  // The origin key stays on the backend; the browser only asks for a signature.
  sign: async (sigInput) => {
    const res = await fetch("/api/sign", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ sigInput }) });
    return ((await res.json()) as { signature: string }).signature;
  },
});

const render = () => {
  $("status").textContent = client.status;
  if (client.status === "active") show("active");
  else if (client.status === "unpaired" || client.status === "ended") show("unpaired");
};
client.on("status", render);
client.on("delivery", (e) => log(`${e.method}: ${e.state}`));
render();

let pairing: Pairing | undefined;
$("pair").addEventListener("click", async () => {
  try {
    log("creating pairing code…");
    pairing = await client.pair();
    show("pairing");
    $<HTMLTextAreaElement>("uri").value = pairing.uri;
    await QRCode.toCanvas($<HTMLCanvasElement>("qr"), pairing.uri, { errorCorrectionLevel: "M", margin: 1, width: 320 });
    const timer = setInterval(() => {
      $("expires").textContent = String(Math.max(0, (pairing?.expiresAt ?? 0) - Math.floor(Date.now() / 1000)));
    }, 500);
    const { sas, walletName } = await pairing.waitForWallet().finally(() => clearInterval(timer));
    $("sas-code").textContent = sas;
    $("wallet-name").textContent = walletName ?? "your wallet";
    show("sas");
    log(`wallet replied; SAS ${sas}`);
  } catch (e) {
    log(`pairing failed: ${(e as Error).message}`);
    render();
  }
});

$("copy").addEventListener("click", () => void navigator.clipboard.writeText($<HTMLTextAreaElement>("uri").value));

$("sas-yes").addEventListener("click", async () => {
  log("waiting for the wallet to confirm…");
  try {
    await pairing?.confirm();
    log("session active");
  } catch (e) {
    log(`confirmation failed: ${(e as Error).message}`);
  }
  render();
});

$("sas-no").addEventListener("click", async () => {
  await pairing?.reject();
  log("codes did not match: session ended");
  render();
});

const samples: Record<string, unknown> = {
  chainId: {},
  connect: { eager: false },
  getPublicKeys: { limit: 1 },
  // A spend of a coin that does not exist: a wallet that simulates the request, as it
  // must (spec 11.1), refuses this with 4000. That refusal is the point of the button.
  signCoinSpends: {
    coinSpends: [{ coin: { parent_coin_info: "0x" + "11".repeat(32), puzzle_hash: "0x" + "22".repeat(32), amount: "1000" }, puzzle_reveal: "0x80", solution: "0x80" }],
    partialSign: false,
  },
};

// `signMessage` has to name a key the wallet actually holds, so ask for one first and
// keep it for later requests.
let exposedKey: string | undefined;
const paramsFor = async (method: string): Promise<unknown> => {
  if (method !== "signMessage") return samples[method];
  exposedKey ??= ((await client.request("getPublicKeys", { limit: 1 })) as string[])[0];
  if (exposedKey === undefined) throw new Error("the wallet exposed no public key");
  return { message: "48656c6c6f2066726f6d205863686f6e6e656374", publicKey: exposedKey };
};

for (const btn of document.querySelectorAll<HTMLButtonElement>("button[data-method]")) {
  btn.addEventListener("click", async () => {
    const method = btn.dataset["method"] ?? "";
    log(`→ ${method}`);
    try {
      const result = await client.request(method, await paramsFor(method));
      log(`← ${method}: ${JSON.stringify(result)}`);
    } catch (e) {
      if (e instanceof XchonnectRpcError) log(`← ${method}: error ${e.code} ${e.message}`);
      else if (e instanceof RelayError) log(`relay error: ${e.code}`);
      else log(`error: ${(e as Error).message}`);
    }
  });
}

$("rotate").addEventListener("click", async () => {
  await client.rotate();
  log("rotation offered");
});
$("end").addEventListener("click", async () => {
  await client.end("user disconnected");
  log("disconnected");
});
