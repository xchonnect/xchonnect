// Content Security Policy regression guard for the WASM core (TASK-32 AC2, spec 12).
//
// A signing page must be servable under a strict CSP that does NOT grant `unsafe-eval`.
// wasm-bindgen's glue only needs `'wasm-unsafe-eval'` (the dedicated keyword for
// `WebAssembly.compile`/`Instance`), and nothing in it may fall back to `eval` or the
// `Function` constructor. Three checks:
//
//  1. Static: the emitted glue contains no dynamic code generation at all.
//  2. Node: the module loads and works with V8's code generation from strings disabled
//     (`--disallow-code-generation-from-strings`), the engine-level analogue of a CSP
//     without `unsafe-eval`.
//  3. Browser: a real headless Chromium loads the module from a local server that sends
//     an enforcing `Content-Security-Policy` header without `unsafe-eval`, with a
//     negative control that proves the header is being enforced. Skipped (not failed)
//     when no Chrome/Chromium binary is present.
import { execFileSync, spawn } from "node:child_process";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";

const WASM_DIR = new URL("../wasm/", import.meta.url);
const GLUE = readFileSync(new URL("xchonnect.js", WASM_DIR), "utf8");
const WASM = readFileSync(new URL("xchonnect_bg.wasm", WASM_DIR));

/** The policy a signing page is expected to be able to use (spec 12, bindings/wasm/README.md). */
const STRICT_CSP =
  "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; connect-src 'self'; " +
  "img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; " +
  "report-uri /csp-report";
/** The same policy without the WASM keyword: the module must NOT load under it. */
const NO_WASM_CSP = STRICT_CSP.replace(" 'wasm-unsafe-eval'", "");

describe("wasm glue contains no dynamic code generation", () => {
  // `eval(...)`, `window.eval(...)`, `new Function("…")`, `Function("…")`,
  // `setTimeout("…")` and friends all require `unsafe-eval`.
  const forbidden: [string, RegExp][] = [
    ["eval(", /(^|[^.\w$])eval\s*\(/],
    ["indirect eval", /\.\s*eval\s*\(/],
    ["new Function", /new\s+Function\s*\(/],
    ["Function constructor call", /(^|[^.\w$])Function\s*\(/],
    ["string timer", /set(?:Timeout|Interval)\s*\(\s*["'`]/],
  ];
  for (const [name, re] of forbidden) {
    it(`has no ${name}`, () => {
      expect(GLUE).not.toMatch(re);
    });
  }

  it("asserts the documented policy grants no unsafe-eval", () => {
    // `'wasm-unsafe-eval'` is the narrow WASM keyword; plain `'unsafe-eval'` is what
    // spec 12 forbids on signing pages.
    expect(STRICT_CSP).not.toContain("'unsafe-eval'");
    expect(NO_WASM_CSP).not.toContain("unsafe-eval");
    expect(STRICT_CSP).toContain("'wasm-unsafe-eval'");
    expect(readFileSync(new URL("../../bindings/wasm/README.md", import.meta.url), "utf8")).toContain(
      "'wasm-unsafe-eval'",
    );
  });
});

describe("Node", () => {
  it("loads and runs with code generation from strings disabled", () => {
    const script = `
      import { readFileSync } from "node:fs";
      // Proves the flag is active: without it this would not throw.
      let evalBlocked = false;
      try { (0, eval)("1+1"); } catch { evalBlocked = true; }
      if (!evalBlocked) { console.error("eval was not blocked"); process.exit(2); }
      const core = await import(${JSON.stringify(new URL("xchonnect.js", WASM_DIR).href)});
      core.initSync({ module: readFileSync(${JSON.stringify(new URL("xchonnect_bg.wasm", WASM_DIR).pathname)}) });
      const token = core.generateToken();
      const hash = core.tokenHash(token);
      const unsigned = core.UnsignedPairing.prepare("https://relay.example", "dapp.example",
        Buffer.alloc(16, 1).toString("base64url"), token, 120, 1790000000, "k1", undefined, false);
      const seed = Buffer.alloc(32, 7).toString("base64url");
      const uri = unsigned.finish(core.devSign(seed, unsigned.sigInput()), core.devPublicKey(seed)).uri();
      if (!/^xchonnect:v1\\?/.test(uri)) { console.error("bad uri: " + uri); process.exit(3); }
      process.stdout.write(JSON.stringify({ token, hash, uri }));
    `;
    const out = execFileSync(
      process.execPath,
      ["--disallow-code-generation-from-strings", "--input-type=module", "-e", script],
      { encoding: "utf8", stdio: ["ignore", "pipe", "inherit"] },
    );
    const got = JSON.parse(out) as { token: string; hash: string; uri: string };
    expect(got.token).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(got.hash).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(got.uri).toContain("xchonnect:v1?");
  });
});

// --- headless browser -----------------------------------------------------------------

/** Headless command line per engine; the page reports its own result over HTTP. */
type Engine = { engine: "chromium" | "gecko"; args: (profile: string, url: string) => string[] };

const CHROMIUM: Engine = {
  engine: "chromium",
  args: (profile, url) => [
    "--headless=new",
    "--disable-gpu",
    "--no-sandbox",
    "--no-first-run",
    "--no-default-browser-check",
    "--disable-extensions",
    "--disable-dev-shm-usage",
    `--user-data-dir=${profile}`,
    url,
  ],
};
const GECKO: Engine = {
  engine: "gecko",
  args: (profile, url) => ["--headless", "--no-remote", "--new-instance", "--profile", profile, url],
};

/** Candidate browsers, in the order they are tried. `XCHONNECT_CHROME` /
 * `XCHONNECT_FIREFOX` override the search (CI runners place them differently). */
const CANDIDATES: [string, string | undefined, Engine][] = [
  ["chrome", process.env.XCHONNECT_CHROME, CHROMIUM],
  ["chrome", "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", CHROMIUM],
  ["chrome", "/usr/bin/google-chrome", CHROMIUM],
  ["chrome", "/usr/bin/google-chrome-stable", CHROMIUM],
  ["chromium", "/Applications/Chromium.app/Contents/MacOS/Chromium", CHROMIUM],
  ["chromium", "/opt/homebrew/bin/chromium", CHROMIUM],
  ["chromium", "/usr/bin/chromium", CHROMIUM],
  ["chromium", "/usr/bin/chromium-browser", CHROMIUM],
  ["chromium", "/snap/bin/chromium", CHROMIUM],
  ["firefox", process.env.XCHONNECT_FIREFOX, GECKO],
  ["firefox", "/Applications/Firefox.app/Contents/MacOS/firefox", GECKO],
  ["firefox", "/usr/bin/firefox", GECKO],
  ["firefox", "/snap/bin/firefox", GECKO],
];

/** One browser per name, the first that exists. */
const browsers = [...new Map(
  CANDIDATES.filter(([, bin]) => bin && existsSync(bin))
    .reverse()
    .map(([name, bin, engine]) => [name, { name, bin: bin as string, engine }]),
).values()];

/** The page under test: registers a violation listener, then loads the module. */
const PAGE_SCRIPT = `
const violations = [];
document.addEventListener("securitypolicyviolation", (e) =>
  violations.push(e.effectiveDirective + " " + (e.blockedURI || "inline")));
const send = (r) => fetch("/result", { method: "POST", body: JSON.stringify({ ...r, violations }) });
(async () => {
  try {
    const core = await import("/xchonnect.js");
    await core.default({ module_or_path: "/xchonnect_bg.wasm" });
    const token = core.generateToken();
    const hash = core.tokenHash(token);
    await send({ ok: /^[A-Za-z0-9_-]{43}$/.test(token) && hash.length === 43, token });
  } catch (e) {
    await send({ ok: false, error: String(e && e.message ? e.message : e) });
  }
})();
`;

const PAGE_HTML =
  '<!doctype html><meta charset="utf-8"><title>csp</title><script type="module" src="/main.js"></script>';

type PageResult = { ok: boolean; token?: string; error?: string; violations: string[] };

type Browser = { name: string; bin: string; engine: Engine };

/**
 * Drive Safari through `safaridriver` (there is no headless mode and no way to pass a
 * URL on the command line). Returns `null` when Safari cannot be automated, which is the
 * default: a human has to tick Safari Settings > Advanced > "Show features for web
 * developers" and then Develop > "Allow Remote Automation" once. `safaridriver --enable`
 * needs an administrator password, so it cannot be done from a test.
 */
async function safariNavigate(url: string): Promise<{ ok: true } | { skip: string }> {
  const port = 45_000 + Math.floor(Math.random() * 2000);
  const driver = spawn("/usr/bin/safaridriver", ["-p", String(port)], { stdio: "ignore" });
  const base = `http://127.0.0.1:${port}`;
  try {
    for (let i = 0; i < 20; i++) {
      try {
        const res = await fetch(`${base}/session`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ capabilities: { alwaysMatch: { browserName: "safari" } } }),
        });
        const body = (await res.json()) as { value?: { sessionId?: string; message?: string } };
        if (!res.ok || !body.value?.sessionId) {
          return { skip: body.value?.message ?? `safaridriver returned ${res.status}` };
        }
        const session = body.value.sessionId;
        await fetch(`${base}/session/${session}/url`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ url }),
        });
        // The page reports its own result; the session can go once it has loaded.
        await new Promise((r) => setTimeout(r, 1500));
        await fetch(`${base}/session/${session}`, { method: "DELETE" });
        return { ok: true };
      } catch {
        await new Promise((r) => setTimeout(r, 250)); // driver still starting
      }
    }
    return { skip: "safaridriver did not accept connections" };
  } finally {
    driver.kill("SIGKILL");
  }
}

/** Opens `url` in a browser; `skip` means the browser could not be automated at all. */
type Launch = (url: string) => Promise<{ skip?: string; stop?: () => void }>;

const spawnLaunch =
  (browser: Browser): Launch =>
  (url) => {
    const profile = mkdtempSync(join(tmpdir(), "xchonnect-csp-"));
    const proc = spawn(browser.bin, browser.engine.args(profile, url), { stdio: "ignore" });
    return Promise.resolve({
      stop: () => {
        proc.kill("SIGKILL");
        try {
          rmSync(profile, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 });
        } catch {
          // The browser may still be unlinking its own profile files; a leftover
          // temporary directory must not fail the check.
        }
      },
    });
  };

const safariLaunch: Launch = async (url) => {
  const r = await safariNavigate(url);
  return "skip" in r ? { skip: r.skip } : {};
};

/** Serve the module under `csp`, open it, and return what the page reported. */
async function runUnderCsp(launch: Launch, csp: string): Promise<PageResult | { skip: string }> {
  const reports: string[] = [];
  let resolveResult: (r: PageResult) => void = () => {};
  const result = new Promise<PageResult>((r) => {
    resolveResult = r;
  });

  const body = (req: IncomingMessage) =>
    new Promise<string>((resolve) => {
      let s = "";
      req.on("data", (c) => {
        s += c;
      });
      req.on("end", () => resolve(s));
    });

  const server: Server = createServer((req: IncomingMessage, res: ServerResponse) => {
    const url = (req.url ?? "/").split("?")[0];
    if (req.method === "POST" && url === "/result") {
      void body(req).then((s) => {
        res.writeHead(204).end();
        try {
          resolveResult(JSON.parse(s) as PageResult);
        } catch {
          resolveResult({ ok: false, error: `unparseable result ${s}`, violations: [] });
        }
      });
      return;
    }
    if (req.method === "POST" && url === "/csp-report") {
      void body(req).then((s) => {
        reports.push(s);
        res.writeHead(204).end();
      });
      return;
    }
    const send = (type: string, content: string | Buffer) => {
      res.writeHead(200, { "content-type": type, "content-security-policy": csp }).end(content);
    };
    // Browsers request this unprompted; serving it keeps the violation list clean.
    if (url === "/favicon.ico") return send("image/x-icon", Buffer.alloc(0));
    if (url === "/") return send("text/html; charset=utf-8", PAGE_HTML);
    if (url === "/main.js") return send("text/javascript; charset=utf-8", PAGE_SCRIPT);
    if (url === "/xchonnect.js") return send("text/javascript; charset=utf-8", GLUE);
    if (url === "/xchonnect_bg.wasm") return send("application/wasm", WASM);
    res.writeHead(404, { "content-security-policy": csp }).end();
  });

  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const addr = server.address();
  const port = typeof addr === "object" && addr ? addr.port : 0;
  const launched = await launch(`http://127.0.0.1:${port}/`);
  try {
    if (launched.skip !== undefined) return { skip: launched.skip };
    const timeout = new Promise<PageResult>((_, reject) =>
      setTimeout(() => reject(new Error("the page reported nothing within 60 s")), 60_000),
    );
    const r = await Promise.race([result, timeout]);
    // CSP reports (report-uri) arrive out of band; give them a moment to land.
    await new Promise((r2) => setTimeout(r2, 500));
    return { ...r, violations: [...r.violations, ...reports] };
  } finally {
    launched.stop?.();
    await new Promise<void>((r) => server.close(() => r()));
  }
}

const targets: [string, Launch][] = [
  ...browsers.map((b): [string, Launch] => [b.name, spawnLaunch(b)]),
  // Safari last: it needs "Allow Remote Automation" and is skipped without it.
  ...(existsSync("/usr/bin/safaridriver")
    ? ([["safari", safariLaunch]] as [string, Launch][])
    : []),
];

afterAll(() => {
  if (targets.length === 0) {
    console.warn("no Chrome/Chromium/Firefox/Safari found: browser CSP checks skipped");
  }
});

const describeBrowser = targets.length > 0 ? describe : describe.skip;

describeBrowser(`real browsers (${targets.map(([n]) => n).join(", ") || "none found"})`, () => {
  for (const [name, launch] of targets) {
    it(
      `${name} loads and runs the module under a strict CSP without unsafe-eval`,
      async (ctx) => {
        const r = await runUnderCsp(launch, STRICT_CSP);
        if ("skip" in r) {
          console.warn(`${name}: not automatable here, check skipped (${r.skip})`);
          return ctx.skip();
        }
        expect(r.error ?? null).toBeNull();
        expect(r.violations).toEqual([]);
        expect(r.ok).toBe(true);
        expect(r.token).toMatch(/^[A-Za-z0-9_-]{43}$/);
      },
      120_000,
    );

    // Negative control: without 'wasm-unsafe-eval' the browser must refuse to compile
    // the module. Were it to pass, the check above would prove nothing about
    // enforcement.
    it(
      `${name} is blocked when the policy grants neither wasm-unsafe-eval nor unsafe-eval`,
      async (ctx) => {
        const r = await runUnderCsp(launch, NO_WASM_CSP);
        if ("skip" in r) return ctx.skip();
        expect(r.ok).toBe(false);
        expect(`${r.error ?? ""} ${r.violations.join(" ")}`.toLowerCase()).toMatch(
          /wasm|webassembly|script-src/,
        );
      },
      120_000,
    );
  }
});
