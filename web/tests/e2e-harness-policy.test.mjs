import assert from "node:assert/strict";
import test from "node:test";
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";

const read = (path) => readFileSync(new URL(`../${path}`, import.meta.url), "utf8");
const webRoot = fileURLToPath(new URL("../", import.meta.url));

test("e2e loopback sink is default-off and limited to exact cache probes", () => {
  const vite = read("vite.config.ts");
  const playwright = read("playwright.config.ts");
  assert.match(vite, /process\.env\.ICEQ_E2E === "1"/);
  assert.match(vite, /new Set\(\["\/api\/e2e-cache-probe", "\/ws\/e2e-cache-probe"\]\)/);
  assert.match(vite, /request\.headers\["x-iceq-e2e-cache-probe"\] !== "1"/);
  assert.match(playwright, /command: "npm run dev -- --host 127\.0\.0\.1 --port 4173"/);
  assert.match(playwright, /env: \{ ICEQ_E2E: "1" \}/);
  assert.match(playwright, /reuseExistingServer: false/);
});

test("non-service-worker specs block workers and the offline policy spec keeps them real", () => {
  for (const path of ["e2e/pwa.spec.ts", "e2e/responsive-auth.spec.ts", "e2e/indexeddb-isolation.spec.ts"]) {
    assert.match(read(path), /test\.use\(\{ serviceWorkers: "block" \}\)/, `${path} must block service workers`);
  }
  assert.doesNotMatch(read("e2e/offline-recovery.spec.ts"), /serviceWorkers: "block"/);
});

test("live production-stack spec keeps the real service worker enabled", () => {
  const liveSpec = read("e2e/live-panic-wipe.spec.ts");
  const liveConfig = read("playwright.live.config.ts");
  const defaultConfig = read("playwright.config.ts");
  assert.doesNotMatch(
    liveSpec,
    /serviceWorkers:\s*["']block["']/,
    "the live production-stack check must not manufacture a service-worker registration failure",
  );
  assert.match(
    liveConfig,
    /process\.env\.ICEQ_LIVE_BASE_URL\s*\?\?\s*["']https:\/\/localhost:8443["']/,
    "the live test must default to the repository's isolated clearnet rehearsal listener",
  );
  assert.doesNotMatch(liveSpec, /localhost:9543/, "the spec must not override the live config with a removed temporary stack port");
  assert.match(liveConfig, /testMatch:\s*["']live-panic-wipe\.spec\.ts["']/, "the dedicated live config must select the real-backend spec");
  assert.match(
    liveConfig,
    /name:\s*["']chromium-live["'][\s\S]*--ignore-certificate-errors/,
    "the local TLS Chromium project must let its service worker trust Caddy's disposable certificate",
  );
  assert.match(liveSpec, /navigator\.serviceWorker\.ready/, "the live spec must prove that the real service worker becomes active");
  assert.match(liveSpec, /unexpectedResponses/, "expected negative API controls must be audited separately from JavaScript errors");
  assert.doesNotMatch(liveSpec, /localStorage\.clear\(\)/, "the live wipe test must inspect local residue rather than erase its own evidence");
  assert.match(liveSpec, /wrong local passphrase must not leave the browser/, "the live spec must prove local passphrase verification makes no request");
  assert.match(liveSpec, /expect\(unlockInput\)\.toBeVisible/, "the post-reload vault boundary must be mandatory");
  assert.doesNotMatch(liveSpec, /failure\.method === "(?:POST|PUT)"/, "aborted security writes must never be allowlisted");
  assert.match(
    liveSpec,
    /isCompletedNoContentResponse\(failure, diagnostics\.responses\)/,
    "Chromium 204 response-finalization events must be accepted only when correlated with a recorded successful response",
  );
  assert.match(
    liveSpec,
    /response\.requestId === failure\.requestId[\s\S]*response\.status === 204[\s\S]*response\.method === failure\.method[\s\S]*response\.path === failure\.path[\s\S]*response\.phase === failure\.phase/,
    "the 204 correlation must bind the exact Playwright request identity, status, method, path and lifecycle phase",
  );
  assert.match(liveSpec, /failure\.path === "\/api\/keys\/bundle"/);
  assert.match(liveSpec, /failure\.path === "\/api\/auth\/panic-wipe-public-key"/);
  assert.match(liveSpec, /key bundle publication must succeed/);
  assert.match(liveSpec, /wipe-key enrollment must succeed/);
  assert.match(
    defaultConfig,
    /testIgnore:\s*\[[\s\S]*["']\*\*\/live-panic-wipe\.spec\.ts["'][\s\S]*\]/,
    "the synthetic default E2E suite must exclude the real-backend spec",
  );
});

test("synthetic transport handles the production poll route and rejects the obsolete route", () => {
  const helpers = read("e2e/helpers.ts");
  assert.match(helpers, /url\.pathname === "\/api\/transport\/poll"/);
  assert.doesNotMatch(helpers, /\/api\/messages\/poll/);
  assert.match(helpers, /target\.pathname === "\/ws"/);
  assert.match(helpers, /target\.pathname === "\/" && target\.searchParams\.has\("token"\)/);
  assert.match(helpers, /unhandled synthetic route/);
});

test("authenticated harness seeds production identity while publishing public directory data only", () => {
  const helpers = read("e2e/helpers.ts");
  assert.match(helpers, /signal\.generateIdentityKeyPair\(\)/);
  assert.match(helpers, /signal\.saveOwnIdentity\(identity, registrationId, namespace\)/);
  assert.match(helpers, /signal\.generatePreKeyBundle\(identity, 1, 1, registrationId, namespace\)/);
  assert.match(helpers, /useSignalStore\.getState\(\)\.ready/);
  assert.match(helpers, /getByRole\("alert"\)/);
  const publicDirectoryBoundary = helpers.slice(
    helpers.indexOf("export async function publishSyntheticDirectory"),
    helpers.indexOf("export async function assertSignalHealthy"),
  );
  assert.doesNotMatch(publicDirectoryBoundary, /privateKey|private_key/);
});

// --- Release safety: the production-preview E2E bridge (e2e/bridge/e2eBridge.ts)
// must never reach a real deploy. Three checks, each proving a different
// layer: config never enables it outside the one dedicated E2E path, no
// production/release surface sets the env var that gates it, and (the
// strongest proof) an actual clean-env build produces no trace of it.

test("ICEQ_E2E is never enabled by Dockerfiles, production Compose, Caddy, CI, or env templates", () => {
  const repoRoot = fileURLToPath(new URL("../../", import.meta.url));
  let output = "";
  try {
    output = execFileSync("git", ["grep", "-n", "-I", "ICEQ_E2E"], { cwd: repoRoot, encoding: "utf8" });
  } catch (err) {
    if (err.status === 1) return; // git grep: no matches anywhere in the repo -- trivially safe
    throw err;
  }
  const productionSurface = /(^|\/)(Dockerfile[^/]*|docker-compose[^/]*\.ya?ml|Caddyfile[^/]*|\.env[^/]*)$|^\.github\/workflows\/.*\.ya?ml$/;
  const offenders = output.trim().split("\n")
    .map((line) => line.split(":")[0])
    // The disposable acceptance stack is test infrastructure, not a
    // production surface, and doesn't set it anyway.
    .filter((filePath) => filePath !== "deploy/docker-compose.acceptance.yml" && productionSurface.test(filePath));
  assert.deepEqual(offenders, [], `ICEQ_E2E must never appear in a production/release surface: ${offenders.join(", ")}`);
});

test("the e2e bridge can only be produced by playwright.sw.config.ts's build step", () => {
  const devConfig = read("playwright.config.ts");
  const swConfig = read("playwright.sw.config.ts");
  const vite = read("vite.config.ts");
  // The main E2E config also sets ICEQ_E2E=1 (for the cache-probe plugin),
  // but its webServer only ever runs the dev server -- `vite dev` never
  // executes build.rollupOptions, so that alone can never produce the
  // bridge entry.
  assert.match(devConfig, /command: "npm run dev/);
  assert.doesNotMatch(devConfig, /npm run build/);
  // Only the SW config actually builds with ICEQ_E2E set.
  assert.match(swConfig, /command: "npm run build && npm run preview/);
  assert.match(swConfig, /env: \{ ICEQ_E2E: "1" \}/);
  // And the build-time gate has exactly this one trigger condition.
  assert.match(vite, /rollupOptions: process\.env\.ICEQ_E2E === "1" \? \{/);
});

test("a normal production build (no ICEQ_E2E) contains no trace of the e2e bridge", () => {
  const cleanEnv = { ...process.env };
  delete cleanEnv.ICEQ_E2E;
  // Same command the real Dockerfile (web/Dockerfile) and CI run --
  // proves the built artifact, not just the source's intent.
  execFileSync("npm", ["run", "build"], { cwd: webRoot, env: cleanEnv, stdio: "pipe", timeout: 60_000 });

  const distDir = new URL("../dist/", import.meta.url);
  assert.ok(!existsSync(new URL("e2e-bridge.js", distDir)), "dist/e2e-bridge.js must not exist in a normal build");

  const assetsDir = new URL("assets/", distDir);
  const jsFiles = readdirSync(assetsDir).filter((name) => name.endsWith(".js"));
  assert.ok(jsFiles.length > 0, "expected at least one built JS asset to inspect");
  for (const file of jsFiles) {
    const contents = readFileSync(new URL(file, assetsDir), "utf8");
    assert.doesNotMatch(contents, /__iceqE2EBridge/, `${file} must not reference the e2e bridge window global`);
  }

  const html = readFileSync(new URL("index.html", distDir), "utf8");
  assert.doesNotMatch(html, /e2e-bridge/, "index.html must not reference the e2e bridge");
});

// --- Production CSP: WebAssembly is required by the cryptographic library ---
// The CurveASM WebAssembly module (curve25519 / Double Ratchet) is
// bundled in the main JS payload. Browsers that strictly enforce CSP
// (Safari / WebKit) block WebAssembly.instantiate() when script-src
// lacks the narrow wasm-unsafe-eval keyword — a keyword that allows
// WASM compilation without opening the general unsafe-eval hole for
// JavaScript.

test("production script-src allows wasm-unsafe-eval and rejects unsafe-eval", () => {
  const repoRoot = fileURLToPath(new URL("../../", import.meta.url));
  const caddyfile = readFileSync(`${repoRoot}/deploy/Caddyfile`, "utf8");

  // Extract the Content-Security-Policy header line from the
  // (security_headers) snippet — the single source of truth for
  // every response the edge emits.
  const cspMatch = caddyfile.match(/Content-Security-Policy\s+"([^"]+)"/);
  assert.ok(cspMatch, "Caddyfile must define a Content-Security-Policy header");
  const csp = cspMatch[1];

  // script-src MUST include wasm-unsafe-eval so WebAssembly.instantiate
  // works in Safari / WebKit.
  assert.match(csp, /script-src[^;]*'wasm-unsafe-eval'/, "script-src must allow 'wasm-unsafe-eval' for cryptographic WASM");

  // The general eval hole must stay closed.
  assert.doesNotMatch(csp, /'unsafe-eval'/, "script-src must not allow general 'unsafe-eval'");

  // Production enforces HTTPS everywhere — upgrade-insecure-requests
  // converts any stale HTTP reference the browser encounters.
  assert.match(csp, /upgrade-insecure-requests/, "CSP must include upgrade-insecure-requests for production TLS enforcement");
});

test("production Caddyfile has no preview-only HTTP listener", () => {
  const repoRoot = fileURLToPath(new URL("../../", import.meta.url));
  const caddyfile = readFileSync(`${repoRoot}/deploy/Caddyfile`, "utf8");

  // The preview-only :80 block exists solely for the disposable
  // preview stack (iceq-rc1-preview). It must never reach the
  // public / production branch.
  assert.doesNotMatch(caddyfile, /^:80\s*\{/m, "production Caddyfile must not contain a preview-only :80 HTTP listener block");
});
