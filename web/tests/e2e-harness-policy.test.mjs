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
