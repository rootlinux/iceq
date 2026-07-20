import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";

const read = (path) => readFileSync(new URL(`../${path}`, import.meta.url), "utf8");

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
