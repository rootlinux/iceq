import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

// main.tsx's service-worker registration must stay gated to
// production builds. Registering in dev leaves a stale worker
// intercepting fetches (via public/sw.js's own hardened cache
// policy — see service-worker-policy.test.mjs) across dev-server
// restarts, and there is no reason to run it outside of production.

const __dirname = dirname(fileURLToPath(import.meta.url));
const mainSource = readFileSync(resolve(__dirname, "../src/main.tsx"), "utf8");

test("main.tsx only registers the service worker outside of dev builds", () => {
  assert.match(mainSource, /if \(!__DEV__ && "serviceWorker" in navigator\)/);
});

test("main.tsx declares __DEV__ so the registration gate type-checks", () => {
  assert.match(mainSource, /declare const __DEV__: boolean;/);
});
