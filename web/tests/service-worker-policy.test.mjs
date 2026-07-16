import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import vm from "node:vm";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const sw = readFileSync(resolve(root, process.env.ICEQ_SW_PATH ?? "public/sw.js"), "utf8");

function dispatched(path, overrides = {}, response = { ok: true, redirected: false, type: "basic", headers: { get: () => "text/javascript" }, clone() { return this; } }) {
  const listeners = {};
  const context = {
    URL,
    self: { location: { origin: "https://iceq.test" }, addEventListener: (name, fn) => { listeners[name] = fn; }, skipWaiting() {}, clients: { claim() {} }, registration: {} },
    caches: { open: async () => ({ match: async () => null, put: async () => { puts += 1; } }), keys: async () => [] },
    clients: { matchAll: async () => [], openWindow: async () => {} },
    fetch: async () => response,
  };
  let puts = 0;
  vm.runInNewContext(sw, context);
  let promise;
  listeners.fetch({ request: { method: "GET", destination: "script", mode: "cors", credentials: "omit", headers: { has: () => false }, url: `https://iceq.test${path}`, ...overrides }, respondWith: (value) => { promise = value; } });
  return { handled: Boolean(promise), settle: async () => { if (promise) await promise; return puts; } };
}
const intercepted = (path, overrides = {}) => dispatched(path, overrides).handled;

test("service worker caches an explicit versioned static allowlist only", () => {
  assert.match(sw, /HASHED_ASSET/);
  assert.match(sw, /\\\/assets\\\//);
  assert.match(sw, /url\.search !== ["']["']/);
  assert.match(sw, /request\.destination === ["']document["']/);
  assert.match(sw, /request\.mode === ["']navigate["']/);
  assert.doesNotMatch(sw, /everything else|Network First/i);
  assert.doesNotMatch(sw, /pathname\.endsWith\(["']\.png["']\)/);
});

test("only Vite hash-versioned JS and CSS are eligible for runtime caching", () => {
  assert.match(sw, /\[a-zA-Z0-9_-\].*\{8,/);
  assert.match(sw, /\(js\|css\)/);
  const fetchPolicy = sw.slice(0, sw.indexOf('self.addEventListener("push"'));
  assert.doesNotMatch(fetchPolicy, /manifest\.json|icon-192|icon-512|apple-touch-icon/);
});

test("runtime policy positively accepts hashed assets and rejects every unversioned or sensitive shape", () => {
  assert.equal(intercepted("/assets/index-AbCdEf12.js"), true);
  assert.equal(intercepted("/assets/index-AbCdEf12.css", { destination: "style" }), true);
  for (const path of ["/assets/index.js", "/assets/index-short.js", "/assets/index-AbCdEf12.js?v=2", "/manifest.json", "/icons/icon-192.png", "/api/assets/index-AbCdEf12.js", "/download/assets/index-AbCdEf12.js"]) assert.equal(intercepted(path), false, path);
  assert.equal(intercepted("/assets/index-AbCdEf12.js", { mode: "navigate", destination: "document" }), false);
  assert.equal(intercepted("/assets/index-AbCdEf12.js", { headers: { has: (name) => name === "authorization" } }), false);
  assert.equal(intercepted("/assets/index-AbCdEf12.js", { credentials: "same-origin" }), false);
});

test("runtime cache rejects redirects, opaque responses, errors, and content-type poisoning", async () => {
  const cases = [
    { ok: true, redirected: true, type: "basic", contentType: "text/javascript" },
    { ok: true, redirected: false, type: "opaque", contentType: "text/javascript" },
    { ok: true, redirected: false, type: "basic", contentType: "text/html" },
    { ok: true, redirected: false, type: "basic", contentType: "text/css" },
    { ok: false, redirected: false, type: "basic", contentType: "text/javascript" },
  ];
  for (const item of cases) {
    const response = { ok: item.ok, redirected: item.redirected, type: item.type, headers: { get: () => item.contentType }, clone() { return this; } };
    const run = dispatched("/assets/index-AbCdEf12.js", {}, response);
    assert.equal(run.handled, true);
    assert.equal(await run.settle(), 0, JSON.stringify(item));
  }
  const valid = dispatched("/assets/index-AbCdEf12.css", { destination: "style" }, { ok: true, redirected: false, type: "basic", headers: { get: () => "text/css; charset=utf-8" }, clone() { return this; } });
  assert.equal(await valid.settle(), 1);
});

test("service worker never intercepts sensitive or authenticated routes", () => {
  for (const path of ["/api", "/ws", "/auth", "/upload", "/download"]) {
    assert.ok(sw.includes(path), `missing network-only guard for ${path}`);
  }
  assert.match(sw, /request\.headers\.has\(["']authorization["']\)/i);
  assert.match(sw, /request\.credentials !== ["']omit["']/);
});

test("activation deletes every cache except the current cache", () => {
  assert.match(sw, /key !== CACHE_NAME/);
  assert.match(sw, /caches\.delete\(key\)/);
});
