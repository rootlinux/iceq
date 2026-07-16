import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const sw = readFileSync(resolve(root, "public/sw.js"), "utf8");

test("service worker caches an explicit versioned static allowlist only", () => {
  assert.match(sw, /STATIC_ASSETS/);
  assert.match(sw, /request\.destination === ["']document["']/);
  assert.match(sw, /request\.mode === ["']navigate["']/);
  assert.doesNotMatch(sw, /everything else|Network First/i);
  assert.doesNotMatch(sw, /pathname\.endsWith\(["']\.png["']\)/);
});

test("service worker never intercepts sensitive or authenticated routes", () => {
  for (const path of ["/api", "/ws", "/auth", "/upload", "/download"]) {
    assert.ok(sw.includes(path), `missing network-only guard for ${path}`);
  }
  assert.match(sw, /request\.headers\.has\(["']authorization["']\)/i);
  assert.match(sw, /request\.credentials === ["']include["']/);
});

test("activation deletes every cache except the current cache", () => {
  assert.match(sw, /key !== CACHE_NAME/);
  assert.match(sw, /caches\.delete\(key\)/);
});

