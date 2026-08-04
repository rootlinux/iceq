import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));
const keysSource = readFileSync(join(__dirname, "../src/api/keys.ts"), "utf8");

test("addPreKeys accepts the backend 204 No Content contract", async () => {
  assert.match(keysSource, /fetchWithAuth\("\/api\/keys\/prekeys"/);
  assert.doesNotMatch(keysSource, /fetchJSON<\{\s*accepted:\s*number\s*\}>\("\/api\/keys\/prekeys"/);
  assert.match(keysSource, /return\s+\{\s*accepted:\s*prekeys\.length\s*\}/);
});

test("getPrekeyCount reads the server-side unused prekey count", async () => {
  assert.match(keysSource, /export async function getPrekeyCount\(signal\?: AbortSignal\): Promise<number>/);
  assert.match(keysSource, /fetchJSON<\{\s*count:\s*number\s*\}>\("\/api\/keys\/prekeys\/count",\s*\{\s*method:\s*"GET",\s*signal\s*\}\)/s);
});

test("authenticated layout aborts the complete Signal provisioning chain on teardown", () => {
  const layoutSource = readFileSync(join(__dirname, "../src/components/Layout/MainLayout.tsx"), "utf8");
  const storeSource = readFileSync(join(__dirname, "../src/store/signalStore.ts"), "utf8");
  assert.match(layoutSource, /refreshPrekeyCount\(controller\.signal\)/);
  assert.match(storeSource, /refreshPrekeyCount:\s*\(signal\?:\s*AbortSignal\)\s*=>\s*Promise<void>/);
  assert.match(storeSource, /getPrekeyCount\(signal\)/);
});
