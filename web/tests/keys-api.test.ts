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
  assert.match(keysSource, /export async function getPrekeyCount\(\): Promise<number>/);
  assert.match(keysSource, /fetchJSON<\{\s*count:\s*number\s*\}>\("\/api\/keys\/prekeys\/count",\s*\{\s*method:\s*"GET"\s*\}\)/s);
});
