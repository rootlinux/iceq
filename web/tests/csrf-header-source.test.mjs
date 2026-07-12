import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const client = readFileSync(new URL("../src/api/client.ts", import.meta.url), "utf8");
const auth = readFileSync(new URL("../src/api/auth.ts", import.meta.url), "utf8");

test("API client defines the IceQ CSRF header contract", () => {
  assert.match(client, /const CSRF_HEADER_NAME\s*=\s*"X-IceQ-CSRF"/);
  assert.match(client, /const CSRF_HEADER_VALUE\s*=\s*"1"/);
});

test("cookie refresh sends the CSRF header", () => {
  assert.match(client, /headers:\s*\{\s*"Content-Type":\s*"application\/json",\s*\[CSRF_HEADER_NAME\]:\s*CSRF_HEADER_VALUE\s*\}/s);
});

test("authenticated mutating fetches add the CSRF header automatically", () => {
  assert.match(client, /if\s*\(requiresCSRF\(method\)\)\s*\{\s*headers\[CSRF_HEADER_NAME\]\s*=\s*CSRF_HEADER_VALUE;\s*\}/s);
  assert.match(client, /function requiresCSRF\(method: string\): boolean/);
});

test("logout remains a mutating fetchWithAuth call covered by automatic CSRF", () => {
  assert.match(auth, /fetchWithAuth\("\/api\/auth\/logout"/);
  assert.match(auth, /method:\s*"POST"/);
});
