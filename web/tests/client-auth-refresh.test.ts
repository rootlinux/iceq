import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));
const clientSource = readFileSync(join(__dirname, "../src/api/client.ts"), "utf8");

test("cookie-backed refresh stores only the access token in localStorage", () => {
  assert.match(clientSource, /body:\s*JSON\.stringify\(\{\}\)/);
  assert.match(clientSource, /localStorage\.setItem\(ACCESS_TOKEN_KEY,\s*j\.access_token\)/);
  assert.match(clientSource, /localStorage\.removeItem\(REFRESH_TOKEN_KEY\)/);
  assert.match(clientSource, /get refreshToken\(\): string \| null \{\s*return null;\s*\}/);
});

test("failed refresh clears legacy refresh token and emits auth-expired", () => {
  assert.match(clientSource, /localStorage\.removeItem\(ACCESS_TOKEN_KEY\)/);
  assert.match(clientSource, /localStorage\.removeItem\(REFRESH_TOKEN_KEY\)/);
  assert.match(clientSource, /iceq:auth-expired/);
});
