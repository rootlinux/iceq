import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));
const securitySettings = readFileSync(
  resolve(__dirname, "../src/components/Settings/SecuritySettings.tsx"),
  "utf8",
);

test("security settings renders local identity fingerprint guidance without exporting private keys", () => {
  assert.match(securitySettings, /loadIdentity/);
  assert.match(securitySettings, /identity\.publicKey/);
  assert.match(securitySettings, /Local identity fingerprint/);
  assert.match(securitySettings, /Compare this fingerprint out-of-band with contacts\./);
  assert.match(securitySettings, /This only verifies\s+the key stored on this device\./);
  assert.doesNotMatch(securitySettings, /identity\.privateKey/);
  assert.doesNotMatch(securitySettings, /privateKey/);
});
