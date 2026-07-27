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
const englishCatalog = readFileSync(resolve(__dirname, "../src/i18n/en.ts"), "utf8");

test("security settings renders local identity fingerprint guidance without exporting private keys", () => {
  assert.match(securitySettings, /loadIdentity/);
  assert.match(securitySettings, /identity\.publicKey/);
  assert.match(securitySettings, /security\.localFingerprint/);
  assert.match(securitySettings, /security\.fingerprintHelp/);
  assert.match(englishCatalog, /Local identity fingerprint/);
  assert.match(englishCatalog, /Compare this fingerprint out-of-band with contacts\./);
  assert.match(englishCatalog, /This only verifies the key stored on this device\./);
  assert.doesNotMatch(securitySettings, /identity\.privateKey/);
  assert.doesNotMatch(securitySettings, /\.privateKey/);
});
