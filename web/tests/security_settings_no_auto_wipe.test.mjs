import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

test("security settings renders privacy and identity safety without automatic wipe API", async () => {
  const source = await readFile(new URL("../src/components/Settings/SecuritySettings.tsx", import.meta.url), "utf8");

  assert.doesNotMatch(source, /api\/settings|panic_wipe|getSettings|putSettings|autoWipe/);
  assert.match(source, /<PrivacySettings\s*\/>/);
  assert.match(source, /<SafetyQr/);
  assert.match(source, /inspectPeer/);
  assert.doesNotMatch(source, /if \(status\.kind === "error"\)\s*\{\s*return/);
});
