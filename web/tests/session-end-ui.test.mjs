import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

test("cleanup failures render a persistent accessible retry surface with localized safe copy", async () => {
  const app = await readFile(new URL("../src/App.tsx", import.meta.url), "utf8");
  const en = await readFile(new URL("../src/i18n/en.ts", import.meta.url), "utf8");
  const tr = await readFile(new URL("../src/i18n/tr.ts", import.meta.url), "utf8");
  assert.match(app, /iceq:local-cleanup-failed/);
  assert.match(app, /role="alert"/);
  assert.match(app, /cleanup\.retry/);
  assert.match(app, /retryLocalCleanup/);
  assert.match(app, /ICEQ_CLEANUP_REQUIRED_MARKER_KEY/);
  assert.doesNotMatch(app, /clearAllIceQLocalData/);
  for (const source of [en, tr]) {
    assert.match(source, /"cleanup\.failed"/);
    assert.match(source, /"cleanup\.retry"/);
  }
});

test("security settings exposes authenticated panic wipe behind strong confirmation", async () => {
  const source = await readFile(new URL("../src/components/Settings/SecuritySettings.tsx", import.meta.url), "utf8");
  assert.match(source, /panicWipe/);
  assert.match(source, /window\.confirm/);
  assert.match(source, /security\.panicWipeConfirm/);
});

test("WebSocket 4403 delegates to the auth lifecycle without replaying the panic API", async () => {
  const source = await readFile(new URL("../src/hooks/useWebSocket.ts", import.meta.url), "utf8");
  assert.match(source, /handleServerWipe\(\)/);
  assert.doesNotMatch(source, /clearLocalState\(\)/);
  assert.doesNotMatch(source, /panicWipe\(\)/);
});
