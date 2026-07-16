import assert from "node:assert/strict";
import test from "node:test";
import { defaultPrivacySettings, permitsPrivacySignal } from "../src/lib/privacySettings.ts";

test("privacy signals have independent conservative defaults", () => {
  assert.deepEqual(defaultPrivacySettings, { presence: false, typing: false, deliveryReceipts: true, readReceipts: false });
  assert.equal(permitsPrivacySignal("typing", { ...defaultPrivacySettings, typing: false, presence: true }), false);
  assert.equal(permitsPrivacySignal("presence", { ...defaultPrivacySettings, typing: true, presence: false }), false);
  assert.equal(permitsPrivacySignal("deliveryReceipts", defaultPrivacySettings), true);
  assert.equal(permitsPrivacySignal("readReceipts", defaultPrivacySettings), false);
});
