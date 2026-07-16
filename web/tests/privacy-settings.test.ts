import assert from "node:assert/strict";
import test from "node:test";
import { defaultPrivacySettings, permitsPrivacySignal, shouldProcessPrivacyEnvelope } from "../src/lib/privacySettings.ts";

test("privacy signals have independent conservative defaults", () => {
  assert.deepEqual(defaultPrivacySettings, { presence: false, typing: false, deliveryReceipts: true, readReceipts: false });
  assert.equal(permitsPrivacySignal("typing", { ...defaultPrivacySettings, typing: false, presence: true }), false);
  assert.equal(permitsPrivacySignal("presence", { ...defaultPrivacySettings, typing: true, presence: false }), false);
  assert.equal(permitsPrivacySignal("deliveryReceipts", defaultPrivacySettings), true);
  assert.equal(permitsPrivacySignal("readReceipts", defaultPrivacySettings), false);
});

test("disabled privacy signals are neither sent nor processed independently",()=>{
	const allOff={presence:false,typing:false,deliveryReceipts:false,readReceipts:false};
	assert.equal(shouldProcessPrivacyEnvelope("presence",undefined,allOff),false);
	assert.equal(shouldProcessPrivacyEnvelope("typing",undefined,allOff),false);
	assert.equal(shouldProcessPrivacyEnvelope("ack","delivered",allOff),false);
	assert.equal(shouldProcessPrivacyEnvelope("ack","read",allOff),false);
	assert.equal(shouldProcessPrivacyEnvelope("ack","persisted",allOff),true);
	assert.equal(shouldProcessPrivacyEnvelope("message",undefined,allOff),true);
});
