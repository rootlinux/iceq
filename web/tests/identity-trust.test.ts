import test from "node:test";
import assert from "node:assert/strict";
import "fake-indexeddb/auto";

import { clearAll } from "../src/lib/indexeddb.ts";
import {
  acceptPeerIdentity,
  assessPeerIdentity,
  getPeerTrust,
  isPeerSendAllowed,
  verifyPeerIdentity,
} from "../src/lib/identityTrust.ts";
import { createSafetyQrPayload, parseSafetyQrPayload } from "../src/components/Settings/SafetyQr.tsx";

const first = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const changed = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";

test.beforeEach(async () => clearAll());

test("TOFU pins public fingerprint and unchanged identity remains trusted", async () => {
  assert.equal((await assessPeerIdentity(42, first)).status, "trusted");
  assert.equal((await assessPeerIdentity(42, first)).status, "trusted");
  const stored = await getPeerTrust(42);
  assert.equal(stored?.fingerprint, first);
  assert.equal("privateKey" in (stored ?? {}), false);
});

test("changed identity blocks until explicit acceptance and can be verified", async () => {
  await assessPeerIdentity(42, first);
  const warning = await assessPeerIdentity(42, changed);
  assert.equal(warning.status, "changed");
  assert.equal(warning.sendAllowed, false);
  assert.equal(await isPeerSendAllowed(42), false);
  assert.equal((await getPeerTrust(42))?.pendingFingerprint, changed);

  await acceptPeerIdentity(42, changed);
  assert.equal((await assessPeerIdentity(42, changed)).sendAllowed, true);
  await verifyPeerIdentity(42, changed);
  assert.equal((await getPeerTrust(42))?.verified, true);
});

test("safety QR contains only version and canonical public fingerprint", () => {
  const raw = createSafetyQrPayload("12345 67890");
  assert.deepEqual(parseSafetyQrPayload(raw), { version: 1, fingerprint: "1234567890" });
  assert.deepEqual(Object.keys(JSON.parse(raw)).sort(), ["fingerprint", "version"]);
  assert.throws(() => parseSafetyQrPayload('{"version":1,"fingerprint":"123","token":"secret"}'));
});
