import test from "node:test";
import assert from "node:assert/strict";
import "fake-indexeddb/auto";

import { clearAll, getActiveCryptoNamespace, setActiveCryptoNamespace } from "../src/lib/indexeddb.ts";
import { getSignalStore } from "../src/lib/indexeddb.ts";
import { encryptMessage, generateIdentityKeyPair, saveOwnIdentity as persistOwnIdentity } from "../src/lib/signal.ts";
import { decryptMessage } from "../src/lib/signal.ts";
import { PreKeyWhisperMessage } from "@privacyresearch/libsignal-protocol-protobuf-ts";
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

test.beforeEach(async () => { await clearAll(); setActiveCryptoNamespace({ uin: 7, deviceId: "identity-test-device" }); });

test("TOFU pins public fingerprint and unchanged identity remains trusted", async () => {
  assert.equal((await assessPeerIdentity(42, first,getActiveCryptoNamespace())).status, "trusted");
  assert.equal((await assessPeerIdentity(42, first,getActiveCryptoNamespace())).status, "trusted");
  const stored = await getPeerTrust(42,getActiveCryptoNamespace());
  assert.equal(stored?.fingerprint, first);
  assert.equal("privateKey" in (stored ?? {}), false);
});

test("changed identity blocks until explicit acceptance and can be verified", async () => {
  await assessPeerIdentity(42, first,getActiveCryptoNamespace());
  const warning = await assessPeerIdentity(42, changed,getActiveCryptoNamespace());
  assert.equal(warning.status, "changed");
  assert.equal(warning.sendAllowed, false);
  assert.equal(await isPeerSendAllowed(42,getActiveCryptoNamespace()), false);
  assert.equal((await getPeerTrust(42,getActiveCryptoNamespace()))?.pendingFingerprint, changed);

  await acceptPeerIdentity(42, changed,getActiveCryptoNamespace());
  assert.equal((await assessPeerIdentity(42, changed,getActiveCryptoNamespace())).sendAllowed, true);
  await verifyPeerIdentity(42, changed,getActiveCryptoNamespace());
  assert.equal((await getPeerTrust(42,getActiveCryptoNamespace()))?.verified, true);
});

test("safety QR contains only version and canonical public fingerprint", () => {
  const raw = createSafetyQrPayload("12345 67890");
  assert.deepEqual(parseSafetyQrPayload(raw), { version: 1, fingerprint: "1234567890" });
  assert.deepEqual(Object.keys(JSON.parse(raw)).sort(), ["fingerprint", "version"]);
  assert.throws(() => parseSafetyQrPayload('{"version":1,"fingerprint":"123","token":"secret"}'));
});

test("inbound libsignal identity rotation durably blocks subsequent encryption", async () => {
  const own = await generateIdentityKeyPair();
  await persistOwnIdentity(own, 7, getActiveCryptoNamespace());
  const store = getSignalStore(getActiveCryptoNamespace());
  const oldKey = new Uint8Array(33); oldKey[0] = 5;
  const newKey = new Uint8Array(33); newKey[0] = 5; newKey[1] = 9;
  await store.saveIdentity("42.1", oldKey.buffer);
  await assessPeerIdentity(42, first,getActiveCryptoNamespace());

  assert.equal(await store.isTrustedIdentity("42.1", newKey.buffer, 1), false);
  assert.equal(await isPeerSendAllowed(42,getActiveCryptoNamespace()), false);
  await assert.rejects(() => encryptMessage(42, new TextEncoder().encode("blocked"),getActiveCryptoNamespace()), /identity changed/i);
});

test("real inbound prekey decrypt rejects rotated identity before libsignal processing", async () => {
  const own = await generateIdentityKeyPair(); await persistOwnIdentity(own, 7, getActiveCryptoNamespace());
  const store = getSignalStore(getActiveCryptoNamespace());
  const oldKey = new Uint8Array(33); oldKey[0] = 5;
  const rotated = new Uint8Array(33); rotated[0] = 5; rotated[1] = 7;
  await store.saveIdentity("42.1", oldKey.buffer);
  const proto = PreKeyWhisperMessage.encode({
    identityKey: rotated, registrationId: 42, preKeyId: 1, signedPreKeyId: 1,
    baseKey: new Uint8Array(33), message: new Uint8Array([0x33]),
  }).finish();
  const wire = new Uint8Array(proto.length + 1); wire[0] = 0x33; wire.set(proto, 1);
  const encoded = Buffer.from(wire).toString("base64url");
  await assert.rejects(() => decryptMessage(42, encoded, "prekey_message",getActiveCryptoNamespace()), /identity changed/i);
  assert.equal(await isPeerSendAllowed(42,getActiveCryptoNamespace()), false);
});

test("inbound prekey compares against durable peer trust even before a Signal session exists", async () => {
  const own = await generateIdentityKeyPair(); await persistOwnIdentity(own, 7, getActiveCryptoNamespace());
  await assessPeerIdentity(42, first,getActiveCryptoNamespace());
  const rotated = new Uint8Array(33); rotated[0] = 5; rotated[1] = 7;
  const proto = PreKeyWhisperMessage.encode({ identityKey: rotated, registrationId: 42, preKeyId: 1, signedPreKeyId: 1, baseKey: new Uint8Array(33), message: new Uint8Array([0x33]) }).finish();
  const wire = new Uint8Array(proto.length + 1); wire[0] = 0x33; wire.set(proto, 1);
  await assert.rejects(() => decryptMessage(42, Buffer.from(wire).toString("base64url"), "prekey_message",getActiveCryptoNamespace()), /identity changed/i);
});

test("acceptance rejects a fingerprint that is not the current pending identity", async () => {
  await assessPeerIdentity(42, first,getActiveCryptoNamespace()); await assessPeerIdentity(42, changed,getActiveCryptoNamespace());
  await assert.rejects(() => acceptPeerIdentity(42, first,getActiveCryptoNamespace()), /pending identity/i);
  assert.equal(await isPeerSendAllowed(42,getActiveCryptoNamespace()), false);
});

test("failed identity-state cleanup aborts acceptance without unblocking sends", async () => {
  await assessPeerIdentity(42, first,getActiveCryptoNamespace()); await assessPeerIdentity(42, changed,getActiveCryptoNamespace());
  const originalDelete = IDBObjectStore.prototype.delete;
  IDBObjectStore.prototype.delete = function (): IDBRequest<undefined> { throw new Error("forced cleanup failure"); };
  try {
    await assert.rejects(() => acceptPeerIdentity(42, changed,getActiveCryptoNamespace()), /forced cleanup failure/i);
  } finally { IDBObjectStore.prototype.delete = originalDelete; }
  assert.equal(await isPeerSendAllowed(42,getActiveCryptoNamespace()), false);
  assert.equal((await getPeerTrust(42,getActiveCryptoNamespace()))?.fingerprint, first);
});
