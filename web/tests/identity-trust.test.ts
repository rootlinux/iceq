import test from "node:test";
import assert from "node:assert/strict";
import "fake-indexeddb/auto";

import {
  clearAll,
  cryptoRecordKey,
  getActiveCryptoNamespace,
  setActiveCryptoNamespace,
  getSignalStore,
  savePeerTrust,
  type CryptoNamespace,
} from "../src/lib/indexeddb.ts";
import {
  decryptMessage,
  encryptMessage,
  encodeIdentityKeyForWire,
  generateIdentityKeyPair,
  generatePreKeyBundle,
  generateRegistrationId,
  restoreSignalIdentityPublicKey,
  restoreSignalPublicKey,
  saveOwnIdentity as persistOwnIdentity,
  verifySignedPreKeyBundle,
} from "../src/lib/signal.ts";
import { padPlaintext } from "../src/lib/messagePadding.ts";
import { PreKeyWhisperMessage } from "@privacyresearch/libsignal-protocol-protobuf-ts";
import {
  Direction,
  EncryptionResultMessageType,
  KeyHelper,
  SessionBuilder,
  SessionCipher,
  SignalProtocolAddress,
} from "@privacyresearch/libsignal-protocol-typescript";
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

// Must match STORE_PEER_IDENTITIES in indexeddb.ts. Duplicated here (not
// exported -- no production test hooks) so tests can seed pre-fix,
// legacy-shaped records directly: the fixed saveIdentity() always writes
// the canonical key now, so it can no longer be used to create the legacy
// state these migration tests need to start from.
const RAW_PEER_IDENTITIES_STORE = "identities";

async function makePeerDevice() {
  const identity = await KeyHelper.generateIdentityKeyPair();
  const signed = await KeyHelper.generateSignedPreKey(identity, 1);
  return {
    identityKey: identity.pubKey,
    signedPreKey: { keyId: signed.keyId, publicKey: signed.keyPair.pubKey, signature: signed.signature },
    registrationId: 12345,
  };
}

// Writes directly into the raw "identities" IndexedDB store, bypassing
// IndexedDBSignalProtocolStore entirely, to simulate a record left over
// from before identifiers were canonicalized.
async function seedRawPeerIdentity(ns: CryptoNamespace, rawIdentifier: string, publicKey: ArrayBuffer): Promise<void> {
  const db: IDBDatabase = await new Promise((resolve, reject) => {
    const req = indexedDB.open("iceq", 6); // DB_VERSION in indexeddb.ts
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
  await new Promise<void>((resolve, reject) => {
    const tx = db.transaction(RAW_PEER_IDENTITIES_STORE, "readwrite");
    tx.objectStore(RAW_PEER_IDENTITIES_STORE).put({ publicKey, firstSeenAt: Date.now() }, cryptoRecordKey(ns, "peer-identity", rawIdentifier));
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
  db.close();
}

async function readRawPeerIdentity(ns: CryptoNamespace, rawIdentifier: string): Promise<{ publicKey: ArrayBuffer } | undefined> {
  const db: IDBDatabase = await new Promise((resolve, reject) => {
    const req = indexedDB.open("iceq", 6);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
  const value = await new Promise<{ publicKey: ArrayBuffer } | undefined>((resolve, reject) => {
    const tx = db.transaction(RAW_PEER_IDENTITIES_STORE, "readonly");
    const req = tx.objectStore(RAW_PEER_IDENTITIES_STORE).get(cryptoRecordKey(ns, "peer-identity", rawIdentifier));
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
  db.close();
  return value;
}

// SessionCipher.encrypt()'s `body` is a "binary string" -- one JS string
// char per ciphertext byte -- so it has to be walked byte-by-byte rather
// than treated as UTF-16 text. Mirrors signal.ts's private
// binaryStringToArrayBuffer + arrayBufferToB64Url composition.
function cipherBodyToB64Url(body: string): string {
  const bytes = new Uint8Array(body.length);
  for (let i = 0; i < body.length; i++) bytes[i] = body.charCodeAt(i) & 0xff;
  return Buffer.from(bytes).toString("base64url");
}

// Mirrors signal.ts's private clearPendingPreKey patch. The privacyresearch
// port only clears session.pendingPreKey on the decrypt side, never on
// encrypt -- encryptMessage applies this fix-up after every real send. The
// tests below drive SessionCipher directly (to control exactly when a
// prekey vs. whisper message comes out), so they need the same patch.
async function clearPendingPreKeyForTest(store: ReturnType<typeof getSignalStore>, encodedAddress: string): Promise<void> {
  const raw = await store.loadSession(encodedAddress);
  if (!raw) return;
  const parsed = JSON.parse(raw) as { sessions?: Record<string, { pendingPreKey?: unknown }> };
  if (!parsed.sessions) return;
  for (const session of Object.values(parsed.sessions)) delete session.pendingPreKey;
  await store.storeSession(encodedAddress, JSON.stringify(parsed));
}

// Sets up two real, independent identities -- "me" (myUin/myDeviceId, the
// receiver under test) and a peer (peerUin/peerDeviceId) -- each with its
// own store, and drives the peer through a real X3DH
// SessionBuilder.processPreKey against my real advertised bundle. This is
// exactly what signal.ts's private seedSessionFromBundle does in
// production after fetching a bundle from the server; it's reproduced by
// hand here so these tests can drive a genuine inbound decrypt without
// mocking the network layer.
async function establishInboundSession(myUin: number, peerUin: number, myDeviceId: string, peerDeviceId: string) {
  const myNs: CryptoNamespace = { uin: myUin, deviceId: myDeviceId };
  const peerNs: CryptoNamespace = { uin: peerUin, deviceId: peerDeviceId };

  const myIdentity = await generateIdentityKeyPair();
  const myRegistrationId = generateRegistrationId();
  await persistOwnIdentity(myIdentity, myRegistrationId, myNs);
  const myBundle = await generatePreKeyBundle(myIdentity, 1, 1, myRegistrationId, myNs);

  const peerIdentity = await generateIdentityKeyPair();
  const peerRegistrationId = generateRegistrationId();
  await persistOwnIdentity(peerIdentity, peerRegistrationId, peerNs);
  const peerStore = getSignalStore(peerNs);

  await verifySignedPreKeyBundle(myBundle);
  const oneTimePreKey = myBundle.one_time_pre_keys[0]!;
  const myDeviceForPeer = {
    identityKey: restoreSignalIdentityPublicKey(myBundle.identity_key),
    signedPreKey: {
      keyId: myBundle.signed_pre_key.id,
      publicKey: restoreSignalPublicKey(myBundle.signed_pre_key.public_key),
      signature: Buffer.from(myBundle.signed_pre_key.signature, "base64url"),
    },
    preKey: { keyId: oneTimePreKey.id, publicKey: restoreSignalPublicKey(oneTimePreKey.public_key) },
    registrationId: myRegistrationId,
  };
  const myAddress = new SignalProtocolAddress(String(myUin), 1);
  await new SessionBuilder(peerStore, myAddress).processPreKey(myDeviceForPeer);

  return { myNs, peerNs, peerStore, peerIdentity, myAddress };
}

async function peerEncrypts(peerStore: ReturnType<typeof getSignalStore>, myAddress: InstanceType<typeof SignalProtocolAddress>, plaintext: string) {
  const cipher = new SessionCipher(peerStore, myAddress);
  const padded = padPlaintext(new TextEncoder().encode(plaintext));
  const buf = padded.buffer.slice(padded.byteOffset, padded.byteOffset + padded.byteLength);
  const result = await cipher.encrypt(buf);
  const msgType: "prekey_message" | "signal_message" =
    result.type === EncryptionResultMessageType.PreKeyWhisperMessage ? "prekey_message" : "signal_message";
  return { ciphertext: cipherBodyToB64Url(result.body), msgType };
}

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

test("SessionBuilder's real isTrustedIdentity/saveIdentity calls now agree and correctly reject a rotated identity", async () => {
  const own = await generateIdentityKeyPair();
  await persistOwnIdentity(own, 7, getActiveCryptoNamespace());
  const ns = getActiveCryptoNamespace();
  const store = getSignalStore(ns);

  // Mirrors signal.ts exactly: new SignalProtocolAddress(String(uin), 1).
  const remoteAddress = new SignalProtocolAddress("42", 1);
  assert.equal(remoteAddress.name, "42");
  assert.equal(remoteAddress.toString(), "42.1");

  const originalDevice = await makePeerDevice();
  const rotatedDevice = await makePeerDevice(); // fresh identity key: rotation or a MITM-supplied bundle

  await new SessionBuilder(store, remoteAddress).processPreKey(originalDevice);

  // Canonicalization makes isTrustedIdentity/saveIdentity agree now,
  // regardless of which string shape libsignal (or a direct caller) uses
  // to ask.
  assert.equal(await store.isTrustedIdentity(remoteAddress.toString(), originalDevice.identityKey, Direction.SENDING), true);
  assert.equal(await store.isTrustedIdentity(remoteAddress.name, originalDevice.identityKey, Direction.SENDING), true);
  assert.equal(await store.isTrustedIdentity(remoteAddress.toString(), rotatedDevice.identityKey, Direction.SENDING), false);
  assert.equal(await store.isTrustedIdentity(remoteAddress.name, rotatedDevice.identityKey, Direction.SENDING), false);

  // The fix's core promise: SessionBuilder's own internal check -- the one
  // the previous version of this test proved was silently inert -- now
  // actually rejects a second processPreKey() call for a rotated identity.
  await assert.rejects(() => new SessionBuilder(store, remoteAddress).processPreKey(rotatedDevice), /identity key changed/i);

  // The original identity is still the one on file; nothing was silently
  // replaced.
  assert.equal(await store.isTrustedIdentity(remoteAddress.name, originalDevice.identityKey, Direction.SENDING), true);
  assert.equal(await store.isTrustedIdentity(remoteAddress.name, rotatedDevice.identityKey, Direction.SENDING), false);
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

// ----------------------------------------------------------------------------
// Canonical identifier fix: saveIdentity/isTrustedIdentity/identity-change
// persistence/inbound trust checks must all agree on the same peer identity
// regardless of which string shape ("<uin>" vs "<uin>.<deviceId>") they're
// handed, must migrate/consolidate legacy records safely, and must fail
// closed on any unresolved ambiguity.
// ----------------------------------------------------------------------------

test("saveIdentity then isTrustedIdentity agree when called with the same identifier shape", async () => {
  const own = await generateIdentityKeyPair(); await persistOwnIdentity(own, 7, getActiveCryptoNamespace());
  const store = getSignalStore(getActiveCryptoNamespace());
  const key = new Uint8Array(33); key[0] = 5; key[1] = 1;

  await store.saveIdentity("42", key.buffer);
  assert.equal(await store.isTrustedIdentity("42", key.buffer, Direction.SENDING), true);

  await store.saveIdentity("42.1", key.buffer);
  assert.equal(await store.isTrustedIdentity("42.1", key.buffer, Direction.SENDING), true);
});

test("a qualified saveIdentity is visible to a bare isTrustedIdentity lookup", async () => {
  const own = await generateIdentityKeyPair(); await persistOwnIdentity(own, 7, getActiveCryptoNamespace());
  const store = getSignalStore(getActiveCryptoNamespace());
  const original = new Uint8Array(33); original[0] = 5; original[1] = 1;
  const rotated = new Uint8Array(33); rotated[0] = 5; rotated[1] = 2;

  await store.saveIdentity("42.1", original.buffer);
  assert.equal(await store.isTrustedIdentity("42", original.buffer, Direction.SENDING), true);
  assert.equal(await store.isTrustedIdentity("42", rotated.buffer, Direction.SENDING), false);
});

test("a bare saveIdentity is visible to a qualified isTrustedIdentity lookup", async () => {
  const own = await generateIdentityKeyPair(); await persistOwnIdentity(own, 7, getActiveCryptoNamespace());
  const store = getSignalStore(getActiveCryptoNamespace());
  const original = new Uint8Array(33); original[0] = 5; original[1] = 1;
  const rotated = new Uint8Array(33); rotated[0] = 5; rotated[1] = 2;

  await store.saveIdentity("42", original.buffer);
  assert.equal(await store.isTrustedIdentity("42.1", original.buffer, Direction.SENDING), true);
  assert.equal(await store.isTrustedIdentity("42.1", rotated.buffer, Direction.SENDING), false);
});

test("a legacy qualified-only record is treated as the peer's existing identity and consolidated onto the canonical key", async () => {
  const own = await generateIdentityKeyPair(); await persistOwnIdentity(own, 7, getActiveCryptoNamespace());
  const ns = getActiveCryptoNamespace();
  const store = getSignalStore(ns);
  const key = new Uint8Array(33); key[0] = 5; key[1] = 1;

  await seedRawPeerIdentity(ns, "42.1", key.buffer);
  assert.equal(await store.isTrustedIdentity("42", key.buffer, Direction.SENDING), true);

  // A write -- exactly like the library issues after every successful
  // trust check -- consolidates the legacy record onto the canonical key.
  assert.equal(await store.saveIdentity("42.1", key.buffer), true);

  assert.equal(await readRawPeerIdentity(ns, "42.1"), undefined);
  const canonical = await readRawPeerIdentity(ns, "42");
  assert.ok(canonical);
  assert.deepEqual(new Uint8Array(canonical!.publicKey), key);
});

test("identical legacy bare and qualified records consolidate onto the canonical key without changing the trusted key", async () => {
  const own = await generateIdentityKeyPair(); await persistOwnIdentity(own, 7, getActiveCryptoNamespace());
  const ns = getActiveCryptoNamespace();
  const store = getSignalStore(ns);
  const key = new Uint8Array(33); key[0] = 5; key[1] = 1;

  await seedRawPeerIdentity(ns, "42", key.buffer);
  await seedRawPeerIdentity(ns, "42.1", key.buffer);

  assert.equal(await store.isTrustedIdentity("42", key.buffer, Direction.SENDING), true);
  assert.equal(await store.saveIdentity("42.1", key.buffer), true);

  assert.equal(await readRawPeerIdentity(ns, "42.1"), undefined);
  assert.ok(await readRawPeerIdentity(ns, "42"));

  const rotated = new Uint8Array(33); rotated[0] = 5; rotated[1] = 9;
  assert.equal(await store.isTrustedIdentity("42", rotated.buffer, Direction.SENDING), false);
});

test("conflicting legacy bare and qualified records fail closed and surface as a pending identity change", async () => {
  const own = await generateIdentityKeyPair(); await persistOwnIdentity(own, 7, getActiveCryptoNamespace());
  const ns = getActiveCryptoNamespace();
  const store = getSignalStore(ns);
  const bareKey = new Uint8Array(33); bareKey[0] = 5; bareKey[1] = 1;
  const qualifiedKey = new Uint8Array(33); qualifiedKey[0] = 5; qualifiedKey[1] = 2;

  await seedRawPeerIdentity(ns, "42", bareKey.buffer);
  await seedRawPeerIdentity(ns, "42.1", qualifiedKey.buffer);

  // Never silently prefer one side, regardless of which key the incoming
  // message happens to match.
  assert.equal(await store.isTrustedIdentity("42", bareKey.buffer, Direction.SENDING), false);
  assert.equal(await store.isTrustedIdentity("42", qualifiedKey.buffer, Direction.SENDING), false);
  assert.equal(await store.saveIdentity("42.1", qualifiedKey.buffer), false);
  assert.equal(await store.saveIdentity("42", bareKey.buffer), false);

  // Neither record was touched.
  const stillBare = await readRawPeerIdentity(ns, "42");
  const stillQualified = await readRawPeerIdentity(ns, "42.1");
  assert.deepEqual(new Uint8Array(stillBare!.publicKey), bareKey);
  assert.deepEqual(new Uint8Array(stillQualified!.publicKey), qualifiedKey);

  // Surfaced through the existing verification flow, not a bespoke state.
  const trust = await getPeerTrust(42, ns);
  assert.equal(trust?.pendingFingerprint, encodeIdentityKeyForWire(qualifiedKey));
  assert.equal(await isPeerSendAllowed(42, ns), false);
});

test("repeated saves after legacy consolidation are idempotent", async () => {
  const own = await generateIdentityKeyPair(); await persistOwnIdentity(own, 7, getActiveCryptoNamespace());
  const ns = getActiveCryptoNamespace();
  const store = getSignalStore(ns);
  const key = new Uint8Array(33); key[0] = 5; key[1] = 1;

  await seedRawPeerIdentity(ns, "42.1", key.buffer);

  for (let i = 0; i < 3; i++) {
    assert.equal(await store.saveIdentity("42.1", key.buffer), true);
    assert.equal(await store.isTrustedIdentity("42", key.buffer, Direction.SENDING), true);
    assert.equal(await readRawPeerIdentity(ns, "42.1"), undefined);
    const canonical = await readRawPeerIdentity(ns, "42");
    assert.deepEqual(new Uint8Array(canonical!.publicKey), key);
  }
});

test("a fresh store instance against the same IndexedDB state still trusts a previously-saved identity (reload)", async () => {
  const own = await generateIdentityKeyPair(); await persistOwnIdentity(own, 7, getActiveCryptoNamespace());
  const ns = getActiveCryptoNamespace();
  const key = new Uint8Array(33); key[0] = 5; key[1] = 1;
  const rotated = new Uint8Array(33); rotated[0] = 5; rotated[1] = 9;

  const firstInstance = getSignalStore(ns);
  await firstInstance.saveIdentity("42.1", key.buffer);

  // A page reload has no in-memory state to carry over -- the store is
  // fully stateless (every read/write goes through IndexedDB), so a fresh
  // instance is the faithful way to simulate this.
  const reloadedInstance = getSignalStore(ns);
  assert.equal(await reloadedInstance.isTrustedIdentity("42", key.buffer, Direction.SENDING), true);
  assert.equal(await reloadedInstance.isTrustedIdentity("42.1", key.buffer, Direction.SENDING), true);
  assert.equal(await reloadedInstance.isTrustedIdentity("42", rotated.buffer, Direction.SENDING), false);
});

test("a peer identity saved under one account namespace is not visible under a different account namespace", async () => {
  const ownA = await generateIdentityKeyPair(); const nsA: CryptoNamespace = { uin: 7, deviceId: "device-account-a" };
  await persistOwnIdentity(ownA, 7, nsA);
  const ownB = await generateIdentityKeyPair(); const nsB: CryptoNamespace = { uin: 99, deviceId: "device-account-b" };
  await persistOwnIdentity(ownB, 99, nsB);

  const keyA = new Uint8Array(33); keyA[0] = 5; keyA[1] = 1;
  const storeA = getSignalStore(nsA);
  await storeA.saveIdentity("42.1", keyA.buffer);

  // Same peer uin (42) under a different account namespace: B has never
  // seen this peer, regardless of what A already pinned -- first sighting,
  // free to pin a completely different key without any cross-account
  // interference.
  const keyB = new Uint8Array(33); keyB[0] = 5; keyB[1] = 200;
  const storeB = getSignalStore(nsB);
  assert.equal(await storeB.isTrustedIdentity("42", keyB.buffer, Direction.SENDING), true);
  assert.equal(await storeB.saveIdentity("42.1", keyB.buffer), true);
  assert.equal(await storeB.isTrustedIdentity("42", keyB.buffer, Direction.SENDING), true);
  assert.equal(await storeB.isTrustedIdentity("42", keyA.buffer, Direction.SENDING), false); // B never saw A's key

  // A's own state is completely untouched.
  assert.equal(await storeA.isTrustedIdentity("42", keyA.buffer, Direction.SENDING), true);
  assert.equal(await storeA.isTrustedIdentity("42", keyB.buffer, Direction.SENDING), false);
});

test("a recovery-imported peer trust record does not block or replace a fresh TOFU pin in the raw store", async () => {
  const ns = getActiveCryptoNamespace();
  const { myAddress, peerStore, peerIdentity } = await establishInboundSession(ns.uin, 42, ns.deviceId, "identity-test-peer-device");

  // Recovery restores STORE_IDENTITY (already done above, inside
  // establishInboundSession) and STORE_PEER_TRUST, but deliberately does
  // not restore the raw STORE_PEER_IDENTITIES pins (see
  // recoveryPackage.ts) -- simulate that asymmetric post-recovery state
  // directly via the real exported savePeerTrust, since this state IS
  // meant to be reached through the public API.
  const peerFingerprint = encodeIdentityKeyForWire(peerIdentity.publicKey);
  await savePeerTrust({ version: 1, peerUin: 42, fingerprint: peerFingerprint, verified: true, firstSeenAt: Date.now(), updatedAt: Date.now() }, ns);

  const { ciphertext, msgType } = await peerEncrypts(peerStore, myAddress, "hello after recovery");
  const plaintext = await decryptMessage(42, ciphertext, msgType, ns);
  assert.equal(new TextDecoder().decode(plaintext), "hello after recovery");

  // The raw store's own pin is independent of STORE_PEER_TRUST -- it
  // started fresh (first sighting) despite peer trust already "knowing"
  // this peer, and correctly picked up the real identity from the decrypt.
  const store = getSignalStore(ns);
  const peerKeyBuffer = peerIdentity.publicKey.buffer;
  assert.equal(await store.isTrustedIdentity("42", peerKeyBuffer, Direction.SENDING), true);
});

test("a real end-to-end prekey message is decrypted and the sender's identity is pinned under the canonical key", async () => {
  const ns = getActiveCryptoNamespace();
  const { myAddress, peerStore, peerIdentity } = await establishInboundSession(ns.uin, 42, ns.deviceId, "identity-test-peer-device");

  const { ciphertext, msgType } = await peerEncrypts(peerStore, myAddress, "first contact");
  assert.equal(msgType, "prekey_message");

  const plaintext = await decryptMessage(42, ciphertext, msgType, ns);
  assert.equal(new TextDecoder().decode(plaintext), "first contact");

  // Pinned under the canonical (bare-uin) key, and visible to both the
  // shape isTrustedIdentity actually receives (bare) and the qualified
  // shape saveIdentity receives.
  const store = getSignalStore(ns);
  const peerKeyBuffer = peerIdentity.publicKey.buffer;
  assert.equal(await store.isTrustedIdentity("42", peerKeyBuffer, Direction.SENDING), true);
  assert.equal(await store.isTrustedIdentity("42.1", peerKeyBuffer, Direction.SENDING), true);
});

test("a real end-to-end continued-ratchet message is decrypted after the first prekey message", async () => {
  const ns = getActiveCryptoNamespace();
  const { myAddress, peerStore } = await establishInboundSession(ns.uin, 42, ns.deviceId, "identity-test-peer-device");

  const firstMessage = await peerEncrypts(peerStore, myAddress, "first contact");
  assert.equal(firstMessage.msgType, "prekey_message");
  assert.equal(new TextDecoder().decode(await decryptMessage(42, firstMessage.ciphertext, firstMessage.msgType, ns)), "first contact");

  await clearPendingPreKeyForTest(peerStore, myAddress.toString());

  const secondMessage = await peerEncrypts(peerStore, myAddress, "continued ratchet");
  assert.equal(secondMessage.msgType, "signal_message");
  assert.equal(new TextDecoder().decode(await decryptMessage(42, secondMessage.ciphertext, secondMessage.msgType, ns)), "continued ratchet");
});

test("a rotated identity is rejected before any session state is persisted, and the established session is untouched", async () => {
  const ns = getActiveCryptoNamespace();
  const { myAddress, peerStore } = await establishInboundSession(ns.uin, 42, ns.deviceId, "identity-test-peer-device");

  const firstMessage = await peerEncrypts(peerStore, myAddress, "first contact");
  assert.equal(new TextDecoder().decode(await decryptMessage(42, firstMessage.ciphertext, firstMessage.msgType, ns)), "first contact");

  const store = getSignalStore(ns);
  // The session on MY side is keyed by the PEER's address (42.1), not by
  // myAddress (7.1, which is what the peer's own store uses to address ME
  // -- see peerEncrypts() above). Mirrors decryptMessage()'s own
  // `new SignalProtocolAddress(String(senderUin), 1)` construction.
  const sessionBefore = await store.loadSession("42.1");
  assert.ok(sessionBefore);

  // The peer's identity changes mid-conversation -- e.g. a reinstall or a
  // MITM presenting a fresh bundle -- and a new prekey message arrives
  // claiming to be the same peer.
  const rotatedIdentity = new Uint8Array(33); rotatedIdentity[0] = 5; rotatedIdentity[1] = 250;
  const proto = PreKeyWhisperMessage.encode({
    identityKey: rotatedIdentity, registrationId: 42, preKeyId: 1, signedPreKeyId: 1,
    baseKey: new Uint8Array(33), message: new Uint8Array([0x33]),
  }).finish();
  const wire = new Uint8Array(proto.length + 1); wire[0] = 0x33; wire.set(proto, 1);
  const encoded = Buffer.from(wire).toString("base64url");

  await assert.rejects(() => decryptMessage(42, encoded, "prekey_message", ns), /identity changed/i);

  // No plaintext was returned (the rejects() above already proves that --
  // decryptMessage never resolves on a mismatch). The real, established
  // session from the first message is byte-for-byte unchanged:
  // assertInboundIdentityTrusted throws before the library is even
  // called, so storeSession() is never reached for this attempt (verified
  // directly against session-cipher.js/session-builder.js source).
  const sessionAfter = await store.loadSession("42.1");
  assert.equal(sessionAfter, sessionBefore);

  // The send path independently reaches the same conclusion through the
  // existing verification flow -- not a bespoke, one-off state.
  assert.equal(await isPeerSendAllowed(42, ns), false);
});
