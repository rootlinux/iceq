import test from "node:test";
import assert from "node:assert/strict";
import "fake-indexeddb/auto";

import {
  clearAll,
  saveIdentity,
  savePeerTrust,
  setActiveCryptoNamespace,
  type CryptoNamespace,
} from "../src/lib/indexeddb.ts";
import { assessPeerIdentity } from "../src/lib/identityTrust.ts";
import {
  inspectPeerSafety,
  PEER_SAFETY_LOCAL_IDENTITY_UNAVAILABLE,
  type InspectPeerSafetyDeps,
} from "../src/lib/peerSafetyInspection.ts";

const ns: CryptoNamespace = { uin: 7, deviceId: "peer-safety-test-device" };
const localIdentity = {
  publicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
  privateKey: "private",
  registrationId: 1,
};
const peerKeyOne = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";
const peerKeyTwo = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI";

function bundle(identityKey: string) {
  return {
    identity_key: identityKey,
    signed_pre_key: { id: 1, public_key: "spk", signature: "sig" },
    registration_id: 1,
  };
}

function deps(identityKey: string): InspectPeerSafetyDeps {
  return {
    loadIdentity: async () => localIdentity,
    fetchBundle: async () => bundle(identityKey),
    verifySignedPreKeyBundle: async () => true,
    assessPeerIdentity,
    computeSafetyNumber: async (a, b) => `${a.uin}:${b.uin}`,
  };
}

test.beforeEach(async () => {
  await clearAll();
  setActiveCryptoNamespace(ns);
  await saveIdentity(ns, localIdentity);
});

test("first contact is trusted and not yet verified", async () => {
  const result = await inspectPeerSafety(7, 42, ns, deps(peerKeyOne));
  assert.equal(result.changed, false);
  assert.equal(result.verified, false);
});

test("changed identity is surfaced and blocks the verified flag", async () => {
  await assessPeerIdentity(42, peerKeyOne, ns);
  const result = await inspectPeerSafety(7, 42, ns, deps(peerKeyTwo));
  assert.equal(result.changed, true);
  assert.equal(result.verified, false);
});

test("a stale verified flag does not survive a key change that was never re-verified", async () => {
  // Pin, mark verified, then the peer's key changes server-side --
  // the exact staleness scenario a separate, non-live-checked
  // verification store would get wrong.
  await assessPeerIdentity(42, peerKeyOne, ns);
  await savePeerTrust(
    { version: 1, peerUin: 42, fingerprint: peerKeyOne, verified: true, firstSeenAt: 1, updatedAt: 1 },
    ns,
  );
  const result = await inspectPeerSafety(7, 42, ns, deps(peerKeyTwo));
  assert.equal(result.verified, false, "a stale verified:true must not survive a fingerprint change");
  assert.equal(result.changed, true);
});

test("a verified record for the current key reads as verified", async () => {
  await assessPeerIdentity(42, peerKeyOne, ns);
  await savePeerTrust(
    { version: 1, peerUin: 42, fingerprint: peerKeyOne, verified: true, firstSeenAt: 1, updatedAt: 1 },
    ns,
  );
  const result = await inspectPeerSafety(7, 42, ns, deps(peerKeyOne));
  assert.equal(result.verified, true);
  assert.equal(result.changed, false);
});

test("throws a distinguishable error when no local identity exists yet", async () => {
  await assert.rejects(
    () => inspectPeerSafety(7, 42, ns, { ...deps(peerKeyOne), loadIdentity: async () => null }),
    (error: Error) => error.message === PEER_SAFETY_LOCAL_IDENTITY_UNAVAILABLE,
  );
});
