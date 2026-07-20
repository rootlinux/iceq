import test from "node:test";
import assert from "node:assert/strict";

import { ApiError } from "../src/api/client.js";
import { ensureOwnBundle, ensureSignalProvisioning } from "../src/lib/signalBootstrap.js";

test("ensureOwnBundle does nothing when the remote bundle already exists", async () => {
  let uploaded = false;

  const result = await ensureOwnBundle(42, {
    fetchBundle: async () => ({
      identity_key: "identity",
      signed_pre_key: { id: 1, public_key: "spk", signature: "sig" },
      registration_id: 7,
    }),
    loadIdentity: async () => ({publicKey:"identity",privateKey:"private",registrationId:7}),
    deriveStoredPublic:async()=>"identity",
    restoreIdentity: () => ({publicKey:new Uint8Array(),privateKey:new Uint8Array(),registrationId:7}),
    generatePreKeyBundle: async () => {
      throw new Error("generatePreKeyBundle should not be called");
    },
    uploadBundle: async () => {
      uploaded = true;
    },
  });

  assert.equal(result, "ok");
  assert.equal(uploaded, false);
});

test("ensureOwnBundle reconciles legacy crypto even when a scoped identity already exists", async () => {
  const identity={publicKey:"identity",privateKey:"private",registrationId:7};
  let migrated=false;

  const result=await ensureOwnBundle(42,{
    fetchBundle:async()=>({identity_key:"identity",signed_pre_key:{id:1,public_key:"spk",signature:"sig"},registration_id:7}),
    loadIdentity:async()=>identity,
    migrateLegacyIdentity:async()=>{migrated=true;return identity;},
    deriveStoredPublic:async()=>"identity",
    restoreIdentity:()=>({publicKey:new Uint8Array(),privateKey:new Uint8Array(),registrationId:7}),
    generatePreKeyBundle:async()=>{throw new Error("generatePreKeyBundle should not be called");},
    uploadBundle:async()=>{throw new Error("uploadBundle should not be called");},
  });

  assert.equal(result,"ok");
  assert.equal(migrated,true);
});

test("ensureOwnBundle repairs a missing remote bundle when local identity exists", async () => {
  let uploaded = false;

  const result = await ensureOwnBundle(42, {
    fetchBundle: async () => {
      throw new ApiError("404 Not Found", 404, "BUNDLE_NOT_FOUND");
    },
    loadIdentity: async () => ({
      publicKey: "pub",
      privateKey: "priv",
      registrationId: 77,
    }),
    restoreIdentity: (stored) => ({
      publicKey: new Uint8Array([5, 1, 2]),
      privateKey: new Uint8Array([3, 4]),
      registrationId: stored.registrationId,
    }),
    generatePreKeyBundle: async (_identity, _start, _count, registrationId) => ({
      identity_key: "identity",
      signed_pre_key: { id: 9, public_key: "spk", signature: "sig" },
      one_time_pre_keys: [{ id: 10, public_key: "otpk" }],
      registration_id: registrationId,
    }),
    uploadBundle: async (bundle) => {
      uploaded = true;
      assert.equal(bundle.registration_id, 77);
      assert.equal(bundle.identity_key, "identity");
    },
  });

  assert.equal(result, "repaired");
  assert.equal(uploaded, true);
});

test("ensureOwnBundle fails with a clear error when the remote bundle is missing and this device has no local identity", async () => {
  await assert.rejects(
    ensureOwnBundle(42, {
      fetchBundle: async () => {
        throw new ApiError("404 Not Found", 404, "BUNDLE_NOT_FOUND");
      },
      loadIdentity: async () => null,
      restoreIdentity: () => {
        throw new Error("restoreIdentity should not be called");
      },
      generatePreKeyBundle: async () => {
        throw new Error("generatePreKeyBundle should not be called");
      },
      uploadBundle: async () => {
        throw new Error("uploadBundle should not be called");
      },
    }),
    /missing this device's IceQ encryption keys/i,
  );
});

test("ensureSignalProvisioning leaves healthy server-side prekey pools alone", async () => {
  let generated = false;
  let uploaded = false;

  const result = await ensureSignalProvisioning(42, {
    fetchBundle: async () => ({
      identity_key: "identity",
      signed_pre_key: { id: 1, public_key: "spk", signature: "sig" },
      registration_id: 7,
    }),
    loadIdentity: async () => ({publicKey:"identity",privateKey:"private",registrationId:7}),
    deriveStoredPublic:async()=>"identity",
    restoreIdentity: () => ({publicKey:new Uint8Array(),privateKey:new Uint8Array(),registrationId:7}),
    generatePreKeyBundle: async () => {
      throw new Error("generatePreKeyBundle should not be called");
    },
    uploadBundle: async () => {
      throw new Error("uploadBundle should not be called");
    },
    getPrekeyCount: async () => 12,
    loadNextPreKeyId: async () => 22,
    saveNextPreKeyId: async () => {
      throw new Error("saveNextPreKeyId should not be called");
    },
    generateOneTimePreKeys: async () => {
      generated = true;
      return [];
    },
    addPreKeys: async () => {
      uploaded = true;
      return { accepted: 0 };
    },
  });

  assert.deepEqual(result, { bundle: "ok", replenished: false, prekeyCount: 12 });
  assert.equal(generated, false);
  assert.equal(uploaded, false);
});

test("ensureSignalProvisioning tops up low server-side prekey pools with monotonic ids", async () => {
  const savedCursors: number[] = [];
  let generatedStart = 0;
  let generatedCount = 0;
  let uploadedIds: number[] = [];

  const result = await ensureSignalProvisioning(42, {
    fetchBundle: async () => ({
      identity_key: "identity",
      signed_pre_key: { id: 1, public_key: "spk", signature: "sig" },
      registration_id: 7,
    }),
    loadIdentity: async () => ({publicKey:"identity",privateKey:"private",registrationId:7}),
    deriveStoredPublic:async()=>"identity",
    restoreIdentity: () => ({publicKey:new Uint8Array(),privateKey:new Uint8Array(),registrationId:7}),
    generatePreKeyBundle: async () => {
      throw new Error("generatePreKeyBundle should not be called");
    },
    uploadBundle: async () => {
      throw new Error("uploadBundle should not be called");
    },
    getPrekeyCount: async () => 3,
    loadNextPreKeyId: async () => null,
    saveNextPreKeyId: async (id) => {
      savedCursors.push(id);
    },
    generateOneTimePreKeys: async (startId, count) => {
      generatedStart = startId;
      generatedCount = count;
      return Array.from({ length: count }, (_, i) => ({ id: startId + i, public_key: `pk-${startId + i}` }));
    },
    addPreKeys: async (prekeys) => {
      uploadedIds = prekeys.map((p) => p.id);
      return { accepted: prekeys.length };
    },
  });

  assert.equal(generatedStart, 22);
  assert.equal(generatedCount, 17);
  assert.deepEqual(savedCursors, [39]);
  assert.deepEqual(uploadedIds, Array.from({ length: 17 }, (_, i) => 22 + i));
  assert.deepEqual(result, { bundle: "ok", replenished: true, prekeyCount: 20 });
});
