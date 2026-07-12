import test from "node:test";
import assert from "node:assert/strict";

import { ApiError } from "../src/api/client.js";
import { ensureOwnBundle } from "../src/lib/signalBootstrap.js";

test("ensureOwnBundle does nothing when the remote bundle already exists", async () => {
  let uploaded = false;

  const result = await ensureOwnBundle(42, {
    fetchBundle: async () => ({
      identity_key: "identity",
      signed_pre_key: { id: 1, public_key: "spk", signature: "sig" },
      registration_id: 7,
    }),
    loadIdentity: async () => null,
    restoreIdentity: () => {
      throw new Error("restoreIdentity should not be called");
    },
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
