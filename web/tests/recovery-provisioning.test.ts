import test from "node:test";
import assert from "node:assert/strict";
import {
  provisionRecoveryPrekeys,
  IdentityKeyMismatchError,
  type RecoveryProvisioningDeps,
} from "../src/lib/signalBootstrap.ts";
import type { CryptoNamespace, PendingRecoveryProvisioning, StoredIdentity } from "../src/lib/indexeddb.ts";
import type { PreKeyBundleUpload, RemotePreKeyBundle } from "../src/api/keys.ts";

// ---------------------------------------------------------------------------
// Test helpers — minimal fake implementations of RecoveryProvisioningDeps
// ---------------------------------------------------------------------------

const TEST_NS: CryptoNamespace = { uin: 12345678, deviceId: "test-device-abcdefghijklmnop" };
const TEST_IDENTITY_FINGERPRINT = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const TEST_STORED_IDENTITY: StoredIdentity = {
  publicKey: TEST_IDENTITY_FINGERPRINT,
  privateKey: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
  registrationId: 1234,
};

const TEST_SERVER_DIRECTORY: RemotePreKeyBundle = {
  identity_key: TEST_IDENTITY_FINGERPRINT,
  registration_id: 1234,
  signed_pre_key: { id: 42, public_key: "old-signed-pk", signature: "old-sig" },
};

type GeneratedBundle = PreKeyBundleUpload & { deviceId: number };

function makeBundle(id: number): GeneratedBundle {
  return {
    identity_key: TEST_IDENTITY_FINGERPRINT,
    registration_id: 1234,
    deviceId: 1,
    signed_pre_key: { id: id, public_key: `spk-${id}`, signature: `sig-${id}` },
    one_time_pre_keys: [
      { id: id * 100 + 1, public_key: `opk-${id * 100 + 1}` },
      { id: id * 100 + 2, public_key: `opk-${id * 100 + 2}` },
    ],
  };
}

interface FakeDepsOpts {
  storedIdentity?: StoredIdentity | null;
  serverDirectory?: RemotePreKeyBundle;
  uploadFails?: boolean;
  uploadAttempts?: Array<PreKeyBundleUpload>;
  pendingRecord?: PendingRecoveryProvisioning | null;
}

function fakeDeps(opts: FakeDepsOpts = {}): RecoveryProvisioningDeps {
  const uploadAttempts: Array<PreKeyBundleUpload> = [];
  let pending: PendingRecoveryProvisioning | null = opts.pendingRecord ?? null;

  return {
    loadIdentity: async (_ns) => {
      // Verify the namespace matches — the caller must pass the correct one.
      if (_ns && (_ns.uin !== TEST_NS.uin || _ns.deviceId !== TEST_NS.deviceId)) {
        return null;
      }
      if ("storedIdentity" in opts) return opts.storedIdentity!;
      return TEST_STORED_IDENTITY;
    },

    fetchBundle: async (_uin) => {
      return opts.serverDirectory ?? TEST_SERVER_DIRECTORY;
    },

    restoreIdentity: (stored) => {
      return {
        ...stored,
        registrationId: stored.registrationId ?? 1234,
        pubKey: new Uint8Array(32),
        privKey: new Uint8Array(32),
      };
    },

    deriveStoredPublic: async (_privateKey) => TEST_IDENTITY_FINGERPRINT,

    generatePreKeyBundle: async (_identity, _start, _count, _regId, _ns) => {
      return makeBundle(1);
    },

    uploadBundle: async (bundle) => {
      uploadAttempts.push(bundle);
      if (opts.uploadFails) {
        throw new Error("network error");
      }
    },

    loadPendingRecord: async (_ns) => pending,

    savePendingRecord: async (record) => {
      pending = record;
    },

    clearPendingRecord: async (_ns) => {
      pending = null;
    },
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test("provisionRecoveryPrekeys uses the caller's namespace, not a hardcoded one", async () => {
  // Verify that passing a specific namespace causes loadIdentity to receive
  // exactly that namespace (not "recovery-device").
  const customNs: CryptoNamespace = { uin: 99999999, deviceId: "custom-device-id-abcdefghij" };

  let receivedNs: CryptoNamespace | undefined;
  let receivedUploadNs: CryptoNamespace | undefined;

  const deps: RecoveryProvisioningDeps = {
    loadIdentity: async (ns) => {
      receivedNs = ns;
      return {
        publicKey: "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
        privateKey: "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD",
        registrationId: 5678,
      };
    },
    fetchBundle: async () => ({
      identity_key: "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
      registration_id: 5678,
      signed_pre_key: { id: 1, public_key: "pk", signature: "sig" },
    }),
    restoreIdentity: (stored) => ({ ...stored, registrationId: stored.registrationId ?? 5678, pubKey: new Uint8Array(32), privKey: new Uint8Array(32) }),
    deriveStoredPublic: async () => "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
    generatePreKeyBundle: async (_id, _s, _c, _r, ns) => {
      receivedUploadNs = ns;
      return makeBundle(99);
    },
    uploadBundle: async () => {},
    loadPendingRecord: async (_ns) => null,
    savePendingRecord: async () => {},
    clearPendingRecord: async (_ns) => {},
  };

  await provisionRecoveryPrekeys(customNs, deps);

  assert.ok(receivedNs, "loadIdentity must be called with the namespace");
  assert.equal(receivedNs!.uin, customNs.uin, "namespace UIN must match caller's namespace");
  assert.equal(receivedNs!.deviceId, customNs.deviceId, "namespace deviceId must match caller's namespace — not hardcoded 'recovery-device'");
  assert.ok(receivedUploadNs, "generatePreKeyBundle must be called with the namespace");
  assert.equal(receivedUploadNs!.deviceId, customNs.deviceId, "prekey generation must use caller's namespace");
});

test("provisionRecoveryPrekeys fails closed on identity mismatch — uploads nothing", async () => {
  const uploadAttempts: Array<PreKeyBundleUpload> = [];
  let pendingSaved = false;

  const deps = fakeDeps({
    serverDirectory: {
      identity_key: "DIFFERENT_IDENTITY_KEY_AAAAAAAAAAAAAAAAA", // mismatch
      registration_id: 1234,
      signed_pre_key: { id: 1, public_key: "pk", signature: "sig" },
    },
  });
  // Override to track calls precisely.
  const originalUpload = deps.uploadBundle;
  deps.uploadBundle = async (bundle) => {
    uploadAttempts.push(bundle);
    await originalUpload(bundle);
  };
  const originalSave = deps.savePendingRecord;
  deps.savePendingRecord = async (record) => {
    pendingSaved = true;
    await originalSave(record);
  };

  await assert.rejects(
    () => provisionRecoveryPrekeys(TEST_NS, deps),
    IdentityKeyMismatchError,
  );

  assert.equal(uploadAttempts.length, 0, "must NOT upload anything on identity mismatch");
  assert.equal(pendingSaved, false, "must NOT persist pending record on identity mismatch");
});

test("provisionRecoveryPrekeys persists pending record before upload", async () => {
  const events: string[] = [];

  const deps = fakeDeps();
  const originalSave = deps.savePendingRecord;
  deps.savePendingRecord = async (record) => {
    events.push("save");
    await originalSave(record);
  };
  const originalUpload = deps.uploadBundle;
  deps.uploadBundle = async (bundle) => {
    events.push("upload");
    await originalUpload(bundle);
  };

  await provisionRecoveryPrekeys(TEST_NS, deps);

  assert.equal(events[0], "save", "pending record must be persisted BEFORE upload");
  assert.equal(events[1], "upload", "upload must follow pending record persistence");
});

test("provisionRecoveryPrekeys clears pending record after successful upload", async () => {
  let pending: PendingRecoveryProvisioning | null = null;
  let cleared = false;

  const deps = fakeDeps();
  deps.savePendingRecord = async (record) => { pending = record; };
  deps.clearPendingRecord = async (_ns) => { cleared = true; pending = null; };

  await provisionRecoveryPrekeys(TEST_NS, deps);

  assert.equal(cleared, true, "pending record must be cleared after successful upload");
  assert.equal(pending, null, "no pending record must remain after successful provisioning");
});

test("provisionRecoveryPrekeys retains pending record on upload failure", async () => {
  let pending: PendingRecoveryProvisioning | null = null;

  const deps = fakeDeps({ uploadFails: true });
  deps.savePendingRecord = async (record) => { pending = record; };
  deps.clearPendingRecord = async (_ns) => { pending = null; };

  await assert.rejects(() => provisionRecoveryPrekeys(TEST_NS, deps));

  assert.ok(pending, "pending record must survive upload failure");
  assert.ok(pending!.bundle, "pending record must contain the bundle");
  assert.equal(pending!.namespace.uin, TEST_NS.uin, "pending record must preserve namespace UIN");
  assert.equal(pending!.namespace.deviceId, TEST_NS.deviceId, "pending record must preserve namespace deviceId");
  assert.equal(pending!.identityFingerprint, TEST_IDENTITY_FINGERPRINT, "pending record must preserve identity fingerprint");
});

test("provisionRecoveryPrekeys retries exact same bundle — does not regenerate keys", async () => {
  // First call: generate, persist, upload fails.
  const genCalls: Array<number> = [];
  const deps = fakeDeps({ uploadFails: true });
  deps.generatePreKeyBundle = async (..._args) => {
    genCalls.push(1);
    return makeBundle(genCalls.length);
  };

  await assert.rejects(() => provisionRecoveryPrekeys(TEST_NS, deps));
  assert.equal(genCalls.length, 1, "first call generates a bundle");

  // Second call: pending record exists with matching fingerprint.
  // Must reuse the exact same bundle WITHOUT regenerating keys.
  let retryBundle: PreKeyBundleUpload | undefined;
  deps.uploadFails = false;
  deps.uploadBundle = async (bundle) => {
    retryBundle = bundle;
  };

  await provisionRecoveryPrekeys(TEST_NS, deps);

  assert.equal(genCalls.length, 1, "retry must NOT regenerate keys — generatePreKeyBundle must not be called again");
  assert.ok(retryBundle, "retry must upload the bundle from the pending record");
  assert.equal(retryBundle!.identity_key, TEST_IDENTITY_FINGERPRINT, "retry must use the same identity key");
});

test("provisionRecoveryPrekeys recovers after simulated page reload", async () => {
  // Simulate a page reload: the in-memory state is gone, but the pending
  // record is in IndexedDB. A new call to provisionRecoveryPrekeys must
  // detect the pending record and retry the exact same bundle.
  let pending: PendingRecoveryProvisioning | null = null;

  // First "session": generate and fail.
  const deps1 = fakeDeps({ uploadFails: true });
  deps1.savePendingRecord = async (record) => { pending = record; };

  await assert.rejects(() => provisionRecoveryPrekeys(TEST_NS, deps1));
  assert.ok(pending, "pending record must exist after failed upload");

  // Second "session" (page reload): pending record is in IndexedDB.
  // The in-memory state is gone — only the pending record survives.
  let reloadUploadBundle: PreKeyBundleUpload | undefined;
  let reloadGenCalled = false;

  const deps2 = fakeDeps();
  deps2.loadPendingRecord = async (_ns) => pending; // Simulates IndexedDB read
  deps2.generatePreKeyBundle = async () => {
    reloadGenCalled = true;
    return makeBundle(999);
  };
  deps2.uploadBundle = async (bundle) => {
    reloadUploadBundle = bundle;
  };
  deps2.savePendingRecord = async () => {};
  deps2.clearPendingRecord = async () => { pending = null; };

  await provisionRecoveryPrekeys(TEST_NS, deps2);

  assert.equal(reloadGenCalled, false, "after reload, must NOT regenerate keys — reuse pending record");
  assert.ok(reloadUploadBundle, "after reload, must upload the bundle from pending record");
  assert.equal(reloadUploadBundle!.identity_key, TEST_IDENTITY_FINGERPRINT, "after reload, identity must match pending record");
  assert.equal(pending, null, "after successful upload, pending record must be cleared");
});

test("provisionRecoveryPrekeys rejects mismatched namespace in pending record", async () => {
  const wrongNsPending: PendingRecoveryProvisioning = {
    bundle: {
      identityKey: TEST_IDENTITY_FINGERPRINT,
      registrationId: 1234,
      deviceId: 1,
      signedPreKey: { keyId: 1, publicKey: "spk-1", signature: "sig-1" },
      oneTimePreKeys: [
        { keyId: 101, publicKey: "opk-101" },
      ],
    },
    namespace: { uin: 99999999, deviceId: "wrong-device-id-abcdefghijklmn" }, // different namespace
    identityFingerprint: TEST_IDENTITY_FINGERPRINT,
    createdAt: Date.now(),
  };

  const deps = fakeDeps({ pendingRecord: wrongNsPending });

  await assert.rejects(
    () => provisionRecoveryPrekeys(TEST_NS, deps),
    /namespace does not match/,
  );
});

test("provisionRecoveryPrekeys clears stale pending record when identity was deleted", async () => {
  let cleared = false;
  const stalePending: PendingRecoveryProvisioning = {
    bundle: {
      identityKey: TEST_IDENTITY_FINGERPRINT,
      registrationId: 1234,
      deviceId: 1,
      signedPreKey: { keyId: 1, publicKey: "spk-1", signature: "sig-1" },
      oneTimePreKeys: [{ keyId: 101, publicKey: "opk-101" }],
    },
    namespace: TEST_NS,
    identityFingerprint: TEST_IDENTITY_FINGERPRINT,
    createdAt: Date.now(),
  };

  const deps = fakeDeps({ pendingRecord: stalePending, storedIdentity: null }); // identity gone
  deps.clearPendingRecord = async (_ns) => { cleared = true; };

  await assert.rejects(
    () => provisionRecoveryPrekeys(TEST_NS, deps),
    /No recovered identity found/,
  );

  assert.equal(cleared, true, "stale pending record must be cleared when identity is gone");
});

test("provisionRecoveryPrekeys clears pending record on fingerprint mismatch and fails closed", async () => {
  let cleared = false;
  const stalePending: PendingRecoveryProvisioning = {
    bundle: {
      identityKey: "DIFFERENT_OLD_FINGERPRINT_AAAAAAAAAAA",
      registrationId: 1234,
      deviceId: 1,
      signedPreKey: { keyId: 1, publicKey: "spk-1", signature: "sig-1" },
      oneTimePreKeys: [{ keyId: 101, publicKey: "opk-101" }],
    },
    namespace: TEST_NS,
    identityFingerprint: "DIFFERENT_OLD_FINGERPRINT_AAAAAAAAAAA", // doesn't match current identity
    createdAt: Date.now(),
  };

  const deps = fakeDeps({ pendingRecord: stalePending });
  deps.clearPendingRecord = async (_ns) => { cleared = true; };

  await assert.rejects(
    () => provisionRecoveryPrekeys(TEST_NS, deps),
    IdentityKeyMismatchError,
  );

  assert.equal(cleared, true, "pending record with mismatched fingerprint must be cleared");
});
