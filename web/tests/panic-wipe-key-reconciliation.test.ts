import test from "node:test";
import assert from "node:assert/strict";
import "fake-indexeddb/auto";

import { setActiveCryptoNamespace, type CryptoNamespace } from "../src/lib/indexeddb.ts";
import { createSecurityPassphrase, lockSecurityVault } from "../src/lib/securityVault.ts";
import {
  bytesToBase64std,
  clearLocalWipeKey,
  loadAndDecryptWipePrivateKey,
  loadOrCreateWipeKeyPair,
  reconcileWipeKey,
  storeEncryptedWipePrivateKey,
} from "../src/lib/panicWipeKey.ts";

const PASSPHRASE = "correct horse battery staple wipe key test";

/** Sets the active namespace, locks any prior vault handle, and creates a
 *  fresh security vault so every test owns an isolated key namespace. */
async function bootstrapVault(ns: CryptoNamespace): Promise<void> {
  setActiveCryptoNamespace(ns);
  lockSecurityVault();
  await createSecurityPassphrase(PASSPHRASE);
}

// --- reconcileWipeKey --------------------------------------------------

test("reconcileWipeKey reports a match when the server's key equals the local key", async () => {
  await bootstrapVault({ uin: 3001, deviceId: "wipe_key_recon_dev_0001" });
  const local = new Uint8Array(32);
  local[0] = 1;
  const result = await reconcileWipeKey(local, async () => ({ public_key: bytesToBase64std(local) }));
  assert.deepEqual(result, { status: "match" });
});

test("reconcileWipeKey reports a mismatch when a different key is enrolled", async () => {
  await bootstrapVault({ uin: 3002, deviceId: "wipe_key_recon_dev_0002" });
  const local = new Uint8Array(32);
  local[0] = 1;
  const serverKey = new Uint8Array(32);
  serverKey[0] = 2;
  const result = await reconcileWipeKey(local, async () => ({ public_key: bytesToBase64std(serverKey) }));
  assert.deepEqual(result, { status: "mismatch" });
});

test("reconcileWipeKey reports server-has-no-key when nothing is enrolled yet", async () => {
  await bootstrapVault({ uin: 3003, deviceId: "wipe_key_recon_dev_0003" });
  const local = new Uint8Array(32);
  local[0] = 1;
  const result = await reconcileWipeKey(local, async () => ({ public_key: null }));
  assert.deepEqual(result, { status: "server-has-no-key" });
});

// --- clearLocalWipeKey ---------------------------------------------------

test("clearLocalWipeKey removes the stored key so loadAndDecryptWipePrivateKey returns null", async () => {
  await bootstrapVault({ uin: 3004, deviceId: "wipe_key_recon_dev_0004" });
  await storeEncryptedWipePrivateKey("opaque-blob", new Uint8Array(32));
  await clearLocalWipeKey();
  const loaded = await loadAndDecryptWipePrivateKey();
  assert.equal(loaded, null);
});

// --- loadOrCreateWipeKeyPair in-flight guard -----------------------------

test("concurrent loadOrCreateWipeKeyPair calls in the same tick share one generated key", async () => {
  await bootstrapVault({ uin: 3005, deviceId: "wipe_key_recon_dev_0005" });
  const [a, b] = await Promise.all([loadOrCreateWipeKeyPair(), loadOrCreateWipeKeyPair()]);
  assert.equal(a.isNew, true);
  assert.equal(b.isNew, true);
  assert.deepEqual(a.publicKeyBytes, b.publicKeyBytes, "concurrent callers must not generate two different keys");
  assert.equal(a.encryptedPrivateBlob, b.encryptedPrivateBlob);
});

test("the in-flight guard clears after resolving: a later call is independent", async () => {
  await bootstrapVault({ uin: 3006, deviceId: "wipe_key_recon_dev_0006" });
  const first = await loadOrCreateWipeKeyPair();
  await storeEncryptedWipePrivateKey(first.encryptedPrivateBlob, first.publicKeyBytes);

  const second = await loadOrCreateWipeKeyPair();
  assert.equal(second.isNew, false, "once stored, a later call must load the existing key, not generate another");
  assert.deepEqual(second.publicKeyBytes, first.publicKeyBytes);
});
