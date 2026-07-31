import assert from "node:assert/strict";
import test from "node:test";
import "fake-indexeddb/auto";
import { createSecurityPassphrase, unlockSecurityVault, getVaultKey, lockSecurityVault, isVaultUnlocked, hasSecurityPassphrase } from "../src/lib/securityVault";
import { setActiveCryptoNamespace, getActiveCryptoNamespace, loadSecurityVaultSalt, loadSecurityVaultBlob, type CryptoNamespace } from "../src/lib/indexeddb";

const NAMESPACE: CryptoNamespace = { uin: 2001, deviceId: "vault_test_dev_0001" };

test("createSecurityPassphrase derives a key and stores only a verification blob in IndexedDB", async () => {
  setActiveCryptoNamespace(NAMESPACE);
  lockSecurityVault();

  await createSecurityPassphrase("correct horse battery staple 1");
  assert.equal(isVaultUnlocked(), true);
  assert.notEqual(getVaultKey(), null);

  const ns = getActiveCryptoNamespace();
  const saltRecord = await loadSecurityVaultSalt(ns);
  const vaultRecord = await loadSecurityVaultBlob(ns);

  assert.ok(vaultRecord, "vault blob must be stored");
  assert.ok(saltRecord, "salt must be stored");
  assert.equal(typeof vaultRecord.blob, "string");
  assert.ok(vaultRecord.blob.length > 0);
  assert.equal(typeof saltRecord.salt, "string");
  assert.ok(saltRecord.salt.length > 0);

  assert.ok(!vaultRecord.blob.includes("correct"), "vault blob must not contain plaintext passphrase");
  assert.ok(!vaultRecord.blob.includes("horse"), "vault blob must not contain plaintext passphrase");
});

test("unlockSecurityVault with correct passphrase unlocks the vault", async () => {
  setActiveCryptoNamespace({ uin: 2001, deviceId: "vault_test_dev_0001_b" });
  lockSecurityVault();

  await createSecurityPassphrase("SnowfallOvertheMountain");
  lockSecurityVault();
  assert.equal(isVaultUnlocked(), false);
  assert.equal(getVaultKey(), null);

  const ok = await unlockSecurityVault("SnowfallOvertheMountain");
  assert.equal(ok, true);
  assert.equal(isVaultUnlocked(), true);
  assert.notEqual(getVaultKey(), null);
});

test("unlockSecurityVault with wrong passphrase fails closed", async () => {
  setActiveCryptoNamespace({ uin: 2001, deviceId: "vault_test_dev_0001_c" });
  lockSecurityVault();

  await createSecurityPassphrase("the right passphrase 1");
  lockSecurityVault();

  const ok = await unlockSecurityVault("the wrong passphrase 2");
  assert.equal(ok, false);
  assert.equal(isVaultUnlocked(), false);
  assert.equal(getVaultKey(), null);
});

test("lockSecurityVault clears the derived key from memory", async () => {
  setActiveCryptoNamespace({ uin: 2001, deviceId: "vault_test_dev_0001_d" });
  lockSecurityVault();

  await createSecurityPassphrase("memory clearing test 1");
  assert.notEqual(getVaultKey(), null);

  lockSecurityVault();
  assert.equal(getVaultKey(), null);
  assert.equal(isVaultUnlocked(), false);
});

test("hasSecurityPassphrase returns false before creation", async () => {
  setActiveCryptoNamespace({ uin: 2002, deviceId: "vault_test_dev_0002" });
  lockSecurityVault();
  assert.equal(await hasSecurityPassphrase(), false);
});

test("hasSecurityPassphrase returns true after creation", async () => {
  setActiveCryptoNamespace({ uin: 2002, deviceId: "vault_test_dev_0002" });
  lockSecurityVault();
  await createSecurityPassphrase("verification test phrase 1");
  assert.equal(await hasSecurityPassphrase(), true);
});

test("re-creating the passphrase is rejected — vault already exists", async () => {
  setActiveCryptoNamespace({ uin: 2003, deviceId: "vault_test_dev_0003" });
  lockSecurityVault();

  await createSecurityPassphrase("First passphrase ok");
  lockSecurityVault();

  // Second creation must fail closed — vault already exists.
  await assert.rejects(async () => createSecurityPassphrase("Second passphrase ok"), /already exists/);

  // The original passphrase must still unlock the original vault.
  lockSecurityVault();
  const ok = await unlockSecurityVault("First passphrase ok");
  assert.equal(ok, true);
  assert.equal(isVaultUnlocked(), true);
});

test("unlock returns false when no vault exists", async () => {
  setActiveCryptoNamespace({ uin: 2004, deviceId: "vault_test_dev_0004" });
  lockSecurityVault();
  const ok = await unlockSecurityVault("anything ok 1");
  assert.equal(ok, false);
});

test("getVaultKey returns the same CryptoKey across calls within a session", async () => {
  setActiveCryptoNamespace({ uin: 2001, deviceId: "vault_test_dev_0001_e" });
  lockSecurityVault();

  await createSecurityPassphrase("session key test 1");
  const key1 = getVaultKey();
  const key2 = getVaultKey();
  assert.notEqual(key1, null);
  assert.strictEqual(key1, key2);
});

test("derived key is never stored in localStorage", async () => {
  setActiveCryptoNamespace({ uin: 2001, deviceId: "vault_test_dev_0001_g" });
  lockSecurityVault();
  if (typeof localStorage === "undefined") return;

  localStorage.clear();

  await createSecurityPassphrase("no localStorage leak 1");

  for (let i = 0; i < localStorage.length; i++) {
    const k = localStorage.key(i)!;
    const v = localStorage.getItem(k)!;
    assert.ok(!v.includes("no localStorage"), `localStorage key '${k}' should not contain passphrase`);
  }

  lockSecurityVault();
  const key = getVaultKey();
  assert.ok(typeof key !== "string", "derived key should not be a string");
});

test("rejects passphrase shorter than 12 characters", async () => {
  setActiveCryptoNamespace(NAMESPACE);
  lockSecurityVault();
  await assert.rejects(async () => createSecurityPassphrase("short1"));
});

test("rejects passphrase with only lowercase letters", async () => {
  setActiveCryptoNamespace(NAMESPACE);
  lockSecurityVault();
  await assert.rejects(async () => createSecurityPassphrase("onlylowercase"));
});

test("accepts passphrase with uppercase and longer than 12 chars", async () => {
  setActiveCryptoNamespace({ uin: 2001, deviceId: "vault_test_dev_0001_f" });
  lockSecurityVault();
  await createSecurityPassphrase("ThisIsAValidPassphrase");
  const ok = await unlockSecurityVault("ThisIsAValidPassphrase");
  assert.equal(ok, true);
});

test("accepts passphrase with digits and longer than 12 chars", async () => {
  setActiveCryptoNamespace({ uin: 2005, deviceId: "vault_test_dev_0005" });
  lockSecurityVault();
  await createSecurityPassphrase("passphrase12345!");
  const ok = await unlockSecurityVault("passphrase12345!");
  assert.equal(ok, true);
});

// --- Reload simulation: the vault blob exists in IndexedDB but the
// in-memory vaultKey is null because JavaScript module state does not
// survive page reloads. This is the exact scenario that caused the
// "security vault is locked" defect at the Panic Wipe step. ---

test("hasSecurityPassphrase returns true after creation but isVaultUnlocked is false after simulated reload", async () => {
  const ns: CryptoNamespace = { uin: 2006, deviceId: "vault_reload_dev_0006" };
  setActiveCryptoNamespace(ns);
  lockSecurityVault();

  // Create the vault — this sets vaultKey in memory AND persists to IndexedDB.
  await createSecurityPassphrase("AfterReloadVaultKeyIsGone1");
  assert.equal(isVaultUnlocked(), true);
  assert.equal(await hasSecurityPassphrase(), true);

  // Simulate a page reload: the vault blob persists in IndexedDB but the
  // in-memory vaultKey is gone (module re-initialized).
  lockSecurityVault();
  assert.equal(isVaultUnlocked(), false);

  // After the "reload", the vault still exists on disk...
  assert.equal(await hasSecurityPassphrase(), true);
  // ...but the in-memory key is gone — exactly the defect scenario.
  assert.equal(getVaultKey(), null);
});

test("unlockSecurityVault after simulated reload restores the in-memory key", async () => {
  const ns: CryptoNamespace = { uin: 2007, deviceId: "vault_reload_dev_0007" };
  setActiveCryptoNamespace(ns);
  lockSecurityVault();

  await createSecurityPassphrase("ResumeAfterReloadKey1");
  lockSecurityVault(); // simulate reload

  const ok = await unlockSecurityVault("ResumeAfterReloadKey1");
  assert.equal(ok, true);
  assert.equal(isVaultUnlocked(), true);
  assert.notEqual(getVaultKey(), null);
});

test("wrong passphrase after simulated reload fails locally and leaves vault locked", async () => {
  const ns: CryptoNamespace = { uin: 2008, deviceId: "vault_reload_dev_0008" };
  setActiveCryptoNamespace(ns);
  lockSecurityVault();

  await createSecurityPassphrase("CorrectAfterReload1");
  lockSecurityVault(); // simulate reload

  const ok = await unlockSecurityVault("WrongAfterReloadPass1");
  assert.equal(ok, false);
  assert.equal(isVaultUnlocked(), false);
  assert.equal(getVaultKey(), null);
});

test("passphrase is never written to IndexedDB or localStorage in plaintext", async () => {
  const ns: CryptoNamespace = { uin: 2009, deviceId: "vault_leak_dev_0009" };
  setActiveCryptoNamespace(ns);
  lockSecurityVault();
  if (typeof localStorage !== "undefined") localStorage.clear();

  const PASSPHRASE = "NoPlaintextStorage9";
  await createSecurityPassphrase(PASSPHRASE);

  // Check all IndexedDB records for the passphrase plaintext.
  const saltRecord = await loadSecurityVaultSalt(ns);
  const vaultRecord = await loadSecurityVaultBlob(ns);
  assert.ok(!saltRecord.salt.includes(PASSPHRASE), "salt must not contain plaintext passphrase");
  assert.ok(!vaultRecord.blob.includes(PASSPHRASE), "vault blob must not contain plaintext passphrase");

  // Check localStorage.
  if (typeof localStorage !== "undefined") {
    for (let i = 0; i < localStorage.length; i++) {
      const k = localStorage.key(i)!;
      const v = localStorage.getItem(k)!;
      assert.ok(!v.includes(PASSPHRASE), `localStorage key '${k}' must not contain plaintext passphrase`);
    }
  }

  lockSecurityVault();
  await unlockSecurityVault(PASSPHRASE);

  // The passphrase was held in a local variable during unlock — it must have
  // been garbage-collected. IndexedDB must not contain it.
  const saltRecord2 = await loadSecurityVaultSalt(ns);
  assert.ok(!saltRecord2.salt.includes(PASSPHRASE), "salt must not contain plaintext passphrase after unlock");
});

// --- Key usages: the unlocked vault key must support both encrypt and
// decrypt, because panicWipeKey.ts encrypts the private signing key with
// the vault key during Panic Wipe enrollment. Before the fix,
// unlockSecurityVault imported the key with only ["decrypt"], so any
// encrypt call after a reload failed with "key.usages does not permit
// this operation" (Chromium) or "CryptoKey doesn't support encryption"
// (WebKit). ---

test("vault key after unlock supports encrypt and decrypt", async () => {
  const ns: CryptoNamespace = { uin: 2010, deviceId: "vault_usages_dev_0010" };
  setActiveCryptoNamespace(ns);
  lockSecurityVault();

  await createSecurityPassphrase("EncryptDecryptUsageTest1");
  lockSecurityVault(); // simulate reload

  const ok = await unlockSecurityVault("EncryptDecryptUsageTest1");
  assert.equal(ok, true);

  const key = getVaultKey();
  assert.notEqual(key, null);
  assert.equal(key!.type, "secret");
  assert.equal(key!.algorithm.name, "AES-GCM");
  assert.equal(key!.extractable, false);

  // The key must have both usages.
  assert.ok(key!.usages.includes("encrypt"), "unlocked key must support encrypt");
  assert.ok(key!.usages.includes("decrypt"), "unlocked key must support decrypt");

  // Prove it can actually encrypt data.
  const iv = new Uint8Array(12);
  globalThis.crypto.getRandomValues(iv);
  const plaintext = new TextEncoder().encode("panic-wipe-private-key-pkcs8-bytes");
  const ciphertext = await globalThis.crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv.buffer as unknown as BufferSource },
    key!,
    plaintext.buffer as unknown as BufferSource,
  );
  assert.ok(ciphertext.byteLength > 0);

  // And decrypt it back.
  const decrypted = await globalThis.crypto.subtle.decrypt(
    { name: "AES-GCM", iv: iv.buffer as unknown as BufferSource },
    key!,
    ciphertext,
  );
  assert.deepEqual(new Uint8Array(decrypted), plaintext);
});

test("vault key after creation (no reload) also supports encrypt and decrypt", async () => {
  const ns: CryptoNamespace = { uin: 2011, deviceId: "vault_usages_dev_0011" };
  setActiveCryptoNamespace(ns);
  lockSecurityVault();

  await createSecurityPassphrase("FreshKeyUsageTest1");
  const key = getVaultKey();
  assert.notEqual(key, null);
  assert.ok(key!.usages.includes("encrypt"), "fresh key must support encrypt");
  assert.ok(key!.usages.includes("decrypt"), "fresh key must support decrypt");
});

// --- Vault overwrite prevention ---

test("first creation succeeds", async () => {
  const ns: CryptoNamespace = { uin: 2012, deviceId: "vault_owp_dev_0012" };
  setActiveCryptoNamespace(ns);
  lockSecurityVault();

  await createSecurityPassphrase("FirstEverVaultKey12");
  assert.equal(isVaultUnlocked(), true);
  assert.equal(await hasSecurityPassphrase(), true);
});

test("second creation attempt fails closed", async () => {
  const ns: CryptoNamespace = { uin: 2013, deviceId: "vault_owp_dev_0013" };
  setActiveCryptoNamespace(ns);
  lockSecurityVault();

  await createSecurityPassphrase("OriginalVaultKey13");
  lockSecurityVault();

  await assert.rejects(
    async () => createSecurityPassphrase("DifferentVaultKey13"),
    /already exists/,
  );
  // Vault remains locked because the second creation was rejected.
  assert.equal(isVaultUnlocked(), false);
});

test("original passphrase still unlocks after rejected overwrite", async () => {
  const ns: CryptoNamespace = { uin: 2014, deviceId: "vault_owp_dev_0014" };
  setActiveCryptoNamespace(ns);
  lockSecurityVault();

  await createSecurityPassphrase("OriginalOnlyKey14");

  // Attempt overwrite — must fail.
  lockSecurityVault();
  await assert.rejects(
    async () => createSecurityPassphrase("NotGonnaWork14"),
    /already exists/,
  );

  // Original passphrase still works because the vault was not overwritten.
  lockSecurityVault();
  const ok = await unlockSecurityVault("OriginalOnlyKey14");
  assert.equal(ok, true);
});

test("different passphrase does not replace existing vault", async () => {
  const ns: CryptoNamespace = { uin: 2015, deviceId: "vault_owp_dev_0015" };
  setActiveCryptoNamespace(ns);
  lockSecurityVault();

  await createSecurityPassphrase("TheRealPassphrase15");
  lockSecurityVault();

  await assert.rejects(
    async () => createSecurityPassphrase("ImpostorPassphrase15"),
    /already exists/,
  );

  // The impostor must not unlock.
  lockSecurityVault();
  let ok = await unlockSecurityVault("ImpostorPassphrase15");
  assert.equal(ok, false);

  // The real one must.
  lockSecurityVault();
  ok = await unlockSecurityVault("TheRealPassphrase15");
  assert.equal(ok, true);
});

// --- Vault key non-extractability ---

test("vault key is never extractable", async () => {
  const ns: CryptoNamespace = { uin: 2016, deviceId: "vault_extract_dev_0016" };
  setActiveCryptoNamespace(ns);
  lockSecurityVault();

  await createSecurityPassphrase("NonExtractableKey16");
  const key = getVaultKey();
  assert.equal(key!.extractable, false);

  lockSecurityVault();
  await unlockSecurityVault("NonExtractableKey16");
  const key2 = getVaultKey();
  assert.equal(key2!.extractable, false);
});
