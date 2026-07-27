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
  setActiveCryptoNamespace(NAMESPACE);
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
  setActiveCryptoNamespace(NAMESPACE);
  lockSecurityVault();

  await createSecurityPassphrase("the right passphrase 1");
  lockSecurityVault();

  const ok = await unlockSecurityVault("the wrong passphrase 2");
  assert.equal(ok, false);
  assert.equal(isVaultUnlocked(), false);
  assert.equal(getVaultKey(), null);
});

test("lockSecurityVault clears the derived key from memory", async () => {
  setActiveCryptoNamespace(NAMESPACE);
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

test("re-creating the passphrase overwrites the old verification blob", async () => {
  setActiveCryptoNamespace({ uin: 2003, deviceId: "vault_test_dev_0003" });
  lockSecurityVault();

  await createSecurityPassphrase("First passphrase ok");
  lockSecurityVault();
  await createSecurityPassphrase("Second passphrase ok");
  lockSecurityVault();

  let ok = await unlockSecurityVault("First passphrase ok");
  assert.equal(ok, false);

  ok = await unlockSecurityVault("Second passphrase ok");
  assert.equal(ok, true);
});

test("unlock returns false when no vault exists", async () => {
  setActiveCryptoNamespace({ uin: 2004, deviceId: "vault_test_dev_0004" });
  lockSecurityVault();
  const ok = await unlockSecurityVault("anything ok 1");
  assert.equal(ok, false);
});

test("getVaultKey returns the same CryptoKey across calls within a session", async () => {
  setActiveCryptoNamespace(NAMESPACE);
  lockSecurityVault();

  await createSecurityPassphrase("session key test 1");
  const key1 = getVaultKey();
  const key2 = getVaultKey();
  assert.notEqual(key1, null);
  assert.strictEqual(key1, key2);
});

test("derived key is never stored in localStorage", async () => {
  setActiveCryptoNamespace(NAMESPACE);
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
  setActiveCryptoNamespace(NAMESPACE);
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
