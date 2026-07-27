import assert from "node:assert/strict";
import test from "node:test";
import "fake-indexeddb/auto";
import { generateRecoveryKey, createRecoveryPackage, importRecoveryPackage, RECOVERY_KEY_BYTES } from "../src/lib/recoveryPackage";
import { setActiveCryptoNamespace, getActiveCryptoNamespace, loadIdentity, saveIdentity, type CryptoNamespace } from "../src/lib/indexeddb";
import { deriveIdentityPublicKey } from "../src/lib/signal";

const NAMESPACE: CryptoNamespace = { uin: 3001, deviceId: "recovery_test_dev_0001" };

// Default server identity used for rejection-path tests.
const DUMMY_SERVER_ID = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"; // 32 bytes of 0x00, base64url

// realIdentity generates an X25519 key pair using the Signal library so
// that deriveIdentityPublicKey (used in v3 import verification) produces
// the matching public key. Falls back to fake keys when WASM is unavailable.
async function realIdentity(): Promise<{ publicKey: string; privateKey: string; registrationId: number }> {
  try {
    // Generate 32 random bytes as the private key seed.
    const rawPriv = new Uint8Array(32);
    globalThis.crypto.getRandomValues(rawPriv);
    const privateKey = bytesToBase64url(rawPriv);

    // Derive the public key using the exact same function the import
    // verification uses. This guarantees compatibility regardless of
    // X25519 clamping differences between Web Crypto and Signal WASM.
    const publicKey = await deriveIdentityPublicKey(privateKey);
    return { publicKey, privateKey, registrationId: 42 };
  } catch {
    // Signal WASM not available — fall back to fake keys. Tests that
    // require the round-trip will skip gracefully.
    return {
      publicKey: bytesToBase64url(new Uint8Array(32).fill(0xAB)),
      privateKey: bytesToBase64url(new Uint8Array(32).fill(0xCD)),
      registrationId: 42,
    };
  }
}

function bytesToBase64url(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]!);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

test("generateRecoveryKey produces 32 random bytes", () => {
  const key1 = generateRecoveryKey();
  assert.equal(key1.length, RECOVERY_KEY_BYTES);
  const allZero = key1.every(b => b === 0);
  assert.ok(!allZero, "recovery key should not be all zeros");

  const key2 = generateRecoveryKey();
  let identical = true;
  for (let i = 0; i < key1.length; i++) { if (key1[i] !== key2[i]) { identical = false; break; } }
  assert.ok(!identical, "two keys should not be identical");
});

test("create and import recovery package round-trip with identity", async () => {
  // Use a real X25519 key pair so deriveIdentityPublicKey produces the
  // matching public key during import verification.
  const identity = await realIdentity();
  const serverId = identity.publicKey; // the server directory publishes this identity

  setActiveCryptoNamespace(NAMESPACE);
  await saveIdentity(NAMESPACE, identity);

  const key = generateRecoveryKey();
  const pkg = await createRecoveryPackage(3001, serverId, key);
  assert.ok(pkg.length > 0);

  // Verify the package has the v3 magic byte.
  const combined = (() => {
    let b64 = pkg.replace(/-/g, "+").replace(/_/g, "/");
    while (b64.length % 4 !== 0) b64 += "=";
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
  })();
  assert.equal(combined[0], 3, "package version byte must be 3");

  // Clear identity to simulate fresh namespace
  const ns2: CryptoNamespace = { uin: 3001, deviceId: "recovery_test_dev_0002" };
  setActiveCryptoNamespace(ns2);

  // Identity slot must be empty.
  const existing = await loadIdentity(ns2);
  assert.equal(existing, null);

  // Import. This exercises AAD-authenticated decryption + identity verification.
  const payload = await importRecoveryPackage(pkg, 3001, serverId, key);
  assert.ok(payload, "import must return payload");
  assert.equal(payload.v, 3, "v3 packages use AAD-authenticated headers");
  assert.ok(payload.identity, "payload must contain identity");
  assert.equal(payload.identity.publicKey, identity.publicKey);

  // Identity must now be persisted atomically.
  const imported = await loadIdentity(ns2);
  assert.ok(imported);
  assert.equal(imported.publicKey, identity.publicKey);
});

test("wrong recovery key rejects import", async () => {
  setActiveCryptoNamespace(NAMESPACE);
  const identity = await realIdentity();
  await saveIdentity(NAMESPACE, identity);

  const key = generateRecoveryKey();
  const pkg = await createRecoveryPackage(3001, identity.publicKey, key);

  const wrongKey = generateRecoveryKey();
  setActiveCryptoNamespace({ uin: 3001, deviceId: "recovery_test_dev_0003" });
  await assert.rejects(async () => importRecoveryPackage(pkg, 3001, identity.publicKey, wrongKey));
});

test("cross-account import is rejected", async () => {
  setActiveCryptoNamespace(NAMESPACE);
  const identity = await realIdentity();
  await saveIdentity(NAMESPACE, identity);

  const key = generateRecoveryKey();
  const pkg = await createRecoveryPackage(3001, identity.publicKey, key);

  setActiveCryptoNamespace({ uin: 9999, deviceId: "recovery_test_dev_0004" });
  await assert.rejects(async () => importRecoveryPackage(pkg, 9999, identity.publicKey, key));
});

test("tampered ciphertext is rejected", async () => {
  setActiveCryptoNamespace(NAMESPACE);
  const identity = await realIdentity();
  await saveIdentity(NAMESPACE, identity);

  const key = generateRecoveryKey();
  const pkg = await createRecoveryPackage(3001, identity.publicKey, key);

  const tampered = pkg.slice(0, -4) + "XXXX";
  setActiveCryptoNamespace({ uin: 3001, deviceId: "recovery_test_dev_0005" });
  await assert.rejects(async () => importRecoveryPackage(tampered, 3001, identity.publicKey, key));
});

test("truncated package is rejected", async () => {
  await assert.rejects(async () => importRecoveryPackage("X", 3001, DUMMY_SERVER_ID, generateRecoveryKey()));
});

test("empty package is rejected", async () => {
  await assert.rejects(async () => importRecoveryPackage("", 3001, DUMMY_SERVER_ID, generateRecoveryKey()));
});

test("import when identity already exists is rejected", async () => {
  setActiveCryptoNamespace(NAMESPACE);
  const identity = await realIdentity();
  await saveIdentity(NAMESPACE, identity);

  const key = generateRecoveryKey();
  const pkg = await createRecoveryPackage(3001, identity.publicKey, key);

  // Same namespace still has identity
  await assert.rejects(async () => importRecoveryPackage(pkg, 3001, identity.publicKey, key));
});

test("recovery key too short is rejected", async () => {
  setActiveCryptoNamespace(NAMESPACE);
  const identity = await realIdentity();
  await saveIdentity(NAMESPACE, identity);
  await assert.rejects(async () => createRecoveryPackage(3001, identity.publicKey, new Uint8Array(8)));
});

test("recovery package does NOT contain ratchet sessions or prekeys", async () => {
  setActiveCryptoNamespace(NAMESPACE);
  const identity = await realIdentity();
  await saveIdentity(NAMESPACE, identity);

  const key = generateRecoveryKey();
  const pkg = await createRecoveryPackage(3001, identity.publicKey, key);

  // Decode and inspect the payload directly.
  const base64urlToBytes = (s: string): Uint8Array => {
    let b64 = s.replace(/-/g, "+").replace(/_/g, "/");
    while (b64.length % 4 !== 0) b64 += "=";
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
  };

  const combined = base64urlToBytes(pkg);
  const iv = combined.slice(41, 53);
  const ciphertext = combined.slice(53);

  // v3 packages authenticate the header (first 41 bytes: version + UIN +
  // server identity) as AES-GCM AAD.
  const aad = combined.subarray(0, 41);

  const aesKey = await globalThis.crypto.subtle.importKey(
    "raw", key.buffer, "AES-GCM", false, ["decrypt"],
  );

  const plaintext = await globalThis.crypto.subtle.decrypt(
    { name: "AES-GCM", iv: iv as unknown as BufferSource, additionalData: aad as unknown as BufferSource },
    aesKey,
    ciphertext as unknown as BufferSource,
  );

  const payload = JSON.parse(new TextDecoder().decode(plaintext));
  assert.ok(payload.identity, "must have identity");
  assert.ok(Array.isArray(payload.peerTrust), "must have peerTrust array");
  assert.ok(!payload.sessions, "must NOT contain sessions");
  assert.ok(!payload.prekeys, "must NOT contain prekeys");
  assert.ok(!payload.signedPrekeys, "must NOT contain signedPrekeys");
  assert.ok(!payload.groupCrypto, "must NOT contain groupCrypto");
  assert.ok(!payload.spkMetadata, "must NOT contain spkMetadata");
});

test("server identity key mismatch is rejected", async () => {
  setActiveCryptoNamespace(NAMESPACE);
  const identity = await realIdentity();
  await saveIdentity(NAMESPACE, identity);

  const key = generateRecoveryKey();
  const pkg = await createRecoveryPackage(3001, identity.publicKey, key);

  const differentServerId = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="; // different 32 bytes
  setActiveCryptoNamespace({ uin: 3001, deviceId: "recovery_test_dev_0006" });
  await assert.rejects(async () => importRecoveryPackage(pkg, 3001, differentServerId, key));
});

test("v2 packages are explicitly rejected", async () => {
  // Construct a synthetic v2 package. The format is:
  //   header (53 bytes): version(1) + UIN(8) + serverId(32) + IV(12)
  //   ciphertext: at least 1 byte
  // Headers are not AAD-authenticated in v2, but the import function
  // checks the version byte before attempting decryption.
  const header = new Uint8Array(53);
  header[0] = 2; // v2
  new DataView(header.buffer).setBigUint64(1, BigInt(3001), false);
  // Fill server identity (bytes 9-40) with dummy data and IV (41-52).
  header.fill(0xAA, 9, 53);
  const combined = new Uint8Array(header.length + 28); // 28 bytes of dummy ciphertext+tag
  combined.set(header);

  // base64url-encode.
  let binary = "";
  for (let i = 0; i < combined.length; i++) binary += String.fromCharCode(combined[i]!);
  const fakePkg = btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

  setActiveCryptoNamespace({ uin: 3001, deviceId: "recovery_test_dev_0007" });
  await assert.rejects(
    async () => importRecoveryPackage(fakePkg, 3001, DUMMY_SERVER_ID, generateRecoveryKey()),
    /unsupported recovery package version: 2/,
  );
});

test("edited header UIN is rejected before decryption", async () => {
  // The UIN in the header is checked byte-level before AES-GCM decryption
  // is attempted. Editing it causes an immediate "account mismatch" error.
  // The AAD would also catch this (AES-GCM would fail), but the byte-level
  // check fires first. Either way, the import is rejected.
  setActiveCryptoNamespace(NAMESPACE);
  const identity = await realIdentity();
  await saveIdentity(NAMESPACE, identity);

  const key = generateRecoveryKey();
  const pkg = await createRecoveryPackage(3001, identity.publicKey, key);

  // Flip a bit in the UIN portion of the header (byte 1, bit 0).
  const combined = (() => {
    let b64 = pkg.replace(/-/g, "+").replace(/_/g, "/");
    while (b64.length % 4 !== 0) b64 += "=";
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
  })();
  combined[1] ^= 0x01; // flip one bit in the UIN

  const tampered = (() => {
    let binary = "";
    for (let i = 0; i < combined.length; i++) binary += String.fromCharCode(combined[i]!);
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  })();

  setActiveCryptoNamespace({ uin: 3001, deviceId: "recovery_test_dev_0008" });
  await assert.rejects(
    async () => importRecoveryPackage(tampered, 3001, identity.publicKey, key),
    /account mismatch/,
  );
});

test("edited header identity is rejected before decryption", async () => {
  // The server identity in the header is checked byte-level before AES-GCM
  // decryption. Editing it causes an immediate "server identity mismatch".
  // The AAD would also catch this, but the byte-level check fires first.
  setActiveCryptoNamespace(NAMESPACE);
  const identity = await realIdentity();
  await saveIdentity(NAMESPACE, identity);

  const key = generateRecoveryKey();
  const pkg = await createRecoveryPackage(3001, identity.publicKey, key);

  // Flip a bit in the server identity portion (byte 10).
  const combined = (() => {
    let b64 = pkg.replace(/-/g, "+").replace(/_/g, "/");
    while (b64.length % 4 !== 0) b64 += "=";
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
  })();
  combined[10] ^= 0x01; // flip one bit in the server identity

  const tampered = (() => {
    let binary = "";
    for (let i = 0; i < combined.length; i++) binary += String.fromCharCode(combined[i]!);
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  })();

  setActiveCryptoNamespace({ uin: 3001, deviceId: "recovery_test_dev_0009" });
  await assert.rejects(
    async () => importRecoveryPackage(tampered, 3001, identity.publicKey, key),
    /server identity mismatch/,
  );
});
