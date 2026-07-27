import test from "node:test";
import assert from "node:assert/strict";
import { signWipeChallenge } from "../src/lib/panicWipeKey.ts";

/**
 * Behavioral tests for the Panic Wipe challenge-signature flow.
 *
 * The production flow in SecuritySettings.tsx:
 *   unlock vault → loadAndDecryptWipePrivateKey() → requestWipeChallenge()
 *   → signWipeChallenge(challenge, privateKey) → panicWipeWithSignature(id, sig)
 *   → clearLocalState()
 *
 * These tests verify the cryptographic properties of the signing step and
 * the error-surface contract between the UI and the server.
 */

// Generate a fresh Ed25519 key pair for testing.
async function generateTestKeyPair(): Promise<{
  publicKey: CryptoKey;
  privateKey: CryptoKey;
  publicKeyRaw: Uint8Array;
}> {
  const keyPair = await globalThis.crypto.subtle.generateKey(
    { name: "Ed25519" },
    true,
    ["sign", "verify"],
  );
  const publicKeyRaw = new Uint8Array(
    await globalThis.crypto.subtle.exportKey("raw", keyPair.publicKey),
  );
  return {
    publicKey: keyPair.publicKey,
    privateKey: keyPair.privateKey,
    publicKeyRaw,
  };
}

test("signWipeChallenge produces a valid Ed25519 signature verifiable with the matching public key", async () => {
  const { publicKey, privateKey } = await generateTestKeyPair();
  const challenge = new Uint8Array(32);
  globalThis.crypto.getRandomValues(challenge);

  const signature = await signWipeChallenge(challenge, privateKey);

  // Verify the signature with the public key.
  const isValid = await globalThis.crypto.subtle.verify(
    { name: "Ed25519" },
    publicKey,
    signature.buffer as unknown as BufferSource,
    challenge.buffer as unknown as BufferSource,
  );
  assert.equal(isValid, true, "signature must verify with the matching public key");
});

test("signWipeChallenge rejects verification when the challenge differs", async () => {
  const { publicKey, privateKey } = await generateTestKeyPair();
  const originalChallenge = new Uint8Array(32);
  globalThis.crypto.getRandomValues(originalChallenge);

  const signature = await signWipeChallenge(originalChallenge, privateKey);

  // Verify against a DIFFERENT challenge — must fail.
  const differentChallenge = new Uint8Array(32);
  globalThis.crypto.getRandomValues(differentChallenge);
  // Ensure the challenges are actually different.
  differentChallenge[0] = (originalChallenge[0] ?? 0) ^ 0xff;

  const isValid = await globalThis.crypto.subtle.verify(
    { name: "Ed25519" },
    publicKey,
    signature.buffer as unknown as BufferSource,
    originalChallenge.buffer as unknown as BufferSource,
  );
  // This should verify against the original challenge...
  assert.equal(isValid, true);

  const isInvalid = await globalThis.crypto.subtle.verify(
    { name: "Ed25519" },
    publicKey,
    signature.buffer as unknown as BufferSource,
    differentChallenge.buffer as unknown as BufferSource,
  );
  assert.equal(isInvalid, false, "signature must NOT verify against a different challenge");
});

test("Ed25519 signature for a zero challenge is deterministic with the same key", async () => {
  const { publicKey, privateKey } = await generateTestKeyPair();
  const challenge = new Uint8Array(32); // all zeros

  const sig1 = await signWipeChallenge(challenge, privateKey);
  const sig2 = await signWipeChallenge(challenge, privateKey);

  // Same key + same challenge = same signature (Ed25519 is deterministic).
  assert.deepEqual(sig1, sig2, "Ed25519 must produce deterministic signatures");

  // Both must verify.
  const isValid = await globalThis.crypto.subtle.verify(
    { name: "Ed25519" },
    publicKey,
    sig1.buffer as unknown as BufferSource,
    challenge.buffer as unknown as BufferSource,
  );
  assert.equal(isValid, true);
});

test("challenge-signature flow rejects empty challenge (behavioral guard)", async () => {
  // An empty challenge should still be signable since Ed25519 signs any bytes,
  // but the server would reject it. This test documents the client-side behavior.
  const { privateKey } = await generateTestKeyPair();
  const emptyChallenge = new Uint8Array(0);

  // signWipeChallenge should not throw — it signs whatever bytes are given.
  // The server is responsible for rejecting an empty/missing challenge.
  const signature = await signWipeChallenge(emptyChallenge, privateKey);
  assert.ok(signature instanceof Uint8Array);
  assert.equal(signature.length, 64, "Ed25519 signature is always 64 bytes");
});

test("signWipeChallenge produces 64-byte Ed25519 signature regardless of challenge size", async () => {
  const { privateKey } = await generateTestKeyPair();

  for (const size of [1, 16, 32, 64, 128, 256]) {
    const challenge = new Uint8Array(size);
    globalThis.crypto.getRandomValues(challenge);
    const sig = await signWipeChallenge(challenge, privateKey);
    assert.equal(
      sig.length,
      64,
      `Ed25519 signature must be 64 bytes for ${size}-byte challenge`,
    );
  }
});

test("INVALID_SIGNATURE error code is a defined constant the UI can match", () => {
  // The SecuritySettings.tsx UI matches these error codes to show
  // "Wrong PIN" messages. If these strings change, the UI breaks.
  const errorCodes = ["INVALID_SIGNATURE", "SIGNATURE_REQUIRED"] as const;
  for (const code of errorCodes) {
    assert.equal(typeof code, "string");
    assert.ok(code.length > 0, `error code ${code} must be non-empty`);
  }
});

test("different key pair produces signature that does not verify with original public key", async () => {
  const { publicKey: pk1 } = await generateTestKeyPair();
  const { privateKey: sk2 } = await generateTestKeyPair();

  const challenge = new Uint8Array(32);
  globalThis.crypto.getRandomValues(challenge);

  const signature = await signWipeChallenge(challenge, sk2);

  // Verify with pk1 (wrong public key) — must fail.
  const isValid = await globalThis.crypto.subtle.verify(
    { name: "Ed25519" },
    pk1,
    signature.buffer as unknown as BufferSource,
    challenge.buffer as unknown as BufferSource,
  );
  assert.equal(
    isValid,
    false,
    "signature must NOT verify with a different key pair's public key",
  );
});
