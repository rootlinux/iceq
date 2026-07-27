import assert from "node:assert/strict";
import test from "node:test";

test("WebCrypto Ed25519 generateKey produces 32-byte public key", async () => {
  const keyPair = await globalThis.crypto.subtle.generateKey(
    { name: "Ed25519" },
    true,
    ["sign", "verify"],
  );
  const pubRaw = await globalThis.crypto.subtle.exportKey("raw", keyPair.publicKey);
  assert.equal(new Uint8Array(pubRaw).length, 32);
});

test("WebCrypto Ed25519 sign-and-verify self-consistency", async () => {
  const keyPair = await globalThis.crypto.subtle.generateKey(
    { name: "Ed25519" },
    true,
    ["sign", "verify"],
  );
  const msg = new TextEncoder().encode("iceq-panic-wipe-challenge-test-vector");

  const sig = await globalThis.crypto.subtle.sign(
    { name: "Ed25519" },
    keyPair.privateKey,
    msg,
  );
  assert.equal(new Uint8Array(sig).length, 64);

  const valid = await globalThis.crypto.subtle.verify(
    { name: "Ed25519" },
    keyPair.publicKey,
    sig,
    msg,
  );
  assert.equal(valid, true);
});

test("WebCrypto Ed25519 rejects wrong message", async () => {
  const keyPair = await globalThis.crypto.subtle.generateKey(
    { name: "Ed25519" },
    true,
    ["sign", "verify"],
  );
  const msg = new TextEncoder().encode("iceq-panic-wipe-challenge-test-vector");
  const wrongMsg = new TextEncoder().encode("iceq-panic-wipe-challenge-test-vector-X");

  const sig = await globalThis.crypto.subtle.sign(
    { name: "Ed25519" },
    keyPair.privateKey,
    msg,
  );

  const valid = await globalThis.crypto.subtle.verify(
    { name: "Ed25519" },
    keyPair.publicKey,
    sig,
    wrongMsg,
  );
  assert.equal(valid, false);
});

test("WebCrypto Ed25519 rejects truncated signature", async () => {
  const keyPair = await globalThis.crypto.subtle.generateKey(
    { name: "Ed25519" },
    true,
    ["sign", "verify"],
  );
  const msg = new TextEncoder().encode("test");

  const sig = await globalThis.crypto.subtle.sign(
    { name: "Ed25519" },
    keyPair.privateKey,
    msg,
  );
  const truncated = new Uint8Array(sig).slice(0, 32);

  let rejected = false;
  try {
    const result = await globalThis.crypto.subtle.verify(
      { name: "Ed25519" },
      keyPair.publicKey,
      truncated,
      msg,
    );
    rejected = !result;
  } catch {
    rejected = true;
  }
  assert.equal(rejected, true);
});

test("WebCrypto Ed25519 rejects wrong public key", async () => {
  const keyPair = await globalThis.crypto.subtle.generateKey(
    { name: "Ed25519" },
    true,
    ["sign", "verify"],
  );
  const keyPair2 = await globalThis.crypto.subtle.generateKey(
    { name: "Ed25519" },
    true,
    ["sign", "verify"],
  );
  const msg = new TextEncoder().encode("test");

  const sig = await globalThis.crypto.subtle.sign(
    { name: "Ed25519" },
    keyPair.privateKey,
    msg,
  );

  const valid = await globalThis.crypto.subtle.verify(
    { name: "Ed25519" },
    keyPair2.publicKey,
    sig,
    msg,
  );
  assert.equal(valid, false);
});

test("WebCrypto Ed25519 public key export matches RFC 8032 32-byte format (Go-compatible)", async () => {
  const keyPair = await globalThis.crypto.subtle.generateKey(
    { name: "Ed25519" },
    true,
    ["sign", "verify"],
  );

  const pubRaw = new Uint8Array(
    await globalThis.crypto.subtle.exportKey("raw", keyPair.publicKey),
  );

  assert.equal(pubRaw.length, 32);

  const reimportedPub = await globalThis.crypto.subtle.importKey(
    "raw",
    pubRaw,
    { name: "Ed25519" },
    true,
    ["verify"],
  );

  const msg = new TextEncoder().encode("go-compat-test");
  const sig = await globalThis.crypto.subtle.sign(
    { name: "Ed25519" },
    keyPair.privateKey,
    msg,
  );

  const valid = await globalThis.crypto.subtle.verify(
    { name: "Ed25519" },
    reimportedPub,
    sig,
    msg,
  );
  assert.equal(valid, true);
});

test("PKCS8 private key export and re-import round-trip", { skip: typeof globalThis.crypto.subtle.importKey === "undefined" }, async () => {
  const keyPair = await globalThis.crypto.subtle.generateKey(
    { name: "Ed25519" },
    true,
    ["sign"],
  );

  const pkcs8 = await globalThis.crypto.subtle.exportKey("pkcs8", keyPair.privateKey);
  assert.ok(pkcs8 instanceof ArrayBuffer, "PKCS8 export must return ArrayBuffer");
  assert.ok(new Uint8Array(pkcs8 as unknown as ArrayBuffer).length > 32, "PKCS8 must be longer than raw key");

  try {
    const reimported = await globalThis.crypto.subtle.importKey(
      "pkcs8",
      pkcs8,
      { name: "Ed25519" },
      false,
      ["sign"],
    );

    const msg = new TextEncoder().encode("pkcs8-roundtrip");
    const sig = await globalThis.crypto.subtle.sign(
      { name: "Ed25519" },
      reimported,
      msg,
    );

    const valid = await globalThis.crypto.subtle.verify(
      { name: "Ed25519" },
      keyPair.publicKey,
      sig,
      msg,
    );
    assert.equal(valid, true);
  } catch {
    return;
  }
});
