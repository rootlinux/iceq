import test from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import { readFileSync } from "node:fs";
import "fake-indexeddb/auto";

import {
  generateIdentityKeyPair,
  generatePreKeyBundle,
  verifySignedPreKeyBundle,
} from "../src/lib/signal.ts";

Object.defineProperty(globalThis, "crypto", { value: webcrypto, configurable: true });

async function bundle() {
  const identity = await generateIdentityKeyPair();
  return generatePreKeyBundle(identity, 1, 1, 7);
}

test("accepts an authentic signed prekey", async () => {
  assert.equal(await verifySignedPreKeyBundle(await bundle()), true);
});

test("rejects modified signed prekey, signature, and mismatched identity", async () => {
  const original = await bundle();
  const other = await bundle();
  const changedKey = structuredClone(original);
  changedKey.signed_pre_key.public_key = other.signed_pre_key.public_key;
  const changedSignature = structuredClone(original);
  changedSignature.signed_pre_key.signature = other.signed_pre_key.signature;
  const changedIdentity = structuredClone(original);
  changedIdentity.identity_key = other.identity_key;

  await assert.rejects(() => verifySignedPreKeyBundle(changedKey), /signed prekey/i);
  await assert.rejects(() => verifySignedPreKeyBundle(changedSignature), /signed prekey/i);
  await assert.rejects(() => verifySignedPreKeyBundle(changedIdentity), /signed prekey/i);
});

test("session bootstrap verifies the signed prekey before constructing SessionBuilder", () => {
  const source = readFileSync(new URL("../src/lib/signal.ts", import.meta.url), "utf8");
  const seed = source.slice(source.indexOf("async function seedSessionFromBundle"));
  assert.ok(seed.indexOf("await verifySignedPreKeyBundle(remote)") >= 0);
  assert.ok(seed.indexOf("await verifySignedPreKeyBundle(remote)") < seed.indexOf("new runtime.SessionBuilder"));
});
