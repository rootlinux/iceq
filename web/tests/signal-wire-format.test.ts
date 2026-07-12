import test from "node:test";
import assert from "node:assert/strict";

import {
  encodePreKeyPublicKeyForWire,
  restoreSignalPublicKey,
} from "../src/lib/signal.js";

function decodeBase64Url(input: string): Uint8Array {
  const pad = "=".repeat((4 - (input.length % 4)) % 4);
  const value = atob(input.replace(/-/g, "+").replace(/_/g, "/") + pad);
  return Uint8Array.from(value, (char) => char.charCodeAt(0));
}

test("encodePreKeyPublicKeyForWire strips the Signal 0x05 prefix", () => {
  const prefixed = new Uint8Array(33);
  prefixed[0] = 0x05;
  for (let i = 1; i < prefixed.length; i++) prefixed[i] = i;

  const wire = encodePreKeyPublicKeyForWire(prefixed);
  const decoded = decodeBase64Url(wire);

  assert.equal(decoded.length, 32);
  assert.deepEqual(decoded, prefixed.slice(1));
});

test("encodePreKeyPublicKeyForWire preserves already-raw 32-byte keys", () => {
  const raw = new Uint8Array(32);
  for (let i = 0; i < raw.length; i++) raw[i] = i;

  const wire = encodePreKeyPublicKeyForWire(raw);
  const decoded = decodeBase64Url(wire);

  assert.equal(decoded.length, 32);
  assert.deepEqual(decoded, raw);
});

test("restoreSignalPublicKey re-adds the Signal 0x05 prefix for 32-byte wire keys", () => {
  const raw = new Uint8Array(32);
  for (let i = 0; i < raw.length; i++) raw[i] = i;

  const wire = encodePreKeyPublicKeyForWire(raw);
  const restored = new Uint8Array(restoreSignalPublicKey(wire));

  assert.equal(restored.length, 33);
  assert.equal(restored[0], 0x05);
  assert.deepEqual(restored.slice(1), raw);
});
