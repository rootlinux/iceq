import test from "node:test";
import assert from "node:assert/strict";
import { Blob } from "node:buffer";
import { webcrypto } from "node:crypto";

import {
  decryptFileBlob,
  encryptFileBlob,
  isEncryptedFileManifest,
  MAX_ENCRYPTED_FILE_BYTES,
  withObjectUrl,
} from "../src/lib/fileCrypto.ts";

Object.defineProperty(globalThis, "crypto", { value: webcrypto, configurable: true });

test("rejects an oversized file before reading or encrypting it", async () => {
  let read = false;
  const blob = { size: MAX_ENCRYPTED_FILE_BYTES + 1, type: "text/plain", arrayBuffer: async () => { read = true; return new ArrayBuffer(0); } } as Blob;
  await assert.rejects(() => encryptFileBlob(blob, "large.txt", "uin/7/object"), /too large/i);
  assert.equal(read, false);
});

test("AAD binds object key, MIME, size and sanitized name", async () => {
  const encrypted = await encryptFileBlob(new Blob(["secret"], { type: "text/plain" }), "../secret.txt", "uin/7/object");
  assert.equal(encrypted.manifest.name, "secret.txt");
  assert.equal(await (await decryptFileBlob(encrypted.encryptedBlob, encrypted.manifest, "uin/7/object")).text(), "secret");
  await assert.rejects(() => decryptFileBlob(encrypted.encryptedBlob, encrypted.manifest, "uin/7/other"));
  await assert.rejects(() => decryptFileBlob(encrypted.encryptedBlob, { ...encrypted.manifest, mime_type: "image/png" }, "uin/7/object"));
  await assert.rejects(() => decryptFileBlob(encrypted.encryptedBlob, { ...encrypted.manifest, size: 5 }, "uin/7/object"));
  const tampered = new Uint8Array(await encrypted.encryptedBlob.arrayBuffer());
  tampered[0] ^= 1;
  await assert.rejects(() => decryptFileBlob(new Blob([tampered]), encrypted.manifest, "uin/7/object"));
  await assert.rejects(() => decryptFileBlob(encrypted.encryptedBlob, { ...encrypted.manifest, key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" }, "uin/7/object"));
});

test("object URL is always revoked", async () => {
  const revoked: string[] = [];
  const previousURL = globalThis.URL;
  Object.defineProperty(globalThis, "URL", { value: { createObjectURL: () => "blob:test", revokeObjectURL: (url: string) => revoked.push(url) }, configurable: true });
  try {
    await assert.rejects(() => withObjectUrl(new Blob(["x"]), async () => { throw new Error("download failed"); }));
    assert.deepEqual(revoked, ["blob:test"]);
  } finally {
    Object.defineProperty(globalThis, "URL", { value: previousURL, configurable: true });
  }
});

test("rejects unsafe received names and oversized manifest metadata", () => {
  const base = { version: 1 as const, algorithm: "AES-256-GCM" as const, key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", nonce: "AAAAAAAAAAAAAAAA", mime_type: "text/plain", size: 1 };
  assert.equal(isEncryptedFileManifest({ ...base, name: "../escape.txt" }), false);
  assert.equal(isEncryptedFileManifest({ ...base, size: MAX_ENCRYPTED_FILE_BYTES + 1 }), false);
});
