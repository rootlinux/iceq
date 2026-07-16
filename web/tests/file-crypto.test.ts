import test from "node:test";
import assert from "node:assert/strict";
import { Blob } from "node:buffer";
import { webcrypto } from "node:crypto";

import {
  decryptFileBlob,
  encryptFileBlob,
  isEncryptedFileManifest,
} from "../src/lib/fileCrypto.ts";

Object.defineProperty(globalThis, "crypto", {
  value: webcrypto,
  configurable: true,
});

test("encryptFileBlob returns opaque ciphertext and a decryptable manifest", async () => {
  const plaintext = new Blob(["iceq secret file"], { type: "text/plain" });

  const encrypted = await encryptFileBlob(plaintext, "notes.txt", "uin/7/notes");

  assert.equal(encrypted.encryptedBlob.type, "application/octet-stream");
  assert.equal(encrypted.manifest.version, 1);
  assert.equal(encrypted.manifest.algorithm, "AES-256-GCM");
  assert.equal(encrypted.manifest.mime_type, "text/plain");
  assert.equal(encrypted.manifest.size, plaintext.size);
  assert.equal(encrypted.manifest.name, "notes.txt");
  assert.ok(isEncryptedFileManifest(encrypted.manifest));

  const cipherText = await encrypted.encryptedBlob.text();
  assert.notEqual(cipherText, "iceq secret file");

  const decrypted = await decryptFileBlob(encrypted.encryptedBlob, encrypted.manifest, "uin/7/notes");
  assert.equal(decrypted.type, "text/plain");
  assert.equal(await decrypted.text(), "iceq secret file");
});

test("encryptFileBlob does not preserve unsafe display paths", async () => {
  const plaintext = new Blob(["x"], { type: "" });

  const encrypted = await encryptFileBlob(plaintext, "../private/secret.txt", "uin/7/secret");

  assert.equal(encrypted.manifest.name, "secret.txt");
  assert.equal(encrypted.manifest.mime_type, "application/octet-stream");
});
