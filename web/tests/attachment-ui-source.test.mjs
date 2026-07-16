import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));
const read = (path) => readFileSync(resolve(__dirname, "..", path), "utf8");

test("message input sends direct-message attachments as Signal-encrypted manifests", () => {
  const input = read("src/components/Chat/MessageInput.tsx");

  assert.match(input, /uploadEncryptedFile/);
  assert.match(input, /type="file"/);
  assert.match(input, /handleAttachment/);
  assert.match(input, /kind:\s*"iceq\.attachment\.v1"/);
  assert.match(input, /JSON\.stringify\(\s*attachmentEnvelope/);
  assert.match(input, /encryptMessage\(peerUin as number,\s*encoder\.encode\(attachmentPlaintext\)\)/);
  assert.match(input, /content_type:\s*"file"/);
  assert.match(input, /await attachmentGrantLifecycle\.prepare\(clientId, uploaded\.object_key, peerUin as number\)/);
  assert.match(input, /await attachmentGrantLifecycle\.fail\(clientId\)/);
  assert.match(input, /if \(!send\(\{/);
  assert.doesNotMatch(input, /file_url:\s*upload\.upload_url/);
});

test("message item renders encrypted attachments with a decrypting download action", () => {
  const item = read("src/components/Chat/MessageItem.tsx");

  assert.match(item, /downloadEncryptedFile/);
  assert.match(item, /parseAttachment/);
  assert.match(item, /content_type === "file"/);
  assert.match(item, /withObjectUrl/);
  assert.match(item, /download=\{attachment\.name/);
  assert.match(item, /chat\.download/);
  assert.match(item, /chat\.attachmentUnavailable/);
  assert.match(item, /assertSafeDownloadMetadata/);
});

test("message model carries parsed encrypted attachment metadata separately from plaintext", () => {
  const model = read("src/types/models.ts");

  assert.match(model, /export interface MessageAttachment/);
  assert.match(model, /object_key: string/);
  assert.match(model, /manifest: EncryptedFileManifest/);
  assert.match(model, /attachment\?: MessageAttachment/);
});
