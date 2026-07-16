import { trackObjectURL, untrackObjectURL } from "./localDataCleanup";

export type FileEncryptionAlgorithm = "AES-256-GCM";

export interface EncryptedFileManifest {
  version: 1;
  algorithm: FileEncryptionAlgorithm;
  key: string;
  nonce: string;
  mime_type: string;
  size: number;
  name?: string;
}

export interface EncryptedFileBlob {
  encryptedBlob: Blob;
  manifest: EncryptedFileManifest;
}

const MANIFEST_VERSION = 1;
const ALGORITHM: FileEncryptionAlgorithm = "AES-256-GCM";
const KEY_LENGTH_BITS = 256;
const NONCE_LENGTH_BYTES = 12;
const FALLBACK_MIME = "application/octet-stream";
export const MAX_ENCRYPTED_FILE_BYTES = 25 * 1024 * 1024;

export function assertAcceptableFileSize(size: number): void {
  if (!Number.isSafeInteger(size) || size < 0) throw new Error("invalid file size");
  if (size > MAX_ENCRYPTED_FILE_BYTES) throw new Error("file is too large");
}

export async function encryptFileBlob(blob: Blob, displayName: string | undefined, objectKey: string): Promise<EncryptedFileBlob> {
  assertAcceptableFileSize(blob.size);
  assertCanonicalObjectKey(objectKey);
  const mimeType = normalizeMimeType(blob.type);
  const name = sanitizeDisplayName(displayName);
  const key = await globalThis.crypto.subtle.generateKey(
    { name: "AES-GCM", length: KEY_LENGTH_BITS },
    true,
    ["encrypt", "decrypt"],
  );
  const nonce = new Uint8Array(NONCE_LENGTH_BYTES);
  globalThis.crypto.getRandomValues(nonce);

  const plaintext = await blob.arrayBuffer();
  const ciphertext = await globalThis.crypto.subtle.encrypt(
    { name: "AES-GCM", iv: nonce, additionalData: manifestAAD(objectKey, mimeType, blob.size, name) },
    key,
    plaintext,
  );
  const rawKey = await globalThis.crypto.subtle.exportKey("raw", key);

  return {
    encryptedBlob: new Blob([ciphertext], { type: FALLBACK_MIME }),
    manifest: {
      version: MANIFEST_VERSION,
      algorithm: ALGORITHM,
      key: arrayBufferToB64Url(rawKey),
      nonce: arrayBufferToB64Url(nonce.buffer),
      mime_type: mimeType,
      size: blob.size,
      ...(name ? { name } : {}),
    },
  };
}

export async function decryptFileBlob(
  encryptedBlob: Blob,
  manifest: EncryptedFileManifest,
  objectKey: string,
): Promise<Blob> {
  assertCanonicalObjectKey(objectKey);
  if (!isEncryptedFileManifest(manifest)) {
    throw new Error("invalid encrypted file manifest");
  }
  const key = await globalThis.crypto.subtle.importKey(
    "raw",
    b64UrlToArrayBuffer(manifest.key),
    { name: "AES-GCM", length: KEY_LENGTH_BITS },
    false,
    ["decrypt"],
  );
  const plaintext = await globalThis.crypto.subtle.decrypt(
    { name: "AES-GCM", iv: b64UrlToArrayBuffer(manifest.nonce), additionalData: manifestAAD(objectKey, manifest.mime_type, manifest.size, manifest.name) },
    key,
    await encryptedBlob.arrayBuffer(),
  );
  if (plaintext.byteLength !== manifest.size) throw new Error("decrypted file size does not match manifest");
  return new Blob([plaintext], { type: manifest.mime_type });
}

export async function withObjectUrl<T>(blob: Blob, use: (url: string) => Promise<T> | T): Promise<T> {
  const url = URL.createObjectURL(blob);
  trackObjectURL(url);
  try { return await use(url); } finally { untrackObjectURL(url); URL.revokeObjectURL(url); }
}

export function isEncryptedFileManifest(value: unknown): value is EncryptedFileManifest {
  if (!value || typeof value !== "object") return false;
  const m = value as Partial<EncryptedFileManifest>;
  return m.version === MANIFEST_VERSION
    && m.algorithm === ALGORITHM
    && typeof m.key === "string"
    && b64UrlByteLength(m.key) === 32
    && typeof m.nonce === "string"
    && b64UrlByteLength(m.nonce) === NONCE_LENGTH_BYTES
    && typeof m.mime_type === "string"
    && isStrictMimeType(m.mime_type)
    && typeof m.size === "number"
    && Number.isSafeInteger(m.size)
    && m.size >= 0
    && m.size <= MAX_ENCRYPTED_FILE_BYTES
    && (m.name === undefined || (typeof m.name === "string" && sanitizeDisplayName(m.name) === m.name));
}

export function assertCanonicalObjectKey(value: string): void {
  if (value.length < 3 || value.length > 512 || !/^[A-Za-z0-9][A-Za-z0-9._/-]*$/.test(value)
      || value.includes("//") || value.split("/").some((part) => part === "." || part === ".." || part.length === 0)) {
    throw new Error("invalid object key");
  }
}

export function assertSafeDownloadMetadata(objectKey: string, name: string): void {
  assertCanonicalObjectKey(objectKey);
  if (sanitizeDisplayName(name) !== name) throw new Error("invalid file name");
}

export function serializeEncryptedFileManifest(manifest: EncryptedFileManifest): string {
  if (!isEncryptedFileManifest(manifest)) {
    throw new Error("invalid encrypted file manifest");
  }
  return JSON.stringify(manifest);
}

export function parseEncryptedFileManifest(raw: string): EncryptedFileManifest {
  const parsed = JSON.parse(raw) as unknown;
  if (!isEncryptedFileManifest(parsed)) {
    throw new Error("invalid encrypted file manifest");
  }
  return parsed;
}

function normalizeMimeType(type: string): string {
  const trimmed = type.trim().toLowerCase();
  if (!isStrictMimeType(trimmed)) {
    return FALLBACK_MIME;
  }
  return trimmed;
}

function sanitizeDisplayName(name?: string): string | undefined {
  if (!name) return undefined;
  const normalized = name.replace(/\\/g, "/").split("/").filter(Boolean).pop()?.trim()
    .replace(/[\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/g, "")
    .replace(/[. ]+$/g, "");
  if (!normalized || normalized === "." || normalized === "..") return undefined;
  const bounded = normalized.slice(0, 120);
  const stem = bounded.split(".")[0]!.toUpperCase();
  if (/^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])$/.test(stem)) return undefined;
  return bounded;
}

function isStrictMimeType(value: string): boolean {
  return value.length <= 127 && /^[a-z0-9][a-z0-9!#$&^_.+-]{0,62}\/[a-z0-9][a-z0-9!#$&^_.+-]{0,62}$/.test(value);
}

function manifestAAD(objectKey: string, mimeType: string, size: number, name?: string): ArrayBuffer {
  const encoded = new TextEncoder().encode(JSON.stringify([MANIFEST_VERSION, objectKey, mimeType, size, name ?? ""]));
  return encoded.buffer.slice(encoded.byteOffset, encoded.byteOffset + encoded.byteLength) as ArrayBuffer;
}

function arrayBufferToB64Url(buf: ArrayBuffer): string {
  const bytes = new Uint8Array(buf);
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]!);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function b64UrlToArrayBuffer(s: string): ArrayBuffer {
  const pad = "=".repeat((4 - (s.length % 4)) % 4);
  const b = atob(s.replace(/-/g, "+").replace(/_/g, "/") + pad);
  const out = new Uint8Array(b.length);
  for (let i = 0; i < b.length; i++) out[i] = b.charCodeAt(i);
  return out.buffer;
}

function b64UrlByteLength(s: string): number {
  if (!/^[A-Za-z0-9_-]+$/.test(s)) return -1;
  try {
    return b64UrlToArrayBuffer(s).byteLength;
  } catch {
    return -1;
  }
}
