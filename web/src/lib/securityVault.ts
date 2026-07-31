import { argon2id } from "hash-wasm";
import {
  getActiveCryptoNamespace,
  saveSecurityVaultSalt,
  loadSecurityVaultSalt,
  saveSecurityVaultBlob,
  loadSecurityVaultBlob,
} from "./indexeddb";

const SALT_BYTES = 32;
const VERIFICATION_TOKEN_BYTES = 32;
const KEY_BYTES = 32;

const MIN_PASSPHRASE_LENGTH = 12;

const ARGON2_MEMORY = 65536;
const ARGON2_ITERATIONS = 3;
const ARGON2_PARALLELISM = 4;

const VERIFICATION_PREFIX = new TextEncoder().encode("iceq-vault-v2:");

let vaultKey: CryptoKey | null = null;

function assertPassphrasePolicy(passphrase: string): void {
  if (!passphrase || passphrase.length < MIN_PASSPHRASE_LENGTH) {
    throw new Error(`passphrase must be at least ${MIN_PASSPHRASE_LENGTH} characters`);
  }
  if (!/[A-Z]/.test(passphrase) && !/[0-9]/.test(passphrase) && !/[^A-Za-z0-9]/.test(passphrase)) {
    throw new Error("passphrase must contain at least one non-lowercase character (uppercase, digit, or symbol)");
  }
}

async function deriveKey(passphrase: string, salt: Uint8Array): Promise<Uint8Array> {
  return argon2id({
    password: passphrase,
    salt,
    parallelism: ARGON2_PARALLELISM,
    iterations: ARGON2_ITERATIONS,
    memorySize: ARGON2_MEMORY,
    hashLength: KEY_BYTES,
    outputType: "binary",
  });
}

async function importDerivedKey(keyBytes: Uint8Array, usages: KeyUsage[]): Promise<CryptoKey> {
  return globalThis.crypto.subtle.importKey(
    "raw",
    keyBytes.buffer as unknown as BufferSource,
    { name: "AES-GCM", length: 256 },
    false,
    usages,
  );
}

export async function createSecurityPassphrase(passphrase: string): Promise<void> {
  assertPassphrasePolicy(passphrase);

  // Refuse to overwrite an existing vault. Overwriting would change the
  // salt and verification blob, orphaning any encrypted Panic Wipe private
  // key already stored in IndexedDB under the old vault key. There is no
  // automatic reset or recovery path here — if a legitimate vault-reset is
  // ever needed, it must be a separate, explicit, authenticated operation.
  const ns = getActiveCryptoNamespace();
  if (await hasSecurityPassphrase()) {
    throw new Error("security vault already exists — cannot overwrite");
  }

  const salt = new Uint8Array(SALT_BYTES);
  globalThis.crypto.getRandomValues(salt);

  const keyBytes = await deriveKey(passphrase, salt);
  const derived = await importDerivedKey(keyBytes, ["encrypt", "decrypt"]);

  const verificationToken = new Uint8Array(VERIFICATION_TOKEN_BYTES);
  globalThis.crypto.getRandomValues(verificationToken);
  const verificationPlaintext = new Uint8Array(VERIFICATION_PREFIX.length + verificationToken.length);
  verificationPlaintext.set(VERIFICATION_PREFIX);
  verificationPlaintext.set(verificationToken, VERIFICATION_PREFIX.length);

  const iv = new Uint8Array(12);
  globalThis.crypto.getRandomValues(iv);

  const ciphertext = await globalThis.crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv.buffer as unknown as BufferSource },
    derived,
    verificationPlaintext.buffer as unknown as BufferSource,
  );

  const blob = encodeVaultBlob(iv, new Uint8Array(ciphertext));

  await saveSecurityVaultSalt(ns, bytesToBase64url(salt));
  await saveSecurityVaultBlob(ns, blob);

  vaultKey = derived;
}

export async function unlockSecurityVault(passphrase: string): Promise<boolean> {
  const ns = getActiveCryptoNamespace();
  const saltRecord = await loadSecurityVaultSalt(ns);
  const vaultRecord = await loadSecurityVaultBlob(ns);
  if (!saltRecord || !vaultRecord || !saltRecord.salt || !vaultRecord.blob) return false;

  const salt = base64urlToBytes(saltRecord.salt);
  const { iv, ciphertext } = decodeVaultBlob(vaultRecord.blob);

  let keyBytes: Uint8Array;
  try {
    keyBytes = await deriveKey(passphrase, salt);
  } catch {
    return false;
  }

  let derived: CryptoKey;
  try {
    derived = await importDerivedKey(keyBytes, ["encrypt", "decrypt"]);
  } catch {
    return false;
  }

  try {
    const plaintext = await globalThis.crypto.subtle.decrypt(
      { name: "AES-GCM", iv: iv.buffer as unknown as BufferSource },
      derived,
      ciphertext.buffer as unknown as BufferSource,
    );

    const expectedPrefix = VERIFICATION_PREFIX;
    const pt = new Uint8Array(plaintext);
    for (let i = 0; i < expectedPrefix.length; i++) {
      if (pt[i] !== expectedPrefix[i]) return false;
    }
    if (pt.length !== expectedPrefix.length + VERIFICATION_TOKEN_BYTES) return false;

    vaultKey = derived;
    return true;
  } catch {
    return false;
  }
}

export function getVaultKey(): CryptoKey | null {
  return vaultKey;
}

export function lockSecurityVault(): void {
  vaultKey = null;
}

export function isVaultUnlocked(): boolean {
  return vaultKey !== null;
}

export async function hasSecurityPassphrase(): Promise<boolean> {
  try {
    const ns = getActiveCryptoNamespace();
    const saltRecord = await loadSecurityVaultSalt(ns);
    const vaultRecord = await loadSecurityVaultBlob(ns);
    return !!(saltRecord && vaultRecord && saltRecord.salt && vaultRecord.blob);
  } catch {
    return false;
  }
}

function encodeVaultBlob(iv: Uint8Array, ciphertext: Uint8Array): string {
  const combined = new Uint8Array(1 + iv.length + ciphertext.length);
  combined[0] = iv.length;
  combined.set(iv, 1);
  combined.set(ciphertext, 1 + iv.length);
  return bytesToBase64url(combined);
}

function decodeVaultBlob(blob: string): { iv: Uint8Array; ciphertext: Uint8Array } {
  const combined = base64urlToBytes(blob);
  if (combined.length < 2) throw new Error("truncated vault blob");
  const ivLen = combined[0]!;
  if (combined.length < 1 + ivLen + 1) throw new Error("truncated vault blob");
  const iv = combined.slice(1, 1 + ivLen);
  const ciphertext = combined.slice(1 + ivLen);
  return { iv, ciphertext };
}

function bytesToBase64url(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]!);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64urlToBytes(s: string): Uint8Array {
  let b64 = s.replace(/-/g, "+").replace(/_/g, "/");
  while (b64.length % 4 !== 0) b64 += "=";
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}
