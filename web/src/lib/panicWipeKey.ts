import { getActiveCryptoNamespace, cryptoRecordKey } from "./indexeddb";
import { getVaultKey } from "./securityVault";
import { getWipePublicKey } from "../api/auth";

const WIPE_KEY_STORE = "metadata";
const WIPE_KEY_RECORD_SUFFIX = "panic_wipe_encrypted_private";

export async function generateWipeKeyPair(): Promise<{ publicKeyBytes: Uint8Array; encryptedPrivateBlob: string }> {
  const vaultKey = getVaultKey();
  if (!vaultKey) throw new Error("security vault is locked");

  const keyPair = await globalThis.crypto.subtle.generateKey(
    { name: "Ed25519" },
    true,
    ["sign", "verify"],
  );

  const publicKeyRaw = await globalThis.crypto.subtle.exportKey("raw", keyPair.publicKey);
  const privateKeyPkcs8 = await globalThis.crypto.subtle.exportKey("pkcs8", keyPair.privateKey);

  const encryptedPrivateBlob = await encryptPrivateKey(new Uint8Array(privateKeyPkcs8), vaultKey);

  return {
    publicKeyBytes: new Uint8Array(publicKeyRaw),
    encryptedPrivateBlob,
  };
}

export async function storeEncryptedWipePrivateKey(encryptedBlob: string, publicKeyBytes?: Uint8Array): Promise<void> {
  const ns = getActiveCryptoNamespace();

  return new Promise((resolve, reject) => {
    const openReq = indexedDB.open("iceq", 6);
    openReq.onsuccess = () => {
      const db = openReq.result;
      try {
        const txn = db.transaction(WIPE_KEY_STORE, "readwrite");
        const store = txn.objectStore(WIPE_KEY_STORE);
        const record: { v: number; blob: string; publicKey?: string } = { v: 1, blob: encryptedBlob };
        if (publicKeyBytes) {
          record.publicKey = bytesToBase64url(publicKeyBytes);
        }
        store.put(record, cryptoRecordKey(ns, "metadata", WIPE_KEY_RECORD_SUFFIX));
        txn.oncomplete = () => { db.close(); resolve(); };
        txn.onerror = () => { db.close(); reject(txn.error); };
      } catch (e) { db.close(); reject(e); }
    };
    openReq.onerror = () => reject(openReq.error);
  });
}

export async function loadAndDecryptWipePrivateKey(): Promise<CryptoKey | null> {
  const vaultKey = getVaultKey();
  if (!vaultKey) throw new Error("security vault is locked");

  const ns = getActiveCryptoNamespace();
  const record = await new Promise<{ v: number; blob: string } | undefined>((resolve, reject) => {
    const openReq = indexedDB.open("iceq", 6);
    openReq.onsuccess = () => {
      const db = openReq.result;
      try {
        const txn = db.transaction(WIPE_KEY_STORE, "readonly");
        const store = txn.objectStore(WIPE_KEY_STORE);
        const getReq = store.get(cryptoRecordKey(ns, "metadata", WIPE_KEY_RECORD_SUFFIX));
        getReq.onsuccess = () => resolve(getReq.result as { v: number; blob: string } | undefined);
        getReq.onerror = () => reject(getReq.error);
        txn.oncomplete = () => db.close();
        txn.onerror = () => { db.close(); reject(txn.error); };
      } catch (e) { db.close(); reject(e); }
    };
    openReq.onerror = () => reject(openReq.error);
  });

  if (!record || !record.blob) return null;

  return decryptPrivateKey(record.blob, vaultKey);
}

export interface WipeKeyPairResult {
  publicKeyBytes: Uint8Array;
  encryptedPrivateBlob: string;
  isNew: boolean;
}

// In-flight memo for loadOrCreateWipeKeyPair -- guards against a same-tab
// race (e.g. a double-click on "Complete Setup") where two concurrent
// callers would otherwise both read "no existing key" and both generate
// a DIFFERENT fresh key pair, only one of which the server can ever accept.
// Cross-tab/cross-device races are NOT covered here -- those are handled
// server-side by qEnrollWipePublicKey's atomic set-if-null, with the
// loser's local state reconciled via reconcileWipeKey below.
let inFlightWipeKeyPair: Promise<WipeKeyPairResult> | null = null;

/**
 * loadOrCreateWipeKeyPair implements the load-before-generate pattern for retry-safe enrollment.
 * If a wipe key already exists locally, it returns the existing key pair.
 * Otherwise, it generates a new key pair.
 * This prevents the deadlock where the server accepts K1 but the response is lost,
 * and a retry generates K2, leaving the user permanently stuck.
 */
export async function loadOrCreateWipeKeyPair(): Promise<WipeKeyPairResult> {
  if (inFlightWipeKeyPair) return inFlightWipeKeyPair;
  const attempt = loadOrCreateWipeKeyPairUncached();
  inFlightWipeKeyPair = attempt;
  try {
    return await attempt;
  } finally {
    inFlightWipeKeyPair = null;
  }
}

async function loadOrCreateWipeKeyPairUncached(): Promise<WipeKeyPairResult> {
  const vaultKey = getVaultKey();
  if (!vaultKey) throw new Error("security vault is locked");

  const ns = getActiveCryptoNamespace();

  // Try to load existing key first
  const existingRecord = await new Promise<{ v: number; blob: string; publicKey?: string } | undefined>((resolve, reject) => {
    const openReq = indexedDB.open("iceq", 6);
    openReq.onsuccess = () => {
      const db = openReq.result;
      try {
        const txn = db.transaction(WIPE_KEY_STORE, "readonly");
        const store = txn.objectStore(WIPE_KEY_STORE);
        const getReq = store.get(cryptoRecordKey(ns, "metadata", WIPE_KEY_RECORD_SUFFIX));
        getReq.onsuccess = () => resolve(getReq.result as { v: number; blob: string; publicKey?: string } | undefined);
        getReq.onerror = () => reject(getReq.error);
        txn.oncomplete = () => db.close();
        txn.onerror = () => { db.close(); reject(txn.error); };
      } catch (e) { db.close(); reject(e); }
    };
    openReq.onerror = () => reject(openReq.error);
  });

  // If we have an existing key with a public key, return it
  if (existingRecord && existingRecord.blob && existingRecord.publicKey) {
    try {
      const publicKeyBytes = base64urlToBytes(existingRecord.publicKey);
      return { publicKeyBytes, encryptedPrivateBlob: existingRecord.blob, isNew: false };
    } catch (e) {
      console.warn("Failed to decode existing wipe public key, generating new one:", e);
    }
  }

  // No existing key or couldn't recover it - generate a new one
  const { publicKeyBytes, encryptedPrivateBlob } = await generateWipeKeyPair();
  return { publicKeyBytes, encryptedPrivateBlob, isNew: true };
}

export type WipeKeyReconciliation =
  | { status: "match" }
  | { status: "server-has-no-key" }
  | { status: "mismatch" };

/**
 * reconcileWipeKey -- after any ambiguous outcome from an enrollment or
 * rotation attempt (network drop, an error that might mean "this exact key
 * already landed" or might mean "a DIFFERENT key already won a race"),
 * fetch the server's actual current public key and compare it byte-for-byte
 * against what's stored locally. This is the only source of truth this
 * function trusts -- it never infers success from an HTTP status code.
 *
 *   - "match": the local key IS the enrolled key. Safe to proceed.
 *   - "server-has-no-key": nothing enrolled yet -- the failure was real.
 *     The local key is left alone so a retry reuses it.
 *   - "mismatch": a DIFFERENT key is enrolled server-side (most likely this
 *     device lost a concurrent first-enrollment race). The caller must
 *     clear the orphaned local key -- see clearLocalWipeKey -- and surface
 *     an honest error. It must NOT fabricate a rotation: that would require
 *     a signature from the key that's actually enrolled, which this device
 *     never had.
 */
export async function reconcileWipeKey(
  localPublicKeyBytes: Uint8Array,
  fetchServerPublicKey: () => Promise<{ public_key: string | null }> = getWipePublicKey,
): Promise<WipeKeyReconciliation> {
  const { public_key: serverKeyB64 } = await fetchServerPublicKey();
  if (serverKeyB64 === null) return { status: "server-has-no-key" };
  return serverKeyB64 === bytesToBase64std(localPublicKeyBytes) ? { status: "match" } : { status: "mismatch" };
}

/**
 * clearLocalWipeKey -- delete the locally-stored wipe key pair record.
 * Used when reconcileWipeKey finds the local key does not match what the
 * server has enrolled: keeping an orphaned key around would let a future
 * retry silently resubmit it and hit the same mismatch forever.
 */
export async function clearLocalWipeKey(): Promise<void> {
  const ns = getActiveCryptoNamespace();
  return new Promise((resolve, reject) => {
    const openReq = indexedDB.open("iceq", 6);
    openReq.onsuccess = () => {
      const db = openReq.result;
      try {
        const txn = db.transaction(WIPE_KEY_STORE, "readwrite");
        const store = txn.objectStore(WIPE_KEY_STORE);
        store.delete(cryptoRecordKey(ns, "metadata", WIPE_KEY_RECORD_SUFFIX));
        txn.oncomplete = () => { db.close(); resolve(); };
        txn.onerror = () => { db.close(); reject(txn.error); };
      } catch (e) { db.close(); reject(e); }
    };
    openReq.onerror = () => reject(openReq.error);
  });
}

/**
 * exportWipePrivateKeyRawForRecovery -- decrypts the locally-stored wipe
 * private key and returns its RAW PKCS8 bytes (not a CryptoKey), for
 * embedding into a recovery package. Unlike loadAndDecryptWipePrivateKey,
 * which imports the key as non-extractable (["sign"] only, extractable:
 * false, so it can never leave this function as raw bytes again), this
 * intentionally stops one step earlier -- recovery is the one legitimate
 * reason this codebase ever needs the raw bytes.
 *
 * Returns null (never throws for these) when there's nothing to export:
 * no wipe key generated yet, or the vault is locked. Recovery package
 * generation degrades gracefully without a wipe key rather than failing
 * outright -- see recoveryPackage.ts's gatherRecoveryPayload.
 */
export async function exportWipePrivateKeyRawForRecovery(): Promise<{
  publicKeyBytes: Uint8Array;
  privateKeyPkcs8: Uint8Array;
} | null> {
  const vaultKey = getVaultKey();
  if (!vaultKey) return null;

  const ns = getActiveCryptoNamespace();
  const record = await new Promise<{ v: number; blob: string; publicKey?: string } | undefined>((resolve, reject) => {
    const openReq = indexedDB.open("iceq", 6);
    openReq.onsuccess = () => {
      const db = openReq.result;
      try {
        const txn = db.transaction(WIPE_KEY_STORE, "readonly");
        const store = txn.objectStore(WIPE_KEY_STORE);
        const getReq = store.get(cryptoRecordKey(ns, "metadata", WIPE_KEY_RECORD_SUFFIX));
        getReq.onsuccess = () => resolve(getReq.result as { v: number; blob: string; publicKey?: string } | undefined);
        getReq.onerror = () => reject(getReq.error);
        txn.oncomplete = () => db.close();
        txn.onerror = () => { db.close(); reject(txn.error); };
      } catch (e) { db.close(); reject(e); }
    };
    openReq.onerror = () => reject(openReq.error);
  });

  if (!record || !record.blob || !record.publicKey) return null;

  let privateKeyPkcs8: Uint8Array;
  try {
    privateKeyPkcs8 = await decryptPrivateKeyRawBytes(record.blob, vaultKey);
  } catch {
    return null;
  }
  return { publicKeyBytes: base64urlToBytes(record.publicKey), privateKeyPkcs8 };
}

/**
 * importRecoveredWipeKey -- takes wipe key material already decrypted out
 * of a recovery package (see recoveryPackage.ts's importRecoveryPackage)
 * and re-encrypts it with THIS device's own, freshly-created vault key
 * before persisting. The recovered key becomes indistinguishable from one
 * generated locally: same storage shape, same public key the server
 * already has enrolled -- so no rotation/signature is ever needed, only
 * the idempotent-resubmit path already handled by SecuritySetupKey
 * enrollment (see panicwipe_challenge.go's compare-before-rotate check).
 */
export async function importRecoveredWipeKey(publicKeyBytes: Uint8Array, privateKeyPkcs8: Uint8Array): Promise<void> {
  const vaultKey = getVaultKey();
  if (!vaultKey) throw new Error("security vault is locked");
  const encryptedPrivateBlob = await encryptPrivateKey(privateKeyPkcs8, vaultKey);
  await storeEncryptedWipePrivateKey(encryptedPrivateBlob, publicKeyBytes);
}

export async function signWipeChallenge(challenge: Uint8Array, privateKey: CryptoKey): Promise<Uint8Array> {
  const sig = await globalThis.crypto.subtle.sign(
    { name: "Ed25519" },
    privateKey,
    challenge.buffer as unknown as BufferSource,
  );
  return new Uint8Array(sig);
}

async function encryptPrivateKey(pkcs8Bytes: Uint8Array, vaultKey: CryptoKey): Promise<string> {
  const iv = new Uint8Array(12);
  globalThis.crypto.getRandomValues(iv);

  const ciphertext = await globalThis.crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv.buffer as unknown as BufferSource },
    vaultKey,
    pkcs8Bytes.buffer as unknown as BufferSource,
  );

  const combined = new Uint8Array(1 + iv.length + ciphertext.byteLength);
  combined[0] = iv.length;
  combined.set(iv, 1);
  combined.set(new Uint8Array(ciphertext), 1 + iv.length);
  return bytesToBase64url(combined);
}

async function decryptPrivateKey(blob: string, vaultKey: CryptoKey): Promise<CryptoKey> {
  const plaintext = await decryptPrivateKeyRawBytes(blob, vaultKey);
  return globalThis.crypto.subtle.importKey(
    "pkcs8",
    plaintext as unknown as BufferSource,
    { name: "Ed25519" },
    false,
    ["sign"],
  );
}

// decryptPrivateKeyRawBytes -- the shared AES-GCM unwrap step, stopping at
// raw PKCS8 bytes. decryptPrivateKey (above) imports those bytes into a
// non-extractable CryptoKey for normal signing use;
// exportWipePrivateKeyRawForRecovery (below) needs the raw bytes
// themselves, which is why this is split out rather than inlined into
// decryptPrivateKey.
async function decryptPrivateKeyRawBytes(blob: string, vaultKey: CryptoKey): Promise<Uint8Array> {
  const combined = base64urlToBytes(blob);
  if (combined.length < 2) throw new Error("truncated wipe key blob");
  const ivLen = combined[0]!;
  if (combined.length < 1 + ivLen + 1) throw new Error("truncated wipe key blob");
  const iv = combined.slice(1, 1 + ivLen);
  const ciphertext = combined.slice(1 + ivLen);

  const plaintext = await globalThis.crypto.subtle.decrypt(
    { name: "AES-GCM", iv: iv.buffer as unknown as BufferSource },
    vaultKey,
    ciphertext.buffer as unknown as BufferSource,
  );

  return new Uint8Array(plaintext);
}

function bytesToBase64url(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]!);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// Standard (not URL-safe) base64 -- the wire format the Go backend expects
// for wipe-key bytes specifically (base64.StdEncoding.DecodeString in
// panicwipe_challenge.go). Exported so every caller that needs to compare
// against or submit a wipe public key -- SecuritySetupGate.tsx,
// reconcileWipeKey above -- uses the exact same encoding.
export function bytesToBase64std(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]!);
  return btoa(binary);
}

function base64urlToBytes(s: string): Uint8Array {
  let b64 = s.replace(/-/g, "+").replace(/_/g, "/");
  while (b64.length % 4 !== 0) b64 += "=";
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}
