import { getActiveCryptoNamespace, cryptoRecordKey } from "./indexeddb";
import { getVaultKey } from "./securityVault";

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

export async function storeEncryptedWipePrivateKey(encryptedBlob: string): Promise<void> {
  const ns = getActiveCryptoNamespace();

  return new Promise((resolve, reject) => {
    const openReq = indexedDB.open("iceq", 6);
    openReq.onsuccess = () => {
      const db = openReq.result;
      try {
        const txn = db.transaction(WIPE_KEY_STORE, "readwrite");
        const store = txn.objectStore(WIPE_KEY_STORE);
        store.put({ v: 1, blob: encryptedBlob }, cryptoRecordKey(ns, "metadata", WIPE_KEY_RECORD_SUFFIX));
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

  return globalThis.crypto.subtle.importKey(
    "pkcs8",
    plaintext,
    { name: "Ed25519" },
    false,
    ["sign"],
  );
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
