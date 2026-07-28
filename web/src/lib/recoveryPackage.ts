import {
  getActiveCryptoNamespace,
  loadIdentity,
  loadPeerTrust,
  cryptoRecordKey,
  type CryptoNamespace,
  type StoredIdentity,
  type StoredPeerTrust,
} from "./indexeddb";
import { deriveIdentityPublicKey } from "./signal";
import { exportWipePrivateKeyRawForRecovery } from "./panicWipeKey";

// PACKAGE_VERSION 4 adds an optional wipe-key field (see RecoveryPayload)
// so a recovered device can restore the SAME panic-wipe key pair the
// server already has enrolled, instead of being stuck needing a rotation
// signature from a key it never had. v3 packages (no wipe key field) and
// v4 both authenticate the header as AES-GCM AAD and remain importable.
// Version 2 did not authenticate the header and is rejected.
const PACKAGE_VERSION = 4;
const MIN_SUPPORTED_PACKAGE_VERSION = 3;
const HEADER_AAD_SIZE = 1 + 8 + 32; // version + UIN + server identity (41 bytes)
const HEADER_SIZE = HEADER_AAD_SIZE + 12; // + IV (12 bytes) = 53 bytes
const MIN_RECOVERY_KEY_BYTES = 16;

export const RECOVERY_KEY_BYTES = 32;

interface RecoveryPayload {
  v: number;
  identity: StoredIdentity;
  peerTrust: Array<{ peerUin: number; record: StoredPeerTrust }>;
  // Present only when the source device had already enrolled a panic-wipe
  // key at export time (v4+) and the security vault was unlocked. Absent
  // on v3 packages, and on v4 packages created before wipe-key setup --
  // see RecoveryImportScreen.tsx, which treats a missing field as "fall
  // back to generating a fresh wipe key" rather than an error.
  wipeKey?: { publicKey: string; privateKeyPkcs8: string };
}

export interface RecoveryPackage {
  base64: string;
}

export function generateRecoveryKey(): Uint8Array {
  const key = new Uint8Array(RECOVERY_KEY_BYTES);
  globalThis.crypto.getRandomValues(key);
  return key;
}

function base64urlToBytes(s: string): Uint8Array {
  let b64 = s.replace(/-/g, "+").replace(/_/g, "/");
  while (b64.length % 4 !== 0) b64 += "=";
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function base64urlFromBytes(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]!);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function identityKeyToBytes(s: string): Uint8Array {
  const bytes = base64urlToBytes(s);
  if (bytes.length === 33 && bytes[0] === 0x05) return bytes.slice(1);
  if (bytes.length !== 32) throw new Error("invalid server identity key length");
  return bytes;
}

// publicKeysEqual compares two base64url-encoded X25519 public keys for
// equality, normalizing away the 0x05 Signal prefix and padding differences.
function publicKeysEqual(a: string, b: string): boolean {
  if (a === b) return true;
  const norm = (s: string): string => {
    // Normalize base64url: convert to bytes, then back to unpadded base64url.
    const bytes = base64urlToBytes(s);
    // If the result is 33 bytes with 0x05 prefix, strip it.
    if (bytes.length === 33 && bytes[0] === 0x05) {
      return base64urlFromBytes(bytes.slice(1));
    }
    if (bytes.length === 32) {
      return base64urlFromBytes(bytes);
    }
    // Unknown format — return as-is (comparison will likely fail).
    return s;
  };
  return norm(a) === norm(b);
}

async function gatherRecoveryPayload(ns: CryptoNamespace): Promise<RecoveryPayload> {
  const identity = await loadIdentity(ns);
  if (!identity) throw new Error("no local identity to export");

  const db = await openDB();
  const peerTrustKeys = await getAllPrefixedKeys(db, "peer_trust", `crypto-v1:${ns.uin}:${ns.deviceId}:peer_trust:`);
  const peerTrust: Array<{ peerUin: number; record: StoredPeerTrust }> = [];
  for (const key of peerTrustKeys) {
    const peerUinStr = key.split(":").length >= 6 ? key.split(":")[5] : null;
    if (!peerUinStr) continue;
    const peerUin = parseInt(peerUinStr, 10);
    const record = await loadPeerTrust(peerUin, ns);
    if (record) peerTrust.push({ peerUin, record });
  }

  db.close();

  // Best-effort: a wipe key may not exist yet (vault locked, or this
  // device hasn't enabled panic wipe). Recovery packages degrade
  // gracefully without one rather than failing to generate at all.
  const wipeKeyMaterial = await exportWipePrivateKeyRawForRecovery();
  const wipeKey = wipeKeyMaterial
    ? {
        publicKey: base64urlFromBytes(wipeKeyMaterial.publicKeyBytes),
        privateKeyPkcs8: base64urlFromBytes(wipeKeyMaterial.privateKeyPkcs8),
      }
    : undefined;

  return {
    v: PACKAGE_VERSION,
    identity,
    peerTrust,
    ...(wipeKey ? { wipeKey } : {}),
  };
}

export async function createRecoveryPackage(
  accountUin: number,
  serverIdentityKeyBase64: string,
  recoveryKey: Uint8Array,
): Promise<string> {
  if (recoveryKey.length < MIN_RECOVERY_KEY_BYTES) throw new Error("recovery key too short");
  const ns = getActiveCryptoNamespace();
  if (ns.uin !== accountUin) throw new Error("account UIN mismatch");

  const payload = await gatherRecoveryPayload(ns);
  const payloadJson = new TextEncoder().encode(JSON.stringify(payload));

  const iv = new Uint8Array(12);
  globalThis.crypto.getRandomValues(iv);

  const aesKey = await globalThis.crypto.subtle.importKey(
    "raw", recoveryKey.buffer as unknown as BufferSource, "AES-GCM", false, ["encrypt"],
  );

  const serverIdBytes = identityKeyToBytes(serverIdentityKeyBase64);

  // Build the header: version (1 byte) + UIN (8 bytes BE) +
  // server identity key (32 bytes) + IV (12 bytes) = 53 bytes.
  // The first 41 bytes (version + UIN + server identity) are the AAD —
  // AES-GCM authenticates them so any tampering causes decryption failure.
  const header = new Uint8Array(HEADER_SIZE);
  header[0] = PACKAGE_VERSION;
  new DataView(header.buffer).setBigUint64(1, BigInt(accountUin), false);
  header.set(serverIdBytes, 9);
  header.set(iv, 41);

  // AAD = version + UIN + server identity (41 bytes). The IV is NOT part
  // of AAD — AES-GCM already authenticates the IV as part of its internal
  // authentication tag computation.
  const aad = header.subarray(0, HEADER_AAD_SIZE);

  const ciphertext = await globalThis.crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: iv as unknown as BufferSource,
      additionalData: aad as unknown as BufferSource,
    },
    aesKey,
    payloadJson as unknown as BufferSource,
  );

  const ct = new Uint8Array(ciphertext);
  const combined = new Uint8Array(header.length + ct.length);
  combined.set(header);
  combined.set(ct, header.length);

  return base64urlFromBytes(combined);
}

export async function importRecoveryPackage(
  packageStr: string,
  expectedUin: number,
  serverIdentityKeyBase64: string,
  recoveryKey: Uint8Array,
): Promise<RecoveryPayload> {
  if (!packageStr || packageStr.length < HEADER_SIZE * 2) throw new Error("invalid recovery package: too short");

  const combined = base64urlToBytes(packageStr);
  if (combined.length < HEADER_SIZE + 1) throw new Error("invalid recovery package: too short");

  const version = combined[0];
  // Reject v2 packages — they do not authenticate the header with AAD.
  if (version === 2) {
    throw new Error(
      "unsupported recovery package version: 2. " +
      "This package was created by an older version of IceQ that did not authenticate the package header. " +
      "Please re-create your recovery package from the Security Setup screen on your original device."
    );
  }
  // v3 (no wipe-key field) and v4 (optional wipe-key field) are both
  // importable -- both authenticate the header as AAD. A missing wipe
  // key field is handled below by simply not restoring one.
  if (version === undefined || version < MIN_SUPPORTED_PACKAGE_VERSION || version > PACKAGE_VERSION) {
    throw new Error(`unsupported recovery package version: ${version}`);
  }

  const view = new DataView(combined.buffer, combined.byteOffset, combined.byteLength);
  const pkgUin = Number(view.getBigUint64(1, false));
  if (pkgUin !== expectedUin) throw new Error("recovery package account mismatch");

  const pkgServerId = combined.slice(9, 41);
  const expectedServerId = identityKeyToBytes(serverIdentityKeyBase64);
  if (pkgServerId.byteLength !== expectedServerId.byteLength) throw new Error("server identity mismatch");
  for (let i = 0; i < pkgServerId.byteLength; i++) {
    if (pkgServerId[i] !== expectedServerId[i]) throw new Error("server identity mismatch");
  }

  const iv = combined.slice(41, 53);
  const ciphertext = combined.slice(HEADER_SIZE);

  // AAD = version + UIN + server identity (first 41 bytes of the header).
  // Must match exactly what was passed to encrypt() during package creation.
  const aad = combined.subarray(0, HEADER_AAD_SIZE);

  const aesKey = await globalThis.crypto.subtle.importKey(
    "raw", recoveryKey.buffer as unknown as BufferSource, "AES-GCM", false, ["decrypt"],
  );

  let plaintext: ArrayBuffer;
  try {
    plaintext = await globalThis.crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: iv as unknown as BufferSource,
        additionalData: aad as unknown as BufferSource,
      },
      aesKey,
      ciphertext as unknown as BufferSource,
    );
  } catch {
    throw new Error("recovery package decryption failed -- wrong key or tampered package");
  }

  let payload: RecoveryPayload;
  try {
    payload = JSON.parse(new TextDecoder().decode(plaintext));
  } catch {
    throw new Error("recovery package contains corrupted payload");
  }
  if (!payload || payload.v !== version || !payload.identity) throw new Error("invalid recovery payload");

  // --- Cryptographic identity verification ---
  // Derive the public key from the imported private key and verify it matches
  // both the package's own identity record and the server's published key.
  // This prevents:
  //   - private-key / identity mismatch in the payload
  //   - relabeling a package from account A for account B (server identity
  //     is authenticated via AAD, so the server identity check above already
  //     catches this — but we double-check here for defence in depth)

  const derivedPublicKey = await deriveIdentityPublicKey(payload.identity.privateKey);

  // Normalize both keys before comparing — the identity may have been
  // stored with or without the 0x05 Signal prefix, and base64url encoding
  // may differ in padding.
  if (!publicKeysEqual(derivedPublicKey, payload.identity.publicKey)) {
    throw new Error("recovery package identity mismatch: derived public key does not match payload identity");
  }

  // Verify the derived public key matches the authenticated server directory
  // identity. The server identity in the header was already verified against
  // serverIdentityKeyBase64 at the byte level above AND authenticated via AAD,
  // but this check confirms the private key in the payload corresponds to the
  // same identity. Without this check, a package could contain a valid AAD
  // header but a payload with a different identity keypair.
  if (!publicKeysEqual(derivedPublicKey, serverIdentityKeyBase64)) {
    throw new Error("recovery package identity does not match the published server directory key");
  }

  const targetNs = getActiveCryptoNamespace();
  if (targetNs.uin !== expectedUin) throw new Error("active namespace UIN does not match recovery package");

  const existingIdentity = await loadIdentity(targetNs);
  if (existingIdentity) throw new Error("cannot import recovery package: identity already exists in target namespace");

  // --- Atomic IndexedDB write ---
  // All checks above passed. Write identity and peer trust in a single
  // transaction. If any write fails, the entire transaction is aborted
  // and no partial state is committed.
  const db = await openDB();
  const tx = db.transaction(
    ["identity", "peer_trust", "metadata"],
    "readwrite",
  );

  try {
    const identityStore = tx.objectStore("identity");
    const peerTrustStore = tx.objectStore("peer_trust");

    identityStore.put(
      payload.identity,
      cryptoRecordKey(targetNs, "identity", "self"),
    );

    for (const pt of payload.peerTrust) {
      peerTrustStore.put(
        pt.record,
        cryptoRecordKey(targetNs, "peer_trust", pt.peerUin),
      );
    }

    await transactionDone(tx);
  } catch (err) {
    try { tx.abort(); } catch { /* */ }
    throw err;
  } finally {
    db.close();
  }

  return payload;
}

function openDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open("iceq", 6);
    req.onupgradeneeded = () => {
      const db = req.result;
      const stores = ["identity", "sessions", "prekeys", "signed_prekeys", "identities", "messages", "metadata", "peer_trust", "group_crypto", "transport_seen"];
      for (const name of stores) {
        if (!db.objectStoreNames.contains(name)) {
          db.createObjectStore(name, name === "prekeys" || name === "signed_prekeys" ? { keyPath: "id" } : undefined);
        }
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error ?? new Error("idb open failed"));
  });
}

async function getAllPrefixedKeys(db: IDBDatabase, storeName: string, prefix: string): Promise<string[]> {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, "readonly");
    const store = tx.objectStore(storeName);
    const keys: string[] = [];
    const req = store.openCursor();
    req.onsuccess = () => {
      const cursor = req.result;
      if (!cursor) return resolve(keys);
      if (String(cursor.key).startsWith(prefix)) keys.push(String(cursor.key));
      cursor.continue();
    };
    req.onerror = () => reject(req.error);
  });
}

function transactionDone(tx: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error ?? new Error("transaction failed"));
    tx.onabort = () => reject(new Error("transaction aborted"));
  });
}
