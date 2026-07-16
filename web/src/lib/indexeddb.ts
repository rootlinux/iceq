// src/lib/indexeddb.ts
// IceQ IndexedDB schema. Version 4.
//
// Stores:
//
//   identity          — own identity key pair + registration id.
//                       Keyed by the constant string "self". This
//                       is the only place a long-lived private key
//                       lives on the client.
//
//   sessions          — Signal Protocol session state, keyed by
//                       the peer's SignalProtocolAddress.toString()
//                       form ("<uin>.1"). The value is the
//                       serialized session record (a string) the
//                       SessionCipher hands back via serialize().
//
//   prekeys           — own one-time prekeys, keyed by prekey id.
//                       The bundle we hand to the server on
//                       register / prekey replenishment is a slice
//                       of these.
//
//   signed_prekeys    — own signed prekey(s), keyed by signed
//                       prekey id. Separate from one-time prekeys
//                       because their lifecycle is different: a
//                       signed prekey is long-lived and rotated
//                       on a slower schedule.
//
//   identities        — peer (remote) identity public keys, keyed
//                       by SignalProtocolAddress.toString(). The
//                       privacyresearch storage's
//                       isTrustedIdentity() reads this store to
//                       detect a peer's identity-key change (a
//                       potential MITM signal).
//
//   messages          — decrypted message cache. Optional; the
//                       Zustand chat-store is the source of truth
//                       for in-memory messages. The cache exists
//                       so a page reload can re-render the chat
//                       window while the history API call is in
//                       flight.
//
//   metadata          — small local counters that do not contain
//                       key material. Currently used for the
//                       monotonic one-time-prekey id cursor.
//
// The schema is intentionally small. We do not store ciphertext
// locally — the backend is the durable store. Plaintext is the
// only thing we cache, and we re-derive it from the Signal
// session on first load (if the session is intact).
//
// The whole database is dropped on 4403 (panic-wipe) via
// clearAll(); see lib/wsCloseCodes.ts for the entry point.
//
// Schema v2 (Step 9): adds signed_prekeys and identities. The
// privacyresearch Signal library's StorageType interface needs
// per-peer identity tracking and signed-prekey persistence.
//
// Schema v3: adds metadata for the replenishment prekey-id cursor.

export const ICEQ_INDEXEDDB_NAME = "iceq";
const DB_VERSION = 5;

const STORE_IDENTITY = "identity";
const STORE_SESSIONS = "sessions";
const STORE_PREKEYS = "prekeys";
const STORE_SIGNED_PREKEYS = "signed_prekeys";
const STORE_PEER_IDENTITIES = "identities";
const STORE_MESSAGES = "messages";
const STORE_METADATA = "metadata";
const STORE_PEER_TRUST = "peer_trust";
const STORE_GROUP_CRYPTO = "group_crypto";

const SELF_KEY = "self";
const NEXT_PREKEY_ID_KEY = "next_prekey_id";

// ----------------------------------------------------------------------------
// Identity. Own long-term identity. Persisted in IndexedDB only.
// Zustand NEVER holds the private key — only the Signal bindings
// do, and they hand it back to the bindings API on demand.
// ----------------------------------------------------------------------------
export interface StoredIdentity {
  // Base64url-encoded raw 32-byte X25519 public key.
  publicKey: string;
  // Base64url-encoded private key. KEEP OUT OF localStorage and
  // Zustand. IndexedDB only.
  privateKey: string;
  // 32-bit Signal registration id.
  registrationId: number;
}

const SIGNAL_PUBLIC_KEY_PREFIX = 0x05;
const RAW_X25519_PUBLIC_KEY_LENGTH = 32;

function restoreSignalIdentityPublicKey(publicKey: string): ArrayBuffer {
  const bytes = new Uint8Array(b64ToArrayBuffer(publicKey));
  if (bytes.length === RAW_X25519_PUBLIC_KEY_LENGTH + 1) {
    return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
  }
  if (bytes.length !== RAW_X25519_PUBLIC_KEY_LENGTH) {
    throw new Error(`invalid stored identity public key length: ${bytes.length}`);
  }
  const prefixed = new Uint8Array(RAW_X25519_PUBLIC_KEY_LENGTH + 1);
  prefixed[0] = SIGNAL_PUBLIC_KEY_PREFIX;
  prefixed.set(bytes, 1);
  return prefixed.buffer;
}

export async function saveIdentity(id: StoredIdentity): Promise<void> {
  const db = await openDB();
  await idbPut(db, STORE_IDENTITY, id, SELF_KEY);
  db.close();
}

export async function loadIdentity(): Promise<StoredIdentity | null> {
  const db = await openDB();
  const v = await idbGet<StoredIdentity>(db, STORE_IDENTITY, SELF_KEY);
  db.close();
  return v ?? null;
}

// ----------------------------------------------------------------------------
// Sessions. One row per peer UIN. The value is whatever the
// Signal bindings want to hand back on load — opaque to us.
// ----------------------------------------------------------------------------
export async function saveSession(peerUin: number, record: string): Promise<void> {
  const db = await openDB();
  await idbPut(db, STORE_SESSIONS, record, String(peerUin));
  db.close();
}

export async function loadSession(peerUin: number): Promise<string | null> {
  const db = await openDB();
  const v = await idbGet<string>(db, STORE_SESSIONS, String(peerUin));
  db.close();
  return v ?? null;
}

export async function deleteSession(peerUin: number): Promise<void> {
  const db = await openDB();
  await idbDelete(db, STORE_SESSIONS, String(peerUin));
  db.close();
}

// ----------------------------------------------------------------------------
// PreKeys. The own-device prekey pool.
// ----------------------------------------------------------------------------
export interface StoredPreKey {
  id: number;
  publicKey: string;
  privateKey: string;
}

export async function savePreKey(pk: StoredPreKey): Promise<void> {
  const db = await openDB();
  await idbPut(db, STORE_PREKEYS, pk, pk.id);
  db.close();
}

export async function loadPreKeys(): Promise<StoredPreKey[]> {
  const db = await openDB();
  const v = await idbGetAll<StoredPreKey>(db, STORE_PREKEYS);
  db.close();
  return v ?? [];
}

export async function deletePreKey(id: number): Promise<void> {
  const db = await openDB();
  await idbDelete(db, STORE_PREKEYS, id);
  db.close();
}

export async function loadNextPreKeyId(): Promise<number | null> {
  const db = await openDB();
  const v = await idbGet<number>(db, STORE_METADATA, NEXT_PREKEY_ID_KEY);
  db.close();
  return typeof v === "number" && Number.isFinite(v) ? v : null;
}

export async function saveNextPreKeyId(id: number): Promise<void> {
  const db = await openDB();
  await idbPut(db, STORE_METADATA, id, NEXT_PREKEY_ID_KEY);
  db.close();
}

export interface StoredPeerTrust {
  version: 1;
  peerUin: number;
  fingerprint: string;
  verified: boolean;
  firstSeenAt: number;
  updatedAt: number;
  pendingFingerprint?: string;
}

export async function loadPeerTrust(peerUin: number): Promise<StoredPeerTrust | null> {
  const db = await openDB();
  const value = await idbGet<StoredPeerTrust>(db, STORE_PEER_TRUST, peerUin);
  db.close();
  return value ?? null;
}

export async function savePeerTrust(record: StoredPeerTrust): Promise<void> {
  const db = await openDB();
  await idbPut(db, STORE_PEER_TRUST, record, record.peerUin);
  db.close();
}

export async function resetPeerSignalState(peerUin: number): Promise<void> {
  const db = await openDB();
  const address = `${peerUin}.1`;
  await idbDelete(db, STORE_SESSIONS, address);
  await idbDelete(db, STORE_PEER_IDENTITIES, address);
  db.close();
}

export async function acceptPendingPeerIdentity(peerUin: number, fingerprint: string): Promise<void> {
  const db = await openDB();
  const tx = db.transaction([STORE_PEER_TRUST, STORE_SESSIONS, STORE_PEER_IDENTITIES], "readwrite");
  const done = transactionDone(tx);
  try {
    const trustStore = tx.objectStore(STORE_PEER_TRUST);
    const existing = await requestResult<StoredPeerTrust>(trustStore.get(peerUin));
    if (!existing || existing.pendingFingerprint !== fingerprint) throw new Error("fingerprint does not match the current pending identity");
    const now = Date.now();
    trustStore.put({ ...existing, fingerprint, verified: false, pendingFingerprint: undefined, updatedAt: now } satisfies StoredPeerTrust, peerUin);
    for (const address of [String(peerUin), `${peerUin}.1`]) {
      tx.objectStore(STORE_SESSIONS).delete(address);
      tx.objectStore(STORE_PEER_IDENTITIES).delete(address);
    }
    await done;
  } catch (error) {
    try { tx.abort(); } catch { /* already aborted */ }
    await done.catch(() => undefined);
    throw error;
  } finally { db.close(); }
}

export async function assertInboundIdentityTrusted(peerUin: number, identityKey: ArrayBuffer): Promise<void> {
  const db = await openDB();
  const qualified = await idbGet<StoredPeerIdentity>(db, STORE_PEER_IDENTITIES, `${peerUin}.1`);
  const bare = qualified ?? await idbGet<StoredPeerIdentity>(db, STORE_PEER_IDENTITIES, String(peerUin));
  const trust = await idbGet<StoredPeerTrust>(db, STORE_PEER_TRUST, peerUin);
  const incomingFingerprint = signalIdentityToWire(identityKey);
  if (bare && !arrayBufferEquals(bare.publicKey, identityKey)) {
    db.close(); await persistInboundIdentityChange(String(peerUin), bare.publicKey, identityKey); throw new Error("peer identity changed");
  }
  if (trust && (trust.pendingFingerprint !== undefined || trust.fingerprint !== incomingFingerprint)) {
    await idbPut(db, STORE_PEER_TRUST, { ...trust, pendingFingerprint: incomingFingerprint, updatedAt: Date.now() } satisfies StoredPeerTrust, peerUin);
    db.close(); throw new Error("peer identity changed");
  }
  db.close();
}

async function persistInboundIdentityChange(identifier: string, oldKey: ArrayBuffer, newKey: ArrayBuffer): Promise<void> {
  const match = /^(\d+)(?:\.\d+)?$/.exec(identifier);
  if (!match) return;
  const peerUin = Number(match[1]);
  if (!Number.isSafeInteger(peerUin) || peerUin <= 0) return;
  const db = await openDB();
  const existing = await idbGet<StoredPeerTrust>(db, STORE_PEER_TRUST, peerUin);
  const now = Date.now();
  const record: StoredPeerTrust = existing ?? {
    version: 1,
    peerUin,
    fingerprint: signalIdentityToWire(oldKey),
    verified: false,
    firstSeenAt: now,
    updatedAt: now,
  };
  await idbPut(db, STORE_PEER_TRUST, {
    ...record,
    pendingFingerprint: signalIdentityToWire(newKey),
    updatedAt: now,
  } satisfies StoredPeerTrust, peerUin);
  db.close();
}

function requestResult<T>(request: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => { request.onsuccess = () => resolve(request.result); request.onerror = () => reject(request.error); });
}

function transactionDone(tx: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => { tx.oncomplete = () => resolve(); tx.onerror = () => reject(tx.error); tx.onabort = () => reject(tx.error ?? new Error("identity acceptance transaction aborted")); });
}

function signalIdentityToWire(key: ArrayBuffer): string {
  const bytes = new Uint8Array(key);
  const raw = bytes.length === 33 && bytes[0] === SIGNAL_PUBLIC_KEY_PREFIX ? bytes.slice(1) : bytes;
  if (raw.length !== RAW_X25519_PUBLIC_KEY_LENGTH) throw new Error("invalid peer identity key");
  let binary = "";
  for (const byte of raw) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// ----------------------------------------------------------------------------
// Decrypted message cache. Used by the chat window to re-render
// the last few messages on page reload while the history API
// request is in flight. The list is bounded — the LRU eviction
// is the consumer's responsibility; we just store/load.
// ----------------------------------------------------------------------------
export interface CachedMessage {
  conversation_id: string;
  message: unknown; // matches `Message` shape; stored as `unknown` to keep this file dep-free
  cached_at: number;
}

export async function saveCachedMessage(conversationId: string, message: unknown): Promise<void> {
  const db = await openDB();
  const key = `${conversationId}:${Date.now()}:${Math.random().toString(36).slice(2)}`;
  await idbPut(db, STORE_MESSAGES, { conversation_id: conversationId, message, cached_at: Date.now() }, key);
  db.close();
}

export async function loadCachedMessages(conversationId: string): Promise<unknown[]> {
  const db = await openDB();
  const all = await idbGetAll<CachedMessage>(db, STORE_MESSAGES);
  db.close();
  return (all ?? []).filter((c) => c.conversation_id === conversationId).map((c) => c.message);
}

export async function putGroupCryptoRecord(key: string, value: unknown): Promise<void> {
  const db = await openDB(); await idbPut(db, STORE_GROUP_CRYPTO, value, key); db.close();
}
export async function getGroupCryptoRecord<T>(key: string): Promise<T | null> {
  const db = await openDB(); const value = await idbGet<T>(db, STORE_GROUP_CRYPTO, key); db.close(); return value ?? null;
}
export async function getAllGroupCryptoRecords<T>(): Promise<T[]> {
  const db = await openDB(); const value = await idbGetAll<T>(db, STORE_GROUP_CRYPTO); db.close(); return value;
}
export async function deleteGroupCryptoRecord(key: string): Promise<void> {
  const db = await openDB(); await idbDelete(db, STORE_GROUP_CRYPTO, key); db.close();
}

// ----------------------------------------------------------------------------
// clearAll — called on 4403 (panic-wipe). Drops the whole
// database. We do this with deleteDatabase rather than
// clear() because it also removes the schema, so a re-open
// triggers a fresh onupgradeneeded and we can't accidentally
// resurrect a wiped state from a stale version.
// ----------------------------------------------------------------------------
export async function clearAll(): Promise<void> {
  await new Promise<void>((resolve) => {
    const req = indexedDB.deleteDatabase(ICEQ_INDEXEDDB_NAME);
    req.onsuccess = () => resolve();
    req.onerror = () => resolve(); // best-effort; resolve so caller doesn't hang
    req.onblocked = () => resolve();
  });
}

// ----------------------------------------------------------------------------
// Internal — minimal IDBRequest helpers. We avoid pulling in a
// wrapper library; the surface is small enough that hand-rolling
// is clearer than adding a dep.
// ----------------------------------------------------------------------------
function openDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(ICEQ_INDEXEDDB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(STORE_IDENTITY)) {
        db.createObjectStore(STORE_IDENTITY);
      }
      if (!db.objectStoreNames.contains(STORE_SESSIONS)) {
        db.createObjectStore(STORE_SESSIONS);
      }
      if (!db.objectStoreNames.contains(STORE_PREKEYS)) {
        db.createObjectStore(STORE_PREKEYS, { keyPath: "id" });
      }
      if (!db.objectStoreNames.contains(STORE_MESSAGES)) {
        db.createObjectStore(STORE_MESSAGES);
      }
      // v2: Signal Protocol StorageType interface additions.
      if (!db.objectStoreNames.contains(STORE_SIGNED_PREKEYS)) {
        db.createObjectStore(STORE_SIGNED_PREKEYS, { keyPath: "id" });
      }
      if (!db.objectStoreNames.contains(STORE_PEER_IDENTITIES)) {
        db.createObjectStore(STORE_PEER_IDENTITIES);
      }
      if (!db.objectStoreNames.contains(STORE_METADATA)) {
        db.createObjectStore(STORE_METADATA);
      }
      if (!db.objectStoreNames.contains(STORE_PEER_TRUST)) {
        db.createObjectStore(STORE_PEER_TRUST);
      }
      if (!db.objectStoreNames.contains(STORE_GROUP_CRYPTO)) {
        db.createObjectStore(STORE_GROUP_CRYPTO);
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error ?? new Error("idb open failed"));
  });
}

function idbPut(db: IDBDatabase, store: string, value: unknown, key: IDBValidKey): Promise<void> {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(store, "readwrite");
    tx.objectStore(store).put(value, key);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error ?? new Error("idb put failed"));
  });
}

// Variant for stores created with `keyPath`. Passing a key
// argument to put() against a keyPath store throws
// DataError per spec — IndexedDB extracts the key from the
// value's named property instead.
function idbPutKeyPath(db: IDBDatabase, store: string, value: unknown): Promise<void> {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(store, "readwrite");
    tx.objectStore(store).put(value);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error ?? new Error("idb putKeyPath failed"));
  });
}

function idbGet<T>(db: IDBDatabase, store: string, key: IDBValidKey): Promise<T | undefined> {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(store, "readonly");
    const req = tx.objectStore(store).get(key);
    req.onsuccess = () => resolve(req.result as T | undefined);
    req.onerror = () => reject(req.error ?? new Error("idb get failed"));
  });
}

function idbGetAll<T>(db: IDBDatabase, store: string): Promise<T[]> {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(store, "readonly");
    const req = tx.objectStore(store).getAll();
    req.onsuccess = () => resolve((req.result ?? []) as T[]);
    req.onerror = () => reject(req.error ?? new Error("idb getAll failed"));
  });
}

function idbDelete(db: IDBDatabase, store: string, key: IDBValidKey): Promise<void> {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(store, "readwrite");
    tx.objectStore(store).delete(key);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error ?? new Error("idb delete failed"));
  });
}

// ============================================================================
// Signal Protocol StorageType implementation.
//
// The privacyresearch/libsignal-protocol-typescript library defines a
// `StorageType` interface that the SessionBuilder and SessionCipher
// read from / write to. We implement it on top of the IndexedDB
// schema above so the Signal state survives a page reload (sessions
// are persisted between visits; the chat window's history fetch
// re-derives plaintext from the live session).
//
// Why a class with no instance state: every read/write goes through
// IndexedDB. A singleton-with-no-fields is just a way to group the
// methods under one name (`new IndexedDBSignalProtocolStore()`).
// We export a `getSignalStore()` factory so call sites don't
// instantiate ad-hoc — though that's a stylistic choice; the
// class has no shared state to protect.
// ============================================================================

import type {
  Direction,
  KeyPairType,
  SessionRecordType,
  StorageType,
} from "@privacyresearch/libsignal-protocol-typescript";

interface StoredPreKeyRecord {
  id: number;
  keyPair: KeyPairType<ArrayBufferLike>;
}

interface StoredSignedPreKeyRecord {
  id: number;
  keyPair: KeyPairType<ArrayBufferLike>;
}

interface StoredPeerIdentity {
  publicKey: ArrayBuffer;
  // When we first saw this identity. The trust check uses
  // first-seen-wins (TOFU) and refuses to overwrite.
  firstSeenAt: number;
}

export class IndexedDBSignalProtocolStore implements StorageType {
  // -----------------------------------------------------------------
  // Identity key pair. One row, key="self", in STORE_IDENTITY.
  // The privacyresearch library calls this only for the LOCAL
  // identity; remote identities go in STORE_PEER_IDENTITIES.
  // -----------------------------------------------------------------
  async getIdentityKeyPair(): Promise<KeyPairType<ArrayBuffer> | undefined> {
    const db = await openDB();
    const v = await idbGet<StoredIdentity>(db, STORE_IDENTITY, SELF_KEY);
    db.close();
    if (!v) return undefined;
    return {
      pubKey: restoreSignalIdentityPublicKey(v.publicKey),
      privKey: b64ToArrayBuffer(v.privateKey),
    };
  }

  async getLocalRegistrationId(): Promise<number | undefined> {
    const db = await openDB();
    const v = await idbGet<StoredIdentity>(db, STORE_IDENTITY, SELF_KEY);
    db.close();
    return v?.registrationId;
  }

  // -----------------------------------------------------------------
  // Trust model — the SECURITY-CRITICAL method.
  //
  // Strategy: TOFU (Trust On First Use). The first identity we
  // see for a peer is pinned. Any later change to a peer's
  // identity key returns `false`, which causes the
  // SessionCipher to throw `UntrustedIdentityKeyError` and
  // the chat UI to surface a "their key changed" warning to
  // the user.
  //
  // This is the same model Signal/WhatsApp use. It is
  // vulnerable to a first-message MITM (where an attacker
  // presents their own key the first time the user talks to
  // a given peer) but protects against a later, active
  // attacker who steals a session's ratchet state. The
  // IceQ threat model — server compromise, account
  // hijack, device theft — does not include "active
  // on-path attacker on first contact", and the user can
  // still verify a peer's safety number out of band.
  //
  // If you want a different policy, this is the only
  // method to change. Possible alternatives:
  //   * Always trust:  `return true;`  (vulnerable to MITM
  //                                          at any time)
  //   * Server-pinned: fetch the peer's identity from a
  //                    signed directory and compare
  //                    (rejects key changes the server
  //                    didn't ratify)
  //   * User-pinned:   require the user to mark a key
  //                    trusted via fingerprint verification
  // -----------------------------------------------------------------
  async isTrustedIdentity(
    identifier: string,
    identityKey: ArrayBuffer,
    _direction: Direction,
  ): Promise<boolean> {
    const db = await openDB();
    const existing = await idbGet<StoredPeerIdentity>(db, STORE_PEER_IDENTITIES, identifier);
    db.close();
    if (!existing) return true; // first sighting — accept and let saveIdentity pin it
    if (arrayBufferEquals(existing.publicKey, identityKey)) return true;
    await persistInboundIdentityChange(identifier, existing.publicKey, identityKey);
    return false;
  }

  async saveIdentity(
    encodedAddress: string,
    publicKey: ArrayBuffer,
    _nonblockingApproval?: boolean,
  ): Promise<boolean> {
    const db = await openDB();
    const existing = await idbGet<StoredPeerIdentity>(db, STORE_PEER_IDENTITIES, encodedAddress);
    if (existing && !arrayBufferEquals(existing.publicKey, publicKey)) {
      // Identity changed — refuse to overwrite. The peer needs
      // to re-init the session from a fresh bundle.
      db.close();
      await persistInboundIdentityChange(encodedAddress, existing.publicKey, publicKey);
      return false;
    }
    const rec: StoredPeerIdentity = { publicKey, firstSeenAt: Date.now() };
    await idbPut(db, STORE_PEER_IDENTITIES, rec, encodedAddress);
    db.close();
    return true;
  }

  // -----------------------------------------------------------------
  // One-time prekey pool.
  //
  // STORE_PREKEYS is created with `keyPath: "id"`, so we put
  // the record (which carries the id property) and let
  // IndexedDB extract the key from the value — passing a
  // separate key argument to put() against a keyPath store
  // throws DataError per spec.
  // -----------------------------------------------------------------
  async loadPreKey(keyId: number | string): Promise<KeyPairType<ArrayBuffer> | undefined> {
    const db = await openDB();
    const v = await idbGet<StoredPreKeyRecord>(db, STORE_PREKEYS, keyId as IDBValidKey);
    db.close();
    if (!v) return undefined;
    return { pubKey: v.keyPair.pubKey as ArrayBuffer, privKey: v.keyPair.privKey as ArrayBuffer };
  }

  async storePreKey(keyId: number | string, keyPair: KeyPairType): Promise<void> {
    const db = await openDB();
    const rec: StoredPreKeyRecord = { id: Number(keyId), keyPair: { pubKey: keyPair.pubKey as ArrayBufferLike, privKey: keyPair.privKey as ArrayBufferLike } };
    await idbPutKeyPath(db, STORE_PREKEYS, rec);
    db.close();
  }

  async removePreKey(keyId: number | string): Promise<void> {
    const db = await openDB();
    await idbDelete(db, STORE_PREKEYS, Number(keyId));
    db.close();
  }

  // -----------------------------------------------------------------
  // Signed prekey. Same shape as one-time prekey but stored
  // separately so the long-lived signed prekey doesn't get
  // mixed up with the one-time pool.
  // -----------------------------------------------------------------
  async loadSignedPreKey(keyId: number | string): Promise<KeyPairType<ArrayBuffer> | undefined> {
    const db = await openDB();
    const v = await idbGet<StoredSignedPreKeyRecord>(db, STORE_SIGNED_PREKEYS, keyId as IDBValidKey);
    db.close();
    if (!v) return undefined;
    return { pubKey: v.keyPair.pubKey as ArrayBuffer, privKey: v.keyPair.privKey as ArrayBuffer };
  }

  async storeSignedPreKey(keyId: number | string, keyPair: KeyPairType): Promise<void> {
    const db = await openDB();
    const rec: StoredSignedPreKeyRecord = { id: Number(keyId), keyPair: { pubKey: keyPair.pubKey as ArrayBufferLike, privKey: keyPair.privKey as ArrayBufferLike } };
    await idbPutKeyPath(db, STORE_SIGNED_PREKEYS, rec);
    db.close();
  }

  async removeSignedPreKey(keyId: number | string): Promise<void> {
    const db = await openDB();
    await idbDelete(db, STORE_SIGNED_PREKEYS, Number(keyId));
    db.close();
  }

  // -----------------------------------------------------------------
  // Session records. The privacyresearch library stores the
  // session as a serialized string (JSON of the ratchet
  // state). We key by SignalProtocolAddress.toString(),
  // which is "<uin>.<deviceId>".
  // -----------------------------------------------------------------
  async loadSession(encodedAddress: string): Promise<SessionRecordType | undefined> {
    const db = await openDB();
    const v = await idbGet<SessionRecordType>(db, STORE_SESSIONS, encodedAddress);
    db.close();
    return v;
  }

  async storeSession(encodedAddress: string, record: SessionRecordType): Promise<void> {
    const db = await openDB();
    await idbPut(db, STORE_SESSIONS, record, encodedAddress);
    db.close();
  }

  async removeSession(encodedAddress: string): Promise<void> {
    const db = await openDB();
    await idbDelete(db, STORE_SESSIONS, encodedAddress);
    db.close();
  }
}

// Singleton. The class is stateless (all state is in IndexedDB),
// but a single instance keeps the contract honest — call sites
// always go through getSignalStore() rather than `new`-ing
// ad-hoc, so a future instrumentation hook (metrics, logging)
// has a single chokepoint to attach to.
let _signalStoreSingleton: IndexedDBSignalProtocolStore | null = null;
export function getSignalStore(): IndexedDBSignalProtocolStore {
  if (!_signalStoreSingleton) _signalStoreSingleton = new IndexedDBSignalProtocolStore();
  return _signalStoreSingleton;
}

// ----------------------------------------------------------------------------
// Local helpers for the signal store. These are NOT exported — they exist
// only to keep the storage-class self-contained.
// ----------------------------------------------------------------------------

function b64ToArrayBuffer(b64: string): ArrayBuffer {
  const s = b64.replace(/-/g, "+").replace(/_/g, "/");
  const pad = "=".repeat((4 - (s.length % 4)) % 4);
  const bin = atob(s + pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out.buffer;
}

function arrayBufferEquals(a: ArrayBuffer, b: ArrayBuffer): boolean {
  if (a.byteLength !== b.byteLength) return false;
  const av = new Uint8Array(a);
  const bv = new Uint8Array(b);
  for (let i = 0; i < av.length; i++) if (av[i] !== bv[i]) return false;
  return true;
}
