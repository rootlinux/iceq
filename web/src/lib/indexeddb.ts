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
const DB_VERSION = 6;

const STORE_IDENTITY = "identity";
const STORE_SESSIONS = "sessions";
const STORE_PREKEYS = "prekeys";
const STORE_SIGNED_PREKEYS = "signed_prekeys";
const STORE_PEER_IDENTITIES = "identities";
const STORE_MESSAGES = "messages";
const STORE_METADATA = "metadata";
const STORE_PEER_TRUST = "peer_trust";
const STORE_GROUP_CRYPTO = "group_crypto";
const STORE_TRANSPORT_SEEN = "transport_seen";

const SELF_KEY = "self";
const NEXT_PREKEY_ID_KEY = "next_prekey_id";

export interface CryptoNamespace { uin: number; deviceId: string }
const CRYPTO_KEY_VERSION = "crypto-v1";
const DEVICE_ID_KEY = "crypto_device_id_v1";
const PENDING_REGISTRATION_KEY = "pending_registration_v1";

export function cryptoRecordKey(ns: CryptoNamespace, kind: string, id: string | number): string {
  if (!Number.isSafeInteger(ns.uin) || ns.uin <= 0 || !/^[A-Za-z0-9_-]{16,128}$/.test(ns.deviceId)) {
    throw new Error("invalid crypto namespace");
  }
  return `${CRYPTO_KEY_VERSION}:${ns.uin}:${ns.deviceId}:${kind}:${id}`;
}

let activeCryptoNamespace: CryptoNamespace | null = null;
export function setActiveCryptoNamespace(ns: CryptoNamespace | null): void { activeCryptoNamespace = ns; }
export function getActiveCryptoNamespace(): CryptoNamespace {
  if (!activeCryptoNamespace) throw new Error("crypto namespace is not initialized");
  return activeCryptoNamespace;
}
export function createRegistrationCryptoNamespace():CryptoNamespace{const bytes=new Uint8Array(24);globalThis.crypto.getRandomValues(bytes);let binary="";for(const byte of bytes)binary+=String.fromCharCode(byte);return{uin:Number.MAX_SAFE_INTEGER,deviceId:`registration_${btoa(binary).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"")}`};}

export async function commitCryptoNamespace(from:CryptoNamespace,to:CryptoNamespace):Promise<void>{
  const db=await openDB();const stores=[STORE_IDENTITY,STORE_SESSIONS,STORE_PREKEYS,STORE_SIGNED_PREKEYS,STORE_PEER_IDENTITIES,STORE_METADATA,STORE_PEER_TRUST,STORE_GROUP_CRYPTO];
  const tx=db.transaction(stores,"readwrite");const done=transactionDone(tx);const prefix=`${CRYPTO_KEY_VERSION}:${from.uin}:${from.deviceId}:`;
  try{await Promise.all(stores.map(name=>new Promise<void>((resolve,reject)=>{const store=tx.objectStore(name);const req=store.openCursor();req.onsuccess=()=>{const cursor=req.result;if(!cursor)return resolve();const key=String(cursor.key);if(!key.startsWith(prefix)){cursor.continue();return;}const next=`${CRYPTO_KEY_VERSION}:${to.uin}:${to.deviceId}:${key.slice(prefix.length)}`;const collision=store.get(next);collision.onerror=()=>reject(collision.error);collision.onsuccess=()=>{if(collision.result!==undefined){tx.abort();reject(new Error("crypto namespace destination collision"));return;}const value=cursor.value as Record<string,unknown>;if(name===STORE_PREKEYS||name===STORE_SIGNED_PREKEYS)store.put({...value,id:next});else store.put(value,next);cursor.delete();cursor.continue();};};req.onerror=()=>reject(req.error);})));await done;}catch(error){try{tx.abort();}catch{/* already complete */}await done.catch(()=>undefined);throw error;}finally{db.close();}
}

let indexedDBRuntimeGeneration = 0;
let deviceIdFlight: Promise<string>|null=null;
const DEVICE_ID_RUNTIME_RESET_ERROR = "IndexedDB runtime reset during device ID initialization";

export function resetIndexedDBRuntime(): void {
  indexedDBRuntimeGeneration += 1;
  deviceIdFlight = null;
  activeCryptoNamespace = null;
}

export function loadOrCreateDeviceId(): Promise<string> {
  if(deviceIdFlight)return deviceIdFlight;
  const generation = indexedDBRuntimeGeneration;
  const resetError = (): Error => new Error(DEVICE_ID_RUNTIME_RESET_ERROR);
  const operation = (async()=>{
    const db=await openDB();
    try {
      if(generation!==indexedDBRuntimeGeneration)throw resetError();
      return await new Promise<string>((resolve,reject)=>{
        const tx=db.transaction(STORE_METADATA,"readwrite");
        const store=tx.objectStore(STORE_METADATA);
        const get=store.get(DEVICE_ID_KEY);
        let value="";
        get.onsuccess=()=>{
          if(generation!==indexedDBRuntimeGeneration){try{tx.abort();}catch{/* already settled */}return;}
          if(typeof get.result==="string"&&get.result){value=get.result;return;}
          const bytes=new Uint8Array(24);globalThis.crypto.getRandomValues(bytes);let binary="";
          for(const byte of bytes)binary+=String.fromCharCode(byte);
          value=btoa(binary).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
          store.put(value,DEVICE_ID_KEY);
        };
        tx.oncomplete=()=>generation===indexedDBRuntimeGeneration?resolve(value):reject(resetError());
        tx.onerror=()=>reject(generation===indexedDBRuntimeGeneration?(tx.error??new Error("device id transaction failed")):resetError());
        tx.onabort=()=>reject(generation===indexedDBRuntimeGeneration?(tx.error??new Error("device id transaction aborted")):resetError());
      });
    } finally { db.close(); }
  })();
  let flight: Promise<string>;
  flight=operation.catch(error=>{if(deviceIdFlight===flight)deviceIdFlight=null;throw error;});
  deviceIdFlight=flight;
  return flight;
}

export async function loadPendingRegistration<T>(): Promise<T | null> {
  const db=await openDB();try{return (await idbGet<T>(db,STORE_METADATA,PENDING_REGISTRATION_KEY))??null;}finally{db.close();}
}
export async function savePendingRegistration<T>(value:T):Promise<void>{const db=await openDB();try{await idbPut(db,STORE_METADATA,value,PENDING_REGISTRATION_KEY);}finally{db.close();}}
export async function clearPendingRegistration():Promise<void>{const db=await openDB();try{await idbDelete(db,STORE_METADATA,PENDING_REGISTRATION_KEY);}finally{db.close();}}

// ----------------------------------------------------------------------------
// Recovery provisioning — durable pending record
// ----------------------------------------------------------------------------
//
// After importing a recovery package, the identity key is in IndexedDB but
// the server still has the OLD device's prekey bundle. Provisioning fresh
// prekeys requires generating a bundle and uploading it. If the upload fails
// (network), we must retry the EXACT same bundle — not regenerate keys.
//
// This record stores the staging bundle + namespace + identity fingerprint
// so recovery can resume after a page reload without re-importing the
// recovery package.

const PENDING_RECOVERY_PROVISIONING_PREFIX = "pending_recovery_provisioning_v1";

function pendingRecoveryProvisioningKey(ns: CryptoNamespace): string {
  return `${PENDING_RECOVERY_PROVISIONING_PREFIX}:${ns.uin}:${ns.deviceId}`;
}

export interface PendingRecoveryProvisioning {
  // The exact PreKeyBundleUpload to retry on failure.
  bundle: {
    identityKey: string;
    registrationId: number;
    deviceId: number;
    signedPreKey: { keyId: number; publicKey: string; signature: string };
    oneTimePreKeys: Array<{ keyId: number; publicKey: string }>;
  };
  // The namespace the identity was imported into.
  namespace: CryptoNamespace;
  // Derived public key of the recovered identity (fingerprint for mismatch detection).
  identityFingerprint: string;
  // When the record was created (for debugging).
  createdAt: number;
}

export async function loadPendingRecoveryProvisioning(ns: CryptoNamespace): Promise<PendingRecoveryProvisioning | null> {
  const db = await openDB();
  try {
    return (await idbGet<PendingRecoveryProvisioning>(db, STORE_METADATA, pendingRecoveryProvisioningKey(ns))) ?? null;
  } finally {
    db.close();
  }
}

export async function savePendingRecoveryProvisioning(record: PendingRecoveryProvisioning): Promise<void> {
  const db = await openDB();
  try {
    await idbPut(db, STORE_METADATA, record, pendingRecoveryProvisioningKey(record.namespace));
  } finally {
    db.close();
  }
}

export async function clearPendingRecoveryProvisioning(ns: CryptoNamespace): Promise<void> {
  const db = await openDB();
  try {
    await idbDelete(db, STORE_METADATA, pendingRecoveryProvisioningKey(ns));
  } finally {
    db.close();
  }
}

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

export async function saveIdentity(ns: CryptoNamespace, id: StoredIdentity): Promise<void> {
  const db = await openDB();
  await idbPut(db, STORE_IDENTITY, id, cryptoRecordKey(ns, "identity", SELF_KEY));
  db.close();
}

export async function loadIdentity(ns: CryptoNamespace): Promise<StoredIdentity | null> {
  const db = await openDB();
  const v = await idbGet<StoredIdentity>(db, STORE_IDENTITY, cryptoRecordKey(ns, "identity", SELF_KEY));
  db.close();
  return v ?? null;
}

export async function migrateVerifiedLegacyIdentity(ns: CryptoNamespace, authenticatedPublicKey: string, derivePublic: (privateKey:string)=>Promise<string>): Promise<StoredIdentity | null> {
  const scoped = await loadIdentity(ns);
  if (scoped) {
    let scopedPublic: string;
    try { scopedPublic = await derivePublic(scoped.privateKey); } catch { throw new LegacyIdentityMismatchError(); }
    if (
      !constantTimeStringEqual(scopedPublic, authenticatedPublicKey) ||
      !constantTimeStringEqual(scopedPublic, scoped.publicKey)
    ) throw new LegacyIdentityMismatchError();
  }
  const db = await openDB();
  const legacy = await idbGet<StoredIdentity>(db, STORE_IDENTITY, SELF_KEY);
  if (!legacy) { db.close(); await deleteUnscopedLegacyCryptoRecords(); return scoped; }
  let derived: string;
  try { derived=await derivePublic(legacy.privateKey); } catch { await idbDelete(db, STORE_IDENTITY, SELF_KEY); db.close(); await deleteUnscopedLegacyCryptoRecords(); throw new LegacyIdentityMismatchError(); }
  if (!constantTimeStringEqual(derived, authenticatedPublicKey)) {
    await idbDelete(db, STORE_IDENTITY, SELF_KEY);
    db.close(); await deleteUnscopedLegacyCryptoRecords(); throw new LegacyIdentityMismatchError();
  }
  db.close();
  if (scoped && (
    scoped.registrationId !== legacy.registrationId ||
    !constantTimeStringEqual(scoped.privateKey, legacy.privateKey)
  )) {
    throw new Error("legacy crypto destination collision");
  }
  const normalized=scoped??{...legacy,publicKey:derived};
  await migrateLegacyCryptoRecordsAtomically(ns, legacy, normalized);
  return normalized;
}
export class LegacyIdentityMismatchError extends Error { constructor(){super("legacy identity mismatch");this.name="LegacyIdentityMismatchError";} }

interface LegacyMigrationStore {
  name: string;
  kind: string;
  keyPath: boolean;
  shouldMigrate?: (key: IDBValidKey) => boolean;
}

const LEGACY_MIGRATION_STORES: LegacyMigrationStore[] = [
  { name: STORE_IDENTITY, kind: "identity", keyPath: false },
  { name: STORE_SESSIONS, kind: "session", keyPath: false },
  { name: STORE_PREKEYS, kind: "prekey", keyPath: true },
  { name: STORE_SIGNED_PREKEYS, kind: "signed-prekey", keyPath: true },
  { name: STORE_PEER_IDENTITIES, kind: "peer-identity", keyPath: false },
  {
    name: STORE_METADATA,
    kind: "metadata",
    keyPath: false,
    shouldMigrate: (key) => key !== DEVICE_ID_KEY && key !== PENDING_REGISTRATION_KEY,
  },
  { name: STORE_PEER_TRUST, kind: "peer-trust", keyPath: false },
  { name: STORE_GROUP_CRYPTO, kind: "sender-key", keyPath: false },
];

interface LegacyMigrationRecord {
  store: LegacyMigrationStore;
  sourceKey: IDBValidKey;
  destinationKey: string;
  value: unknown;
}

function migrateLegacyCryptoRecordsAtomically(
  ns: CryptoNamespace,
  verifiedLegacyIdentity: StoredIdentity,
  normalizedIdentity: StoredIdentity,
): Promise<void> {
  return openDB().then((db) => new Promise<void>((resolve, reject) => {
    const tx = db.transaction(LEGACY_MIGRATION_STORES.map(({ name }) => name), "readwrite");
    const keys = new Map<string, IDBValidKey[]>();
    const values = new Map<string, unknown[]>();
    let pendingSnapshots = LEGACY_MIGRATION_STORES.length * 2;
    let migrationError: Error | null = null;

    const abort = (error: Error): void => {
      migrationError = error;
      try { tx.abort(); } catch { /* transaction already settled */ }
    };

    const applyMigration = (records: LegacyMigrationRecord[]): void => {
      try {
        for (const record of records) {
          const objectStore = tx.objectStore(record.store.name);
          const value = record.store.name === STORE_IDENTITY && record.sourceKey === SELF_KEY
            ? normalizedIdentity
            : record.value;
          if (record.store.keyPath) {
            if (typeof value !== "object" || value === null) {
              abort(new Error("invalid legacy key record"));
              return;
            }
            objectStore.put({ ...value, id: record.destinationKey });
          } else {
            objectStore.put(value, record.destinationKey);
          }
          objectStore.delete(record.sourceKey);
        }
      } catch (error) {
        abort(error instanceof Error ? error : new Error("legacy crypto migration write failed"));
      }
    };

    const preflightDestinations = (records: LegacyMigrationRecord[]): void => {
      if (records.length === 0) {
        abort(new Error("verified legacy identity disappeared during migration"));
        return;
      }
      let pendingCollisions = records.length;
      let collisionFound = false;
      for (const record of records) {
        const request = tx.objectStore(record.store.name).getKey(record.destinationKey);
        request.onerror = () => abort(request.error ?? new Error("legacy crypto collision check failed"));
        request.onsuccess = () => {
          const identityKeys = keys.get(STORE_IDENTITY) ?? [];
          const identityValues = values.get(STORE_IDENTITY) ?? [];
          const destinationIdentityIndex = identityKeys.findIndex((key) => key === record.destinationKey);
          const transactionalScopedIdentity = identityValues[destinationIdentityIndex] as StoredIdentity | undefined;
          const identicalScopedIdentity =
            record.store.name === STORE_IDENTITY &&
            record.sourceKey === SELF_KEY &&
            transactionalScopedIdentity !== undefined &&
            transactionalScopedIdentity.registrationId === normalizedIdentity.registrationId &&
            constantTimeStringEqual(transactionalScopedIdentity.privateKey, normalizedIdentity.privateKey) &&
            constantTimeStringEqual(transactionalScopedIdentity.publicKey, normalizedIdentity.publicKey);
          if (request.result !== undefined && !identicalScopedIdentity) collisionFound = true;
          pendingCollisions -= 1;
          if (pendingCollisions !== 0) return;
          if (collisionFound) {
            abort(new Error("legacy crypto destination collision"));
            return;
          }
          applyMigration(records);
        };
      }
    };

    const buildMigration = (): void => {
      const currentIdentityKeys = keys.get(STORE_IDENTITY) ?? [];
      const currentIdentityValues = values.get(STORE_IDENTITY) ?? [];
      const identityIndex = currentIdentityKeys.findIndex((key) => key === SELF_KEY);
      const currentIdentity = currentIdentityValues[identityIndex] as StoredIdentity | undefined;
      if (
        !currentIdentity ||
        currentIdentity.registrationId !== verifiedLegacyIdentity.registrationId ||
        !constantTimeStringEqual(currentIdentity.privateKey, verifiedLegacyIdentity.privateKey)
      ) {
        abort(new Error("verified legacy identity changed during migration"));
        return;
      }

      const records: LegacyMigrationRecord[] = [];
      for (const store of LEGACY_MIGRATION_STORES) {
        const storeKeys = keys.get(store.name) ?? [];
        const storeValues = values.get(store.name) ?? [];
        for (let index = 0; index < storeKeys.length; index += 1) {
          const sourceKey = storeKeys[index]!;
          if (typeof sourceKey !== "string" && typeof sourceKey !== "number") {
            abort(new Error("invalid legacy crypto record key"));
            return;
          }
          if (String(sourceKey).startsWith(`${CRYPTO_KEY_VERSION}:`)) continue;
          if (store.shouldMigrate && !store.shouldMigrate(sourceKey)) continue;
          records.push({
            store,
            sourceKey,
            destinationKey: cryptoRecordKey(ns, store.kind, sourceKey),
            value: storeValues[index],
          });
        }
      }
      preflightDestinations(records);
    };

    const snapshotComplete = (): void => {
      pendingSnapshots -= 1;
      if (pendingSnapshots === 0) buildMigration();
    };

    for (const store of LEGACY_MIGRATION_STORES) {
      const objectStore = tx.objectStore(store.name);
      const keyRequest = objectStore.getAllKeys();
      const valueRequest = objectStore.getAll();
      keyRequest.onerror = () => abort(keyRequest.error ?? new Error("legacy crypto key scan failed"));
      valueRequest.onerror = () => abort(valueRequest.error ?? new Error("legacy crypto value scan failed"));
      keyRequest.onsuccess = () => { keys.set(store.name, keyRequest.result); snapshotComplete(); };
      valueRequest.onsuccess = () => { values.set(store.name, valueRequest.result); snapshotComplete(); };
    }

    tx.oncomplete = () => { db.close(); resolve(); };
    tx.onerror = () => { /* onabort reports the stable error */ };
    tx.onabort = () => {
      db.close();
      reject(migrationError ?? tx.error ?? new Error("legacy crypto migration aborted"));
    };
  }));
}

async function deleteUnscopedLegacyCryptoRecords(): Promise<void> {
  const db=await openDB(); const stores=[STORE_IDENTITY,STORE_SESSIONS,STORE_PREKEYS,STORE_SIGNED_PREKEYS,STORE_PEER_IDENTITIES,STORE_PEER_TRUST,STORE_GROUP_CRYPTO];
  for(const name of stores){const tx=db.transaction(name,"readwrite");const store=tx.objectStore(name);const done=transactionDone(tx);await new Promise<void>((resolve,reject)=>{const req=store.openCursor();req.onsuccess=()=>{const cursor=req.result;if(!cursor)return resolve();if(String(cursor.key).startsWith(`${CRYPTO_KEY_VERSION}:`)){cursor.continue();return;}const deletion=cursor.delete();deletion.onsuccess=()=>cursor.continue();deletion.onerror=()=>reject(deletion.error);};req.onerror=()=>reject(req.error);});await done;}
  db.close();
}
export async function quarantineUnverifiedLegacyCrypto():Promise<void>{await deleteUnscopedLegacyCryptoRecords();}

// ----------------------------------------------------------------------------
// Sessions. One row per peer UIN. The value is whatever the
// Signal bindings want to hand back on load — opaque to us.
// ----------------------------------------------------------------------------
export async function saveSession(ns: CryptoNamespace, peerUin: number, record: string): Promise<void> {
  const db = await openDB();
  await idbPut(db, STORE_SESSIONS, record, cryptoRecordKey(ns, "session", peerUin));
  db.close();
}

export async function loadSession(ns: CryptoNamespace, peerUin: number): Promise<string | null> {
  const db = await openDB();
  const v = await idbGet<string>(db, STORE_SESSIONS, cryptoRecordKey(ns, "session", peerUin));
  db.close();
  return v ?? null;
}

export async function deleteSession(ns: CryptoNamespace, peerUin: number): Promise<void> {
  const db = await openDB();
  await idbDelete(db, STORE_SESSIONS, cryptoRecordKey(ns, "session", peerUin));
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

export async function savePreKey(ns: CryptoNamespace, pk: StoredPreKey): Promise<void> {
  const db = await openDB();
  await idbPutKeyPath(db, STORE_PREKEYS, { ...pk, keyId: pk.id, id: cryptoRecordKey(ns, "prekey", pk.id) });
  db.close();
}

export async function loadPreKeys(ns: CryptoNamespace): Promise<StoredPreKey[]> {
  const db = await openDB();
  const v = (await idbGetAll<StoredPreKey & {keyId?:number}>(db, STORE_PREKEYS)).filter((record) =>
    String(record.id).startsWith(cryptoRecordKey(ns, "prekey", "")),
  ).map(record=>({...record,id:record.keyId??Number(record.id)}));
  db.close();
  return v ?? [];
}

export async function deletePreKey(ns: CryptoNamespace, id: number): Promise<void> {
  const db = await openDB();
  await idbDelete(db, STORE_PREKEYS, cryptoRecordKey(ns, "prekey", id));
  db.close();
}

export async function loadNextPreKeyId(ns: CryptoNamespace): Promise<number | null> {
  const db = await openDB();
  const v = await idbGet<number>(db, STORE_METADATA, cryptoRecordKey(ns, "metadata", NEXT_PREKEY_ID_KEY));
  db.close();
  return typeof v === "number" && Number.isFinite(v) ? v : null;
}

export async function saveNextPreKeyId(ns: CryptoNamespace, id: number): Promise<void> {
  const db = await openDB();
  const key = cryptoRecordKey(ns, "metadata", NEXT_PREKEY_ID_KEY);
  const current = await idbGet<number>(db, STORE_METADATA, key);
  await idbPut(db, STORE_METADATA, Math.max(current ?? 0, id), key);
  db.close();
}

export async function reserveNextPreKeyIds(ns:CryptoNamespace,count:number,fallback:number):Promise<number>{
  if(!Number.isSafeInteger(count)||count<1)throw new Error("invalid prekey reservation count");const db=await openDB();try{return await new Promise<number>((resolve,reject)=>{const tx=db.transaction(STORE_METADATA,"readwrite");const store=tx.objectStore(STORE_METADATA);const key=cryptoRecordKey(ns,"metadata",NEXT_PREKEY_ID_KEY);const get=store.get(key);let start=fallback;get.onsuccess=()=>{if(typeof get.result==="number"&&Number.isFinite(get.result))start=Math.max(fallback,get.result);store.put(start+count,key);};tx.oncomplete=()=>resolve(start);tx.onerror=()=>reject(tx.error??new Error("prekey reservation failed"));});}finally{db.close();}
}
export interface SignedPreKeyRotationMetadata{publishedAt:number;rotateAfter:number;currentId:number;previousExpiresAt?:number}
export async function saveSignedPreKeyRotationMetadata(ns:CryptoNamespace,value:SignedPreKeyRotationMetadata):Promise<void>{const db=await openDB();await idbPut(db,STORE_METADATA,value,cryptoRecordKey(ns,"metadata","signed-prekey-rotation"));db.close();}
export async function loadSignedPreKeyRotationMetadata(ns:CryptoNamespace):Promise<SignedPreKeyRotationMetadata|null>{const db=await openDB();const value=await idbGet<SignedPreKeyRotationMetadata>(db,STORE_METADATA,cryptoRecordKey(ns,"metadata","signed-prekey-rotation"));db.close();return value??null;}

export interface StoredPeerTrust {
  version: 1;
  peerUin: number;
  fingerprint: string;
  verified: boolean;
  firstSeenAt: number;
  updatedAt: number;
  pendingFingerprint?: string;
}

export async function loadPeerTrust(peerUin: number, ns:CryptoNamespace): Promise<StoredPeerTrust | null> {
  const db = await openDB();
  const value = await idbGet<StoredPeerTrust>(db, STORE_PEER_TRUST, cryptoRecordKey(ns, "peer-trust", peerUin));
  db.close();
  return value ?? null;
}

export async function savePeerTrust(record: StoredPeerTrust, ns:CryptoNamespace): Promise<void> {
  const db = await openDB();
  await idbPut(db, STORE_PEER_TRUST, record, cryptoRecordKey(ns, "peer-trust", record.peerUin));
  db.close();
}

export async function resetPeerSignalState(peerUin: number, ns:CryptoNamespace): Promise<void> {
  const db = await openDB();
  const address = `${peerUin}.1`;
  await idbDelete(db, STORE_SESSIONS, cryptoRecordKey(ns,"session",address));
  await idbDelete(db, STORE_PEER_IDENTITIES, cryptoRecordKey(ns,"peer-identity",address));
  db.close();
}

export async function acceptPendingPeerIdentity(peerUin: number, fingerprint: string, operationNs:CryptoNamespace): Promise<void> {
  const db = await openDB();
  const tx = db.transaction([STORE_PEER_TRUST, STORE_SESSIONS, STORE_PEER_IDENTITIES], "readwrite");
  const done = transactionDone(tx);
  try {
    const trustStore = tx.objectStore(STORE_PEER_TRUST);
    const ns=operationNs; const trustKey=cryptoRecordKey(ns,"peer-trust",peerUin);
    const existing = await requestResult<StoredPeerTrust>(trustStore.get(trustKey));
    if (!existing || existing.pendingFingerprint !== fingerprint) throw new Error("fingerprint does not match the current pending identity");
    const now = Date.now();
    trustStore.put({ ...existing, fingerprint, verified: false, pendingFingerprint: undefined, updatedAt: now } satisfies StoredPeerTrust, trustKey);
    for (const address of [String(peerUin), `${peerUin}.1`]) {
      tx.objectStore(STORE_SESSIONS).delete(cryptoRecordKey(ns,"session",address));
      tx.objectStore(STORE_PEER_IDENTITIES).delete(cryptoRecordKey(ns,"peer-identity",address));
    }
    await done;
  } catch (error) {
    try { tx.abort(); } catch { /* already aborted */ }
    await done.catch(() => undefined);
    throw error;
  } finally { db.close(); }
}

export async function assertInboundIdentityTrusted(peerUin: number, identityKey: ArrayBuffer, operationNs:CryptoNamespace): Promise<void> {
  const db = await openDB();
  const ns=operationNs;
  const qualified = await idbGet<StoredPeerIdentity>(db, STORE_PEER_IDENTITIES, cryptoRecordKey(ns,"peer-identity",`${peerUin}.1`));
  const bare = qualified ?? await idbGet<StoredPeerIdentity>(db, STORE_PEER_IDENTITIES, cryptoRecordKey(ns,"peer-identity",String(peerUin)));
  const trustKey=cryptoRecordKey(ns,"peer-trust",peerUin); const trust = await idbGet<StoredPeerTrust>(db, STORE_PEER_TRUST, trustKey);
  const incomingFingerprint = signalIdentityToWire(identityKey);
  if (bare && !arrayBufferEquals(bare.publicKey, identityKey)) {
    db.close(); await persistInboundIdentityChange(String(peerUin), bare.publicKey, identityKey,ns); throw new Error("peer identity changed");
  }
  if (trust && (trust.pendingFingerprint !== undefined || trust.fingerprint !== incomingFingerprint)) {
    await idbPut(db, STORE_PEER_TRUST, { ...trust, pendingFingerprint: incomingFingerprint, updatedAt: Date.now() } satisfies StoredPeerTrust, trustKey);
    db.close(); throw new Error("peer identity changed");
  }
  db.close();
}

async function persistInboundIdentityChange(identifier: string, oldKey: ArrayBuffer, newKey: ArrayBuffer, ns:CryptoNamespace): Promise<void> {
  const match = /^(\d+)(?:\.\d+)?$/.exec(identifier);
  if (!match) return;
  const peerUin = Number(match[1]);
  if (!Number.isSafeInteger(peerUin) || peerUin <= 0) return;
  const db = await openDB();
  const trustKey=cryptoRecordKey(ns,"peer-trust",peerUin); const existing = await idbGet<StoredPeerTrust>(db, STORE_PEER_TRUST, trustKey);
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
  } satisfies StoredPeerTrust, trustKey);
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

export async function putGroupCryptoRecord(ns:CryptoNamespace,key: string, value: unknown): Promise<void> {
  const db = await openDB(); await idbPut(db, STORE_GROUP_CRYPTO, value, cryptoRecordKey(ns,"sender-key",key)); db.close();
}
export async function compareAndSwapGroupCryptoRecord<T extends {state?:unknown}>(ns:CryptoNamespace,key:string,expectedRevision:number|null,value:T):Promise<boolean>{
  const db=await openDB();const tx=db.transaction(STORE_GROUP_CRYPTO,"readwrite");const done=transactionDone(tx);
  try{
    const scoped=cryptoRecordKey(ns,"sender-key",key);const store=tx.objectStore(STORE_GROUP_CRYPTO);const current=await requestResult<{state?:{revision?:number}}|undefined>(store.get(scoped));
    const matches=expectedRevision===null?current===undefined:current!==undefined&&(current.state?.revision??0)===expectedRevision;
    if(!matches){tx.abort();await done.catch(()=>undefined);return false;}
    store.put(value,scoped);await done;return true;
  }finally{db.close();}
}
export async function getGroupCryptoRecord<T>(ns:CryptoNamespace,key: string): Promise<T | null> {
  const db = await openDB(); const value = await idbGet<T>(db, STORE_GROUP_CRYPTO, cryptoRecordKey(ns,"sender-key",key)); db.close(); return value ?? null;
}
export async function getAllGroupCryptoRecords<T>(ns:CryptoNamespace): Promise<T[]> {
  const db = await openDB(); const prefix=cryptoRecordKey(ns,"sender-key",""); const value = await idbGetAllEntries<T>(db, STORE_GROUP_CRYPTO); db.close(); return value.filter(v=>String(v.key).startsWith(prefix)).map(v=>v.value);
}
export async function deleteGroupCryptoRecord(ns:CryptoNamespace,key: string): Promise<void> {
  const db = await openDB(); await idbDelete(db, STORE_GROUP_CRYPTO, cryptoRecordKey(ns,"sender-key",key)); db.close();
}

// ----------------------------------------------------------------------------
// clearAll — called on 4403 (panic-wipe). Drops the whole
// database. We do this with deleteDatabase rather than
// clear() because it also removes the schema, so a re-open
// triggers a fresh onupgradeneeded and we can't accidentally
// resurrect a wiped state from a stale version.
// ----------------------------------------------------------------------------
export async function clearAll(): Promise<void> {
  resetIndexedDBRuntime();
  await new Promise<void>((resolve, reject) => {
    const req = indexedDB.deleteDatabase(ICEQ_INDEXEDDB_NAME);
    req.onsuccess = () => resolve();
    req.onerror = () => reject(req.error ?? new Error("IndexedDB deletion failed"));
    req.onblocked = () => reject(new Error("IndexedDB deletion was blocked"));
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
      if (!db.objectStoreNames.contains(STORE_TRANSPORT_SEEN)) {
        db.createObjectStore(STORE_TRANSPORT_SEEN);
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error ?? new Error("idb open failed"));
  });
}

interface TransportSeenRecord { status: "processing" | "seen"; ownerToken?: string; claimedAt: number; leaseUntil?: number; expiresAt?: number }

/** Atomically claims a stable transport id across tabs and page reloads. */
export async function claimTransportEnvelopeID(id: string, expiresAt?: number): Promise<string | null> {
  if (!id) return null;
	const ownerToken = crypto.randomUUID();
  const db = await openDB();
  try {
    return await new Promise<string | null>((resolve, reject) => {
      const tx = db.transaction(STORE_TRANSPORT_SEEN, "readwrite");
      const store = tx.objectStore(STORE_TRANSPORT_SEEN);
      const get = store.get(id);
	  let claimed: string | null = null;
      get.onsuccess = () => {
        const current = get.result as TransportSeenRecord | undefined;
        const now = Date.now();
        const currentValid = current && (current.expiresAt === undefined || current.expiresAt > now);
        if (currentValid && (current.status === "seen" || (current.leaseUntil ?? 0) > now)) return;
		store.put({ status: "processing", ownerToken, claimedAt: now, leaseUntil: now + 60_000, ...(expiresAt !== undefined ? { expiresAt } : {}) } satisfies TransportSeenRecord, id);
		claimed = ownerToken;
      };
      tx.oncomplete = () => resolve(claimed);
      tx.onerror = () => reject(tx.error ?? new Error("transport seen claim failed"));
      tx.onabort = () => reject(tx.error ?? new Error("transport seen claim aborted"));
    });
  } finally { db.close(); }
}

/** Commits a previously claimed id only after dispatch completed. */
export async function commitTransportEnvelopeID(id: string, ownerToken: string): Promise<boolean> {
  const db = await openDB();
  try {
	return await new Promise<boolean>((resolve, reject) => {
      const tx = db.transaction(STORE_TRANSPORT_SEEN, "readwrite");
      const store = tx.objectStore(STORE_TRANSPORT_SEEN);
      const get = store.get(id);
	  let committed = false;
	  get.onsuccess = () => {
        const current = get.result as TransportSeenRecord | undefined;
		if (current?.status === "processing" && current.ownerToken === ownerToken) {
		  store.put({ ...current, status: "seen", ownerToken: undefined, leaseUntil: undefined } satisfies TransportSeenRecord, id);
		  committed = true;
		}
      };
	  tx.oncomplete = () => resolve(committed);
      tx.onerror = () => reject(tx.error ?? new Error("transport seen commit failed"));
    });
  } finally { db.close(); }
}

/** True only after dispatch and the durable seen commit completed. */
export async function isTransportEnvelopeCommitted(id: string): Promise<boolean> {
  const db = await openDB();
  try {
    const current = await idbGet<TransportSeenRecord>(db, STORE_TRANSPORT_SEEN, id);
    return current?.status === "seen" && (current.expiresAt === undefined || current.expiresAt > Date.now());
  } finally { db.close(); }
}

export async function releaseTransportEnvelopeID(id: string, ownerToken: string): Promise<boolean> {
  const db = await openDB();
	try {
	  return await new Promise<boolean>((resolve, reject) => {
		const tx = db.transaction(STORE_TRANSPORT_SEEN, "readwrite");
		const store = tx.objectStore(STORE_TRANSPORT_SEEN);
		const get = store.get(id);
		let released = false;
		get.onsuccess = () => {
		  const current = get.result as TransportSeenRecord | undefined;
		  if (current?.status === "processing" && current.ownerToken === ownerToken) { store.delete(id); released = true; }
		};
		tx.oncomplete = () => resolve(released);
		tx.onerror = () => reject(tx.error ?? new Error("transport seen release failed"));
	  });
	} finally { db.close(); }
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

function idbGetAllEntries<T>(db: IDBDatabase, store: string): Promise<Array<{key: IDBValidKey; value: T}>> {
  return new Promise((resolve,reject)=>{const tx=db.transaction(store,"readonly");const out:Array<{key:IDBValidKey;value:T}>=[];const req=tx.objectStore(store).openCursor();req.onsuccess=()=>{const cursor=req.result;if(!cursor)return resolve(out);out.push({key:cursor.key,value:cursor.value as T});cursor.continue();};req.onerror=()=>reject(req.error??new Error("idb cursor failed"));});
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
  id: IDBValidKey;
  keyPair: KeyPairType<ArrayBufferLike>;
}

interface StoredSignedPreKeyRecord {
  id: IDBValidKey;
  keyPair: KeyPairType<ArrayBufferLike>;
}

interface StoredPeerIdentity {
  publicKey: ArrayBuffer;
  // When we first saw this identity. The trust check uses
  // first-seen-wins (TOFU) and refuses to overwrite.
  firstSeenAt: number;
}

export class IndexedDBSignalProtocolStore implements StorageType {
  constructor(public readonly namespace: CryptoNamespace) {}
  // -----------------------------------------------------------------
  // Identity key pair. One row, key="self", in STORE_IDENTITY.
  // The privacyresearch library calls this only for the LOCAL
  // identity; remote identities go in STORE_PEER_IDENTITIES.
  // -----------------------------------------------------------------
  async getIdentityKeyPair(): Promise<KeyPairType<ArrayBuffer> | undefined> {
    const db = await openDB();
    const v = await idbGet<StoredIdentity>(db, STORE_IDENTITY, cryptoRecordKey(this.namespace, "identity", SELF_KEY));
    db.close();
    if (!v) return undefined;
    return {
      pubKey: restoreSignalIdentityPublicKey(v.publicKey),
      privKey: b64ToArrayBuffer(v.privateKey),
    };
  }

  async getLocalRegistrationId(): Promise<number | undefined> {
    const db = await openDB();
    const v = await idbGet<StoredIdentity>(db, STORE_IDENTITY, cryptoRecordKey(this.namespace, "identity", SELF_KEY));
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
    const existing = await idbGet<StoredPeerIdentity>(db, STORE_PEER_IDENTITIES, cryptoRecordKey(this.namespace, "peer-identity", identifier));
    db.close();
    if (!existing) return true; // first sighting — accept and let saveIdentity pin it
    if (arrayBufferEquals(existing.publicKey, identityKey)) return true;
    await persistInboundIdentityChange(identifier, existing.publicKey, identityKey,this.namespace);
    return false;
  }

  async saveIdentity(
    encodedAddress: string,
    publicKey: ArrayBuffer,
    _nonblockingApproval?: boolean,
  ): Promise<boolean> {
    const db = await openDB();
    const key = cryptoRecordKey(this.namespace, "peer-identity", encodedAddress);
    const existing = await idbGet<StoredPeerIdentity>(db, STORE_PEER_IDENTITIES, key);
    if (existing && !arrayBufferEquals(existing.publicKey, publicKey)) {
      // Identity changed — refuse to overwrite. The peer needs
      // to re-init the session from a fresh bundle.
      db.close();
      await persistInboundIdentityChange(encodedAddress, existing.publicKey, publicKey,this.namespace);
      return false;
    }
    const rec: StoredPeerIdentity = { publicKey, firstSeenAt: Date.now() };
    await idbPut(db, STORE_PEER_IDENTITIES, rec, key);
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
    const v = await idbGet<StoredPreKeyRecord>(db, STORE_PREKEYS, cryptoRecordKey(this.namespace, "prekey", keyId));
    db.close();
    if (!v) return undefined;
    return { pubKey: v.keyPair.pubKey as ArrayBuffer, privKey: v.keyPair.privKey as ArrayBuffer };
  }

  async storePreKey(keyId: number | string, keyPair: KeyPairType): Promise<void> {
    const db = await openDB();
    const rec: StoredPreKeyRecord = { id: cryptoRecordKey(this.namespace, "prekey", keyId), keyPair: { pubKey: keyPair.pubKey as ArrayBufferLike, privKey: keyPair.privKey as ArrayBufferLike } };
    await idbPutKeyPath(db, STORE_PREKEYS, rec);
    db.close();
  }

  async removePreKey(keyId: number | string): Promise<void> {
    const db = await openDB();
    await idbDelete(db, STORE_PREKEYS, cryptoRecordKey(this.namespace, "prekey", keyId));
    db.close();
  }

  // -----------------------------------------------------------------
  // Signed prekey. Same shape as one-time prekey but stored
  // separately so the long-lived signed prekey doesn't get
  // mixed up with the one-time pool.
  // -----------------------------------------------------------------
  async loadSignedPreKey(keyId: number | string): Promise<KeyPairType<ArrayBuffer> | undefined> {
    const db = await openDB();
    const v = await idbGet<StoredSignedPreKeyRecord>(db, STORE_SIGNED_PREKEYS, cryptoRecordKey(this.namespace, "signed-prekey", keyId));
    db.close();
    if (!v) return undefined;
    return { pubKey: v.keyPair.pubKey as ArrayBuffer, privKey: v.keyPair.privKey as ArrayBuffer };
  }

  async storeSignedPreKey(keyId: number | string, keyPair: KeyPairType): Promise<void> {
    const db = await openDB();
    const rec: StoredSignedPreKeyRecord = { id: cryptoRecordKey(this.namespace, "signed-prekey", keyId), keyPair: { pubKey: keyPair.pubKey as ArrayBufferLike, privKey: keyPair.privKey as ArrayBufferLike } };
    await idbPutKeyPath(db, STORE_SIGNED_PREKEYS, rec);
    db.close();
  }

  async removeSignedPreKey(keyId: number | string): Promise<void> {
    const db = await openDB();
    await idbDelete(db, STORE_SIGNED_PREKEYS, cryptoRecordKey(this.namespace, "signed-prekey", keyId));
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
    const v = await idbGet<SessionRecordType>(db, STORE_SESSIONS, cryptoRecordKey(this.namespace, "session", encodedAddress));
    db.close();
    return v;
  }

  async storeSession(encodedAddress: string, record: SessionRecordType): Promise<void> {
    const db = await openDB();
    await idbPut(db, STORE_SESSIONS, record, cryptoRecordKey(this.namespace, "session", encodedAddress));
    db.close();
  }

  async removeSession(encodedAddress: string): Promise<void> {
    const db = await openDB();
    await idbDelete(db, STORE_SESSIONS, cryptoRecordKey(this.namespace, "session", encodedAddress));
    db.close();
  }
}

// Singleton. The class is stateless (all state is in IndexedDB),
// but a single instance keeps the contract honest — call sites
// always go through getSignalStore() rather than `new`-ing
// ad-hoc, so a future instrumentation hook (metrics, logging)
// has a single chokepoint to attach to.
export function getSignalStore(namespace: CryptoNamespace): IndexedDBSignalProtocolStore {
  return new IndexedDBSignalProtocolStore(namespace);
}

// ----------------------------------------------------------------------------
// Security vault — passphrase verification blob (never contains the passphrase
// or derived key; only a PBKDF2-derived AES-GCM-encrypted known prefix).
// ----------------------------------------------------------------------------

const SECURITY_VAULT_SALT_KEY = "security_vault_salt";
const SECURITY_VAULT_BLOB_KEY = "security_vault";
const SECURITY_SETUP_COMPLETE_KEY = "security_setup_complete";

export async function saveSecurityVaultSalt(ns: CryptoNamespace, salt: string): Promise<void> {
  const db = await openDB();
  await idbPut(db, STORE_METADATA, { v: 1, salt }, cryptoRecordKey(ns, "metadata", SECURITY_VAULT_SALT_KEY));
  db.close();
}

export async function loadSecurityVaultSalt(ns: CryptoNamespace): Promise<{ v: number; salt: string } | null> {
  const db = await openDB();
  const v = await idbGet<{ v: number; salt: string }>(db, STORE_METADATA, cryptoRecordKey(ns, "metadata", SECURITY_VAULT_SALT_KEY));
  db.close();
  return v ?? null;
}

export async function saveSecurityVaultBlob(ns: CryptoNamespace, blob: string): Promise<void> {
  const db = await openDB();
  await idbPut(db, STORE_METADATA, { v: 1, blob }, cryptoRecordKey(ns, "metadata", SECURITY_VAULT_BLOB_KEY));
  db.close();
}

export async function loadSecurityVaultBlob(ns: CryptoNamespace): Promise<{ v: number; blob: string } | null> {
  const db = await openDB();
  const v = await idbGet<{ v: number; blob: string }>(db, STORE_METADATA, cryptoRecordKey(ns, "metadata", SECURITY_VAULT_BLOB_KEY));
  db.close();
  return v ?? null;
}

export async function deleteSecurityVaultRecords(ns: CryptoNamespace): Promise<void> {
  const db = await openDB();
  await idbDelete(db, STORE_METADATA, cryptoRecordKey(ns, "metadata", SECURITY_VAULT_SALT_KEY));
  await idbDelete(db, STORE_METADATA, cryptoRecordKey(ns, "metadata", SECURITY_VAULT_BLOB_KEY));
  db.close();
}

export async function hasSecuritySetupCompleted(ns: CryptoNamespace): Promise<boolean> {
  const db = await openDB();
  const v = await idbGet<{ v: number }>(db, STORE_METADATA, cryptoRecordKey(ns, "metadata", SECURITY_SETUP_COMPLETE_KEY));
  db.close();
  return v?.v === 1;
}

export async function setSecuritySetupCompleted(ns: CryptoNamespace): Promise<void> {
  const db = await openDB();
  await idbPut(db, STORE_METADATA, { v: 1 }, cryptoRecordKey(ns, "metadata", SECURITY_SETUP_COMPLETE_KEY));
  db.close();
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

function constantTimeStringEqual(a: string, b: string): boolean {
  const aa = new TextEncoder().encode(a); const bb = new TextEncoder().encode(b);
  let mismatch = aa.length ^ bb.length; const n = Math.max(aa.length, bb.length);
  for (let i = 0; i < n; i++) mismatch |= (aa[i % (aa.length || 1)] ?? 0) ^ (bb[i % (bb.length || 1)] ?? 0);
  return mismatch === 0;
}
