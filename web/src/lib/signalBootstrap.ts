import { ApiError } from "../api/client";
import {
  addPreKeys,
  fetchBundle,
  getPrekeyCount,
  uploadBundle,
  type OneTimePreKeyUpload,
  type PreKeyBundleUpload,
  type RemotePreKeyBundle,
} from "../api/keys";
import {
  loadIdentity,
  loadOrCreateDeviceId,
  migrateVerifiedLegacyIdentity,
  LegacyIdentityMismatchError,
  quarantineUnverifiedLegacyCrypto,
  loadNextPreKeyId,
  saveNextPreKeyId,
  reserveNextPreKeyIds,
  setActiveCryptoNamespace,
  loadPendingRecoveryProvisioning,
  savePendingRecoveryProvisioning,
  clearPendingRecoveryProvisioning,
  type CryptoNamespace,
  type StoredIdentity,
  type PendingRecoveryProvisioning,
} from "./indexeddb";
import {
  generateOneTimePreKeys,
  generatePreKeyBundle,
  deriveIdentityPublicKey,
  restoreOwnIdentity,
  type IdentityKeyPair,
} from "./signal";
import { resumeAuthenticatedRegistration } from "./registrationRecovery";

const DEFAULT_PREKEY_START = 1;
const DEFAULT_ONE_TIME_PREKEY_COUNT = 20;
const LEGACY_NEXT_PREKEY_ID = 22;
const PREKEY_LOW_WATERMARK = 10;
const PREKEY_TARGET_COUNT = 20;

type RestoredIdentity = IdentityKeyPair & { registrationId: number };

interface GeneratedBundle extends PreKeyBundleUpload {}

export interface SignalBootstrapDeps {
  fetchBundle: (uin: number) => Promise<RemotePreKeyBundle>;
  loadIdentity: (ns?: CryptoNamespace) => Promise<StoredIdentity | null>;
  migrateLegacyIdentity?: (
    ns: CryptoNamespace,
    authenticatedPublicKey: string,
    derivePublic: (privateKey: string) => Promise<string>,
  ) => Promise<StoredIdentity | null>;
  loadOrCreateDeviceId?: () => Promise<string>;
  deriveStoredPublic?: (privateKey:string)=>Promise<string>;
  restoreIdentity: (stored: StoredIdentity) => RestoredIdentity;
  generatePreKeyBundle: (
    identity: IdentityKeyPair,
    startId: number,
    oneTimeCount: number,
    registrationId: number,
    namespace?: CryptoNamespace,
  ) => Promise<GeneratedBundle>;
  uploadBundle: (bundle: PreKeyBundleUpload) => Promise<void>;
  getPrekeyCount: () => Promise<number>;
  loadNextPreKeyId: (ns?: CryptoNamespace) => Promise<number | null>;
  saveNextPreKeyId: (id: number, ns?: CryptoNamespace) => Promise<void>;
  reserveNextPreKeyIds?: (ns:CryptoNamespace,count:number,fallback:number)=>Promise<number>;
  generateOneTimePreKeys: (startId: number, count: number, namespace?: CryptoNamespace) => Promise<OneTimePreKeyUpload[]>;
  addPreKeys: (prekeys: OneTimePreKeyUpload[]) => Promise<{ accepted: number }>;
}

const defaultDeps: SignalBootstrapDeps = {
  fetchBundle,
  loadIdentity: (ns) => loadIdentity(ns!),
  migrateLegacyIdentity: migrateVerifiedLegacyIdentity,
  loadOrCreateDeviceId,
  deriveStoredPublic: deriveIdentityPublicKey,
  restoreIdentity: restoreOwnIdentity,
  generatePreKeyBundle: (identity,start,count,registration,ns)=>generatePreKeyBundle(identity,start,count,registration,ns!),
  uploadBundle,
  getPrekeyCount,
  loadNextPreKeyId: (ns) => loadNextPreKeyId(ns!),
  saveNextPreKeyId: (id, ns) => saveNextPreKeyId(ns!, id),
  reserveNextPreKeyIds,
  generateOneTimePreKeys: (start,count,ns)=>generateOneTimePreKeys(start,count,ns!),
  addPreKeys,
};

export async function ensureOwnBundle(
  uin: number,
  deps: SignalBootstrapDeps = defaultDeps,
): Promise<"ok" | "repaired"> {
  if(deps===defaultDeps)await resumeAuthenticatedRegistration(uin);
  const ns: CryptoNamespace = { uin, deviceId: await resolveDeviceId(deps) };
  setActiveCryptoNamespace(ns);
  let directory: RemotePreKeyBundle | null = null;
  try {
    directory = await deps.fetchBundle(uin);
  } catch (error) {
    if (!(error instanceof ApiError) || error.status !== 404) {
      throw error;
    }
  }

  let stored = await deps.loadIdentity(ns);
  if (directory && deps.migrateLegacyIdentity) {
    try { stored = await deps.migrateLegacyIdentity(ns, directory.identity_key, deriveIdentityPublicKey); }
    catch (error) { if (error instanceof LegacyIdentityMismatchError) throw new IdentityKeyMismatchError(); throw error; }
  }
  if(!stored&&!directory&&deps===defaultDeps)await quarantineUnverifiedLegacyCrypto();
  if (!stored && directory) throw new MissingLocalIdentityError();
  if (!stored) {
    throw new Error(
      "This account is missing this device's IceQ encryption keys. Sign in from the original device or register a new account.",
    );
  }

  const identity = deps.restoreIdentity(stored);
  const derivedPublic=await (deps.deriveStoredPublic??(async()=>stored.publicKey))(stored.privateKey);
  if (!constantTimeEqual(derivedPublic,stored.publicKey)||directory && !constantTimeEqual(derivedPublic, directory.identity_key)) {
    throw new IdentityKeyMismatchError();
  }
  if (directory) return "ok";
  const bundle = await deps.generatePreKeyBundle(
    identity,
    DEFAULT_PREKEY_START,
    DEFAULT_ONE_TIME_PREKEY_COUNT,
    identity.registrationId,
    ns,
  );
  await deps.uploadBundle(bundle);
  return "repaired";
}

// ---------------------------------------------------------------------------
// Recovery prekey provisioning
// ---------------------------------------------------------------------------
//
// After importing a recovery package, the recovered identity key is in
// IndexedDB but the server still has the OLD device's prekey bundle.
// ensureOwnBundle() returns "ok" immediately when it sees a server bundle
// exists — it has no way to know the bundle belongs to a different device.
//
// provisionRecoveryPrekeys is the explicit state machine for recovery:
//
//  1. Load the recovered identity (must exist — caller verified import).
//  2. Derive the public key and confirm it matches the server directory.
//     Identity mismatch → fail closed WITHOUT uploading anything.
//  3. Generate a fresh signed prekey + one-time prekeys. Private halves
//     are persisted to IndexedDB by generatePreKeyBundle BEFORE this
//     function calls uploadBundle.
//  4. Upload the new bundle, replacing the old device's bundle on the
//     server. The identity_key is unchanged (same recovered identity);
//     only the signed prekey and one-time prekeys are new.
//  5. If upload fails, the staged keys are already in IndexedDB. The
//     caller retries the same keys — they are NOT regenerated.
//
// The caller MUST NOT report recovery as complete until this function
// returns successfully.

export interface RecoveryProvisioningDeps {
  loadIdentity: (ns?: CryptoNamespace) => Promise<StoredIdentity | null>;
  fetchBundle: (uin: number) => Promise<RemotePreKeyBundle>;
  restoreIdentity: (stored: StoredIdentity) => RestoredIdentity;
  deriveStoredPublic?: (privateKey: string) => Promise<string>;
  generatePreKeyBundle: (
    identity: IdentityKeyPair,
    startId: number,
    oneTimeCount: number,
    registrationId: number,
    namespace?: CryptoNamespace,
  ) => Promise<GeneratedBundle>;
  uploadBundle: (bundle: PreKeyBundleUpload) => Promise<void>;
  loadPendingRecord: (ns: CryptoNamespace) => Promise<PendingRecoveryProvisioning | null>;
  savePendingRecord: (record: PendingRecoveryProvisioning) => Promise<void>;
  clearPendingRecord: (ns: CryptoNamespace) => Promise<void>;
}

const defaultRecoveryDeps: RecoveryProvisioningDeps = {
  loadIdentity: (ns) => loadIdentity(ns!),
  fetchBundle,
  restoreIdentity: restoreOwnIdentity,
  deriveStoredPublic: deriveIdentityPublicKey,
  generatePreKeyBundle: (identity, start, count, registration, ns) => generatePreKeyBundle(identity, start, count, registration, ns!),
  uploadBundle,
  loadPendingRecord: (ns) => loadPendingRecoveryProvisioning(ns),
  savePendingRecord: savePendingRecoveryProvisioning,
  clearPendingRecord: (ns) => clearPendingRecoveryProvisioning(ns),
};

// provisionRecoveryPrekeys generates fresh prekeys for a recovered identity
// and uploads them to the server. The caller MUST pass the existing active
// namespace — the namespace is NEVER invented or mutated by this function.
//
// Durable recovery-provisioning record (IndexedDB):
//
//  1. Check for an existing pending record. If one exists with a matching
//     identity fingerprint, the private key halves were already persisted
//     by a prior generatePreKeyBundle call. Reuse the exact same public
//     bundle for the upload retry — keys are NEVER regenerated.
//
//  2. If no pending record exists, load the recovered identity, verify it
//     against the server directory (fail closed on mismatch), generate
//     fresh prekeys, persist the pending record to IndexedDB, then upload.
//
//  3. After a successful upload, clear the pending record.
//
//  4. If upload fails, the pending record remains. The caller can retry
//     after a page reload — the pending record survives browser restarts.
//
// The recovered identity key is NEVER changed. Only the signed prekey and
// one-time prekeys are replaced. The global active namespace is NEVER
// mutated — the caller owns namespace management.
export async function provisionRecoveryPrekeys(
  ns: CryptoNamespace,
  deps: RecoveryProvisioningDeps = defaultRecoveryDeps,
): Promise<void> {
  // 0. Check for a pending record from a previous attempt.
  //    If one exists with a matching identity fingerprint, the private key
  //    halves are already in IndexedDB. Reuse the exact same public bundle.
  const pending = await deps.loadPendingRecord(ns);
  if (pending) {
    // Verify the namespace matches — if the caller passes a different
    // namespace, something is wrong.
    if (pending.namespace.uin !== ns.uin || pending.namespace.deviceId !== ns.deviceId) {
      throw new Error("Pending recovery provisioning record namespace does not match active namespace.");
    }

    // Load the identity to verify the fingerprint still matches.
    const stored = await deps.loadIdentity(ns);
    if (!stored) {
      // Identity was deleted (e.g., IndexedDB cleared). Clear the stale
      // pending record so the caller falls through to full provisioning.
      await deps.clearPendingRecord(ns);
      throw new Error("No recovered identity found. Import the recovery package first.");
    }

    const derivedPublic = await (deps.deriveStoredPublic ?? (async () => stored.publicKey))(stored.privateKey);
    if (!constantTimeEqual(derivedPublic, pending.identityFingerprint)) {
      // Identity changed — the pending record is for a different identity.
      // Clear it so the caller can re-provision.
      await deps.clearPendingRecord(ns);
      throw new IdentityKeyMismatchError();
    }

    // ---- Revalidate server identity before retrying the upload ----
    // Fetch the current server identity bundle and verify ALL THREE match:
    // server identity, local derived identity, and pending-record fingerprint.
    // If the server identity changed between the first failed attempt and
    // this retry (e.g., another device rotated keys), fail closed and
    // upload NOTHING.
    let serverDirectory: RemotePreKeyBundle;
    try {
      serverDirectory = await deps.fetchBundle(ns.uin);
    } catch (fetchErr) {
      throw new Error(`Cannot fetch server key directory for retry: ${(fetchErr as Error).message}`);
    }

    if (!constantTimeEqual(derivedPublic, serverDirectory.identity_key)) {
      // Server identity does not match local identity. The server's key
      // directory has changed since the pending record was created. Fail
      // closed — do NOT upload anything, do NOT overwrite server identity.
      await deps.clearPendingRecord(ns);
      throw new IdentityKeyMismatchError();
    }

    // All three match: server identity, local derived identity, and
    // pending-record fingerprint. Safe to retry the exact same bundle.
    // Map from camelCase (IndexedDB storage format) to snake_case
    // (PreKeyBundleUpload wire format).
    await deps.uploadBundle({
      identity_key: pending.bundle.identityKey,
      registration_id: pending.bundle.registrationId,
      signed_pre_key: {
        id: pending.bundle.signedPreKey.keyId,
        public_key: pending.bundle.signedPreKey.publicKey,
        signature: pending.bundle.signedPreKey.signature,
      },
      one_time_pre_keys: pending.bundle.oneTimePreKeys.map((k) => ({
        id: k.keyId,
        public_key: k.publicKey,
      })),
    });
    // Upload succeeded — clear the pending record.
    await deps.clearPendingRecord(ns);
    return;
  }

  // 1. Load recovered identity from the caller's namespace.
  const stored = await deps.loadIdentity(ns);
  if (!stored) {
    throw new Error("No recovered identity found. Import the recovery package first.");
  }

  // 2. Fetch server directory and verify identity match.
  let directory: RemotePreKeyBundle;
  try {
    directory = await deps.fetchBundle(ns.uin);
  } catch (error) {
    throw new Error(`Cannot fetch server key directory: ${(error as Error).message}`);
  }

  const derivedPublic = await (deps.deriveStoredPublic ?? (async () => stored.publicKey))(stored.privateKey);
  if (!constantTimeEqual(derivedPublic, directory.identity_key)) {
    // Identity mismatch — fail closed WITHOUT uploading anything.
    throw new IdentityKeyMismatchError();
  }

  // 3. Restore identity and generate fresh prekeys.
  //    generatePreKeyBundle persists private halves to IndexedDB before
  //    returning — the keys are staged locally regardless of upload outcome.
  const identity = deps.restoreIdentity(stored);
  const bundle = await deps.generatePreKeyBundle(
    identity,
    DEFAULT_PREKEY_START,
    DEFAULT_ONE_TIME_PREKEY_COUNT,
    identity.registrationId,
    ns,
  );

  // 4. Persist the pending record BEFORE uploading. This makes the bundle
  //    durable across page reloads. The fingerprint ensures the record
  //    matches the recovered identity.
  const pendingRecord: PendingRecoveryProvisioning = {
    bundle: {
      identityKey: bundle.identity_key,
      registrationId: bundle.registration_id,
      deviceId: 1,
      signedPreKey: {
        keyId: bundle.signed_pre_key.id,
        publicKey: bundle.signed_pre_key.public_key,
        signature: bundle.signed_pre_key.signature,
      },
      oneTimePreKeys: bundle.one_time_pre_keys.map((k) => ({
        keyId: k.id,
        publicKey: k.public_key,
      })),
    },
    namespace: { uin: ns.uin, deviceId: ns.deviceId },
    identityFingerprint: derivedPublic,
    createdAt: Date.now(),
  };
  await deps.savePendingRecord(pendingRecord);

  // 5. Upload the bundle. The identity_key is the same recovered key;
  //    only the signed prekey and one-time prekeys are replaced.
  //    If this fails, the pending record survives and the caller retries
  //    the exact same bundle (step 0 above reuses it).
  try {
    await deps.uploadBundle(bundle);
  } catch (uploadErr) {
    // Pending record stays — caller retries same bundle on next attempt.
    throw uploadErr;
  }

  // 6. Upload confirmed — clear the pending record.
  await deps.clearPendingRecord(ns);
}

export interface SignalProvisioningResult {
  bundle: "ok" | "repaired";
  replenished: boolean;
  prekeyCount: number;
}

export async function ensureSignalProvisioning(
  uin: number,
  deps: SignalBootstrapDeps = defaultDeps,
): Promise<SignalProvisioningResult> {
  const bundle = await ensureOwnBundle(uin, deps);
  const count = await deps.getPrekeyCount();
  if (count >= PREKEY_LOW_WATERMARK) {
    return { bundle, replenished: false, prekeyCount: count };
  }

  const topUpCount = PREKEY_TARGET_COUNT - count;
  const ns: CryptoNamespace = { uin, deviceId: await resolveDeviceId(deps) };
  const startId = deps.reserveNextPreKeyIds
    ? await deps.reserveNextPreKeyIds(ns,topUpCount,LEGACY_NEXT_PREKEY_ID)
    : (await deps.loadNextPreKeyId(ns)) ?? LEGACY_NEXT_PREKEY_ID;
  if(!deps.reserveNextPreKeyIds)await deps.saveNextPreKeyId(startId + topUpCount, ns);
  const prekeys = await deps.generateOneTimePreKeys(startId, topUpCount, ns);
  const uploaded = await deps.addPreKeys(prekeys);

  return {
    bundle,
    replenished: uploaded.accepted > 0,
    prekeyCount: count + uploaded.accepted,
  };
}

export class IdentityKeyMismatchError extends Error {
  constructor() { super("Local encryption identity does not match this account's key directory."); this.name = "IdentityKeyMismatchError"; }
}
export class MissingLocalIdentityError extends Error{constructor(){super("This account is missing this device's IceQ encryption keys.");this.name="MissingLocalIdentityError";}}

function constantTimeEqual(a: string, b: string): boolean {
  const aa = new TextEncoder().encode(a); const bb = new TextEncoder().encode(b);
  let mismatch = aa.length ^ bb.length;
  const length = Math.max(aa.length, bb.length);
  for (let i = 0; i < length; i++) mismatch |= (aa[i % aa.length] ?? 0) ^ (bb[i % bb.length] ?? 0);
  return mismatch === 0;
}

function resolveDeviceId(deps: SignalBootstrapDeps): Promise<string> {
  if (deps.loadOrCreateDeviceId) return deps.loadOrCreateDeviceId();
  if (deps === defaultDeps) return loadOrCreateDeviceId();
  return Promise.resolve("dependency-test-device");
}
