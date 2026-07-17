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
  type CryptoNamespace,
  type StoredIdentity,
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
  if (!stored && directory && deps === defaultDeps) {
    try { stored = await migrateVerifiedLegacyIdentity(ns, directory.identity_key, deriveIdentityPublicKey); }
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
