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
  loadNextPreKeyId,
  saveNextPreKeyId,
  type StoredIdentity,
} from "./indexeddb";
import {
  generateOneTimePreKeys,
  generatePreKeyBundle,
  restoreOwnIdentity,
  type IdentityKeyPair,
} from "./signal";

const DEFAULT_PREKEY_START = 1;
const DEFAULT_ONE_TIME_PREKEY_COUNT = 20;
const LEGACY_NEXT_PREKEY_ID = 22;
const PREKEY_LOW_WATERMARK = 10;
const PREKEY_TARGET_COUNT = 20;

type RestoredIdentity = IdentityKeyPair & { registrationId: number };

interface GeneratedBundle extends PreKeyBundleUpload {}

export interface SignalBootstrapDeps {
  fetchBundle: (uin: number) => Promise<RemotePreKeyBundle>;
  loadIdentity: () => Promise<StoredIdentity | null>;
  restoreIdentity: (stored: StoredIdentity) => RestoredIdentity;
  generatePreKeyBundle: (
    identity: IdentityKeyPair,
    startId: number,
    oneTimeCount: number,
    registrationId: number,
  ) => Promise<GeneratedBundle>;
  uploadBundle: (bundle: PreKeyBundleUpload) => Promise<void>;
  getPrekeyCount: () => Promise<number>;
  loadNextPreKeyId: () => Promise<number | null>;
  saveNextPreKeyId: (id: number) => Promise<void>;
  generateOneTimePreKeys: (startId: number, count: number) => Promise<OneTimePreKeyUpload[]>;
  addPreKeys: (prekeys: OneTimePreKeyUpload[]) => Promise<{ accepted: number }>;
}

const defaultDeps: SignalBootstrapDeps = {
  fetchBundle,
  loadIdentity,
  restoreIdentity: restoreOwnIdentity,
  generatePreKeyBundle,
  uploadBundle,
  getPrekeyCount,
  loadNextPreKeyId,
  saveNextPreKeyId,
  generateOneTimePreKeys,
  addPreKeys,
};

export async function ensureOwnBundle(
  uin: number,
  deps: SignalBootstrapDeps = defaultDeps,
): Promise<"ok" | "repaired"> {
  try {
    await deps.fetchBundle(uin);
    return "ok";
  } catch (error) {
    if (!(error instanceof ApiError) || error.status !== 404) {
      throw error;
    }
  }

  const stored = await deps.loadIdentity();
  if (!stored) {
    throw new Error(
      "This account is missing this device's IceQ encryption keys. Sign in from the original device or register a new account.",
    );
  }

  const identity = deps.restoreIdentity(stored);
  const bundle = await deps.generatePreKeyBundle(
    identity,
    DEFAULT_PREKEY_START,
    DEFAULT_ONE_TIME_PREKEY_COUNT,
    identity.registrationId,
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
  const startId = (await deps.loadNextPreKeyId()) ?? LEGACY_NEXT_PREKEY_ID;
  await deps.saveNextPreKeyId(startId + topUpCount);
  const prekeys = await deps.generateOneTimePreKeys(startId, topUpCount);
  const uploaded = await deps.addPreKeys(prekeys);

  return {
    bundle,
    replenished: uploaded.accepted > 0,
    prekeyCount: count + uploaded.accepted,
  };
}
