import { ApiError } from "../api/client";
import { fetchBundle, uploadBundle, type PreKeyBundleUpload, type RemotePreKeyBundle } from "../api/keys";
import { loadIdentity, type StoredIdentity } from "./indexeddb";
import {
  generatePreKeyBundle,
  restoreOwnIdentity,
  type IdentityKeyPair,
} from "./signal";

const DEFAULT_PREKEY_START = 1;
const DEFAULT_ONE_TIME_PREKEY_COUNT = 20;

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
}

const defaultDeps: SignalBootstrapDeps = {
  fetchBundle,
  loadIdentity,
  restoreIdentity: restoreOwnIdentity,
  generatePreKeyBundle,
  uploadBundle,
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
