import type { CryptoNamespace } from "./indexeddb";
import type { OneTimePreKeyUpload, SignedPreKeyUpload } from "../api/keys";
import { uploadBundle } from "../api/keys";
import { fetchBundle } from "../api/keys";
import { me, cryptoBinding } from "../api/auth";
import { ApiError } from "../api/client";
import { clearPendingRegistration, commitCryptoNamespace, loadOrCreateDeviceId, loadPendingRegistration, savePendingRegistration, setActiveCryptoNamespace } from "./indexeddb";

export interface RegistrationBundle {
  identity_key: string;
  signed_pre_key: SignedPreKeyUpload;
  one_time_pre_keys: OneTimePreKeyUpload[];
  registration_id: number;
}

export interface PendingRegistration {
  version: 1;
  username: string;
  status: "prepared" | "registering" | "registered";
  stagingNamespace: CryptoNamespace;
  identityKey: string;
  bundle: RegistrationBundle;
  accountUin?: number;
  deviceId?: string;
}

export interface RegistrationStateStore {
  load(): Promise<PendingRegistration | null>;
  save(state: PendingRegistration): Promise<void>;
  clear(): Promise<void>;
}

interface RegistrationDependencies {
  store: RegistrationStateStore;
  prepare(): Promise<Omit<PendingRegistration, "version" | "username" | "status">>;
  register(input: { username: string; password: string; identityKey: string }): Promise<{ uin: number }>;
  authenticatedAccount(): Promise<{uin:number;username:string}|null>;
  fetchDirectory(uin:number): Promise<{identity_key:string}|null>;
  deviceId(): Promise<string>;
  upload(bundle: RegistrationBundle): Promise<void>;
  commit(from: CryptoNamespace, to: CryptoNamespace): Promise<void>;
}

export async function runRegistration(
  input: { username: string; password: string },
  deps: RegistrationDependencies,
  onStage?: (stage: "generating" | "registering" | "uploading") => void,
): Promise<CryptoNamespace> {
  let pending = await deps.store.load();
  if (pending && pending.username !== input.username) {
    throw new Error("unfinished registration belongs to another username");
  }
  if (!pending) {
    onStage?.("generating");
    const prepared = await deps.prepare();
    pending = { version: 1, username: input.username, status: "prepared", ...prepared };
    await deps.store.save(pending);
  }

  if (pending.status === "prepared") {
    if(await deps.authenticatedAccount())throw new Error("prepared registration cannot attach to an authenticated account");
      onStage?.("registering");
      pending = { ...pending, status: "registering" };
      await deps.store.save(pending);
      // Once this request starts its outcome is ambiguous. A retry must recover
      // through the authenticated account and directory, never POST /register again.
      const registered = await deps.register({ username: input.username, password: input.password, identityKey: pending.identityKey });
      pending = { ...pending, status: "registered", accountUin: registered.uin, deviceId: await deps.deviceId() };
      await deps.store.save(pending);
  }

  const account=await deps.authenticatedAccount();
  if(!account)throw new Error("registration outcome is ambiguous; login to recover safely");
  if(account.username.trim()!==pending.username.trim())throw new Error("authenticated account username does not own pending registration");
  if(pending.accountUin!==undefined&&pending.accountUin!==account.uin)throw new Error("authenticated account does not own pending registration");
  const directory=await deps.fetchDirectory(account.uin);
  if(directory&&!constantTimeEqual(directory.identity_key,pending.identityKey))throw new Error("pending registration identity does not match key directory");
  if(!directory&&pending.accountUin===undefined)throw new Error("registering state has no trusted account binding or key directory proof");
  if(pending.status==="registering"){
    pending={...pending,status:"registered",accountUin:account.uin,deviceId:await deps.deviceId()};
    await deps.store.save(pending);
  }

  if (!pending.accountUin || !pending.deviceId) throw new Error("registered state is incomplete");
  onStage?.("uploading");
  await deps.upload(pending.bundle);
  const target = { uin: pending.accountUin, deviceId: pending.deviceId };
  await deps.commit(pending.stagingNamespace, target);
  await deps.store.clear();
  return target;
}

export interface ResumeDependencies {
  loadPending(): Promise<PendingRegistration | null>;
  me(): Promise<{ uin: number; username: string }>;
  fetchBundle(uin: number): Promise<{ identity_key: string }>;
  cryptoBinding(): Promise<{ uin: number; identity_key: string }>;
  savePending(state: PendingRegistration): Promise<void>;
  loadOrCreateDeviceId(): Promise<string>;
  uploadBundle(bundle: RegistrationBundle): Promise<void>;
  commitCryptoNamespace(from: CryptoNamespace, to: CryptoNamespace): Promise<void>;
  clearPendingRegistration(): Promise<void>;
  setActiveCryptoNamespace(ns: CryptoNamespace): void;
}

/** Produces the production dependencies wired to live browser storage and APIs. */
export function createResumeDeps(): ResumeDependencies {
  return {
    loadPending: () => loadPendingRegistration<PendingRegistration>(),
    me: () => me(),
    fetchBundle: (uin) => fetchBundle(uin),
    cryptoBinding: () => cryptoBinding(),
    savePending: (s) => savePendingRegistration(s),
    loadOrCreateDeviceId: () => loadOrCreateDeviceId(),
    uploadBundle: (b) => uploadBundle(b),
    commitCryptoNamespace: (from, to) => commitCryptoNamespace(from, to),
    clearPendingRegistration: () => clearPendingRegistration(),
    setActiveCryptoNamespace: (ns) => { setActiveCryptoNamespace(ns); },
  };
}

/** Completes the post-register transaction after a reload restored the cookie session. */
export async function resumeAuthenticatedRegistration(
  accountUin: number,
  deps?: ResumeDependencies,
): Promise<boolean> {
  const d = deps ?? createResumeDeps();
  let pending = await d.loadPending();
  if (!pending) return false;
  if (pending.status === "prepared") throw new Error("prepared registration cannot attach to an authenticated account");
  const account = await d.me();
  if (account.uin !== accountUin || account.username.trim() !== pending.username.trim()) throw new Error("authenticated account does not own pending registration");
  let directory: { identity_key: string } | null = null;
  try { directory = await d.fetchBundle(accountUin); } catch (error) {
    if (!(error instanceof ApiError) || error.status !== 404) throw error;
  }

  // If the key directory exists and identities don't match, fail closed.
  if (directory && !constantTimeEqual(directory.identity_key, pending.identityKey)) throw new Error("pending registration identity does not match key directory");

  // If the key directory doesn't exist yet (bundle was never uploaded because
  // the client lost the register response), try the crypto-binding endpoint.
  // It returns the identity_key stored at POST /register time — the server's
  // own record of what public key belongs to this authenticated account.
  if (!directory) {
    try {
      const binding = await d.cryptoBinding();
      if (binding.uin !== accountUin) throw new Error("crypto-binding returned wrong account");
      if (!constantTimeEqual(binding.identity_key, pending.identityKey)) {
        throw new Error("pending registration identity does not match server-stored identity");
      }
      // Server confirms this public identity was registered for this account.
      // This is the missing proof that lets us safely resume.
    } catch (error) {
      if (error instanceof Error && (error.message.includes("pending registration identity") || error.message.includes("crypto-binding returned wrong account"))) throw error;
      if (pending.accountUin === undefined) throw new Error("registering state has no trusted account binding or key directory proof");
    }
  }

  if (pending.accountUin !== undefined && pending.accountUin !== accountUin) throw new Error("pending registration belongs to another account");
  if (pending.status !== "registered") {
    pending = { ...pending, status: "registered", accountUin, deviceId: await d.loadOrCreateDeviceId() };
    await d.savePending(pending);
  }
  if (!pending.deviceId) {
    pending = { ...pending, deviceId: await d.loadOrCreateDeviceId() };
    await d.savePending(pending);
  }
  await d.uploadBundle(pending.bundle);
  const deviceId = pending.deviceId;
  if (!deviceId) throw new Error("pending registration device is missing");
  const target = { uin: accountUin, deviceId };
  await d.commitCryptoNamespace(pending.stagingNamespace, target);
  await d.clearPendingRegistration();
  d.setActiveCryptoNamespace(target);
  return true;
}

function constantTimeEqual(a:string,b:string):boolean{const aa=new TextEncoder().encode(a),bb=new TextEncoder().encode(b);let diff=aa.length^bb.length;const length=Math.max(aa.length,bb.length);for(let i=0;i<length;i++)diff|=(aa[i]??0)^(bb[i]??0);return diff===0;}
