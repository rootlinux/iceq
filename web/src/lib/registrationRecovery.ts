import type { CryptoNamespace } from "./indexeddb";
import type { OneTimePreKeyUpload, SignedPreKeyUpload } from "../api/keys";
import { uploadBundle } from "../api/keys";
import { fetchBundle } from "../api/keys";
import { me } from "../api/auth";
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

/** Completes the post-register transaction after a reload restored the cookie session. */
export async function resumeAuthenticatedRegistration(accountUin: number): Promise<boolean> {
  let pending=await loadPendingRegistration<PendingRegistration>();
  if(!pending)return false;
  if(pending.status==="prepared")throw new Error("prepared registration cannot attach to an authenticated account");
  const account=await me();
  if(account.uin!==accountUin||account.username.trim()!==pending.username.trim())throw new Error("authenticated account does not own pending registration");
  let directory:{identity_key:string}|null=null;try{directory=await fetchBundle(accountUin);}catch(error){if(!(error instanceof ApiError)||error.status!==404)throw error;}
  if(directory&&!constantTimeEqual(directory.identity_key,pending.identityKey))throw new Error("pending registration identity does not match key directory");
  if(!directory&&pending.accountUin===undefined)throw new Error("registering state has no trusted account binding or key directory proof");
  if(pending.accountUin!==undefined&&pending.accountUin!==accountUin)throw new Error("pending registration belongs to another account");
  if(pending.status!=="registered"){pending={...pending,status:"registered",accountUin,deviceId:await loadOrCreateDeviceId()};await savePendingRegistration(pending);}
  if(!pending.deviceId){pending={...pending,deviceId:await loadOrCreateDeviceId()};await savePendingRegistration(pending);}
  await uploadBundle(pending.bundle);
  const deviceId=pending.deviceId;if(!deviceId)throw new Error("pending registration device is missing");
  const target={uin:accountUin,deviceId};
  await commitCryptoNamespace(pending.stagingNamespace,target);
  await clearPendingRegistration();setActiveCryptoNamespace(target);return true;
}

function constantTimeEqual(a:string,b:string):boolean{const aa=new TextEncoder().encode(a),bb=new TextEncoder().encode(b);let diff=aa.length^bb.length;const length=Math.max(aa.length,bb.length);for(let i=0;i<length;i++)diff|=(aa[i]??0)^(bb[i]??0);return diff===0;}
