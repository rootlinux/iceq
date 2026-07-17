import { compareAndSwapGroupCryptoRecord, deleteGroupCryptoRecord, getAllGroupCryptoRecords, getGroupCryptoRecord, putGroupCryptoRecord, type CryptoNamespace } from "./indexeddb";

export type GroupCryptoKind = "sender" | "receiver";
export interface StoredGroupCryptoState {
  version: 1; kind: GroupCryptoKind; group_id: string; epoch: number; sender_uin: number;
  updated_at: number; state: unknown;
  created_at?: number;
}
export interface AuthenticatedGroupContentRecord {
  version: 1; kind: "authenticated_content"; group_id: string; epoch: number;
  cache_key: string; created_at: number; expires_at: number; content: unknown;
}
const AUTHENTICATED_CONTENT_TTL_MS=86_400_000;
const distributionIdOf=(record:StoredGroupCryptoState):string|undefined=>record.kind==="receiver"&&typeof record.state==="object"&&record.state!==null&&"distribution_id" in record.state?String((record.state as {distribution_id:unknown}).distribution_id):undefined;
const keyFor = (g:string,e:number,u:number,k:GroupCryptoKind,distributionId?:string):string => `${g}:${e}:${u}:${k}${k==="receiver"&&distributionId?`:${distributionId}`:""}`;
export function compareAndSwapSenderState(ns:CryptoNamespace,record:StoredGroupCryptoState,expectedRevision:number|null):Promise<boolean>{
  if(record.kind!=="sender")throw new Error("sender CAS requires sender state");
  return compareAndSwapGroupCryptoRecord(ns,keyFor(record.group_id,record.epoch,record.sender_uin,"sender"),expectedRevision,structuredClone(record));
}

export async function saveGroupCryptoState(ns:CryptoNamespace,record: StoredGroupCryptoState): Promise<void> {
  if (record.version !== 1 || !record.group_id || record.epoch < 1 || record.sender_uin < 1) throw new Error("invalid group crypto state");
  const key=keyFor(record.group_id,record.epoch,record.sender_uin,record.kind,distributionIdOf(record));
  const existing=await getGroupCryptoRecord<StoredGroupCryptoState>(ns,key);
  const persisted=structuredClone({...record,created_at:existing?.created_at??record.created_at??Date.now()});
  await putGroupCryptoRecord(ns,key,persisted);
  if(record.kind==="receiver"&&distributionIdOf(record)&&!await getGroupCryptoRecord(ns,keyFor(record.group_id,record.epoch,record.sender_uin,record.kind))) {
    await putGroupCryptoRecord(ns,keyFor(record.group_id,record.epoch,record.sender_uin,record.kind),structuredClone(persisted));
  }
}
export async function loadGroupCryptoState(ns:CryptoNamespace,groupId:string,epoch:number,senderUin:number,kind:GroupCryptoKind,distributionId?:string):Promise<StoredGroupCryptoState|null> {
  if(kind!=="receiver"||distributionId)return getGroupCryptoRecord(ns,keyFor(groupId,epoch,senderUin,kind,distributionId));
  const preferred=await getGroupCryptoRecord<StoredGroupCryptoState>(ns,keyFor(groupId,epoch,senderUin,kind));if(preferred)return preferred;
  const candidates=(await getAllGroupCryptoRecords<StoredGroupCryptoState>(ns)).filter(r=>r?.version===1&&r.kind==="receiver"&&r.group_id===groupId&&r.epoch===epoch&&r.sender_uin===senderUin);
  return candidates.sort((a,b)=>(b.created_at??b.updated_at)-(a.created_at??a.updated_at)||b.updated_at-a.updated_at)[0]??null;
}
export async function pruneObsoleteGroupEpochs(ns:CryptoNamespace,groupId:string,currentEpoch:number,graceMs=86_400_000,now=Date.now()):Promise<void> {
  const cutoff=now-graceMs; const all=await getAllGroupCryptoRecords<StoredGroupCryptoState>(ns);
  await Promise.all(all.filter(r=>r?.version===1&&(r.kind==="sender"||r.kind==="receiver")&&r.group_id===groupId&&r.epoch<currentEpoch&&(r.created_at??r.updated_at)<cutoff).flatMap(r=>{
    const exact=keyFor(r.group_id,r.epoch,r.sender_uin,r.kind,distributionIdOf(r));
    return r.kind==="receiver"?[deleteGroupCryptoRecord(ns,exact),deleteGroupCryptoRecord(ns,keyFor(r.group_id,r.epoch,r.sender_uin,r.kind))]:[deleteGroupCryptoRecord(ns,exact)];
  }));
}
export async function loadAuthenticatedGroupContent(ns:CryptoNamespace,cacheKey:string,groupId:string,epoch:number,now=Date.now()):Promise<unknown|null>{
  const key=`content:${cacheKey}`;const record=await getGroupCryptoRecord<AuthenticatedGroupContentRecord>(ns,key);
  if(!record)return null;
  if(record.kind!=="authenticated_content"||record.group_id!==groupId||record.epoch!==epoch||record.cache_key!==cacheKey||record.expires_at<=now){await deleteGroupCryptoRecord(ns,key);return null;}
  return structuredClone(record.content);
}
export async function saveAuthenticatedGroupContent(ns:CryptoNamespace,cacheKey:string,groupId:string,epoch:number,content:unknown,now=Date.now(),ttlMs=AUTHENTICATED_CONTENT_TTL_MS):Promise<void>{
  const key=`content:${cacheKey}`;const existing=await getGroupCryptoRecord<AuthenticatedGroupContentRecord>(ns,key);
  if(existing?.kind==="authenticated_content"&&(existing.group_id!==groupId||existing.epoch!==epoch))throw new Error("authenticated content cache context mismatch");
  const createdAt=existing?.kind==="authenticated_content"?existing.created_at:now;
  const expiresAt=existing?.kind==="authenticated_content"?existing.expires_at:createdAt+ttlMs;
  await putGroupCryptoRecord(ns,key,structuredClone({version:1,kind:"authenticated_content",group_id:groupId,epoch,cache_key:cacheKey,created_at:createdAt,expires_at:expiresAt,content} satisfies AuthenticatedGroupContentRecord));
}
export async function pruneAuthenticatedGroupContent(ns:CryptoNamespace,groupId:string,now=Date.now()):Promise<void>{
  const all=await getAllGroupCryptoRecords<AuthenticatedGroupContentRecord>(ns);
  await Promise.all(all.filter(r=>r?.kind==="authenticated_content"&&r.group_id===groupId&&r.expires_at<=now).map(r=>deleteGroupCryptoRecord(ns,`content:${r.cache_key}`)));
}
