import { deleteGroupCryptoRecord, getAllGroupCryptoRecords, getGroupCryptoRecord, putGroupCryptoRecord } from "./indexeddb";

export type GroupCryptoKind = "sender" | "receiver";
export interface StoredGroupCryptoState {
  version: 1; kind: GroupCryptoKind; group_id: string; epoch: number; sender_uin: number;
  updated_at: number; state: unknown;
  created_at?: number;
}
const keyFor = (g:string,e:number,u:number,k:GroupCryptoKind):string => `${g}:${e}:${u}:${k}`;

export async function saveGroupCryptoState(record: StoredGroupCryptoState): Promise<void> {
  if (record.version !== 1 || !record.group_id || record.epoch < 1 || record.sender_uin < 1) throw new Error("invalid group crypto state");
  const key=keyFor(record.group_id,record.epoch,record.sender_uin,record.kind);
  const existing=await getGroupCryptoRecord<StoredGroupCryptoState>(key);
  await putGroupCryptoRecord(key, structuredClone({...record,created_at:existing?.created_at??record.created_at??Date.now()}));
}
export function loadGroupCryptoState(groupId:string,epoch:number,senderUin:number,kind:GroupCryptoKind):Promise<StoredGroupCryptoState|null> {
  return getGroupCryptoRecord(keyFor(groupId,epoch,senderUin,kind));
}
export async function pruneObsoleteGroupEpochs(groupId:string,currentEpoch:number,graceMs=86_400_000,now=Date.now()):Promise<void> {
  const cutoff=now-graceMs; const all=await getAllGroupCryptoRecords<StoredGroupCryptoState>();
  await Promise.all(all.filter(r=>r.group_id===groupId&&r.epoch<currentEpoch&&(r.created_at??r.updated_at)<cutoff).map(r=>deleteGroupCryptoRecord(keyFor(r.group_id,r.epoch,r.sender_uin,r.kind))));
}
export function loadAuthenticatedGroupContent(cacheKey:string):Promise<unknown|null>{return getGroupCryptoRecord(`content:${cacheKey}`);}
export function saveAuthenticatedGroupContent(cacheKey:string,content:unknown):Promise<void>{return putGroupCryptoRecord(`content:${cacheKey}`,structuredClone(content));}
