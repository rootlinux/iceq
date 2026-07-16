import { deleteGroupCryptoRecord, getAllGroupCryptoRecords, getGroupCryptoRecord, putGroupCryptoRecord } from "./indexeddb";

export type GroupCryptoKind = "sender" | "receiver";
export interface StoredGroupCryptoState {
  version: 1; kind: GroupCryptoKind; group_id: string; epoch: number; sender_uin: number;
  updated_at: number; state: unknown;
}
const keyFor = (g:string,e:number,u:number,k:GroupCryptoKind):string => `${g}:${e}:${u}:${k}`;

export async function saveGroupCryptoState(record: StoredGroupCryptoState): Promise<void> {
  if (record.version !== 1 || !record.group_id || record.epoch < 1 || record.sender_uin < 1) throw new Error("invalid group crypto state");
  await putGroupCryptoRecord(keyFor(record.group_id,record.epoch,record.sender_uin,record.kind), structuredClone(record));
}
export function loadGroupCryptoState(groupId:string,epoch:number,senderUin:number,kind:GroupCryptoKind):Promise<StoredGroupCryptoState|null> {
  return getGroupCryptoRecord(keyFor(groupId,epoch,senderUin,kind));
}
export async function pruneObsoleteGroupEpochs(groupId:string,currentEpoch:number,graceMs=86_400_000):Promise<void> {
  const cutoff=Date.now()-graceMs; const all=await getAllGroupCryptoRecords<StoredGroupCryptoState>();
  await Promise.all(all.filter(r=>r.group_id===groupId&&r.epoch<currentEpoch&&r.updated_at<cutoff).map(r=>deleteGroupCryptoRecord(keyFor(r.group_id,r.epoch,r.sender_uin,r.kind))));
}
