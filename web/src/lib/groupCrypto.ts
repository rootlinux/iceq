import { decryptGroupMessage, createReceiverState, createSenderState, encryptGroupMessage, type ReceiverState, type SenderKeyCiphertext, type SenderKeyDistribution, type SenderState } from "./senderKeys";
import { loadGroupCryptoState, saveGroupCryptoState } from "./groupCryptoStore";

export const GROUP_DISTRIBUTION_KIND = "iceq.sender-key-distribution.v1";
export const GROUP_CONTENT_KIND = "iceq.group-content.v1";
export interface GroupContent { kind: typeof GROUP_CONTENT_KIND; content_type:"text"|"image"|"file"; text?:string; attachment?:unknown }
export interface OpaqueSenderKeyInboxItem { sender_uin:number; ciphertext:string; msg_type:"prekey_message"|"signal_message"; distribution_id?:string }
interface LocalStored { sender: SenderState; distributed_to: number[] }

export async function ensureGroupSender(groupId:string,epoch:number,selfUin:number,memberUins:number[],sendDistribution:(uin:number, plaintext:Uint8Array, distribution:SenderKeyDistribution)=>Promise<void>):Promise<SenderState> {
  const stored=await loadGroupCryptoState(groupId,epoch,selfUin,"sender");
  let local:LocalStored;
  if (stored) local=stored.state as LocalStored; else { const made=await createSenderState(groupId,epoch,selfUin); local={sender:made.state,distributed_to:[]}; }
  const distribution:SenderKeyDistribution = stripPrivate(local.sender);
  if(!await loadGroupCryptoState(groupId,epoch,selfUin,"receiver")) {
    await saveGroupCryptoState({version:1,kind:"receiver",group_id:groupId,epoch,sender_uin:selfUin,updated_at:Date.now(),state:createReceiverState(distribution)});
  }
  const roster=[...new Set(memberUins)].filter(u=>u!==selfUin).sort((a,b)=>a-b);
  const pending=roster.filter(u=>!local.distributed_to.includes(u));
  for(const uin of pending) {
    await sendDistribution(uin,new TextEncoder().encode(JSON.stringify({kind:GROUP_DISTRIBUTION_KIND,distribution})),distribution);
    local.distributed_to.push(uin);
  }
  await saveGroupCryptoState({version:1,kind:"sender",group_id:groupId,epoch,sender_uin:selfUin,updated_at:Date.now(),state:local});
  return local.sender;
}

export async function sealGroupContent(state:SenderState,content:GroupContent):Promise<SenderKeyCiphertext> {
  const result=await encryptGroupMessage(state,new TextEncoder().encode(JSON.stringify(content)));
  const stored=await loadGroupCryptoState(state.group_id,state.epoch,state.sender_uin,"sender");
  const local=(stored?.state as LocalStored|undefined)??{sender:state,distributed_to:[]}; local.sender=result.state;
  await saveGroupCryptoState({version:1,kind:"sender",group_id:state.group_id,epoch:state.epoch,sender_uin:state.sender_uin,updated_at:Date.now(),state:local});
  return result.envelope;
}
export async function installSenderDistribution(senderUin:number,value:unknown,currentEpoch:number,currentMembers:number[]):Promise<boolean> {
  if(!isObj(value)||value.kind!==GROUP_DISTRIBUTION_KIND||!isObj(value.distribution))return false;
  const d=value.distribution as unknown as SenderKeyDistribution;
  if(d.sender_uin!==senderUin||d.epoch!==currentEpoch||!currentMembers.includes(senderUin))throw new Error("unauthorized sender-key distribution");
  const receiver=createReceiverState(d);
  await saveGroupCryptoState({version:1,kind:"receiver",group_id:d.group_id,epoch:d.epoch,sender_uin:d.sender_uin,updated_at:Date.now(),state:receiver}); return true;
}
export async function hydrateSenderKeyInbox(groupId:string,currentEpoch:number,currentMembers:number[],fetchInbox:()=>Promise<OpaqueSenderKeyInboxItem[]>,decryptPairwise:(senderUin:number,ciphertext:string,msgType:"prekey_message"|"signal_message")=>Promise<Uint8Array>):Promise<number> {
  let installed=0;
  for(const item of await fetchInbox()) {
    const existing=await loadGroupCryptoState(groupId,currentEpoch,item.sender_uin,"receiver");
    if(item.distribution_id&&existing&&(existing.state as ReceiverState).distribution_id===item.distribution_id)continue;
    const plaintext=await decryptPairwise(item.sender_uin,item.ciphertext,item.msg_type);
    const value:unknown=JSON.parse(new TextDecoder().decode(plaintext));
    if(!isObj(value)||value.kind!==GROUP_DISTRIBUTION_KIND||!isObj(value.distribution)||value.distribution.group_id!==groupId)throw new Error("sender-key inbox context is not authorized");
    if(await installSenderDistribution(item.sender_uin,value,currentEpoch,currentMembers))installed++;
  }
  return installed;
}
export async function openGroupContent(envelope:SenderKeyCiphertext,currentEpoch:number,currentMembers:number[],allowObsoleteDecrypt=false):Promise<GroupContent> {
  const obsolete=envelope.epoch!==currentEpoch;
  if((obsolete&&!allowObsoleteDecrypt)||(!obsolete&&!currentMembers.includes(envelope.sender_uin)))throw new Error("group sender or epoch is no longer authorized");
  const stored=await loadGroupCryptoState(envelope.group_id,envelope.epoch,envelope.sender_uin,"receiver");
  if(!stored)throw new Error("sender key distribution is missing");
  const receiver=stored.state as ReceiverState;
  const plaintext=await decryptGroupMessage(receiver,envelope);
  await saveGroupCryptoState({...stored,updated_at:Date.now(),state:receiver});
  const parsed:unknown=JSON.parse(new TextDecoder().decode(plaintext));
  if(!isObj(parsed)||parsed.kind!==GROUP_CONTENT_KIND||!["text","image","file"].includes(String(parsed.content_type)))throw new Error("invalid encrypted group content");
  return parsed as unknown as GroupContent;
}
export function encodeGroupCiphertext(v:SenderKeyCiphertext):string { return btoa(unescape(encodeURIComponent(JSON.stringify(v)))).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/g,""); }
export function decodeGroupCiphertext(v:string):SenderKeyCiphertext { const p="=".repeat((4-v.length%4)%4);return JSON.parse(decodeURIComponent(escape(atob(v.replace(/-/g,"+").replace(/_/g,"/")+p)))) as SenderKeyCiphertext; }
function stripPrivate(s:SenderState):SenderKeyDistribution { const {signing_private_key:_,...d}=s;return d; }
function isObj(v:unknown):v is Record<string,unknown>{return typeof v==="object"&&v!==null&&!Array.isArray(v);}
