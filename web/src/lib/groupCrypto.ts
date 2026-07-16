import { decryptGroupMessage, createReceiverState, createSenderState, encryptGroupMessage, type ReceiverState, type SenderKeyCiphertext, type SenderKeyDistribution, type SenderState } from "./senderKeys";
import { compareAndSwapSenderState, loadAuthenticatedGroupContent, loadGroupCryptoState, pruneAuthenticatedGroupContent, saveAuthenticatedGroupContent, saveGroupCryptoState } from "./groupCryptoStore";
import { assertCanonicalObjectKey, isEncryptedFileManifest } from "./fileCrypto";

export const GROUP_DISTRIBUTION_KIND = "iceq.sender-key-distribution.v1";
export const GROUP_CONTENT_KIND = "iceq.group-content.v1";
export interface GroupContent { kind: typeof GROUP_CONTENT_KIND; content_type:"text"|"image"|"file"; text?:string; attachment?:unknown }
export interface ExpectedGroupRouting { group_id:string; sender_uin:number; epoch?:number }
export interface OpaqueSenderKeyInboxItem { epoch?:number; sender_uin:number; ciphertext:string; msg_type:"prekey_message"|"signal_message"; distribution_id?:string; retired_at?:string }
interface LocalStored { sender: SenderState; distributed_to: number[]; revision?:number }
const localSenderQueues=new Map<string,Promise<void>>();
async function withSenderLock<T>(key:string,operation:()=>Promise<T>):Promise<T>{
  if(typeof navigator!=="undefined"&&navigator.locks)return navigator.locks.request(`iceq:sender:${key}`,operation);
  const previous=localSenderQueues.get(key)??Promise.resolve();let release!:()=>void;const current=new Promise<void>(resolve=>{release=resolve;});const tail=previous.then(()=>current);localSenderQueues.set(key,tail);
  await previous;try{return await operation();}finally{release();if(localSenderQueues.get(key)===tail)localSenderQueues.delete(key);}
}
export function authenticatedGroupMessageFields(content:GroupContent,_untrustedOuterContentType:string):{plaintext:string;content_type:GroupContent["content_type"]}{
  return {plaintext:content.content_type==="file"?JSON.stringify(content.attachment??null):(content.text??""),content_type:content.content_type};
}

export async function ensureGroupSender(groupId:string,epoch:number,selfUin:number,memberUins:number[],sendDistribution:(uin:number, plaintext:Uint8Array, distribution:SenderKeyDistribution)=>Promise<void>):Promise<SenderState> {
  return withSenderLock(`${groupId}:${epoch}:${selfUin}`,async()=>{
    const stored=await loadGroupCryptoState(groupId,epoch,selfUin,"sender");
    let local:LocalStored;
    if (stored) local=stored.state as LocalStored; else { const made=await createSenderState(groupId,epoch,selfUin); local={sender:made.state,distributed_to:[],revision:0}; }
    const distribution:SenderKeyDistribution = stripPrivate(local.sender);
    if(!await loadGroupCryptoState(groupId,epoch,selfUin,"receiver",distribution.distribution_id))await saveGroupCryptoState({version:1,kind:"receiver",group_id:groupId,epoch,sender_uin:selfUin,updated_at:Date.now(),state:createReceiverState(distribution)});
    const roster=[...new Set(memberUins)].filter(u=>u!==selfUin).sort((a,b)=>a-b);
    for(const uin of roster.filter(u=>!local.distributed_to.includes(u))){await sendDistribution(uin,new TextEncoder().encode(JSON.stringify({kind:GROUP_DISTRIBUTION_KIND,distribution})),distribution);local.distributed_to.push(uin);}
    await saveGroupCryptoState({version:1,kind:"sender",group_id:groupId,epoch,sender_uin:selfUin,updated_at:Date.now(),state:local});
    return local.sender;
  });
}

export async function sealGroupContent(state:SenderState,content:GroupContent):Promise<SenderKeyCiphertext> {
  const lockKey=`${state.group_id}:${state.epoch}:${state.sender_uin}`;
  return withSenderLock(lockKey,async()=>{
    for(let attempt=0;attempt<4;attempt++){
      const stored=await loadGroupCryptoState(state.group_id,state.epoch,state.sender_uin,"sender");
      const local=(stored?.state as LocalStored|undefined)??{sender:state,distributed_to:[],revision:0};const revision=local.revision??0;
      const result=await encryptGroupMessage(local.sender,new TextEncoder().encode(JSON.stringify(content)));
      const next:LocalStored={...local,sender:result.state,revision:revision+1};
      const record={version:1 as const,kind:"sender" as const,group_id:state.group_id,epoch:state.epoch,sender_uin:state.sender_uin,created_at:stored?.created_at,updated_at:Date.now(),state:next};
      if(stored?await compareAndSwapSenderState(record,revision):(await saveGroupCryptoState(record),true))return result.envelope;
    }
    throw new Error("sender state changed concurrently");
  });
}
export async function installSenderDistribution(senderUin:number,value:unknown,currentEpoch:number,currentMembers:number[]):Promise<boolean> {
  if(!isObj(value)||value.kind!==GROUP_DISTRIBUTION_KIND||!isObj(value.distribution))return false;
  const d=value.distribution as unknown as SenderKeyDistribution;
  if(d.sender_uin!==senderUin||d.epoch!==currentEpoch||!currentMembers.includes(senderUin))throw new Error("unauthorized sender-key distribution");
  const receiver=createReceiverState(d);
  await saveGroupCryptoState({version:1,kind:"receiver",group_id:d.group_id,epoch:d.epoch,sender_uin:d.sender_uin,updated_at:Date.now(),state:receiver}); return true;
}
export async function processDirectControlMessage(senderUin:number,plaintext:Uint8Array,resolveGroup:(groupId:string)=>Promise<{epoch:number;members:number[]}>):Promise<boolean>{
  let value:unknown;try{value=JSON.parse(new TextDecoder().decode(plaintext));}catch{return false;}
  if(!isObj(value)||value.kind!==GROUP_DISTRIBUTION_KIND)return false;
  if(!isObj(value.distribution)||typeof value.distribution.group_id!=="string")throw new Error("invalid sender-key control message");
  const roster=await resolveGroup(value.distribution.group_id);
  await installSenderDistribution(senderUin,value,roster.epoch,roster.members);
  return true;
}
export async function hydrateSenderKeyInbox(groupId:string,currentEpoch:number,currentMembers:number[],fetchInbox:()=>Promise<OpaqueSenderKeyInboxItem[]>,decryptPairwise:(senderUin:number,ciphertext:string,msgType:"prekey_message"|"signal_message")=>Promise<Uint8Array>):Promise<number> {
  let installed=0;
  for(const item of await fetchInbox()) {
    const itemEpoch=item.epoch??currentEpoch;
    if(itemEpoch>currentEpoch)throw new Error("sender-key inbox epoch is not authorized");
    const existing=item.distribution_id?await loadGroupCryptoState(groupId,itemEpoch,item.sender_uin,"receiver",item.distribution_id):null;
    if(existing)continue;
    const plaintext=await decryptPairwise(item.sender_uin,item.ciphertext,item.msg_type);
    const value:unknown=JSON.parse(new TextDecoder().decode(plaintext));
    if(!isObj(value)||value.kind!==GROUP_DISTRIBUTION_KIND||!isObj(value.distribution)||value.distribution.group_id!==groupId)throw new Error("sender-key inbox context is not authorized");
    if(item.distribution_id&&value.distribution.distribution_id!==item.distribution_id)throw new Error("sender-key inbox distribution id is not authorized");
    if(itemEpoch===currentEpoch){if(await installSenderDistribution(item.sender_uin,value,currentEpoch,currentMembers))installed++;}
    else {
      const d=value.distribution as unknown as SenderKeyDistribution;
      if(d.group_id!==groupId||d.epoch!==itemEpoch||d.sender_uin!==item.sender_uin)throw new Error("historical sender-key distribution is not authorized");
      const retiredAt=item.retired_at?Date.parse(item.retired_at):Date.now();
      if(!Number.isFinite(retiredAt))throw new Error("historical sender-key retirement is invalid");
      await saveGroupCryptoState({version:1,kind:"receiver",group_id:groupId,epoch:itemEpoch,sender_uin:item.sender_uin,created_at:retiredAt,updated_at:Date.now(),state:createReceiverState(d)});installed++;
    }
  }
  return installed;
}
export async function openGroupContent(envelope:SenderKeyCiphertext,currentEpoch:number,currentMembers:number[],allowObsoleteDecrypt=false,now=Date.now(),expected?:ExpectedGroupRouting):Promise<GroupContent> {
  if(expected&&(envelope.group_id!==expected.group_id||envelope.sender_uin!==expected.sender_uin||(expected.epoch!==undefined&&envelope.epoch!==expected.epoch)))throw new Error("group routing context mismatch");
  const obsolete=envelope.epoch!==currentEpoch;
  if((obsolete&&!allowObsoleteDecrypt)||(!obsolete&&!currentMembers.includes(envelope.sender_uin)))throw new Error("group sender or epoch is no longer authorized");
  const cacheKey=`${envelope.group_id}:${envelope.epoch}:${envelope.sender_uin}:${envelope.distribution_id}:${envelope.iteration}:${envelope.signature}`;
  await pruneAuthenticatedGroupContent(envelope.group_id,now);
  if(allowObsoleteDecrypt){const cached=await loadAuthenticatedGroupContent(cacheKey,envelope.group_id,envelope.epoch,now);if(cached){if(!isValidGroupContent(cached))throw new Error("invalid cached group content");return cached;}}
  const stored=await loadGroupCryptoState(envelope.group_id,envelope.epoch,envelope.sender_uin,"receiver",envelope.distribution_id);
  if(!stored)throw new Error("sender key distribution is missing");
  const receiver=stored.state as ReceiverState;
  const plaintext=await decryptGroupMessage(receiver,envelope);
  await saveGroupCryptoState({...stored,updated_at:Date.now(),state:receiver});
  const parsed:unknown=JSON.parse(new TextDecoder().decode(plaintext));
  if(!isValidGroupContent(parsed))throw new Error("invalid encrypted group content");
  await saveAuthenticatedGroupContent(cacheKey,envelope.group_id,envelope.epoch,parsed,now);
  return parsed as unknown as GroupContent;
}
export function encodeGroupCiphertext(v:SenderKeyCiphertext):string { return btoa(unescape(encodeURIComponent(JSON.stringify(v)))).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/g,""); }
export function decodeGroupCiphertext(v:string):SenderKeyCiphertext { const p="=".repeat((4-v.length%4)%4);return JSON.parse(decodeURIComponent(escape(atob(v.replace(/-/g,"+").replace(/_/g,"/")+p)))) as SenderKeyCiphertext; }
function stripPrivate(s:SenderState):SenderKeyDistribution { const {signing_private_key:_,...d}=s;return d; }
function isObj(v:unknown):v is Record<string,unknown>{return typeof v==="object"&&v!==null&&!Array.isArray(v);}
function hasOnlyKeys(v:Record<string,unknown>,allowed:string[]):boolean{return Object.keys(v).every(k=>allowed.includes(k));}
function isValidGroupContent(v:unknown):v is GroupContent{
  if(!isObj(v)||v.kind!==GROUP_CONTENT_KIND||!hasOnlyKeys(v,["kind","content_type","text","attachment"]))return false;
  if(v.content_type==="text"||v.content_type==="image")return typeof v.text==="string"&&new TextEncoder().encode(v.text).length<=16_384&&v.attachment===undefined;
  if(v.content_type!=="file"||v.text!==undefined||!isObj(v.attachment)||!hasOnlyKeys(v.attachment,["kind","object_key","manifest"])||v.attachment.kind!=="iceq.attachment.v1"||typeof v.attachment.object_key!=="string"||!isObj(v.attachment.manifest)||!hasOnlyKeys(v.attachment.manifest,["version","algorithm","key","nonce","mime_type","size","name"])||!isEncryptedFileManifest(v.attachment.manifest))return false;
  try{assertCanonicalObjectKey(v.attachment.object_key);return true;}catch{return false;}
}
