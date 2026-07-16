import assert from "node:assert/strict";
import test from "node:test";
import "fake-indexeddb/auto";
import { saveAuthenticatedGroupContent, saveGroupCryptoState, loadGroupCryptoState, pruneObsoleteGroupEpochs } from "../src/lib/groupCryptoStore";
import { authenticatedGroupMessageFields, hydrateSenderKeyInbox, GROUP_CONTENT_KIND, GROUP_DISTRIBUTION_KIND, openGroupContent, processDirectControlMessage, sealGroupContent } from "../src/lib/groupCrypto";
import { createReceiverState, createSenderState, encryptGroupMessage } from "../src/lib/senderKeys";
import { getGroupCryptoRecord } from "../src/lib/indexeddb";

test("group state is versioned and keyed by group, epoch, and sender", async () => {
  indexedDB.deleteDatabase("iceq");
  const record = { version: 1 as const, kind: "receiver" as const, group_id: "g", epoch: 3, sender_uin: 9, updated_at: 100, state: { secret: "opaque" } };
  await saveGroupCryptoState(record);
  assert.deepEqual(await loadGroupCryptoState("g", 3, 9, "receiver"), {...record,created_at:(await loadGroupCryptoState("g",3,9,"receiver"))?.created_at});
  assert.equal(await loadGroupCryptoState("g", 4, 9, "receiver"), null);
});

test("offline group open hydrates opaque pairwise distributions before content history", async () => {
  const distribution = { version:1 as const, distribution_id:"d-offline", group_id:"offline", epoch:4, sender_uin:9, chain_key:"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE", iteration:0, signing_public_key:"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI" };
  const installed = await hydrateSenderKeyInbox("offline",4,[7,9],async()=>[{sender_uin:9,ciphertext:"opaque",msg_type:"signal_message"}],async()=>new TextEncoder().encode(JSON.stringify({kind:GROUP_DISTRIBUTION_KIND,distribution})));
  assert.equal(installed,1);
  assert.ok(await loadGroupCryptoState("offline",4,9,"receiver"));
});

test("offline inbox rejects stale epoch distributions after membership rotation", async () => {
  const stale = { version:1 as const, distribution_id:"d-stale", group_id:"rotated", epoch:3, sender_uin:9, chain_key:"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE", iteration:0, signing_public_key:"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI" };
  await assert.rejects(()=>hydrateSenderKeyInbox("rotated",4,[7,9],async()=>[{sender_uin:9,ciphertext:"opaque",msg_type:"signal_message"}],async()=>new TextEncoder().encode(JSON.stringify({kind:GROUP_DISTRIBUTION_KIND,distribution:stale}))),/epoch|authorized/);
});

test("multiple same-epoch distribution ids retain and install only newest sender state",async()=>{
  const make=(id:string,key:string)=>({kind:GROUP_DISTRIBUTION_KIND,distribution:{version:1 as const,distribution_id:id,group_id:"multi",epoch:2,sender_uin:9,chain_key:key,iteration:0,signing_public_key:"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI"}});
  const latest=make("new","AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM");const old=make("old","AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE");
  await hydrateSenderKeyInbox("multi",2,[7,9],async()=>[{sender_uin:9,ciphertext:"new",msg_type:"signal_message",distribution_id:"new"},{sender_uin:9,ciphertext:"old",msg_type:"signal_message",distribution_id:"old"}],async(_,cipher)=>new TextEncoder().encode(JSON.stringify(cipher==="new"?latest:old)));
  const stored=await loadGroupCryptoState("multi",2,9,"receiver");assert.equal((stored?.state as {distribution_id:string}).distribution_id,"new");
  assert.equal((await loadGroupCryptoState("multi",2,9,"receiver","old"))?.state && ((await loadGroupCryptoState("multi",2,9,"receiver","old"))!.state as {distribution_id:string}).distribution_id,"old");
});

test("hydrating an older distribution cannot downgrade a preinstalled newest state",async()=>{
  const newest={version:1 as const,distribution_id:"already-new",group_id:"no-downgrade",epoch:2,sender_uin:9,chain_key:"AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM",iteration:0,signing_public_key:"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI"};
  const old={version:1 as const,distribution_id:"late-old",group_id:"no-downgrade",epoch:2,sender_uin:9,chain_key:"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",iteration:0,signing_public_key:"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI"};
  await saveGroupCryptoState({version:1,kind:"receiver",group_id:"no-downgrade",epoch:2,sender_uin:9,updated_at:1,state:createReceiverState(newest)});
  await hydrateSenderKeyInbox("no-downgrade",2,[7,9],async()=>[{sender_uin:9,ciphertext:"old",msg_type:"signal_message",distribution_id:"late-old"}],async()=>new TextEncoder().encode(JSON.stringify({kind:GROUP_DISTRIBUTION_KIND,distribution:old})));
  assert.equal(((await loadGroupCryptoState("no-downgrade",2,9,"receiver"))?.state as {distribution_id:string}).distribution_id,"already-new");
  assert.equal(((await loadGroupCryptoState("no-downgrade",2,9,"receiver","late-old"))?.state as {distribution_id:string}).distribution_id,"late-old");
});

test("exact distribution state decrypts old and new same-epoch ciphertext",async()=>{
  const old=await createSenderState("multi-decrypt",2,9);const newest=await createSenderState("multi-decrypt",2,9);
  await saveGroupCryptoState({version:1,kind:"receiver",group_id:"multi-decrypt",epoch:2,sender_uin:9,updated_at:1,state:createReceiverState(newest.distribution)});
  await saveGroupCryptoState({version:1,kind:"receiver",group_id:"multi-decrypt",epoch:2,sender_uin:9,updated_at:2,state:createReceiverState(old.distribution)});
  const encode=(text:string)=>new TextEncoder().encode(JSON.stringify({kind:GROUP_CONTENT_KIND,content_type:"text",text}));
  const oldCipher=await encryptGroupMessage(old.state,encode("old"));const newCipher=await encryptGroupMessage(newest.state,encode("new"));
  assert.equal((await openGroupContent(oldCipher.envelope,2,[9])).text,"old");
  assert.equal((await openGroupContent(newCipher.envelope,2,[9])).text,"new");
});

test("bounded inbox grace installs an obsolete epoch for history decrypt only",async()=>{
  const historical={kind:GROUP_DISTRIBUTION_KIND,distribution:{version:1 as const,distribution_id:"old-grace",group_id:"grace",epoch:3,sender_uin:9,chain_key:"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",iteration:0,signing_public_key:"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI"}};
  await hydrateSenderKeyInbox("grace",4,[7,9],async()=>[{epoch:3,sender_uin:9,ciphertext:"opaque",msg_type:"signal_message",distribution_id:"old-grace"}],async()=>new TextEncoder().encode(JSON.stringify(historical)));
  assert.ok(await loadGroupCryptoState("grace",3,9,"receiver"));
});

test("obsolete epochs are removed after decrypt-only grace", async () => {
  const old = Date.now() - 10_000;
  await saveGroupCryptoState({ version: 1, kind: "receiver", group_id: "prune", epoch: 1, sender_uin: 1, updated_at: Date.now(), created_at:old, state: {} });
  await saveGroupCryptoState({ version: 1, kind: "receiver", group_id: "prune", epoch: 2, sender_uin: 1, updated_at: Date.now(), state: {} });
  await pruneObsoleteGroupEpochs("prune", 2, 1_000);
  assert.equal(await loadGroupCryptoState("prune", 1, 1, "receiver"), null);
  assert.ok(await loadGroupCryptoState("prune", 2, 1, "receiver"));
});

test("grace expiry is immutable and is not extended by later decrypt updates", async()=>{
  const created=1_000;await saveGroupCryptoState({version:1,kind:"receiver",group_id:"immutable",epoch:1,sender_uin:3,created_at:created,updated_at:9_000,state:{}});
  await saveGroupCryptoState({version:1,kind:"receiver",group_id:"immutable",epoch:1,sender_uin:3,updated_at:19_000,state:{changed:true}});
  await pruneObsoleteGroupEpochs("immutable",2,5_000,20_000);assert.equal(await loadGroupCryptoState("immutable",1,3,"receiver"),null);
});

test("authenticated live group content can be rendered from history cache without bypassing transport replay rejection",async()=>{
  const made=await createSenderState("history-cache",1,5);await saveGroupCryptoState({version:1,kind:"receiver",group_id:"history-cache",epoch:1,sender_uin:5,updated_at:Date.now(),state:createReceiverState(made.distribution)});
  const envelope=await sealGroupContent(made.state,{kind:GROUP_CONTENT_KIND,content_type:"text",text:"cached"});
  assert.equal((await openGroupContent(envelope,1,[5])).text,"cached");
  await assert.rejects(()=>openGroupContent(envelope,1,[5]),/replay/);
  assert.equal((await openGroupContent(envelope,1,[5],true)).text,"cached");
});

test("authenticated plaintext cache expires at its immutable creation deadline",async()=>{
  const made=await createSenderState("cache-expiry",1,5);await saveGroupCryptoState({version:1,kind:"receiver",group_id:"cache-expiry",epoch:1,sender_uin:5,updated_at:1,state:createReceiverState(made.distribution)});
  const encrypted=await encryptGroupMessage(made.state,new TextEncoder().encode(JSON.stringify({kind:GROUP_CONTENT_KIND,content_type:"text",text:"brief"})));
  await openGroupContent(encrypted.envelope,1,[5],false,1_000);
  assert.equal((await openGroupContent(encrypted.envelope,1,[5],true,2_000)).text,"brief");
  await assert.rejects(()=>openGroupContent(encrypted.envelope,1,[5],true,86_401_000),/replay/);
});

test("authenticated cache metadata binds context and cannot extend expiry",async()=>{
  await saveAuthenticatedGroupContent("immutable-cache","cache-group",7,{text:"one"},1_000,5_000);
  await saveAuthenticatedGroupContent("immutable-cache","cache-group",7,{text:"two"},4_000,50_000);
  const record=await getGroupCryptoRecord<{group_id:string;epoch:number;created_at:number;expires_at:number}>("content:immutable-cache");
  assert.deepEqual(record&&{group_id:record.group_id,epoch:record.epoch,created_at:record.created_at,expires_at:record.expires_at},{group_id:"cache-group",epoch:7,created_at:1_000,expires_at:6_000});
});

test("authenticated group content type wins over conflicting outer metadata both ways",()=>{
  assert.deepEqual(authenticatedGroupMessageFields({kind:GROUP_CONTENT_KIND,content_type:"text",text:"hello"},"file"),{plaintext:"hello",content_type:"text"});
  assert.deepEqual(authenticatedGroupMessageFields({kind:GROUP_CONTENT_KIND,content_type:"file",attachment:{id:"x"}},"text"),{plaintext:JSON.stringify({id:"x"}),content_type:"file"});
});

test("outer routing must match the signed group envelope before rendering",async()=>{
  const made=await createSenderState("route-bound",3,9);await saveGroupCryptoState({version:1,kind:"receiver",group_id:"route-bound",epoch:3,sender_uin:9,updated_at:1,state:createReceiverState(made.distribution)});
  const encrypted=await encryptGroupMessage(made.state,new TextEncoder().encode(JSON.stringify({kind:GROUP_CONTENT_KIND,content_type:"text",text:"bound"})));
  await assert.rejects(()=>openGroupContent(encrypted.envelope,3,[9],false,Date.now(),{group_id:"relayed",sender_uin:9}),/routing context/);
  await assert.rejects(()=>openGroupContent(encrypted.envelope,3,[9],false,Date.now(),{group_id:"route-bound",sender_uin:8}),/routing context/);
});

test("authenticated group content rejects oversized text and unsafe file shapes",async()=>{
  const attempt=async(content:unknown)=>{const made=await createSenderState(`schema-${crypto.randomUUID()}`,1,9);await saveGroupCryptoState({version:1,kind:"receiver",group_id:made.state.group_id,epoch:1,sender_uin:9,updated_at:1,state:createReceiverState(made.distribution)});const encrypted=await encryptGroupMessage(made.state,new TextEncoder().encode(JSON.stringify(content)));return openGroupContent(encrypted.envelope,1,[9]);};
  await assert.rejects(()=>attempt({kind:GROUP_CONTENT_KIND,content_type:"text",text:"x".repeat(16_385)}),/content/);
  await assert.rejects(()=>attempt({kind:GROUP_CONTENT_KIND,content_type:"text",text:{toString:"boom"}}),/content/);
  await assert.rejects(()=>attempt({kind:GROUP_CONTENT_KIND,content_type:"file",attachment:{kind:"iceq.attachment.v1",object_key:"../bad",manifest:{}}}),/content/);
  await assert.rejects(()=>attempt({kind:GROUP_CONTENT_KIND,content_type:"text",text:"ok",attachment:{unsafe:true}}),/content/);
});

test("history-first control consumption installs once and later inbox duplicate skips Signal replay",async()=>{
  const distribution={version:1 as const,distribution_id:"history-first-id",group_id:"history-first",epoch:2,sender_uin:9,chain_key:"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",iteration:0,signing_public_key:"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI"};
  const bytes=new TextEncoder().encode(JSON.stringify({kind:GROUP_DISTRIBUTION_KIND,distribution}));
  assert.equal(await processDirectControlMessage(9,bytes,async()=>({epoch:2,members:[7,9]})),true);
  let decrypts=0;const installed=await hydrateSenderKeyInbox("history-first",2,[7,9],async()=>[{sender_uin:9,ciphertext:"replay",msg_type:"signal_message",distribution_id:"history-first-id"}],async()=>{decrypts++;throw new Error("ratchet replay");});
  assert.equal(installed,0);assert.equal(decrypts,0);
});

test("ordinary direct plaintext is not consumed as a control message",async()=>{
  assert.equal(await processDirectControlMessage(9,new TextEncoder().encode("hello"),async()=>{throw new Error("unused");}),false);
});

test("concurrent group seals reserve distinct sender iterations",async()=>{
  const made=await createSenderState("concurrent-seal",1,7);
  await saveGroupCryptoState({version:1,kind:"sender",group_id:"concurrent-seal",epoch:1,sender_uin:7,updated_at:1,state:{sender:made.state,distributed_to:[],revision:0}});
  const [a,b]=await Promise.all([sealGroupContent(made.state,{kind:GROUP_CONTENT_KIND,content_type:"text",text:"a"}),sealGroupContent(made.state,{kind:GROUP_CONTENT_KIND,content_type:"text",text:"b"})]);
  assert.deepEqual([a.iteration,b.iteration].sort((x,y)=>x-y),[0,1]);
});
