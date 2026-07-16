import assert from "node:assert/strict";
import test from "node:test";
import "fake-indexeddb/auto";
import { saveGroupCryptoState, loadGroupCryptoState, pruneObsoleteGroupEpochs } from "../src/lib/groupCryptoStore";
import { hydrateSenderKeyInbox, GROUP_CONTENT_KIND, GROUP_DISTRIBUTION_KIND, openGroupContent, sealGroupContent } from "../src/lib/groupCrypto";
import { createReceiverState, createSenderState } from "../src/lib/senderKeys";

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
