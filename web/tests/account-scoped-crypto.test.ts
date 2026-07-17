import test from "node:test";
import assert from "node:assert/strict";
import "fake-indexeddb/auto";

import {
  clearAll,
  cryptoRecordKey,
  IndexedDBSignalProtocolStore,
  loadIdentity,
  saveIdentity,
  setActiveCryptoNamespace,
  putGroupCryptoRecord,
  getGroupCryptoRecord,
  loadOrCreateDeviceId,
  reserveNextPreKeyIds,
  createRegistrationCryptoNamespace,
  commitCryptoNamespace,
  migrateVerifiedLegacyIdentity,
  savePeerTrust,loadPeerTrust,saveSignedPreKeyRotationMetadata,loadSignedPreKeyRotationMetadata,
  resetPeerSignalState,
  type CryptoNamespace,
} from "../src/lib/indexeddb.ts";
import { ensureOwnBundle, IdentityKeyMismatchError } from "../src/lib/signalBootstrap.ts";
import { deriveIdentityPublicKey, generateIdentityKeyPair, saveOwnIdentity, encodeIdentityKeyForWire } from "../src/lib/signal.ts";
import { ApiError } from "../src/api/client.ts";
import { ensureGroupSenderCAS } from "../src/lib/groupCrypto.ts";
import { loadGroupCryptoState } from "../src/lib/groupCryptoStore.ts";

const a: CryptoNamespace = { uin: 101, deviceId: "device_A_0123456789" };
const b: CryptoNamespace = { uin: 202, deviceId: "device_A_0123456789" };
const identity = { publicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", privateKey: "private", registrationId: 7 };

test.before(clearAll);

test("identity and Signal session records cannot cross account namespaces", async () => {
  await saveIdentity(a, identity);
  assert.deepEqual(await loadIdentity(a), identity);
  assert.equal(await loadIdentity(b), null);

  const storeA = new IndexedDBSignalProtocolStore(a);
  const storeB = new IndexedDBSignalProtocolStore(b);
  await storeA.storeSession("42.1", "opaque-session" as never);
  assert.equal(await storeA.loadSession("42.1"), "opaque-session");
  assert.equal(await storeB.loadSession("42.1"), undefined);
  assert.notEqual(cryptoRecordKey(a, "session", "42.1"), cryptoRecordKey(b, "session", "42.1"));
  const keyPair={pubKey:new Uint8Array(32).buffer,privKey:new Uint8Array(32).buffer};await storeA.storePreKey(9,keyPair);await storeA.storeSignedPreKey(10,keyPair);
  assert.equal(await storeB.loadPreKey(9),undefined);assert.equal(await storeB.loadSignedPreKey(10),undefined);
  const trust={version:1 as const,peerUin:42,fingerprint:identity.publicKey,verified:false,firstSeenAt:1,updatedAt:1};await savePeerTrust(trust,a);assert.equal(await loadPeerTrust(42,b),null);
  await saveSignedPreKeyRotationMetadata(a,{publishedAt:1,rotateAfter:2,currentId:3});assert.equal(await loadSignedPreKeyRotationMetadata(b),null);
  const otherDevice={uin:a.uin,deviceId:"device_B_0123456789"};assert.equal(await loadIdentity(otherDevice),null);assert.equal(await new IndexedDBSignalProtocolStore(otherDevice).loadSession("42.1"),undefined);
});

test("Sender Key records cannot cross account namespaces", async () => {
  setActiveCryptoNamespace(a); await putGroupCryptoRecord(a,"g:1:101:sender", { secret: "opaque" });
  assert.deepEqual(await getGroupCryptoRecord(a,"g:1:101:sender"), {secret:"opaque"});
  setActiveCryptoNamespace(b); assert.equal(await getGroupCryptoRecord(b,"g:1:101:sender"), null);
});

test("peer session reset uses its explicit namespace even if another account is active",async()=>{
  const storeA=new IndexedDBSignalProtocolStore(a),storeB=new IndexedDBSignalProtocolStore(b);await storeA.storeSession("42.1","a-session" as never);await storeB.storeSession("42.1","b-session" as never);
  setActiveCryptoNamespace(b);await resetPeerSignalState(42,a);
  assert.equal(await storeA.loadSession("42.1"),undefined);assert.equal(await storeB.loadSession("42.1"),"b-session");
});

test("concurrent Sender Key operations stay bound to their explicit namespace", async () => {
  let releaseA!: () => void;
  const blockA = new Promise<void>((resolve) => { releaseA = resolve; });
  let enteredA!: () => void;
  const callbackAEntered = new Promise<void>((resolve) => { enteredA = resolve; });

  setActiveCryptoNamespace(a);
  const operationA = ensureGroupSenderCAS(a, "shared-group", 1, a.uin, [a.uin, 900], async () => {
    enteredA();
    await blockA;
  });
  await callbackAEntered;

  // Simulate a second account becoming globally active while A is suspended.
  setActiveCryptoNamespace(b);
  const operationB = ensureGroupSenderCAS(b, "shared-group", 1, b.uin, [b.uin, 900], async () => {});
  await operationB;
  releaseA();
  await operationA;

  const stateA = await loadGroupCryptoState(a, "shared-group", 1, a.uin, "sender");
  const stateB = await loadGroupCryptoState(b, "shared-group", 1, b.uin, "sender");
  assert.ok(stateA);
  assert.ok(stateB);
  assert.equal(await loadGroupCryptoState(a, "shared-group", 1, b.uin, "sender"), null);
  assert.equal(await loadGroupCryptoState(b, "shared-group", 1, a.uin, "sender"), null);
  assert.deepEqual((stateA.state as { distributed_to: number[] }).distributed_to, [900]);
  assert.deepEqual((stateB.state as { distributed_to: number[] }).distributed_to, [900]);
});

test("directory identity mismatch fails closed without uploading a replacement bundle", async () => {
  let uploads = 0;
  await assert.rejects(
    ensureOwnBundle(101, {
      loadOrCreateDeviceId: async () => a.deviceId,
      fetchBundle: async () => ({ identity_key: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", signed_pre_key: { id: 1, public_key: "spk", signature: "sig" }, registration_id: 7 }),
      loadIdentity: async () => identity,
      restoreIdentity: () => ({ publicKey: new Uint8Array(33), privateKey: new Uint8Array(32), registrationId: 7 }),
      generatePreKeyBundle: async () => { throw new Error("must not generate"); },
      uploadBundle: async () => { uploads++; },
    }),
    IdentityKeyMismatchError,
  );
  assert.equal(uploads, 0);
});

test("device id creation and OPK reservations are atomic under concurrency",async()=>{
  const ids=await Promise.all(Array.from({length:20},()=>loadOrCreateDeviceId()));assert.equal(new Set(ids).size,1);
  const ns={uin:303,deviceId:ids[0]!};const reservations=await Promise.all([reserveNextPreKeyIds(ns,5,22),reserveNextPreKeyIds(ns,7,22),reserveNextPreKeyIds(ns,3,22)]);
  const ranges=reservations.map((start,index)=>[start,start+[5,7,3][index]!] as const).sort((x,y)=>x[0]-y[0]);
  for(let i=1;i<ranges.length;i++)assert.ok(ranges[i]![0]>=ranges[i-1]![1]);
});

test("registration staging never writes unscoped or stale-account private material",async()=>{
  setActiveCryptoNamespace(b);const stage=createRegistrationCryptoNamespace();const pair=await generateIdentityKeyPair();await saveOwnIdentity(pair,7,stage);
  assert.equal(await loadIdentity(b),null);const target={uin:101,deviceId:"fresh-device-012345"};await commitCryptoNamespace(stage,target);
  assert.equal((await loadIdentity(stage)),null);assert.equal((await loadIdentity(target))?.publicKey,encodeIdentityKeyForWire(pair.publicKey));
});

test("namespace commit collision atomically preserves both source and destination",async()=>{
  const stage=createRegistrationCryptoNamespace();const target={uin:505,deviceId:"collision-target-device"};
  const source={publicKey:"source",privateKey:"source-private",registrationId:1};const destination={publicKey:"destination",privateKey:"destination-private",registrationId:2};
  await saveIdentity(stage,source);await saveIdentity(target,destination);
  await assert.rejects(commitCryptoNamespace(stage,target),/collision/);
  assert.deepEqual(await loadIdentity(stage),source);assert.deepEqual(await loadIdentity(target),destination);
});

test("legacy migration derives public identity from private bytes instead of trusting stored public",async()=>{
  const correct=await generateIdentityKeyPair();const attacker=await generateIdentityKeyPair();
  const legacyTarget={uin:404,deviceId:"legacy-target-device"};
  await seedLegacyIdentity({publicKey:encodeIdentityKeyForWire(correct.publicKey),privateKey:Buffer.from(attacker.privateKey).toString("base64url"),registrationId:7});
  await assert.rejects(migrateVerifiedLegacyIdentity(legacyTarget,encodeIdentityKeyForWire(correct.publicKey),deriveIdentityPublicKey),/legacy identity mismatch/);
  assert.equal(await loadIdentity(legacyTarget),null);
});

test("valid legacy identity migrates from derived private key and deletes every unscoped record",async()=>{
  const pair=await generateIdentityKeyPair();const publicKey=encodeIdentityKeyForWire(pair.publicKey);const target={uin:606,deviceId:"legacy-success-device"};
  await loadIdentity(target);
  await seedLegacyIdentity({publicKey:"untrusted",privateKey:Buffer.from(pair.privateKey).toString("base64url"),registrationId:9},true);
  const migrated=await migrateVerifiedLegacyIdentity(target,publicKey,deriveIdentityPublicKey);
  assert.equal(migrated?.publicKey,publicKey);assert.equal((await loadIdentity(target))?.publicKey,publicKey);
  assert.equal(await readRawRecord("identity","self"),undefined);assert.equal(await readRawRecord("sessions","legacy-peer"),undefined);
});

function seedLegacyIdentity(value:unknown,session=false):Promise<void>{return new Promise((resolve,reject)=>{const open=indexedDB.open("iceq",6);open.onsuccess=()=>{const db=open.result;const tx=db.transaction(session?["identity","sessions"]:["identity"],"readwrite");tx.objectStore("identity").put(value,"self");if(session)tx.objectStore("sessions").put("legacy-session","legacy-peer");tx.oncomplete=()=>{db.close();resolve();};tx.onerror=()=>reject(tx.error);};open.onerror=()=>reject(open.error);});}
function readRawRecord(store:string,key:string):Promise<unknown>{return new Promise((resolve,reject)=>{const open=indexedDB.open("iceq",6);open.onsuccess=()=>{const db=open.result;const tx=db.transaction(store,"readonly");const get=tx.objectStore(store).get(key);let value:unknown;get.onsuccess=()=>{value=get.result};get.onerror=()=>reject(get.error);tx.oncomplete=()=>{db.close();resolve(value)};tx.onerror=()=>reject(tx.error)};open.onerror=()=>reject(open.error)});}

test("parallel account bootstraps bind bundle generation to their operation namespace",async()=>{
  const seen:string[]=[];const run=(uin:number,deviceId:string)=>ensureOwnBundle(uin,{
    loadOrCreateDeviceId:async()=>deviceId,fetchBundle:async()=>{throw new ApiError("missing",404);},loadIdentity:async()=>identity,
    restoreIdentity:()=>({publicKey:new Uint8Array(33),privateKey:new Uint8Array(32),registrationId:7}),
    generatePreKeyBundle:async(_i,_s,_c,_r,ns)=>{seen.push(`${ns!.uin}:${ns!.deviceId}`);return{identity_key:identity.publicKey,signed_pre_key:{id:1,public_key:"spk",signature:"sig"},one_time_pre_keys:[],registration_id:7};},uploadBundle:async()=>{},
  });
  await Promise.all([run(101,"parallel-device-A"),run(202,"parallel-device-B")]);assert.deepEqual(new Set(seen),new Set(["101:parallel-device-A","202:parallel-device-B"]));
});
