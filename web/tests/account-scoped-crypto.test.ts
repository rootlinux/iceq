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

test("legacy migration preserves session and private prekey material in the verified namespace",async()=>{
  const pair=await generateIdentityKeyPair();const publicKey=encodeIdentityKeyForWire(pair.publicKey);const target={uin:707,deviceId:"legacy-bundle-device"};
  const preKeyPair={pubKey:new Uint8Array([1,2,3]).buffer,privKey:new Uint8Array([4,5,6]).buffer};
  const signedPreKeyPair={pubKey:new Uint8Array([7,8,9]).buffer,privKey:new Uint8Array([10,11,12]).buffer};
  await loadIdentity(target);
  await seedLegacyBundle({publicKey:"untrusted",privateKey:Buffer.from(pair.privateKey).toString("base64url"),registrationId:11},"legacy-peer.1","legacy-session",41,preKeyPair,42,signedPreKeyPair);

  await migrateVerifiedLegacyIdentity(target,publicKey,deriveIdentityPublicKey);

  const store=new IndexedDBSignalProtocolStore(target);
  assert.equal(await store.loadSession("legacy-peer.1"),"legacy-session");
  assert.deepEqual(await store.loadPreKey(41),preKeyPair);
  assert.deepEqual(await store.loadSignedPreKey(42),signedPreKeyPair);
  assert.equal(await readRawRecord("identity","self"),undefined);
  assert.equal(await readRawRecord("sessions","legacy-peer.1"),undefined);
  assert.equal(await readRawRecord("prekeys",41),undefined);
  assert.equal(await readRawRecord("signed_prekeys",42),undefined);
  assert.deepEqual(await readRawRecord("identities",cryptoRecordKey(target,"peer-identity","legacy-peer.1")),{fingerprint:"legacy-peer-fingerprint"});
  assert.equal(await readRawRecord("metadata",cryptoRecordKey(target,"metadata","next_prekey_id")),99);
  assert.deepEqual(await readRawRecord("peer_trust",cryptoRecordKey(target,"peer-trust",900)),{verified:true});
  assert.deepEqual(await readRawRecord("group_crypto",cryptoRecordKey(target,"sender-key","legacy-group")),{chain:"legacy-chain"});
  assert.equal(await readRawRecord("identities","legacy-peer.1"),undefined);
  assert.equal(await readRawRecord("metadata","next_prekey_id"),undefined);
  assert.equal(await readRawRecord("peer_trust",900),undefined);
  assert.equal(await readRawRecord("group_crypto","legacy-group"),undefined);
});

test("legacy migration recovers a surviving bundle when the identical scoped identity already exists",async()=>{
  const pair=await generateIdentityKeyPair();const publicKey=encodeIdentityKeyForWire(pair.publicKey);const target={uin:757,deviceId:"legacy-resume-device"};
  const storedIdentity={publicKey,privateKey:Buffer.from(pair.privateKey).toString("base64url"),registrationId:13};
  const preKeyPair={pubKey:new Uint8Array([21]).buffer,privKey:new Uint8Array([22]).buffer};
  const signedPreKeyPair={pubKey:new Uint8Array([23]).buffer,privKey:new Uint8Array([24]).buffer};
  await saveIdentity(target,storedIdentity);
  await seedLegacyBundle({...storedIdentity,publicKey:"untrusted"},"legacy-resume.1","resume-session",61,preKeyPair,62,signedPreKeyPair);

  const migrated=await migrateVerifiedLegacyIdentity(target,publicKey,deriveIdentityPublicKey);

  const targetStore=new IndexedDBSignalProtocolStore(target);
  assert.deepEqual(migrated,storedIdentity);
  assert.equal(await targetStore.loadSession("legacy-resume.1"),"resume-session");
  assert.deepEqual(await targetStore.loadPreKey(61),preKeyPair);
  assert.deepEqual(await targetStore.loadSignedPreKey(62),signedPreKeyPair);
  assert.equal(await readRawRecord("identity","self"),undefined);
  assert.equal(await readRawRecord("sessions","legacy-resume.1"),undefined);
});

test("legacy migration preserves a verified source bundle when scoped registration metadata conflicts",async()=>{
  const pair=await generateIdentityKeyPair();const publicKey=encodeIdentityKeyForWire(pair.publicKey);const target={uin:767,deviceId:"legacy-registration-collision"};
  const privateKey=Buffer.from(pair.privateKey).toString("base64url");
  const scopedIdentity={publicKey,privateKey,registrationId:90};
  const legacyIdentity={publicKey:"untrusted",privateKey,registrationId:91};
  await saveIdentity(target,scopedIdentity);
  await seedLegacyBundle(legacyIdentity,"legacy-registration.1","registration-session",63,{pubKey:new ArrayBuffer(1),privKey:new ArrayBuffer(1)},64,{pubKey:new ArrayBuffer(1),privKey:new ArrayBuffer(1)});

  await assert.rejects(migrateVerifiedLegacyIdentity(target,publicKey,deriveIdentityPublicKey),/legacy crypto destination collision/);

  assert.deepEqual(await loadIdentity(target),scopedIdentity);
  assert.deepEqual(await readRawRecord("identity","self"),legacyIdentity);
  assert.equal(await readRawRecord("sessions","legacy-registration.1"),"registration-session");
});

test("legacy migration revalidates the scoped identity inside its transaction",async()=>{
  const pair=await generateIdentityKeyPair();const publicKey=encodeIdentityKeyForWire(pair.publicKey);const target={uin:777,deviceId:"legacy-destination-race"};
  const privateKey=Buffer.from(pair.privateKey).toString("base64url");
  const originalScoped={publicKey,privateKey,registrationId:15};
  const replacementScoped={publicKey:"replacement-public",privateKey:"replacement-private",registrationId:99};
  await saveIdentity(target,originalScoped);
  await seedLegacyBundle({...originalScoped,publicKey:"untrusted"},"legacy-race.1","race-session",65,{pubKey:new ArrayBuffer(1),privKey:new ArrayBuffer(1)},66,{pubKey:new ArrayBuffer(1),privKey:new ArrayBuffer(1)});
  let derivations=0;
  const racingDerive=async(key:string):Promise<string>=>{
    derivations+=1;
    if(derivations===2)await saveIdentity(target,replacementScoped);
    return deriveIdentityPublicKey(key);
  };

  await assert.rejects(migrateVerifiedLegacyIdentity(target,publicKey,racingDerive),/legacy crypto destination collision/);

  assert.deepEqual(await loadIdentity(target),replacementScoped);
  assert.equal(await readRawRecord("sessions","legacy-race.1"),"race-session");
});

test("legacy migration write failure rolls back queued copies and source deletions",async()=>{
  const pair=await generateIdentityKeyPair();const publicKey=encodeIdentityKeyForWire(pair.publicKey);const target={uin:787,deviceId:"legacy-write-failure-device"};
  const privateKey=Buffer.from(pair.privateKey).toString("base64url");
  const preKeyPair={pubKey:new Uint8Array([31]).buffer,privKey:new Uint8Array([32]).buffer};
  const signedPreKeyPair={pubKey:new Uint8Array([33]).buffer,privKey:new Uint8Array([34]).buffer};
  await loadIdentity(target);
  await seedLegacyBundle({publicKey:"untrusted",privateKey,registrationId:14},"legacy-write-failure.1","write-failure-session",71,preKeyPair,72,signedPreKeyPair);
  const originalPut=IDBObjectStore.prototype.put;
  IDBObjectStore.prototype.put=function(value:unknown,key?:IDBValidKey):IDBRequest<IDBValidKey>{
    const record=value as {id?:unknown};
    if(this.name==="signed_prekeys"&&typeof record?.id==="string"&&record.id.startsWith("crypto-v1:"))throw new Error("forced destination write failure");
    return key===undefined?originalPut.call(this,value):originalPut.call(this,value,key);
  };
  try{
    await assert.rejects(migrateVerifiedLegacyIdentity(target,publicKey,deriveIdentityPublicKey),/forced destination write failure/);
  }finally{
    IDBObjectStore.prototype.put=originalPut;
  }

  assert.equal(await loadIdentity(target),null);
  assert.equal(await new IndexedDBSignalProtocolStore(target).loadSession("legacy-write-failure.1"),undefined);
  assert.deepEqual(await readRawRecord("identity","self"),{publicKey:"untrusted",privateKey,registrationId:14});
  assert.equal(await readRawRecord("sessions","legacy-write-failure.1"),"write-failure-session");
  assert.deepEqual((await readRawRecord("prekeys",71) as {keyPair:unknown}).keyPair,preKeyPair);
  assert.deepEqual((await readRawRecord("signed_prekeys",72) as {keyPair:unknown}).keyPair,signedPreKeyPair);
});

test("legacy migration rollback preserves the complete source bundle on destination collision",async()=>{
  const pair=await generateIdentityKeyPair();const publicKey=encodeIdentityKeyForWire(pair.publicKey);const target={uin:808,deviceId:"legacy-rollback-device"};
  const preKeyPair={pubKey:new Uint8Array([13]).buffer,privKey:new Uint8Array([14]).buffer};
  const signedPreKeyPair={pubKey:new Uint8Array([15]).buffer,privKey:new Uint8Array([16]).buffer};
  const targetStore=new IndexedDBSignalProtocolStore(target);
  await targetStore.storeSession("legacy-collision.1","existing-session" as never);
  await seedLegacyBundle({publicKey:"untrusted",privateKey:Buffer.from(pair.privateKey).toString("base64url"),registrationId:12},"legacy-collision.1","legacy-session",51,preKeyPair,52,signedPreKeyPair);

  await assert.rejects(migrateVerifiedLegacyIdentity(target,publicKey,deriveIdentityPublicKey),/legacy crypto destination collision/);

  assert.equal(await loadIdentity(target),null);
  assert.equal(await targetStore.loadSession("legacy-collision.1"),"existing-session");
  assert.deepEqual(await readRawRecord("identity","self"),{publicKey:"untrusted",privateKey:Buffer.from(pair.privateKey).toString("base64url"),registrationId:12});
  assert.equal(await readRawRecord("sessions","legacy-collision.1"),"legacy-session");
  assert.deepEqual((await readRawRecord("prekeys",51) as {keyPair:unknown}).keyPair,preKeyPair);
  assert.deepEqual((await readRawRecord("signed_prekeys",52) as {keyPair:unknown}).keyPair,signedPreKeyPair);
  assert.deepEqual(await readRawRecord("identities","legacy-peer.1"),{fingerprint:"legacy-peer-fingerprint"});
  assert.equal(await readRawRecord("metadata","next_prekey_id"),99);
  assert.deepEqual(await readRawRecord("peer_trust",900),{verified:true});
  assert.deepEqual(await readRawRecord("group_crypto","legacy-group"),{chain:"legacy-chain"});
});

async function seedLegacyIdentity(value:unknown,session=false):Promise<void>{await loadIdentity(a);return new Promise((resolve,reject)=>{const open=indexedDB.open("iceq",6);open.onsuccess=()=>{const db=open.result;const tx=db.transaction(session?["identity","sessions"]:["identity"],"readwrite");tx.objectStore("identity").put(value,"self");if(session)tx.objectStore("sessions").put("legacy-session","legacy-peer");tx.oncomplete=()=>{db.close();resolve();};tx.onerror=()=>reject(tx.error);};open.onerror=()=>reject(open.error);});}
async function seedLegacyBundle(identityValue:unknown,sessionKey:string,sessionValue:unknown,preKeyId:number,preKeyPair:unknown,signedPreKeyId:number,signedPreKeyPair:unknown):Promise<void>{await loadIdentity(a);return new Promise((resolve,reject)=>{const open=indexedDB.open("iceq",6);open.onsuccess=()=>{const db=open.result;const tx=db.transaction(["identity","sessions","prekeys","signed_prekeys","identities","metadata","peer_trust","group_crypto"],"readwrite");tx.objectStore("identity").put(identityValue,"self");tx.objectStore("sessions").put(sessionValue,sessionKey);tx.objectStore("prekeys").put({id:preKeyId,keyPair:preKeyPair});tx.objectStore("signed_prekeys").put({id:signedPreKeyId,keyPair:signedPreKeyPair});tx.objectStore("identities").put({fingerprint:"legacy-peer-fingerprint"},"legacy-peer.1");tx.objectStore("metadata").put(99,"next_prekey_id");tx.objectStore("peer_trust").put({verified:true},900);tx.objectStore("group_crypto").put({chain:"legacy-chain"},"legacy-group");tx.oncomplete=()=>{db.close();resolve();};tx.onerror=()=>reject(tx.error);};open.onerror=()=>reject(open.error);});}
function readRawRecord(store:string,key:IDBValidKey):Promise<unknown>{return new Promise((resolve,reject)=>{const open=indexedDB.open("iceq",6);open.onsuccess=()=>{const db=open.result;const tx=db.transaction(store,"readonly");const get=tx.objectStore(store).get(key);let value:unknown;get.onsuccess=()=>{value=get.result};get.onerror=()=>reject(get.error);tx.oncomplete=()=>{db.close();resolve(value)};tx.onerror=()=>reject(tx.error)};open.onerror=()=>reject(open.error)});}

test("parallel account bootstraps bind bundle generation to their operation namespace",async()=>{
  const seen:string[]=[];const run=(uin:number,deviceId:string)=>ensureOwnBundle(uin,{
    loadOrCreateDeviceId:async()=>deviceId,fetchBundle:async()=>{throw new ApiError("missing",404);},loadIdentity:async()=>identity,
    restoreIdentity:()=>({publicKey:new Uint8Array(33),privateKey:new Uint8Array(32),registrationId:7}),
    generatePreKeyBundle:async(_i,_s,_c,_r,ns)=>{seen.push(`${ns!.uin}:${ns!.deviceId}`);return{identity_key:identity.publicKey,signed_pre_key:{id:1,public_key:"spk",signature:"sig"},one_time_pre_keys:[],registration_id:7};},uploadBundle:async()=>{},
  });
  await Promise.all([run(101,"parallel-device-A"),run(202,"parallel-device-B")]);assert.deepEqual(new Set(seen),new Set(["101:parallel-device-A","202:parallel-device-B"]));
});
