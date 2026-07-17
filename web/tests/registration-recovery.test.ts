import test from "node:test";
import assert from "node:assert/strict";

import { runRegistration, type PendingRegistration, type RegistrationStateStore } from "../src/lib/registrationRecovery.ts";

function memoryStore(): RegistrationStateStore {
  let value: PendingRegistration | null = null;
  return { load: async () => value, save: async next => { value = structuredClone(next); }, clear: async () => { value = null; } };
}

test("bundle upload retry reuses durable keys and skips a successful register", async () => {
  const store = memoryStore(); let prepares = 0; let registers = 0; let uploads = 0; let commits = 0;
  const deps = {
    store,
    prepare: async () => { prepares++; return { stagingNamespace: { uin: Number.MAX_SAFE_INTEGER, deviceId: "registration_abcdefghijklmnop" }, identityKey: "identity", bundle: { identity_key: "identity", signed_pre_key: { id: 1, public_key: "spk", signature: "sig" }, one_time_pre_keys: [{ id: 22, public_key: "opk" }], registration_id: 7 } }; },
    register: async () => { registers++; return { uin: 101 }; },
    authenticatedAccount: async () => registers>0?({uin:101,username:"alice"}):null,
    fetchDirectory: async () => null,
    deviceId: async () => "device_abcdefghijklmnop",
    upload: async () => { uploads++; if (uploads === 1) throw new Error("offline"); },
    commit: async () => { commits++; },
  };
  await assert.rejects(runRegistration({ username: "alice", password: "secret123" }, deps), /offline/);
  const afterFailure=await store.load();
  assert.equal(afterFailure?.status,"registered");assert.equal(afterFailure?.accountUin,101);
  assert.deepEqual(afterFailure?.bundle.one_time_pre_keys,[{id:22,public_key:"opk"}]);
  await runRegistration({ username: "alice", password: "secret123" }, deps);
  assert.deepEqual({ prepares, registers, uploads, commits }, { prepares: 1, registers: 1, uploads: 2, commits: 1 });
  assert.equal(await store.load(), null);
});

test("ambiguous register failure retains keys and never posts register twice", async () => {
  const store = memoryStore(); let prepares = 0; let registers = 0;
  const deps = {
    store,
    prepare: async () => { prepares++; return { stagingNamespace: { uin: Number.MAX_SAFE_INTEGER, deviceId: "registration_qrstuvwxyzABCDE" }, identityKey: "same-key", bundle: { identity_key: "same-key", signed_pre_key: { id: 1, public_key: "spk", signature: "sig" }, one_time_pre_keys: [], registration_id: 9 } }; },
    register: async () => { registers++; if (registers === 1) throw new Error("timeout"); return { uin: 202 }; },
    authenticatedAccount: async () => null,
    fetchDirectory: async () => null,
    deviceId: async () => "device_qrstuvwxyzABCDE",
    upload: async () => {}, commit: async () => {},
  };
  await assert.rejects(runRegistration({ username: "bob", password: "secret123" }, deps), /timeout/);
  await assert.rejects(runRegistration({ username: "bob", password: "secret123" }, deps), /ambiguous|login|recover/i);
  assert.equal(prepares, 1); assert.equal(registers, 1);
});

test("registering recovery rejects a mismatched directory identity before upload or commit",async()=>{
  const store=memoryStore();await store.save({version:1,username:"alice",status:"registering",stagingNamespace:{uin:Number.MAX_SAFE_INTEGER,deviceId:"registration_abcdefghijklmnop"},identityKey:"pending-identity",bundle:{identity_key:"pending-identity",signed_pre_key:{id:1,public_key:"spk",signature:"sig"},one_time_pre_keys:[],registration_id:7}});
  let uploads=0,commits=0;
  await assert.rejects(runRegistration({username:"alice",password:"unused"},{store,prepare:async()=>{throw new Error("unused")},register:async()=>{throw new Error("must not register")},authenticatedAccount:async()=>({uin:101,username:"alice"}),fetchDirectory:async()=>({identity_key:"attacker-identity"}),deviceId:async()=>"device_abcdefghijklmnop",upload:async()=>{uploads++},commit:async()=>{commits++}}),/identity.*directory|directory.*identity/i);
  assert.deepEqual({uploads,commits},{uploads:0,commits:0});
});

test("reload recovers a registering stage from the authenticated cookie session", async () => {
  const store = memoryStore();
  const staged: PendingRegistration = { version: 1, username: "carol", status: "registering", stagingNamespace: { uin: Number.MAX_SAFE_INTEGER, deviceId: "registration_FGHIJKLMNOPQR" }, identityKey: "identity", bundle: { identity_key: "identity", signed_pre_key: { id: 1, public_key: "spk", signature: "sig" }, one_time_pre_keys: [], registration_id: 11 } };
  await store.save(staged); let registers = 0; let uploads = 0;
  await runRegistration({ username: "carol", password: "unused-password" }, {
    store, prepare: async () => { throw new Error("must not prepare"); }, register: async () => { registers++; return { uin: 303 }; },
    authenticatedAccount: async () => ({uin:303,username:"carol"}), fetchDirectory:async()=>({identity_key:"identity"}), deviceId: async () => "device_FGHIJKLMNOPQR", upload: async () => { uploads++; }, commit: async () => {},
  });
  assert.equal(registers, 0); assert.equal(uploads, 1);
});

test("a different username cannot overwrite an unfinished registration", async () => {
  const store = memoryStore();
  await store.save({ version: 1, username: "alice", status: "prepared", stagingNamespace: { uin: Number.MAX_SAFE_INTEGER, deviceId: "registration_abcdefghijklmnop" }, identityKey: "identity", bundle: { identity_key: "identity", signed_pre_key: { id: 1, public_key: "spk", signature: "sig" }, one_time_pre_keys: [], registration_id: 7 } });
  await assert.rejects(runRegistration({ username: "mallory", password: "secret123" }, { store, prepare: async () => { throw new Error("no"); }, register: async () => ({ uin: 1 }), authenticatedAccount: async () => null, fetchDirectory:async()=>null, deviceId: async () => "device_abcdefghijklmnop", upload: async () => {}, commit: async () => {} }), /unfinished registration belongs to another username/);
});

for (const status of ["prepared", "registering"] as const) test(`${status} registration rejects an unrelated authenticated account`,async()=>{
  const store=memoryStore();await store.save({version:1,username:"alice",status,stagingNamespace:{uin:Number.MAX_SAFE_INTEGER,deviceId:"registration_abcdefghijklmnop"},identityKey:"identity",bundle:{identity_key:"identity",signed_pre_key:{id:1,public_key:"spk",signature:"sig"},one_time_pre_keys:[],registration_id:7}});
  let uploads=0,commits=0,registers=0;
  await assert.rejects(runRegistration({username:"alice",password:"secret123"},{store,prepare:async()=>{throw new Error("unused")},register:async()=>{registers++;return{uin:101}},authenticatedAccount:async()=>({uin:999,username:"mallory"}),fetchDirectory:async()=>({identity_key:"identity"}),deviceId:async()=>"device_abcdefghijklmnop",upload:async()=>{uploads++},commit:async()=>{commits++}}),/account|owner|username/i);
  assert.deepEqual({uploads,commits,registers},{uploads:0,commits:0,registers:0});
});
