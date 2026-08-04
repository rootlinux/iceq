import test from "node:test";
import assert from "node:assert/strict";

import { ApiError } from "../src/api/client.ts";
import {
  runRegistration,
  resumeAuthenticatedRegistration,
  type PendingRegistration,
  type RegistrationStateStore,
  type ResumeDependencies,
} from "../src/lib/registrationRecovery.ts";

function memoryStore(): RegistrationStateStore {
  let value: PendingRegistration | null = null;
  return { load: async () => value, save: async next => { value = structuredClone(next); }, clear: async () => { value = null; } };
}

function makeStagingNamespace() {
  return { uin: Number.MAX_SAFE_INTEGER, deviceId: "registration_testdevice01" };
}

function makeBundle(identityKey = "test-identity-key-001") {
  return {
    identity_key: identityKey,
    signed_pre_key: { id: 1, public_key: "spk", signature: "sig" },
    one_time_pre_keys: [{ id: 22, public_key: "opk" }],
    registration_id: 7,
  };
}

function makePending(overrides: Partial<PendingRegistration> = {}): PendingRegistration {
  return {
    version: 1,
    username: "alice",
    status: "registering",
    stagingNamespace: makeStagingNamespace(),
    identityKey: "test-identity-key-001",
    bundle: makeBundle("test-identity-key-001"),
    ...overrides,
  };
}

type ResumeMock = {
  pendingState: PendingRegistration | null;
  accountUin: number;
  accountUsername: string;
  directoryIdentity: string | null;
  directoryError: Error | null;
  bindingUin: number;
  bindingIdentity: string;
  bindingError: Error | null;
  uploads: number;
  commits: number;
  saves: { status: string; accountUin?: number; deviceId?: string }[];
  cleared: boolean;
  activeNamespace: { uin: number; deviceId: string } | null;
};

function makeResumeDeps(m: ResumeMock): ResumeDependencies {
  return {
    loadPending: async () => {
      if (!m.pendingState) return null;
      return structuredClone(m.pendingState);
    },
    me: async () => ({ uin: m.accountUin, username: m.accountUsername }),
    fetchBundle: async (_uin: number) => {
      if (m.directoryError) throw m.directoryError;
      if (m.directoryIdentity === null) {
        throw new ApiError("Not Found", 404);
      }
      return { identity_key: m.directoryIdentity! };
    },
    cryptoBinding: async () => {
      if (m.bindingError) throw m.bindingError;
      return { uin: m.bindingUin, identity_key: m.bindingIdentity };
    },
    savePending: async (state: PendingRegistration) => {
      m.saves.push({ status: state.status, accountUin: state.accountUin, deviceId: state.deviceId });
    },
    loadOrCreateDeviceId: async () => "resume_testdev",
    uploadBundle: async (_bundle: any) => {
      m.uploads++;
    },
    commitCryptoNamespace: async (_from: any, _to: any) => {
      m.commits++;
    },
    clearPendingRegistration: async () => {
      m.cleared = true;
    },
    setActiveCryptoNamespace: (ns: any) => {
      m.activeNamespace = ns;
    },
  };
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

// ── resumeAuthenticatedRegistration crypto-binding recovery branch ──

test("ambiguous registration + missing key-directory + matching crypto binding resumes safely", async () => {
  const m: ResumeMock = {
    pendingState: makePending({ status: "registering", accountUin: undefined }),
    accountUin: 42, accountUsername: "alice",
    directoryIdentity: null, directoryError: null,
    bindingUin: 42, bindingIdentity: "test-identity-key-001", bindingError: null,
    uploads: 0, commits: 0, saves: [], cleared: false, activeNamespace: null,
  };
  const deps = makeResumeDeps(m);
  const result = await resumeAuthenticatedRegistration(42, deps);
  assert.equal(result, true);
  assert.ok(m.uploads > 0, "bundle must be uploaded");
  assert.ok(m.commits > 0, "namespace must be committed");
  assert.ok(m.cleared, "pending registration must be cleared");
  assert.deepEqual(m.activeNamespace, { uin: 42, deviceId: "resume_testdev" });
});

test("mismatching crypto binding blocks upload and namespace commit", async () => {
  const m: ResumeMock = {
    pendingState: makePending({ status: "registering", accountUin: undefined }),
    accountUin: 42, accountUsername: "alice",
    directoryIdentity: null, directoryError: null,
    bindingUin: 42, bindingIdentity: "attacker-identity-key", bindingError: null,
    uploads: 0, commits: 0, saves: [], cleared: false, activeNamespace: null,
  };
  const deps = makeResumeDeps(m);
  await assert.rejects(
    resumeAuthenticatedRegistration(42, deps),
    /pending registration identity does not match server-stored identity/,
  );
  assert.equal(m.uploads, 0, "upload must NOT be called on mismatch");
  assert.equal(m.commits, 0, "commit must NOT be called on mismatch");
  assert.equal(m.cleared, false, "pending must NOT be cleared on mismatch");
});

test("wrong UIN blocks recovery", async () => {
  // cryptoBinding returns a different UIN than the caller claims
  const m: ResumeMock = {
    pendingState: makePending({ status: "registering", accountUin: undefined }),
    accountUin: 42, accountUsername: "alice",
    directoryIdentity: null, directoryError: null,
    bindingUin: 99, bindingIdentity: "test-identity-key-001", bindingError: null,
    uploads: 0, commits: 0, saves: [], cleared: false, activeNamespace: null,
  };
  const deps = makeResumeDeps(m);
  await assert.rejects(
    resumeAuthenticatedRegistration(42, deps),
    /crypto-binding returned wrong account/,
  );
  assert.equal(m.uploads, 0);
  assert.equal(m.commits, 0);
});

test("endpoint failure without another trusted proof remains fail-closed", async () => {
  // pending has no accountUin (ambiguous register) and cryptoBinding throws network error
  const m: ResumeMock = {
    pendingState: makePending({ status: "registering", accountUin: undefined }),
    accountUin: 42, accountUsername: "alice",
    directoryIdentity: null, directoryError: null,
    bindingUin: 0, bindingIdentity: "", bindingError: new Error("network unreachable"),
    uploads: 0, commits: 0, saves: [], cleared: false, activeNamespace: null,
  };
  const deps = makeResumeDeps(m);
  await assert.rejects(
    resumeAuthenticatedRegistration(42, deps),
    /no trusted account binding or key directory proof/,
  );
  assert.equal(m.uploads, 0, "must not upload without trusted proof");
  assert.equal(m.commits, 0, "must not commit without trusted proof");
});

test("registration POST is not repeated during resume", async () => {
  // resumeAuthenticatedRegistration must never call the register endpoint
  const m: ResumeMock = {
    pendingState: makePending({ status: "registering", accountUin: undefined }),
    accountUin: 42, accountUsername: "alice",
    directoryIdentity: null, directoryError: null,
    bindingUin: 42, bindingIdentity: "test-identity-key-001", bindingError: null,
    uploads: 0, commits: 0, saves: [], cleared: false, activeNamespace: null,
  };
  const deps = makeResumeDeps(m);
  await resumeAuthenticatedRegistration(42, deps);
  // Proof: the function completed successfully without ever calling register.
  // The resumeDeps interface does not even have a register method — the
  // compiler enforces that resumeAuthenticatedRegistration never calls it.
  assert.equal(m.uploads, 1);
  assert.equal(m.commits, 1);
});

test("repeated resume is idempotent", async () => {
  // First resume
  {
    const m: ResumeMock = {
      pendingState: makePending({ status: "registering", accountUin: undefined }),
      accountUin: 42, accountUsername: "alice",
      directoryIdentity: null, directoryError: null,
      bindingUin: 42, bindingIdentity: "test-identity-key-001", bindingError: null,
      uploads: 0, commits: 0, saves: [], cleared: false, activeNamespace: null,
    };
    await resumeAuthenticatedRegistration(42, makeResumeDeps(m));
    assert.equal(m.uploads, 1);
    assert.equal(m.commits, 1);
    assert.equal(m.cleared, true);
  }

  // Second resume — pending was cleared, so it returns false (nothing to do)
  {
    const m2: ResumeMock = {
      pendingState: null, // <-- already cleared by first resume
      accountUin: 42, accountUsername: "alice",
      directoryIdentity: null, directoryError: null,
      bindingUin: 42, bindingIdentity: "test-identity-key-001", bindingError: null,
      uploads: 0, commits: 0, saves: [], cleared: false, activeNamespace: null,
    };
    const result = await resumeAuthenticatedRegistration(42, makeResumeDeps(m2));
    assert.equal(result, false, "second resume should return false when no pending state");
    assert.equal(m2.uploads, 0, "second resume must not re-upload");
    assert.equal(m2.commits, 0, "second resume must not re-commit");
  }
});

test("aborting registration recovery after upload prevents namespace commit and activation", async () => {
  const m: ResumeMock = {
    pendingState: makePending({ status: "registered", accountUin: 42, deviceId: "resume_testdev" }),
    accountUin: 42, accountUsername: "alice",
    directoryIdentity: "test-identity-key-001", directoryError: null,
    bindingUin: 42, bindingIdentity: "test-identity-key-001", bindingError: null,
    uploads: 0, commits: 0, saves: [], cleared: false, activeNamespace: null,
  };
  const controller = new AbortController();
  const deps = makeResumeDeps(m);
  deps.uploadBundle = async () => {
    m.uploads++;
    controller.abort();
  };

  await assert.rejects(
    resumeAuthenticatedRegistration(42, deps, controller.signal),
    (error: unknown) => (error as { name?: string }).name === "AbortError",
  );
  assert.equal(m.uploads, 1);
  assert.equal(m.commits, 0, "an aborted recovery must not commit staged crypto");
  assert.equal(m.cleared, false, "pending recovery state must remain retryable");
  assert.equal(m.activeNamespace, null, "an aborted recovery must not activate the namespace");
});
