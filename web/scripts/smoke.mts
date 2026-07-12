// scripts/smoke.mts
//
// E2EE smoke test for Step 9 verification. Runs Alice and Bob
// through a real X3DH session-establishment + Double Ratchet
// exchange using the production code in src/lib/signal.ts and
// src/lib/indexeddb.ts, with `fake-indexeddb` for the storage
// layer.
//
// Run: `npx tsx scripts/smoke.mts` from the web/ directory.

import "fake-indexeddb/auto";

// Provide a minimal localStorage / sessionStorage shim. The
// api/client.ts module reaches for localStorage at module
// load; without this Node throws ReferenceError.
const _ls = new Map<string, string>();
const _ss = new Map<string, string>();
const shimStorage = (m: Map<string, string>): Storage => ({
  length: m.size,
  clear: () => m.clear(),
  getItem: (k: string) => m.get(k) ?? null,
  setItem: (k: string, v: string) => { m.set(k, String(v)); },
  removeItem: (k: string) => { m.delete(k); },
  key: (i: number) => Array.from(m.keys())[i] ?? null,
} as unknown as Storage);
(globalThis as unknown as { localStorage: Storage; sessionStorage: Storage }).localStorage = shimStorage(_ls);
(globalThis as unknown as { localStorage: Storage; sessionStorage: Storage }).sessionStorage = shimStorage(_ss);

import {
  IndexedDBSignalProtocolStore,
  clearAll,
} from "../src/lib/indexeddb.ts";
import {
  encryptMessage,
  decryptMessage,
  generateIdentityKeyPair,
  generatePreKeyBundle,
  generateRegistrationId,
  saveOwnIdentity,
} from "../src/lib/signal.ts";
import { tokenStore } from "../src/api/client.ts";

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------

interface UserBundle {
  identityKey: Uint8Array;
  privateKey: Uint8Array;
  registrationId: number;
  bundle: Awaited<ReturnType<typeof generatePreKeyBundle>>;
}

async function setupUser(): Promise<UserBundle> {
  // The Node-shimmed IndexedDB is global — Alice and Bob share
  // it. clearAll() drops the database; the next openDB()
  // re-creates with a fresh schema. We do this before each
  // user's setup so the second setupUser doesn't clobber
  // the first's identity row. After clearAll, the user's
  // own identity + prekeys land in the fresh DB; subsequent
  // re-stages (for "Alice encrypts" / "Bob decrypts") just
  // overwrite the identity row without touching the prekey
  // pool, so Bob's signed prekey stays put.
  await clearAll();
  const identity = await generateIdentityKeyPair();
  const registrationId = generateRegistrationId();
  await saveOwnIdentity(identity, registrationId);
  const bundle = await generatePreKeyBundle(identity, 1, 20, registrationId);
  return { identityKey: identity.publicKey, privateKey: identity.privateKey, registrationId, bundle };
}

async function restageIdentity(who: UserBundle): Promise<void> {
  // Re-write only the identity row, leaving prekeys/sessions
  // intact. This is what we need for the encrypt-then-decrypt
  // flow where the same user's prekeys must survive.
  await saveOwnIdentity(
    { publicKey: who.identityKey, privateKey: who.privateKey },
    who.registrationId,
  );
}

function bundleAsRemoteShape(b: UserBundle): {
  identity_key: string;
  signed_pre_key: { id: number; public_key: string; signature: string };
  pre_key?: { id: number; public_key: string };
  registration_id: number;
} {
  return {
    identity_key: b.bundle.identity_key,
    signed_pre_key: b.bundle.signed_pre_key,
    pre_key: b.bundle.one_time_pre_keys[0]
      ? { id: b.bundle.one_time_pre_keys[0].id, public_key: b.bundle.one_time_pre_keys[0].public_key }
      : undefined,
    registration_id: b.bundle.registration_id,
  };
}

function decodeBase64Url(s: string): Uint8Array {
  const normalized = s.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
  return Uint8Array.from(Buffer.from(padded, "base64"));
}

let pass = 0;
let fail = 0;
function check(name: string, ok: boolean, info?: string): void {
  if (ok) { console.log(`  ✓ ${name}`); pass++; }
  else    { console.log(`  ✗ ${name}${info ? `  →  ${info}` : ""}`); fail++; }
}

// ----------------------------------------------------------------------------
// Test
// ----------------------------------------------------------------------------

async function main(): Promise<void> {
  console.log("\n=== Step 9 E2EE smoke test ===\n");

  // Stub the network — fetchBundle would otherwise hit a real
  // /api/keys/bundle/:uin endpoint.
  let activeRemoteBundle: unknown = null;
  let fetchShouldFail = false;
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async (input: RequestInfo | URL) => {
    const url = typeof input === "string" ? input : input.toString();
    if (url.includes("/api/keys/bundle/")) {
      if (fetchShouldFail) return new Response("bundle gone", { status: 500 });
      return new Response(JSON.stringify(activeRemoteBundle), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }
    if (originalFetch) return originalFetch(input as RequestInfo);
    return new Response("not found", { status: 404 });
  }) as typeof fetch;

  // The auth client requires a token to issue the bundle request.
  tokenStore.set("test-access-token", "test-refresh-token");

  // --- 1. Setup Alice and Bob ---
  console.log("1. Setup Alice and Bob");
  const alice = await setupUser();
  const bob = await setupUser();
  // The privacyresearch lib follows the libsignal wire format:
  // a 0x05 type prefix byte + 32 bytes of Curve25519 key = 33
  // bytes total. This matches the X25519 DJB_TYPE convention.
  check("Alice identity pubKey is 33 bytes (0x05 + key)", alice.identityKey.length === 33 && alice.identityKey[0] === 0x05);
  check("Bob identity pubKey is 33 bytes (0x05 + key)", bob.identityKey.length === 33 && bob.identityKey[0] === 0x05);
  check("Alice bundle.identity_key is base64url", /^[A-Za-z0-9_-]+$/.test(alice.bundle.identity_key));
  check("Bob bundle.identity_key is base64url", /^[A-Za-z0-9_-]+$/.test(bob.bundle.identity_key));
  check("Alice bundle.identity_key decodes to 32 bytes", decodeBase64Url(alice.bundle.identity_key).length === 32);
  check("Bob bundle.identity_key decodes to 32 bytes", decodeBase64Url(bob.bundle.identity_key).length === 32);
  check("Alice has 20 one-time prekeys", alice.bundle.one_time_pre_keys.length === 20);
  check("Bob has 20 one-time prekeys", bob.bundle.one_time_pre_keys.length === 20);

  // --- 2. Alice encrypts to Bob ---
  console.log("\n2. Alice encrypts \"hello bob\" to Bob");
  // Bob's setupUser() cleared the DB and wrote Bob's identity.
  // We need Alice's identity for the encrypt. Re-stage it
  // WITHOUT touching the prekey pool.
  await restageIdentity(alice);
  activeRemoteBundle = bundleAsRemoteShape(bob);
  const sealed = await encryptMessage(/* bobUin */ 1234, new TextEncoder().encode("hello bob"));
  check("Alice's ciphertext is non-empty", sealed.ciphertext.length > 0, `len=${sealed.ciphertext.length}`);
  check("First message is a prekey_message", sealed.msgType === "prekey_message", `got ${sealed.msgType}`);
  check("Ciphertext is not plaintext", sealed.ciphertext !== "hello bob");

  // --- 3. Bob decrypts Alice's message ---
  console.log("\n3. Bob decrypts the message");
  // Re-stage Bob's identity. Bob's prekey pool is already in
  // IDB from setupUser; we only need his identity row.
  await restageIdentity(bob);
  const plain = await decryptMessage(/* senderUin */ 5678, sealed.ciphertext, sealed.msgType);
  const decoded = new TextDecoder().decode(plain);
  check("Bob decrypted to plaintext", decoded === "hello bob", `got "${decoded}"`);

  // --- 4. Session persistence: Alice's second message is signal_message ---
  console.log("\n4. Second message should use signal_message (not prekey_message)");
  // Pretend Bob's server stops serving the bundle — Alice should
  // already have a session and not need it.
  fetchShouldFail = true;
  activeRemoteBundle = null;
  // Re-stage Alice so she's the active user.
  await restageIdentity(alice);
  const sealed2 = await encryptMessage(1234, new TextEncoder().encode("second message"));
  check("Second message is a signal_message", sealed2.msgType === "signal_message", `got ${sealed2.msgType}`);

  // Inspect Alice's session after the second encrypt.
  await restageIdentity(alice);
  const aliceSessionRaw = await new IndexedDBSignalProtocolStore().loadSession("1234.1");
  if (aliceSessionRaw) {
    const parsed = JSON.parse(aliceSessionRaw);
    const sessions = parsed.sessions || {};
    console.log(`     [debug] Alice session has ${Object.keys(sessions).length} baseKey entries`);
    for (const k of Object.keys(sessions)) {
      const s = sessions[k];
      const chainKeys = s.chains ? Object.keys(s.chains) : [];
      console.log(`     [debug]   baseKey=${k.slice(0, 12)}... closed=${s.indexInfo?.closed} chains=${chainKeys.length} pendingPreKey=${s.pendingPreKey ? "set" : "none"}`);
      for (const ck of chainKeys) {
        const c = s.chains[ck];
        console.log(`     [debug]     chain=${ck.slice(0, 12)}... type=${c.chainType} counter=${c.chainKey?.counter}`);
      }
    }
  }

  // Bob decrypts the second message.
  await restageIdentity(bob);
  const bobSessionRaw = await new IndexedDBSignalProtocolStore().loadSession("5678.1");
  if (bobSessionRaw) {
    const parsed = JSON.parse(bobSessionRaw);
    const sessions = parsed.sessions || {};
    console.log(`     [debug] Bob session has ${Object.keys(sessions).length} baseKey entries`);
    for (const k of Object.keys(sessions)) {
      const s = sessions[k];
      const chainKeys = s.chains ? Object.keys(s.chains) : [];
      console.log(`     [debug]   baseKey=${k.slice(0, 12)}... closed=${s.indexInfo?.closed} chains=${chainKeys.length} pendingPreKey=${s.pendingPreKey ? "set" : "none"}`);
      for (const ck of chainKeys) {
        const c = s.chains[ck];
        console.log(`     [debug]     chain=${ck.slice(0, 12)}... type=${c.chainType} counter=${c.chainKey?.counter}`);
      }
    }
  }
  const plain2 = await decryptMessage(5678, sealed2.ciphertext, sealed2.msgType);
  const decoded2 = new TextDecoder().decode(plain2);
  check("Bob decrypted second message", decoded2 === "second message", `got "${decoded2}"`);

  // --- 5. Tamper detection: ciphertext change should fail ---
  console.log("\n5. Tamper detection");
  const tampered = sealed.ciphertext.slice(0, -4) + "AAAA";
  let decryptFailed = false;
  try {
    await decryptMessage(5678, tampered, sealed.msgType);
  } catch {
    decryptFailed = true;
  }
  check("Tampered ciphertext rejected", decryptFailed);

  // --- 6. Trust model: identity-key change is rejected ---
  console.log("\n6. TOFU trust: a different identity key on the same address is rejected");
  // Manually overwrite Bob's stored peer identity for the
  // address "5678.1" with a different key. Then ask
  // isTrustedIdentity — it should return false.
  const bobStore = new IndexedDBSignalProtocolStore();
  // First, save a known identity.
  const realIdentityKey = new ArrayBuffer(32);
  const trusted0 = await bobStore.isTrustedIdentity("test-addr-1", realIdentityKey, 2);
  await bobStore.saveIdentity("test-addr-1", realIdentityKey);
  const trusted1 = await bobStore.isTrustedIdentity("test-addr-1", realIdentityKey, 2);
  check("First sighting trusted", trusted0 === true);
  check("Same key on replay is trusted", trusted1 === true);

  const differentKey = new ArrayBuffer(32);
  new Uint8Array(differentKey)[0] = 0xff;
  const trusted2 = await bobStore.isTrustedIdentity("test-addr-1", differentKey, 2);
  check("Different key on same address is rejected (TOFU)", trusted2 === false);

  // --- 7. Privacy: no keys in localStorage ---
  console.log("\n7. Privacy: identity key storage");
  // localStorage is empty in this Node context; we just verify
  // the store layer has Alice's keys and not the (non-existent)
  // localStorage.
  const aliceStored = await new IndexedDBSignalProtocolStore().getIdentityKeyPair();
  check("Alice's identity is in IndexedDB", aliceStored !== undefined);
  check("Alice's identity pubKey is 33 bytes (0x05 + key)", aliceStored?.pubKey.byteLength === 33 && new Uint8Array(aliceStored.pubKey)[0] === 0x05);
  check("Alice's identity privKey is 32 bytes (raw)", aliceStored?.privKey.byteLength === 32);

  // --- Summary ---
  console.log(`\n=== ${pass} passed, ${fail} failed ===\n`);
  if (fail > 0) process.exit(1);
}

main().catch((e) => { console.error(e); process.exit(1); });
