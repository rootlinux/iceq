// scripts/debug.mts

import "fake-indexeddb/auto";
import { saveIdentity, loadIdentity } from "../src/lib/indexeddb.ts";

const pub = new Uint8Array(32);
const priv = new Uint8Array(32);
const stored = {
  publicKey: btoa(String.fromCharCode(...pub)).replace(/=+$/, ""),
  privateKey: btoa(String.fromCharCode(...priv)).replace(/=+$/, ""),
  registrationId: 1234,
};
console.log("Saving:", { publicKey: stored.publicKey.slice(0, 10) + "...", registrationId: stored.registrationId });
await saveIdentity(stored);
const loaded = await loadIdentity();
console.log("Loaded:", loaded ? { publicKey: loaded.publicKey.slice(0, 10) + "...", registrationId: loaded.registrationId } : null);

import { generateIdentityKeyPair } from "../src/lib/signal.ts";
const kp = await generateIdentityKeyPair();
console.log("Generated pubKey length:", kp.publicKey.length, "privKey length:", kp.privateKey.length);
console.log("First 8 bytes of pubKey:", Array.from(kp.publicKey.slice(0, 8)));
