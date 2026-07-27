import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

// The in-chat safety-number verification modal must reuse the
// existing, tested trust engine (identityTrust.ts's STORE_PEER_TRUST
// via peerSafetyInspection.ts) rather than reimplementing
// verification state in a separate store. A persisted "verified"
// flag that isn't re-checked against the live pinned identity key
// goes stale silently -- see peer-safety-inspection.test.ts's
// staleness test for the concrete failure this guards against.

const __dirname = dirname(fileURLToPath(import.meta.url));
const modalSource = readFileSync(
  resolve(__dirname, "../src/components/Chat/SafetyNumberVerifyModal.tsx"),
  "utf8",
);

test("the in-chat safety modal reuses the shared peer-safety engine", () => {
  assert.match(modalSource, /from "\.\.\/\.\.\/lib\/peerSafetyInspection"/);
  assert.match(modalSource, /from "\.\.\/\.\.\/lib\/identityTrust"/);
});

test("the in-chat safety modal does not define its own verification storage", () => {
  assert.doesNotMatch(modalSource, /indexedDB\.open|createObjectStore|STORE_SAFETY/i);
});
