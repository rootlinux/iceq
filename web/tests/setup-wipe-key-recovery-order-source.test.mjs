import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

// Task #11's fix depends on two ordering invariants that no type check
// would catch if silently reverted -- both components would still
// compile, they'd just quietly reintroduce "recovered device can never
// restore its wipe key" (SecuritySetupGate) or "recovered wipe key sits
// in memory with nowhere safe to go" (RecoveryImportScreen). Guard both
// by scanning source rather than trying to drive full step-machine
// component tests, which this codebase has no rendering harness for.

const __dirname = dirname(fileURLToPath(import.meta.url));
const setupGateSource = readFileSync(
  resolve(__dirname, "../src/components/Auth/SecuritySetupGate.tsx"),
  "utf8",
);
const recoverySource = readFileSync(
  resolve(__dirname, "../src/components/Auth/RecoveryImportScreen.tsx"),
  "utf8",
);

test("SecuritySetupGate enables the wipe key before generating the recovery package", () => {
  const wipeKeyIndex = setupGateSource.indexOf("async function handleEnableWipeKey");
  const recoveryIndex = setupGateSource.indexOf("async function handleGenerateRecovery");
  assert.ok(wipeKeyIndex >= 0, "handleEnableWipeKey must exist");
  assert.ok(recoveryIndex >= 0, "handleGenerateRecovery must exist");

  // handleEnableWipeKey must transition to "recovery" on success -- the
  // wipe key has to exist in IndexedDB before createRecoveryPackage runs.
  const wipeKeyBody = setupGateSource.slice(wipeKeyIndex, recoveryIndex > wipeKeyIndex ? recoveryIndex : undefined);
  assert.match(wipeKeyBody, /setStep\("recovery"\)/);

  // The passphrase step must never jump straight to "recovery" -- that
  // would skip wipe-key enrollment entirely.
  const passphraseIndex = setupGateSource.indexOf("async function handleCreatePassphrase");
  const passphraseBody = setupGateSource.slice(passphraseIndex, wipeKeyIndex);
  assert.match(passphraseBody, /setStep\("wipekey"\)/);
  assert.doesNotMatch(passphraseBody, /setStep\("recovery"\)/);
});

test("SecuritySetupGate's mount check skips the passphrase step when a vault already exists", () => {
  assert.match(setupGateSource, /hasSecurityPassphrase\(\)/);
  assert.match(setupGateSource, /setStep\("wipekey"\)/);
});

test("RecoveryImportScreen creates a vault before importing the package", () => {
  const passphraseHandlerIndex = recoverySource.indexOf("async function handleCreatePassphrase");
  const importHandlerIndex = recoverySource.indexOf("async function handleImport");
  assert.ok(passphraseHandlerIndex >= 0 && importHandlerIndex >= 0);
  assert.ok(passphraseHandlerIndex < importHandlerIndex, "passphrase creation must be defined/wired before import");
  assert.match(recoverySource, /type ImportState = "passphrase" \| "input"/);
});

test("RecoveryImportScreen restores the wipe key on both the happy path and the resumed-retry path", () => {
  const importBody = recoverySource.slice(
    recoverySource.indexOf("async function handleImport"),
    recoverySource.indexOf("async function handleRetryProvisioning"),
  );
  const retryBody = recoverySource.slice(recoverySource.indexOf("async function handleRetryProvisioning"));

  assert.match(importBody, /restorePendingWipeKey\(\)/, "handleImport must attempt wipe-key restoration");
  assert.match(retryBody, /restorePendingWipeKey\(\)/, "handleRetryProvisioning must retry wipe-key restoration too");

  // Setup must only be marked fully complete when the wipe key was
  // actually restored -- see finishRecovery. Otherwise a recovered
  // device with no wipe key would never be routed through SecuritySetupGate
  // to enable one.
  assert.match(recoverySource, /if \(wipeKeyRestored\.current\) \{\s*\n\s*await setSecuritySetupCompleted/);
});

test("the recovered wipe key is never written to IndexedDB unencrypted", () => {
  // importRecoveredWipeKey (panicWipeKey.ts) is the only thing allowed to
  // persist it, and it re-encrypts with the vault key first.
  assert.doesNotMatch(recoverySource, /indexedDB\.open/);
});
