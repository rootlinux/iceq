import { expect, test, type Page, type TestInfo } from "@playwright/test";
import {
  SYNTHETIC_USER,
  assertHermeticNetwork,
  installSyntheticAPI,
  seedSyntheticIdentity,
  type SyntheticUser,
} from "./helpers";

test.use({ serviceWorkers: "block" });

const SECURITY_PASSPHRASE = "BrowserSecurityPassphrase1";
const ACCOUNT_PASSWORD = "synthetic-account-password";

// Both helpers take an explicit `user` (defaulting to the module-level
// SYNTHETIC_USER for the existing single-context tests) so they stay
// correct when a future test drives two isolated browser contexts through
// the same setup flow at once: every write they make -- IndexedDB
// identity, security vault, wipe key -- goes through `page`, which
// Playwright already scopes per browser context, and `user` controls which
// account's directory entry / session gets seeded. Nothing here reads or
// writes shared module state, so two concurrent calls with two different
// (page, user) pairs cannot cross-contaminate each other's identity, vault
// or wipe key.
async function startUnconfiguredSession(page: Page, user: SyntheticUser = SYNTHETIC_USER): Promise<void> {
  await page.goto("/login");
  await seedSyntheticIdentity(page, user, { completeSecuritySetup: false });
  await page.evaluate(async (account) => {
    const { useAuthStore } = await import("/src/store/authStore.ts");
    await useAuthStore.getState().setSession(
      { uin: account.uin, username: account.username },
      account.accessToken,
      account.refreshToken,
    );
  }, user);
  await expect(page).toHaveURL(/\/setup$/);
  await expect(page.getByRole("heading", { name: "Security Setup" })).toBeVisible();
}

// Drives the real SecuritySetupGate step order end to end -- intro ->
// passphrase -> wipekey -> recovery -> confirm (see the SetupStep comment
// in SecuritySetupGate.tsx). Every step performs its real client-side
// crypto and network call through the synthetic API boundary installed by
// installSyntheticAPI: a real local vault is created from the passphrase,
// a real Ed25519 wipe key pair is generated and its public half uploaded,
// and a real recovery package is generated from the real local identity.
// Nothing here reads gate-internal state, sets the completion flag
// directly, or short-circuits key generation/verification.
async function completeSecuritySetup(page: Page, user: SyntheticUser = SYNTHETIC_USER): Promise<void> {
  await page.getByRole("button", { name: "Begin Setup" }).click();
  await page.locator("#setup-passphrase").fill(SECURITY_PASSPHRASE);
  await page.locator("#setup-passphrase-confirm").fill(SECURITY_PASSPHRASE);
  await page.getByRole("button", { name: "Continue" }).click();

  // "wipekey" step: real account-password reauthentication, real Ed25519
  // key generation, real signed enrollment upload -- see
  // SecuritySetupGate.tsx's handleEnableWipeKey.
  await page.locator("#setup-account-password").fill(ACCOUNT_PASSWORD);
  await page.getByRole("button", { name: "Enable Panic Wipe" }).click();

  await page.getByRole("button", { name: "Generate Recovery Key & Package" }).click();
  await expect(page.getByText("Recovery Key", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "I Have Saved Both" }).click();

  await page.getByText("I have saved my Recovery Key", { exact: false }).click();
  await page.getByRole("button", { name: "Complete Setup" }).click();
  await expect(page).toHaveURL(/\/app(?:\/|$)/);
  await expect(page.getByText(user.username, { exact: false })).toBeVisible();
}

async function openSettings(page: Page, testInfo: TestInfo): Promise<void> {
  const mobile = testInfo.project.name.endsWith("android") || testInfo.project.name.endsWith("ios");
  if (testInfo.project.name === "webkit-ios") {
    await page.getByRole("button", { name: "Got it" }).click();
  }
  if (mobile) await page.getByRole("button", { name: "Toggle menu" }).click();
  await page.getByRole("button", { name: "Settings", exact: true }).click();
  await expect(page.getByRole("dialog", { name: "Settings" })).toBeVisible();
}

test("first login remains gated until security setup is durably completed", async ({ page }) => {
  const network = await installSyntheticAPI(page);
  await startUnconfiguredSession(page);
  await completeSecuritySetup(page);

  const enrollment = await page.evaluate(() => {
    const attempt = window.__iceqE2ENetwork.apiAttempts.find((entry) => (
      entry.path === "/api/auth/panic-wipe-public-key" && entry.method === "PUT"
    ));
    return attempt ? JSON.parse(attempt.body) as { public_key?: string; password?: string } : null;
  });
  expect(enrollment).not.toBeNull();
  expect(enrollment?.public_key).toMatch(/^[A-Za-z0-9+/]{43}=$/);
  expect(enrollment?.password).toBe(ACCOUNT_PASSWORD);

  const stored = await page.evaluate(async () => {
    const idb = await import("/src/lib/indexeddb.ts");
    const ns = idb.getActiveCryptoNamespace();
    return {
      setupComplete: await idb.hasSecuritySetupCompleted(ns),
      saltPresent: Boolean(await idb.loadSecurityVaultSalt(ns)),
      vaultPresent: Boolean(await idb.loadSecurityVaultBlob(ns)),
      localStorageValues: Object.values(localStorage),
    };
  });
  expect(stored.setupComplete).toBe(true);
  expect(stored.saltPresent).toBe(true);
  expect(stored.vaultPresent).toBe(true);
  expect(stored.localStorageValues.join(" ")).not.toContain(SECURITY_PASSPHRASE);

  await page.reload();
  await expect(page).toHaveURL(/\/app(?:\/|$)/);
  await expect(page.getByText(SYNTHETIC_USER.username, { exact: false })).toBeVisible();
  await assertHermeticNetwork(page, network);
});

test("passphrase-authorized Panic Wipe signs a challenge before clearing the local account", async ({ page }, testInfo) => {
  const network = await installSyntheticAPI(page);
  await startUnconfiguredSession(page);
  await completeSecuritySetup(page);
  await openSettings(page, testInfo);

  const settings = page.getByRole("dialog", { name: "Settings" });
  await settings.getByRole("button", { name: "Permanently delete account", exact: true }).click();
  const confirmation = page.getByRole("dialog", { name: "Permanently delete account" });
  await confirmation.getByRole("button", { name: "Security Passphrase" }).click();
  await confirmation.locator("#panic-wipe-passphrase").fill(SECURITY_PASSPHRASE);
  await confirmation.getByRole("button", { name: "Permanently delete account", exact: true }).click();

  await expect(page).toHaveURL(/\/login$/);
  await expect(page.getByRole("heading", { name: "Sign in to IceQ" })).toBeVisible();

  const wipeRequest = await page.evaluate(() => {
    const attempt = window.__iceqE2ENetwork.apiAttempts.find((entry) => (
      entry.path === "/api/auth/panic-wipe" && entry.method === "POST"
    ));
    return attempt ? JSON.parse(attempt.body) as { challenge_id?: string; signature?: string } : null;
  });
  expect(wipeRequest?.challenge_id).toBe("synthetic-wipe-challenge-1");
  expect(wipeRequest?.signature).toMatch(/^[A-Za-z0-9+/]{86}==$/);

  const localState = await page.evaluate(() => ({
    accessToken: localStorage.getItem("iceq_access_token"),
    accountUin: localStorage.getItem("iceq_account_uin"),
    passphraseLeaked: Object.values(localStorage).includes("BrowserSecurityPassphrase1"),
  }));
  expect(localState).toEqual({ accessToken: null, accountUin: null, passphraseLeaked: false });
  await assertHermeticNetwork(page, network);
});

// --- Reload / unlock / Panic Wipe enrollment flow ---
// The in-memory vaultKey does NOT survive page reloads. After a reload,
// the SecuritySetupGate must show an "Unlock Security Vault" screen and
// the unlocked key must be usable for Panic Wipe enrollment (which
// encrypts the private signing key with the vault key). Before the fix,
// unlockSecurityVault imported the key with only ["decrypt"], so any
// encrypt call after a reload failed with "key.usages does not permit
// this operation" (Chromium) or "CryptoKey doesn't support encryption"
// (WebKit).

const RELOAD_PASSPHRASE = "ReloadUnlockWipePass1";

test("reload-unlock panic wipe enrollment completes and survives a second reload", async ({ page }) => {
  const network = await installSyntheticAPI(page);
  await startUnconfiguredSession(page);

  // --- Phase 1: Create passphrase only, stop before wipekey ---
  await page.getByRole("button", { name: "Begin Setup" }).click();
  await page.locator("#setup-passphrase").fill(RELOAD_PASSPHRASE);
  await page.locator("#setup-passphrase-confirm").fill(RELOAD_PASSPHRASE);
  await page.getByRole("button", { name: "Continue" }).click();

  // The passphrase step should have advanced to wipekey.
  await expect(page.getByRole("heading", { name: "Enable Panic Wipe" })).toBeVisible();
  await expect(page.locator("#setup-account-password")).toBeVisible();

  // Record the unhandled API count now — after reload, wrong-passphrase
  // attempts must add zero to this.
  const apiAttemptsBeforeLock = await page.evaluate(() => window.__iceqE2ENetwork.apiAttempts.length);

  // --- Phase 2: Reload — the in-memory vaultKey is gone ---
  await page.reload();
  await expect(page).toHaveURL(/\/setup$/);

  // The unlock screen must appear because the vault exists in IndexedDB
  // but the in-memory key is null.
  await expect(page.getByRole("heading", { name: "Unlock Security Vault" })).toBeVisible();
  await expect(page.locator("#setup-unlock-passphrase")).toBeVisible();

  // --- Phase 3: Wrong passphrase — must fail locally, zero network ---
  await page.locator("#setup-unlock-passphrase").fill("WrongPassphrase123!");
  await page.getByRole("button", { name: "Unlock Vault" }).click();
  await expect(page.getByText("Incorrect Security Passphrase")).toBeVisible();

  // Prove zero network requests were made for the wrong-passphrase attempt.
  const apiAttemptsAfterWrong = await page.evaluate(() => window.__iceqE2ENetwork.apiAttempts.length);
  expect(apiAttemptsAfterWrong).toBe(apiAttemptsBeforeLock);

  // Vault must still be locked.
  const stillLocked = await page.evaluate(async () => {
    const { isVaultUnlocked, getVaultKey } = await import("/src/lib/securityVault.ts");
    return { unlocked: isVaultUnlocked(), key: getVaultKey() };
  });
  expect(stillLocked.unlocked).toBe(false);
  expect(stillLocked.key).toBeNull();

  // The passphrase field must be cleared after the failed attempt.
  await expect(page.locator("#setup-unlock-passphrase")).toHaveValue("");

  // --- Phase 4: Correct passphrase — unlocks the vault ---
  await page.locator("#setup-unlock-passphrase").fill(RELOAD_PASSPHRASE);
  await page.getByRole("button", { name: "Unlock Vault" }).click();

  // Must advance to wipekey step (not back to passphrase creation).
  await expect(page.getByRole("heading", { name: "Enable Panic Wipe" })).toBeVisible();

  // Vault must be unlocked and the key must support both encrypt and decrypt.
  const keyUsages = await page.evaluate(async () => {
    const { getVaultKey, isVaultUnlocked } = await import("/src/lib/securityVault.ts");
    const key = getVaultKey();
    return {
      unlocked: isVaultUnlocked(),
      extractable: key?.extractable,
      usages: key?.usages,
    };
  });
  expect(keyUsages.unlocked).toBe(true);
  expect(keyUsages.extractable).toBe(false);
  expect(keyUsages.usages).toContain("encrypt");
  expect(keyUsages.usages).toContain("decrypt");

  // The unlock-passphrase input is no longer in the DOM because the step
  // changed to "wipekey" — its component state was cleared before the
  // transition (verified by the vault-unlocked and key-usages checks above).

  // --- Phase 5: Complete Panic Wipe enrollment ---
  await page.locator("#setup-account-password").fill(ACCOUNT_PASSWORD);
  await page.getByRole("button", { name: "Enable Panic Wipe" }).click();

  // --- Phase 6: Complete recovery ---
  await page.getByRole("button", { name: "Generate Recovery Key & Package" }).click();
  await expect(page.getByText("Recovery Key", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "I Have Saved Both" }).click();
  await page.getByText("I have saved my Recovery Key", { exact: false }).click();
  await page.getByRole("button", { name: "Complete Setup" }).click();
  await expect(page).toHaveURL(/\/app(?:\/|$)/);

  // Verify the wipe key enrollment hit the synthetic API.
  const enrollment = await page.evaluate(() => {
    const attempt = window.__iceqE2ENetwork.apiAttempts.find((entry) => (
      entry.path === "/api/auth/panic-wipe-public-key" && entry.method === "PUT"
    ));
    return attempt ? JSON.parse(attempt.body) as { public_key?: string; password?: string } : null;
  });
  expect(enrollment).not.toBeNull();
  expect(enrollment?.public_key).toMatch(/^[A-Za-z0-9+/]{43}=$/);
  expect(enrollment?.password).toBe(ACCOUNT_PASSWORD);

  // Record the enrolled public key for stability check after second reload.
  const enrolledPubKey = enrollment!.public_key!;

  // Confirm the private key is stored encrypted (not plaintext).
  const storedEncrypted = await page.evaluate(async () => {
    const idb = await import("/src/lib/indexeddb.ts");
    const ns = idb.getActiveCryptoNamespace();
    const record = await new Promise<{ v: number; blob: string; publicKey?: string } | undefined>((resolve) => {
      const openReq = indexedDB.open("iceq", 6);
      openReq.onsuccess = () => {
        const db = openReq.result;
        const txn = db.transaction("metadata", "readonly");
        const store = txn.objectStore("metadata");
        const getReq = store.get(idb.cryptoRecordKey(ns, "metadata", "panic_wipe_encrypted_private"));
        getReq.onsuccess = () => { db.close(); resolve(getReq.result as { v: number; blob: string; publicKey?: string } | undefined); };
        getReq.onerror = () => { db.close(); resolve(undefined); };
      };
    });
    return { encrypted: Boolean(record?.blob && record.blob.length > 0), publicKey: record?.publicKey };
  });
  expect(storedEncrypted.encrypted).toBe(true);
  // The IndexedDB stores the public key in URL-safe base64 (bytesToBase64url),
  // but uploadWipePublicKey sends standard base64 (bytesToBase64std). Both
  // encode the same Ed25519 public key bytes. Normalize to standard base64
  // before comparing.
  const storedPubKeyStd = storedEncrypted.publicKey!
    .replace(/-/g, "+")
    .replace(/_/g, "/");
  // Pad to match standard base64 length (43 chars for Ed25519).
  const storedPubKeyPadded = storedPubKeyStd.length % 4
    ? storedPubKeyStd + "=".repeat(4 - (storedPubKeyStd.length % 4))
    : storedPubKeyStd;
  expect(storedPubKeyPadded).toBe(enrolledPubKey);

  // --- Phase 7: Second reload — setup is now complete, so the app routes
  // directly to /app. The wipe key must remain stable (same public key,
  // encrypted blob intact, no silent regeneration). ---
  await page.reload();
  await expect(page).toHaveURL(/\/app(?:\/|$)/);
  await expect(page.getByText(SYNTHETIC_USER.username, { exact: false })).toBeVisible();

  // The in-memory vault key is gone after reload (expected — it's
  // memory-only), but the wipe key in IndexedDB must be unchanged.
  const vaultStateAfterSecondReload = await page.evaluate(async () => {
    const { isVaultUnlocked, getVaultKey } = await import("/src/lib/securityVault.ts");
    return { unlocked: isVaultUnlocked(), keyNull: getVaultKey() === null };
  });
  expect(vaultStateAfterSecondReload.unlocked).toBe(false);
  expect(vaultStateAfterSecondReload.keyNull).toBe(true);

  // Verify the same wipe key public key is still stored — no silent
  // regeneration or replacement occurred.
  const pubKeyAfterReload = await page.evaluate(async () => {
    const idb = await import("/src/lib/indexeddb.ts");
    const ns = idb.getActiveCryptoNamespace();
    const record = await new Promise<{ v: number; blob: string; publicKey?: string } | undefined>((resolve) => {
      const openReq = indexedDB.open("iceq", 6);
      openReq.onsuccess = () => {
        const db = openReq.result;
        const txn = db.transaction("metadata", "readonly");
        const store = txn.objectStore("metadata");
        const getReq = store.get(idb.cryptoRecordKey(ns, "metadata", "panic_wipe_encrypted_private"));
        getReq.onsuccess = () => { db.close(); resolve(getReq.result as { v: number; blob: string; publicKey?: string } | undefined); };
        getReq.onerror = () => { db.close(); resolve(undefined); };
      };
    });
    return { publicKey: record?.publicKey ?? null, hasEncryptedBlob: Boolean(record?.blob && record.blob.length > 0) };
  });
  const pubKeyStdAfterReload = pubKeyAfterReload.publicKey!
    .replace(/-/g, "+")
    .replace(/_/g, "/");
  const pubKeyPaddedAfterReload = pubKeyStdAfterReload.length % 4
    ? pubKeyStdAfterReload + "=".repeat(4 - (pubKeyStdAfterReload.length % 4))
    : pubKeyStdAfterReload;
  expect(pubKeyPaddedAfterReload).toBe(enrolledPubKey);
  expect(pubKeyAfterReload.hasEncryptedBlob).toBe(true);

  // Confirm the passphrase is never in localStorage.
  const stored = await page.evaluate(() => {
    const values = Object.values(localStorage);
    return values.join(" ");
  });
  expect(stored).not.toContain(RELOAD_PASSPHRASE);

  // All network traffic must stay inside the synthetic API boundary.
  await assertHermeticNetwork(page, network);
});
