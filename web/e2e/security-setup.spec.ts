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
