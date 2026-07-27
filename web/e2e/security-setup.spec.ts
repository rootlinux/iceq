import { expect, test, type Page, type TestInfo } from "@playwright/test";
import {
  SYNTHETIC_USER,
  assertHermeticNetwork,
  installSyntheticAPI,
  seedSyntheticIdentity,
} from "./helpers";

test.use({ serviceWorkers: "block" });

const SECURITY_PASSPHRASE = "BrowserSecurityPassphrase1";

async function startUnconfiguredSession(page: Page): Promise<void> {
  await page.goto("/login");
  await seedSyntheticIdentity(page, SYNTHETIC_USER, { completeSecuritySetup: false });
  await page.evaluate(async (user) => {
    const { useAuthStore } = await import("/src/store/authStore.ts");
    await useAuthStore.getState().setSession(
      { uin: user.uin, username: user.username },
      user.accessToken,
      user.refreshToken,
    );
  }, SYNTHETIC_USER);
  await expect(page).toHaveURL(/\/setup$/);
  await expect(page.getByRole("heading", { name: "Security Setup" })).toBeVisible();
}

async function completeSecuritySetup(page: Page): Promise<void> {
  await page.getByRole("button", { name: "Begin Setup" }).click();
  await page.locator("#setup-passphrase").fill(SECURITY_PASSPHRASE);
  await page.locator("#setup-passphrase-confirm").fill(SECURITY_PASSPHRASE);
  await page.getByRole("button", { name: "Continue" }).click();

  await page.getByRole("button", { name: "Generate Recovery Key & Package" }).click();
  await expect(page.getByText("Recovery Key", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "I Have Saved Both" }).click();

  await page.locator("#setup-account-password").fill("synthetic-account-password");
  await page.getByText("I have saved my Recovery Key", { exact: false }).click();
  await page.getByRole("button", { name: "Complete Setup" }).click();
  await expect(page).toHaveURL(/\/app(?:\/|$)/);
  await expect(page.getByText(SYNTHETIC_USER.username, { exact: false })).toBeVisible();
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
  expect(enrollment?.password).toBe("synthetic-account-password");

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
