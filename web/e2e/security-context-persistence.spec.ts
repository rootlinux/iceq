import { expect, test, type BrowserContext, type Page } from "@playwright/test";
import {
  SYNTHETIC_USER,
  assertHermeticNetwork,
  installSyntheticAPI,
  publishSyntheticDirectory,
  seedSyntheticIdentity,
  type SyntheticDirectoryEntry,
  type SyntheticNetwork,
} from "./helpers";

test.use({ serviceWorkers: "block" });

const SECURITY_PASSPHRASE = "ContextPersistencePassphrase1";
const RECOVERY_PASSPHRASE = "RecoveredContextPassphrase1";
const ACCOUNT_PASSWORD = "synthetic-account-password";

interface LocalSecurityBinding {
  uin: number;
  deviceId: string;
  identityPublicKey: string | null;
  setupComplete: boolean;
  wipePublicKey: string | null;
}

interface RecoveryArtifacts {
  key: string;
  packageContent: string;
}

async function startUnconfiguredSession(page: Page): Promise<void> {
  await page.goto("/login");
  await seedSyntheticIdentity(page, SYNTHETIC_USER, { completeSecuritySetup: false });
  await page.evaluate(async (account) => {
    const { useAuthStore } = await import("/src/store/authStore.ts");
    await useAuthStore.getState().setSession(
      { uin: account.uin, username: account.username },
      account.accessToken,
      account.refreshToken,
    );
  }, SYNTHETIC_USER);
  await expect(page).toHaveURL(/\/setup$/);
}

async function driveSetupToRecovery(page: Page): Promise<void> {
  await page.getByRole("button", { name: "Begin Setup" }).click();
  await page.locator("#setup-passphrase").fill(SECURITY_PASSPHRASE);
  await page.locator("#setup-passphrase-confirm").fill(SECURITY_PASSPHRASE);
  await page.getByRole("button", { name: "Continue" }).click();

  await page.locator("#setup-account-password").fill(ACCOUNT_PASSWORD);
  await page.getByRole("button", { name: "Enable Panic Wipe" }).click();
  await page.getByRole("button", { name: "Generate Recovery Key & Package" }).click();
  await expect(page.getByText("Recovery Key", { exact: true })).toBeVisible();
}

async function captureRecoveryArtifacts(page: Page): Promise<RecoveryArtifacts> {
  const key = (await page.getByText("Recovery Key", { exact: true })
    .locator("..")
    .locator(".text-mono")
    .innerText()).trim();

  const downloadPromise = page.waitForEvent("download");
  await page.getByRole("button", { name: "Download Recovery Package" }).click();
  const download = await downloadPromise;
  const stream = await download.createReadStream();
  if (!stream) throw new Error("recovery package download did not provide a readable stream");

  const chunks: Buffer[] = [];
  for await (const chunk of stream) chunks.push(Buffer.from(chunk));
  const packageContent = Buffer.concat(chunks).toString("utf8").trim();

  expect(key).toMatch(/^[A-Za-z0-9_-]{43}$/);
  expect(packageContent.length).toBeGreaterThan(100);
  return { key, packageContent };
}

async function finishSecuritySetup(page: Page): Promise<void> {
  await page.getByRole("button", { name: "I Have Saved Both" }).click();
  await page.getByText("I have saved my Recovery Key", { exact: false }).click();
  await page.getByRole("button", { name: "Complete Setup" }).click();
  await expect(page).toHaveURL(/\/app(?:\/|$)/);
}

async function readLocalSecurityBinding(page: Page): Promise<LocalSecurityBinding> {
  return page.evaluate(async () => {
    const idb = await import("/src/lib/indexeddb.ts");
    const ns = idb.getActiveCryptoNamespace();
    const identity = await idb.loadIdentity(ns);
    const wipeRecord = await new Promise<{ publicKey?: string } | undefined>((resolve) => {
      const openReq = indexedDB.open("iceq", 6);
      openReq.onsuccess = () => {
        const db = openReq.result;
        const txn = db.transaction("metadata", "readonly");
        const getReq = txn.objectStore("metadata").get(
          idb.cryptoRecordKey(ns, "metadata", "panic_wipe_encrypted_private"),
        );
        getReq.onsuccess = () => resolve(getReq.result as { publicKey?: string } | undefined);
        getReq.onerror = () => resolve(undefined);
        txn.oncomplete = () => db.close();
        txn.onerror = () => db.close();
      };
      openReq.onerror = () => resolve(undefined);
    });

    return {
      uin: ns.uin,
      deviceId: ns.deviceId,
      identityPublicKey: identity?.publicKey ?? null,
      setupComplete: await idb.hasSecuritySetupCompleted(ns),
      wipePublicKey: wipeRecord?.publicKey ?? null,
    };
  });
}

async function recoveredWipeKeySignsFor(page: Page, expectedPublicKey: string): Promise<boolean> {
  return page.evaluate(async (publicKeyB64url) => {
    const { loadAndDecryptWipePrivateKey, signWipeChallenge } = await import("/src/lib/panicWipeKey.ts");
    const privateKey = await loadAndDecryptWipePrivateKey();
    if (!privateKey) return false;

    const challenge = Uint8Array.from({ length: 32 }, (_, index) => index + 17);
    const signature = await signWipeChallenge(challenge, privateKey);
    let encoded = publicKeyB64url.replace(/-/g, "+").replace(/_/g, "/");
    while (encoded.length % 4 !== 0) encoded += "=";
    const publicKeyBytes = Uint8Array.from(atob(encoded), (char) => char.charCodeAt(0));
    const publicKey = await globalThis.crypto.subtle.importKey(
      "raw",
      publicKeyBytes,
      { name: "Ed25519" },
      false,
      ["verify"],
    );
    return globalThis.crypto.subtle.verify(
      { name: "Ed25519" },
      publicKey,
      signature,
      challenge,
    );
  }, expectedPublicKey);
}

async function readPublishedDirectory(page: Page): Promise<SyntheticDirectoryEntry> {
  return page.evaluate((uin) => {
    const directory = JSON.parse(
      localStorage.getItem("__iceq_e2e_public_directory") ?? "{}",
    ) as Record<string, SyntheticDirectoryEntry>;
    const entry = directory[String(uin)];
    if (!entry) throw new Error("synthetic directory entry is missing");
    return entry;
  }, SYNTHETIC_USER.uin);
}

async function signInThroughUI(page: Page): Promise<void> {
  await page.locator("#login-username").fill(SYNTHETIC_USER.username);
  await page.locator("#login-password").fill(ACCOUNT_PASSWORD);
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
}

async function dismissOptionalInstallHint(page: Page): Promise<void> {
  await page.getByRole("button", { name: "Got it" }).click({ timeout: 2_000 }).catch(() => {});
}

async function closeContext(context: BrowserContext): Promise<void> {
  await context.close();
}

test("the same browser resumes the existing identity after sign-out and sign-in", async ({ page }) => {
  test.setTimeout(60_000);

  const network = await installSyntheticAPI(page);
  await startUnconfiguredSession(page);
  await driveSetupToRecovery(page);
  await finishSecuritySetup(page);

  const before = await readLocalSecurityBinding(page);
  expect(before.identityPublicKey).not.toBeNull();
  expect(before.wipePublicKey).not.toBeNull();
  expect(before.setupComplete).toBe(true);

  await dismissOptionalInstallHint(page);
  await page.getByRole("button", { name: "Toggle menu" }).click();
  await page.getByRole("button", { name: "Sign out", exact: true }).click();
  await expect(page).toHaveURL(/\/login$/);

  await signInThroughUI(page);
  await expect(page).toHaveURL(/\/app(?:\/|$)/);
  await expect(page.getByRole("heading", { name: "Security Setup" })).toHaveCount(0);

  const after = await readLocalSecurityBinding(page);
  expect(after).toEqual(before);
  await assertHermeticNetwork(page, network);
});

test("a clean browser stays gated until the saved package restores the original bindings", async ({ browser }, testInfo) => {
  test.setTimeout(60_000);

  const sourceContext = await browser.newContext({
    baseURL: String(testInfo.project.use.baseURL),
    serviceWorkers: "block",
  });
  const sourcePage = await sourceContext.newPage();
  const sourceNetwork = await installSyntheticAPI(sourcePage);

  try {
    await startUnconfiguredSession(sourcePage);
    const directoryEntry = await readPublishedDirectory(sourcePage);
    await driveSetupToRecovery(sourcePage);
    const recovery = await captureRecoveryArtifacts(sourcePage);
    await finishSecuritySetup(sourcePage);
    const sourceBinding = await readLocalSecurityBinding(sourcePage);

    const cleanContext = await browser.newContext({
      baseURL: String(testInfo.project.use.baseURL),
      serviceWorkers: "block",
    });
    const cleanPage = await cleanContext.newPage();
    const cleanNetwork: SyntheticNetwork = await installSyntheticAPI(cleanPage);

    try {
      await cleanPage.goto("/login");
      await publishSyntheticDirectory(cleanPage, SYNTHETIC_USER.uin, directoryEntry);
      await signInThroughUI(cleanPage);

      await expect(cleanPage).toHaveURL(/\/setup$/);
      await expect(cleanPage.getByRole("heading", { name: "Security Setup" })).toBeVisible();

      const beforeRecovery = await cleanPage.evaluate(async () => {
        const idb = await import("/src/lib/indexeddb.ts");
        const ns = idb.getActiveCryptoNamespace();
        return {
          identity: await idb.loadIdentity(ns),
          setupComplete: await idb.hasSecuritySetupCompleted(ns),
        };
      });
      expect(beforeRecovery.identity).toBeNull();
      expect(beforeRecovery.setupComplete).toBe(false);

      await cleanPage.reload();
      await expect(cleanPage).toHaveURL(/\/setup$/);
      await expect(cleanPage.getByRole("heading", { name: "Security Setup" })).toBeVisible();
      await cleanPage.getByRole("button", { name: "Restore from recovery package", exact: true }).click();
      await expect(cleanPage).toHaveURL(/\/recovery$/);

      await cleanPage.locator("#recovery-passphrase").fill(RECOVERY_PASSPHRASE);
      await cleanPage.locator("#recovery-passphrase-confirm").fill(RECOVERY_PASSPHRASE);
      await cleanPage.getByRole("button", { name: "Continue" }).click();

      await cleanPage.locator("#recovery-package-file").setInputFiles({
        name: "iceq-recovery-v4.iceq",
        mimeType: "application/octet-stream",
        buffer: Buffer.from(recovery.packageContent, "utf8"),
      });
      await cleanPage.locator("#recovery-key").fill(recovery.key);
      await cleanPage.getByRole("button", { name: "Import Recovery Package" }).click();
      await expect(cleanPage.getByText("Recovery Complete", { exact: true })).toBeVisible();
      await cleanPage.getByRole("button", { name: "Continue to IceQ" }).click();
      await expect(cleanPage).toHaveURL(/\/app(?:\/|$)/);
      await expect(cleanPage.getByText(SYNTHETIC_USER.username, { exact: false })).toBeVisible();

      const restoredBinding = await readLocalSecurityBinding(cleanPage);
      expect(restoredBinding.uin).toBe(SYNTHETIC_USER.uin);
      expect(restoredBinding.deviceId).not.toBe(sourceBinding.deviceId);
      expect(restoredBinding.identityPublicKey).toBe(sourceBinding.identityPublicKey);
      expect(restoredBinding.wipePublicKey).toBe(sourceBinding.wipePublicKey);
      expect(restoredBinding.setupComplete).toBe(true);
      expect(await recoveredWipeKeySignsFor(cleanPage, sourceBinding.wipePublicKey!)).toBe(true);

      await assertHermeticNetwork(cleanPage, cleanNetwork);
    } finally {
      await closeContext(cleanContext);
    }

    await assertHermeticNetwork(sourcePage, sourceNetwork);
  } finally {
    await closeContext(sourceContext);
  }
});
