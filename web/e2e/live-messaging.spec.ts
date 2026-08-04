/**
 * Real-browser E2E: two independent accounts, encrypted DM and PDF transfer.
 *
 * This suite talks to the live rehearsal stack. Both disposable accounts are
 * removed through the real Panic Wipe UI in the test cleanup.
 */

import { createHash } from "node:crypto";
import { test, expect, type Browser, type BrowserContext, type Page } from "@playwright/test";

const PASSPHRASE = "LiveMessagingSecurityPhrase1!";
const PASSWORD = "LiveMessagingPass1!";

interface LiveUser {
  username: string;
  password: string;
  uin?: number;
}

function disposableUser(suffix: string): LiveUser {
  return {
    username: `live${Date.now().toString(36)}${suffix}`,
    password: PASSWORD,
  };
}

async function registerAndCompleteSetup(page: Page, user: LiveUser): Promise<void> {
  await page.goto("/register", { waitUntil: "networkidle" });
  await page.locator("#register-username").fill(user.username);
  await page.locator("#register-password").fill(user.password);
  await page.getByRole("button", { name: /create account|register/i }).click();
  await expect(page).toHaveURL(/\/(setup|app)/, { timeout: 30_000 });

  if (page.url().includes("/setup")) {
    const beginSetup = page.getByRole("button", { name: "Begin Setup" });
    const passphrase = page.locator("#setup-passphrase");
    for (let attempt = 0; attempt < 3 && !(await passphrase.isVisible()); attempt += 1) {
      await beginSetup.click();
      await passphrase.waitFor({ state: "visible", timeout: 5_000 }).catch(() => undefined);
    }
    await expect(passphrase).toBeVisible({ timeout: 15_000 });
    await passphrase.fill(PASSPHRASE);
    await page.locator("#setup-passphrase-confirm").fill(PASSPHRASE);
    await page.getByRole("button", { name: "Continue" }).click();

    await expect(page.getByRole("heading", { name: "Enable Panic Wipe" })).toBeVisible({ timeout: 15_000 });
    await page.locator("#setup-account-password").fill(user.password);
    await page.getByRole("button", { name: "Enable Panic Wipe" }).click();

    await page.getByRole("button", { name: "Generate Recovery Key & Package" }).click();
    await expect(page.getByRole("heading", { name: "Recovery Key & Package" })).toBeVisible({ timeout: 15_000 });
    await page.getByRole("button", { name: "I Have Saved Both" }).click();
    await page.getByLabel(/I have saved my Recovery Key/).click();
    await page.getByRole("button", { name: "Complete Setup" }).click();
  }

  await expect(page).toHaveURL(/\/app/, { timeout: 20_000 });
  await expect(page.locator('main > header[data-connected="true"]')).toBeVisible({ timeout: 20_000 });
  user.uin = await page.evaluate(async () => {
    const accessToken = localStorage.getItem("iceq_access_token");
    if (!accessToken) throw new Error("authenticated page has no access token");
    const response = await fetch("/api/auth/me", {
      credentials: "include",
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    if (!response.ok) throw new Error(`could not read authenticated identity (${response.status})`);
    const payload = await response.json() as { uin: number };
    return payload.uin;
  });
}

async function openDrawerTab(page: Page, name: "Chats" | "Contacts" | "Groups"): Promise<void> {
  const drawer = page.locator("#navigation-drawer");
  if (await drawer.getAttribute("aria-hidden") !== "false") {
    await page.getByRole("button", { name: "Toggle menu" }).click();
  }
  await page.getByRole("tab", { name, exact: true }).click();
}

async function selectContact(page: Page, username: string): Promise<void> {
  await openDrawerTab(page, "Contacts");
  const contact = page
    .getByRole("region", { name: "Contacts" })
    .getByRole("button")
    .filter({ hasText: username });
  await expect(contact).toBeVisible({ timeout: 20_000 });
  await contact.click();
  await expect(page.locator("main header").filter({ hasText: username })).toBeVisible({ timeout: 15_000 });
}

async function panicWipe(page: Page): Promise<void> {
  if (!/\/app/.test(page.url())) return;
  const drawer = page.locator("#navigation-drawer");
  if (await drawer.getAttribute("aria-hidden") !== "false") {
    await page.getByRole("button", { name: "Toggle menu" }).click();
  }
  await page.getByRole("button", { name: "Settings", exact: true }).click();
  const settings = page.getByRole("dialog", { name: "Settings" });
  await expect(settings).toBeVisible({ timeout: 10_000 });
  await settings.getByRole("button", { name: "Permanently delete account" }).click();
  const confirmation = page.getByRole("dialog").last();
  await confirmation.getByRole("button", { name: "Security Passphrase" }).click();
  await page.locator("#panic-wipe-passphrase").fill(PASSPHRASE);
  await confirmation.getByRole("button", { name: "Permanently delete account" }).click();
  await expect(page).toHaveURL(/\/login/, { timeout: 45_000 });
}

async function createLivePage(browser: Browser): Promise<{ context: BrowserContext; page: Page }> {
  const context = await browser.newContext({ ignoreHTTPSErrors: true, acceptDownloads: true });
  const page = await context.newPage();
  return { context, page };
}

test("two real accounts exchange encrypted messages and an authenticated PDF", async ({ browser }) => {
  test.setTimeout(300_000);
  const accountA = disposableUser("a");
  const accountB = disposableUser("b");
  const a = await createLivePage(browser);
  const b = await createLivePage(browser);

  try {
    await registerAndCompleteSetup(a.page, accountA);
    await registerAndCompleteSetup(b.page, accountB);
    expect(accountA.uin).toBeGreaterThan(0);
    expect(accountB.uin).toBeGreaterThan(0);

    await openDrawerTab(a.page, "Contacts");
    await a.page.getByRole("button", { name: "Add contact" }).click();
    await a.page.locator("#add-contact-uin").fill(String(accountB.uin));
    await a.page.getByRole("button", { name: "Send request" }).click();
    await expect(a.page.getByRole("status")).toContainText("Contact request sent");
    await a.page.getByRole("button", { name: "Close add contact" }).click();

    await openDrawerTab(b.page, "Contacts");
    const incoming = b.page.getByRole("region", { name: "Incoming contact requests" });
    await expect(incoming).toContainText(accountA.username, { timeout: 20_000 });
    await incoming.getByRole("button", { name: "Accept" }).click();
    await expect(incoming).toHaveCount(0, { timeout: 20_000 });

    await selectContact(a.page, accountB.username);
    await selectContact(b.page, accountA.username);

    const messageA = `encrypted-from-a-${Date.now()}`;
    await a.page.getByPlaceholder("Type a message…").fill(messageA);
    await a.page.getByRole("button", { name: "Send", exact: true }).click();
    await expect(b.page.locator("main").getByRole("listitem").getByText(messageA, { exact: true }))
      .toBeVisible({ timeout: 30_000 });

    const messageB = `encrypted-from-b-${Date.now()}`;
    await b.page.getByPlaceholder("Type a message…").fill(messageB);
    await b.page.getByRole("button", { name: "Send", exact: true }).click();
    await expect(a.page.locator("main").getByRole("listitem").getByText(messageB, { exact: true }))
      .toBeVisible({ timeout: 30_000 });

    const pdf = Buffer.from(
      "%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n" +
      "2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n" +
      "3 0 obj<</Type/Page/MediaBox[0 0 612 792]/Parent 2 0 R>>endobj\n" +
      "trailer<</Root 1 0 R>>\n%%EOF\n",
    );
    const filename = `iceq-live-${Date.now()}.pdf`;
    await a.page.locator('input[type="file"]').setInputFiles({
      name: filename,
      mimeType: "application/pdf",
      buffer: pdf,
    });
    const receivedFile = b.page.locator("main").getByRole("listitem").getByText(filename, { exact: true });
    await expect(receivedFile).toBeVisible({ timeout: 45_000 });

    const downloadPromise = b.page.waitForEvent("download");
    await b.page.getByRole("link", { name: /download and decrypt/i }).click();
    const download = await downloadPromise;
    const stream = await download.createReadStream();
    const chunks: Buffer[] = [];
    for await (const chunk of stream) chunks.push(Buffer.from(chunk));
    const downloaded = Buffer.concat(chunks);
    expect(createHash("sha256").update(downloaded).digest("hex"))
      .toBe(createHash("sha256").update(pdf).digest("hex"));
  } finally {
    await panicWipe(a.page).catch(() => undefined);
    await panicWipe(b.page).catch(() => undefined);
    await a.context.close();
    await b.context.close();
  }
});
