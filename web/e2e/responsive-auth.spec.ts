import { expect, test } from "@playwright/test";
import { assertNoSensitiveBody, authenticateSynthetic, installSyntheticAPI } from "./helpers";

test.use({ serviceWorkers: "block" });

async function expectNoHorizontalOverflow(page: import("@playwright/test").Page): Promise<void> {
  await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth)).toBe(true);
}

test("login and register remain usable without horizontal overflow", async ({ page }) => {
  const network = await installSyntheticAPI(page);
  await page.goto("/login");
  await expect(page.getByRole("heading", { name: "Sign in to IceQ" })).toBeVisible();
  await expect(page.locator("#login-username")).toBeVisible();
  await expect(page.locator("#login-password")).toHaveAttribute("type", "password");
  await expectNoHorizontalOverflow(page);

  await page.getByRole("link", { name: "Register" }).click();
  await expect(page.getByRole("heading", { name: "Create your IceQ account" })).toBeVisible();
  await expect(page.locator("#register-username")).toBeVisible();
  await expect(page.locator("#register-password")).toHaveAttribute("type", "password");
  await expectNoHorizontalOverflow(page);
  await assertNoSensitiveBody(page, network);
});

test("authenticated navigation, settings focus, and mobile menu are keyboard safe", async ({ page }, testInfo) => {
  const network = await authenticateSynthetic(page);
  const mobile = testInfo.project.name.endsWith("android") || testInfo.project.name.endsWith("ios");
  if (testInfo.project.name === "webkit-ios") {
    const hint = page.getByRole("dialog", { name: "Install IceQ" });
    await expect(hint).toBeVisible();
    await page.getByRole("button", { name: "Got it" }).click();
    await expect(hint).toBeHidden();
  }
  const toggle = page.getByRole("button", { name: "Toggle menu" });
  const sidebar = page.locator("aside");
  if (mobile) {
    await expect(toggle).toBeVisible();
    await expect(sidebar).toHaveAttribute("data-open", "false");
    await toggle.click();
    await expect(sidebar).toHaveAttribute("data-open", "true");
  } else {
    await expect(toggle).toBeHidden();
    await expect(sidebar).toBeVisible();
  }

  const settingsTrigger = page.getByRole("button", { name: "Settings", exact: true });
  await settingsTrigger.click();
  const dialog = page.getByRole("dialog", { name: "Settings" });
  await expect(dialog).toBeVisible();
  const close = page.getByRole("button", { name: "Close settings" });
  await expect(close).toBeFocused();
  await page.keyboard.press("Tab");
  await expect(dialog.locator(":focus")).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(dialog).toBeHidden();
  await expect(settingsTrigger).toBeFocused();
  await expectNoHorizontalOverflow(page);
  await assertNoSensitiveBody(page, network);
});
