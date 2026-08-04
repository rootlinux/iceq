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
  await expect.poll(() => page.evaluate(async () => (await import("/src/store/signalStore.ts")).useSignalStore.getState().ready)).toBe(true);
  await expect(page.getByRole("alert")).toHaveCount(0);
  if (testInfo.project.name === "webkit-ios") {
    const hint = page.getByRole("dialog", { name: "Install IceQ" });
    await expect(hint).toBeVisible();
    await page.getByRole("button", { name: "Got it" }).click();
    await expect(hint).toBeHidden();
  }
  const toggle = page.getByRole("button", { name: "Toggle menu" });
  // Toggle (logo button) is always visible
  await expect(toggle).toBeVisible();
  await expect(toggle).toHaveAttribute("aria-expanded", "false");
  await expect(toggle).toHaveAttribute("aria-controls", "navigation-drawer");

  // Open drawer — logo button click
  await toggle.click();
  await expect(toggle).toHaveAttribute("aria-expanded", "true");
  // Drawer content should be reachable
  const drawer = page.locator("#navigation-drawer");
  await expect(drawer).toBeVisible();

  // Close via Escape — focus returns to logo toggle
  await page.keyboard.press("Escape");
  await expect(toggle).toHaveAttribute("aria-expanded", "false");
  await expect(toggle).toBeFocused();

  // Open again — open settings from the drawer
  await toggle.click();
  await expect(toggle).toHaveAttribute("aria-expanded", "true");
  await page.getByRole("button", { name: "Settings", exact: true }).click();
  await expect(page.getByRole("dialog", { name: "Settings" })).toBeVisible();

  // Close settings
  await page.getByRole("button", { name: "Close settings" }).click();
  await expect(page.getByRole("dialog", { name: "Settings" })).toBeHidden();

  // Close drawer via Escape
  await page.keyboard.press("Escape");
  await expect(toggle).toHaveAttribute("aria-expanded", "false");

  await assertNoSensitiveBody(page, network);
});
