import { expect, test } from "@playwright/test";
import { assertNoSensitiveBody, authenticateSynthetic, dispatchInstallPrompt } from "./helpers";

test.use({ serviceWorkers: "block" });

test("install UI follows the project capability and clears after action", async ({ page }, testInfo) => {
  const network = await authenticateSynthetic(page);
  if (testInfo.project.name === "webkit-ios") {
    const hint = page.getByRole("dialog", { name: "Install IceQ" });
    await expect(hint).toBeVisible();
    expect(await page.evaluate(() => "BeforeInstallPromptEvent" in window)).toBe(false);
    await page.getByRole("button", { name: "Got it" }).click();
    await expect(hint).toBeHidden();
    await assertNoSensitiveBody(page, network);
    return;
  }
  await dispatchInstallPrompt(page, "accepted");
  const install = page.getByRole("button", { name: "Install", exact: true });
  await expect(install).toBeVisible();
  await install.click();
  await expect.poll(() => page.evaluate(() => Boolean((window as typeof window & { __iceqPromptCalled?: boolean }).__iceqPromptCalled))).toBe(true);
  await expect(install).toBeHidden();
  await assertNoSensitiveBody(page, network);
});

test("dismissal suppression matches the project install capability", async ({ page }, testInfo) => {
  const network = await authenticateSynthetic(page);
  if (testInfo.project.name === "webkit-ios") {
    const hint = page.getByRole("dialog", { name: "Install IceQ" });
    await expect(hint).toBeVisible();
    await page.getByRole("button", { name: "Got it" }).click();
    await page.reload();
    await expect(hint).toBeHidden();
    expect(await page.evaluate(() => localStorage.getItem("iceq_ios_hint_shown"))).toBe("1");
    await assertNoSensitiveBody(page, network);
    return;
  }
  await dispatchInstallPrompt(page);
  await page.getByRole("button", { name: "Dismiss" }).click();

  await page.reload();
  await dispatchInstallPrompt(page);
  await expect(page.getByRole("button", { name: "Install", exact: true })).toBeHidden();

  await page.evaluate(() => localStorage.setItem("iceq_install_dismissed", String(Date.now() - 8 * 24 * 60 * 60 * 1000)));
  await page.reload();
  await dispatchInstallPrompt(page);
  await expect(page.getByRole("button", { name: "Install", exact: true })).toBeVisible();
  await assertNoSensitiveBody(page, network);
});

test("iOS projects show manual install guidance and other projects do not", async ({ page }, testInfo) => {
  const network = await authenticateSynthetic(page);
  const hint = page.getByRole("dialog", { name: "Install IceQ" });
  if (testInfo.project.name === "webkit-ios") {
    await expect(hint).toBeVisible();
    await expect(hint).toContainText("Add to Home Screen");
    await page.getByRole("button", { name: "Got it" }).click();
    await expect(hint).toBeHidden();
  } else {
    await expect(hint).toBeHidden();
  }
  await assertNoSensitiveBody(page, network);
});

test("standalone display mode suppresses synthetic install UI", async ({ page }) => {
  await page.addInitScript(() => {
    Object.defineProperty(navigator, "standalone", { configurable: true, value: true });
    const original = window.matchMedia.bind(window);
    window.matchMedia = (query: string): MediaQueryList => {
      if (query === "(display-mode: standalone)") {
        return {
          matches: true,
          media: query,
          onchange: null,
          addListener: () => undefined,
          removeListener: () => undefined,
          addEventListener: () => undefined,
          removeEventListener: () => undefined,
          dispatchEvent: () => true,
        };
      }
      return original(query);
    };
  });
  const network = await authenticateSynthetic(page);
  await dispatchInstallPrompt(page);
  await expect(page.getByRole("button", { name: "Install", exact: true })).toBeHidden();
  await expect(page.getByRole("dialog", { name: "Install IceQ" })).toBeHidden();
  await assertNoSensitiveBody(page, network);
});
