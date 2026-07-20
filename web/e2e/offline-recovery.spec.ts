import { expect, test } from "@playwright/test";
import { assertNoSensitiveBody, authenticateSynthetic, nativeCacheProbe } from "./helpers";

test("service worker registers and runtime caches exclude authenticated routes", async ({ page }) => {
  const network = await authenticateSynthetic(page);
  const probePaths = ["/api/e2e-cache-probe", "/ws/e2e-cache-probe", "/login", "/app"];
  await page.evaluate(async () => {
    await navigator.serviceWorker.ready;
    await new Promise<void>((resolve) => {
      if (navigator.serviceWorker.controller) return resolve();
      navigator.serviceWorker.addEventListener("controllerchange", () => resolve(), { once: true });
    });
  });
  const statuses = await nativeCacheProbe(page, probePaths);
  expect(statuses).toEqual([204, 204, 200, 200]);
  const evidence = await page.evaluate(async () => {
    const registration = await navigator.serviceWorker.getRegistration("/");
    const cacheNames = await caches.keys();
    const cachedURLs = (await Promise.all(cacheNames.map(async (name) => {
      const requests = await (await caches.open(name)).keys();
      return requests.map((request) => request.url);
    }))).flat();
    return { scope: registration?.scope ?? "", cacheNames, cachedURLs };
  });
  expect(evidence.scope).toBe("http://127.0.0.1:4173/");
  expect(evidence.cacheNames).toContain("iceq-static-v3");
  for (const path of probePaths) {
    expect(evidence.cachedURLs).not.toContain(`http://127.0.0.1:4173${path}`);
  }
  for (const url of evidence.cachedURLs) {
    const path = new URL(url).pathname;
    expect(path).not.toMatch(/^\/(?:api|ws)(?:\/|$)/);
    expect(path).not.toBe("/login");
    expect(path).not.toBe("/app");
  }
  await assertNoSensitiveBody(page, network);
});

test("offline status is announced and clears after connectivity returns", async ({ context, page }) => {
  const network = await authenticateSynthetic(page);
  await context.setOffline(true);
  const status = page.getByRole("status");
  await expect(status).toContainText("offline", { ignoreCase: true });
  await expect(status).toHaveAttribute("aria-live", "polite");
  await context.setOffline(false);
  await expect(status).toBeHidden();
  await assertNoSensitiveBody(page, network);
});
