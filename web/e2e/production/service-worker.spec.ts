import { expect, test } from "@playwright/test";
import { assertNoSensitiveBody, authenticateSynthetic, nativeCacheProbe } from "../helpers";

// This test needs the REAL production service worker: main.tsx only calls
// navigator.serviceWorker.register() when `!__DEV__` (vite.config.ts sets
// __DEV__ = mode !== "production"), and public/sw.js only caches assets
// matching /^\/assets\/[...]-[hash]\.(js|css)$/ -- filenames that only
// exist once Vite has actually fingerprinted them during a production
// build. Neither condition is true under `vite dev`, which is what every
// other E2E project in playwright.config.ts runs against. This file is
// deliberately routed through playwright.sw.config.ts instead, which
// builds and serves the real dist/ output via `vite preview` -- see that
// config for the webServer wiring and baseURL.
const PROD_ORIGIN = "http://127.0.0.1:4174";

test.afterEach(async ({ page }) => {
  // Explicit, scoped cleanup: unregister only the service worker(s) and
  // delete only the cache(s) this test's own page created, rather than
  // relying solely on Playwright's context teardown to discard them.
  await page.evaluate(async () => {
    const registrations = await navigator.serviceWorker.getRegistrations();
    await Promise.all(registrations.map((registration) => registration.unregister()));
    const cacheNames = await caches.keys();
    await Promise.all(cacheNames.map((name) => caches.delete(name)));
  }).catch(() => {
    // Page/context may already be torn down by the time this runs after a
    // failing test -- nothing left to clean up in that case.
  });
});

test("service worker registers and runtime caches exclude authenticated routes", async ({ page }, testInfo) => {
  const network = await authenticateSynthetic(page);
  const probePaths = ["/api/e2e-cache-probe", "/ws/e2e-cache-probe", "/login", "/app"];

  // Deterministic, event-driven wait -- not a timeout guess. `ready`
  // resolves once the registration has an active worker; on a first visit
  // that worker only starts controlling the page once it fires
  // `clients.claim()` (see public/sw.js's activate handler), which is why
  // the controllerchange fallback is still needed even after `ready`.
  const registrationOutcome = await page.evaluate(async () => {
    if (!("serviceWorker" in navigator)) return { supported: false as const };
    await navigator.serviceWorker.ready;
    await new Promise<void>((resolve) => {
      if (navigator.serviceWorker.controller) { resolve(); return; }
      navigator.serviceWorker.addEventListener("controllerchange", () => resolve(), { once: true });
    });
    return { supported: true as const };
  });

  // Report, don't silently skip: if a browser project genuinely doesn't
  // expose navigator.serviceWorker (not observed in this project's 4
  // configured projects as of writing -- Playwright's Chromium and WebKit
  // both support the API -- but kept as a guard against a future project
  // that legitimately doesn't), fail loudly with the project name rather
  // than reporting a false pass.
  expect(registrationOutcome.supported, `${testInfo.project.name}: navigator.serviceWorker is unavailable in this browser project`).toBe(true);

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
  expect(evidence.scope).toBe(`${PROD_ORIGIN}/`);
  expect(evidence.cacheNames).toContain("iceq-static-v3");
  for (const path of probePaths) {
    expect(evidence.cachedURLs).not.toContain(`${PROD_ORIGIN}${path}`);
  }
  for (const url of evidence.cachedURLs) {
    const path = new URL(url).pathname;
    expect(path).not.toMatch(/^\/(?:api|ws)(?:\/|$)/);
    expect(path).not.toBe("/login");
    expect(path).not.toBe("/app");
  }
  await assertNoSensitiveBody(page, network);
});

test("production build serves a valid, linked PWA manifest", async ({ page }) => {
  await page.goto("/login");
  const manifestHref = await page.locator('link[rel="manifest"]').getAttribute("href");
  expect(manifestHref).toBe("/manifest.json");

  const response = await page.request.get(new URL(manifestHref!, PROD_ORIGIN).toString());
  expect(response.status()).toBe(200);
  const manifest = await response.json() as {
    name?: string;
    short_name?: string;
    start_url?: string;
    display?: string;
    icons?: Array<{ src?: string; sizes?: string; type?: string }>;
  };
  expect(manifest.name).toBeTruthy();
  expect(manifest.short_name).toBeTruthy();
  expect(manifest.start_url).toBe("/");
  expect(manifest.display).toBe("standalone");
  expect(manifest.icons?.length ?? 0).toBeGreaterThan(0);

  // Every declared icon must actually be served by the production build,
  // not just referenced -- a broken icon path fails PWA installability
  // checks silently in real browsers. Assert src is non-empty first: a
  // blank fallback would resolve to the origin root, which trivially 200s
  // via index.html and would mask a malformed manifest entry.
  for (const icon of manifest.icons ?? []) {
    expect(icon.src, `manifest icon entry ${JSON.stringify(icon)} must declare a src`).toBeTruthy();
    const iconResponse = await page.request.get(new URL(icon.src!, PROD_ORIGIN).toString());
    expect(iconResponse.status(), `manifest icon ${icon.src} must be served`).toBe(200);
  }
});
