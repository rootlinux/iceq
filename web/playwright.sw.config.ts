import { defineConfig, devices } from "@playwright/test";

// Dedicated config for the service-worker E2E test, which needs the real
// production build: main.tsx only registers a service worker when
// !__DEV__ (true only under `vite build`/`vite preview`, never `vite
// dev`), and public/sw.js's caching only matches Vite's fingerprinted
// production asset filenames. See e2e/production/service-worker.spec.ts
// for the full explanation. Runs on a different port from
// playwright.config.ts's dev-server suite (4174 vs 4173) so the two can
// coexist without a port collision if ever run back to back.
//
// Usage: npm run test:e2e:sw
const baseURL = "http://127.0.0.1:4174";

export default defineConfig({
  testDir: "./e2e/production",
  fullyParallel: false,
  forbidOnly: Boolean(process.env.CI),
  retries: process.env.CI ? 1 : 0,
  reporter: [["list"]],
  use: {
    baseURL,
    trace: "retain-on-failure",
  },
  webServer: {
    // Build first so the worker under test is always the actual current
    // source, not a stale dist/ left over from an earlier run.
    // --strictPort: fail loudly on a port conflict instead of silently
    // binding elsewhere, which would desync from the hardcoded baseURL.
    command: "npm run build && npm run preview -- --host 127.0.0.1 --port 4174 --strictPort",
    env: { ICEQ_E2E: "1" },
    url: baseURL,
    reuseExistingServer: false,
    timeout: 120_000,
  },
  projects: [
    { name: "chromium-desktop", use: { ...devices["Desktop Chrome"] } },
    { name: "chromium-android", use: { ...devices["Pixel 7"] } },
    { name: "webkit-desktop", use: { ...devices["Desktop Safari"] } },
    { name: "webkit-ios", use: { ...devices["iPhone 15"] } },
  ],
});
