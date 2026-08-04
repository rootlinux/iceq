import { defineConfig, devices } from "@playwright/test";

const baseURL = "http://127.0.0.1:4173";

export default defineConfig({
  testDir: "./e2e",
  // e2e/production/ needs a real production build (vite build + vite
  // preview), not this config's dev-server webServer -- see
  // playwright.sw.config.ts, run via `npm run test:e2e:sw`.
  testIgnore: ["**/production/**", "**/live-panic-wipe.spec.ts", "**/live-messaging.spec.ts"],
  fullyParallel: false,
  forbidOnly: Boolean(process.env.CI),
  retries: process.env.CI ? 1 : 0,
  reporter: [["list"]],
  use: {
    baseURL,
    trace: "retain-on-failure",
  },
  webServer: {
    command: "npm run dev -- --host 127.0.0.1 --port 4173",
    env: { ICEQ_E2E: "1" },
    url: baseURL,
    reuseExistingServer: false,
  },
  projects: [
    { name: "chromium-desktop", use: { ...devices["Desktop Chrome"] } },
    { name: "chromium-android", use: { ...devices["Pixel 7"] } },
    { name: "webkit-desktop", use: { ...devices["Desktop Safari"] } },
    { name: "webkit-ios", use: { ...devices["iPhone 15"] } },
  ],
});
