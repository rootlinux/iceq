import { defineConfig, devices } from "@playwright/test";

const baseURL = process.env.ICEQ_LIVE_BASE_URL ?? "https://localhost:8443";

export default defineConfig({
  testDir: "./e2e",
  testMatch: "live-messaging.spec.ts",
  fullyParallel: false,
  workers: 1,
  forbidOnly: true,
  retries: 0,
  reporter: [["list"], ["html", { outputFolder: "/tmp/playwright-live-messaging-report" }]],
  timeout: 300_000,
  use: {
    baseURL,
    ignoreHTTPSErrors: true,
    actionTimeout: 30_000,
    trace: "retain-on-failure",
  },
  projects: [
    {
      name: "chromium-live-messaging",
      use: {
        ...devices["Desktop Chrome"],
        launchOptions: { args: ["--ignore-certificate-errors"] },
      },
    },
  ],
});
