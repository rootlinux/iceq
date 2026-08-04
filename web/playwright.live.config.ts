import { defineConfig, devices } from "@playwright/test";

const baseURL = process.env.ICEQ_LIVE_BASE_URL ?? "https://localhost:8443";

export default defineConfig({
  testDir: "./e2e",
  testMatch: "live-panic-wipe.spec.ts",
  // The live suite shares the rehearsal edge-rate limiter and destructive
  // backend stores. Run one disposable account at a time so the harness tests
  // product behavior rather than racing the intentional anonymous abuse limit.
  fullyParallel: false,
  workers: 1,
  forbidOnly: true,
  retries: 0,
  reporter: [["list"], ["html", { outputFolder: "/tmp/playwright-live-report" }]],
  timeout: 180_000,
  use: {
    baseURL,
    ignoreHTTPSErrors: true,
    trace: "retain-on-failure",
  },
  projects: [
    {
      name: "chromium-live",
      use: {
        ...devices["Desktop Chrome"],
        // Playwright's ignoreHTTPSErrors covers page requests, but Chromium's
        // service-worker loader applies its own certificate validation. The
        // rehearsal listener deliberately uses Caddy's disposable local CA.
        launchOptions: { args: ["--ignore-certificate-errors"] },
      },
    },
    { name: "webkit-live", use: { ...devices["Desktop Safari"] } },
  ],
});
