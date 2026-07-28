import { expect, test } from "@playwright/test";
import { assertNoSensitiveBody, authenticateSynthetic } from "./helpers";

// The service-worker registration/caching test lives in
// e2e/production/service-worker.spec.ts, run via playwright.sw.config.ts
// against a real production build -- see that file's header comment for
// why it can't run here against the Vite dev server.

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
