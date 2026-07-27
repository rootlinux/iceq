import { expect, test } from "@playwright/test";
import { assertHermeticNetwork, authenticateSynthetic } from "./helpers";

test.use({ serviceWorkers: "block" });

test("contact request and acceptance notifications update the sidebar without a reload", async ({ page }, testInfo) => {
  const network = await authenticateSynthetic(page);
  if (testInfo.project.name === "webkit-ios") {
    await page.getByRole("button", { name: "Got it" }).click();
  }
  if (testInfo.project.name.endsWith("android") || testInfo.project.name.endsWith("ios")) {
    await page.getByRole("button", { name: "Toggle menu" }).click();
  }
  await expect(page.getByText("No contacts yet", { exact: false })).toBeVisible();

  await page.evaluate(() => {
    localStorage.setItem("__iceq_e2e_contacts", JSON.stringify([{ 
      uin: 700000099,
      username: "incoming_friend",
      avatar_url: "",
      status: "pending",
      direction: "incoming",
    }]));
    const emit = (window as typeof window & { __iceqE2EQueuePollEnvelope?: (envelope: unknown) => void }).__iceqE2EQueuePollEnvelope;
    emit?.({
      type: "notification",
      id: "contact-request-notification-1",
      ts: Date.now(),
      payload: { kind: "contact_request", title: "Contact request", body: "New request" },
    });
  });

  await expect(page.getByRole("region", { name: "Incoming contact requests" })).toContainText("incoming_friend");
  await expect(page.getByRole("button", { name: "Accept" })).toBeVisible();

  await page.evaluate(() => {
    localStorage.setItem("__iceq_e2e_contacts", JSON.stringify([{ 
      uin: 700000099,
      username: "incoming_friend",
      avatar_url: "",
      status: "accepted",
      direction: "",
    }]));
    const emit = (window as typeof window & { __iceqE2EQueuePollEnvelope?: (envelope: unknown) => void }).__iceqE2EQueuePollEnvelope;
    emit?.({
      type: "notification",
      id: "contact-accepted-notification-1",
      ts: Date.now(),
      payload: { kind: "contact_accepted", title: "Contact accepted", body: "Request accepted" },
    });
  });

  await expect(page.getByRole("region", { name: "Contacts" })).toContainText("incoming_friend");
  await expect(page.getByRole("button", { name: "Accept" })).toHaveCount(0);
  await assertHermeticNetwork(page, network);
});
