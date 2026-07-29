import { expect, test, type Page } from "@playwright/test";
import { assertHermeticNetwork, authenticateSynthetic, type SyntheticUser } from "./helpers";

// contact-notifications.spec.ts covers the sidebar's reaction to an
// injected envelope within a single browser context. This test drives the
// full chain across two independently authenticated contexts: A sends a
// real request through the real UI and real API call, B sees it live, B
// accepts through the real UI and real API call, and A sees the
// acceptance live -- plus duplicate prevention and reload reconciliation.
//
// There is no real backend in this synthetic harness (see helpers.ts):
// each page's synthetic API is its own closure-scoped simulation with no
// state shared between contexts. seedIncomingContactRequest/
// seedContactAccepted below play the part a real server would -- relaying
// the *result* of one context's real mutation into the other context's
// local state and live poll queue, exactly like contact-notifications.spec.ts's
// proven injected-envelope mechanism.

test.use({ serviceWorkers: "block" });

const USER_A: SyntheticUser = {
  uin: 700000201,
  username: "synthetic_alice_two_ctx",
  accessToken: "synthetic.access.token.two-ctx-a",
  refreshToken: "synthetic-refresh-token-two-ctx-a",
};
const USER_B: SyntheticUser = {
  uin: 700000202,
  username: "synthetic_bob_two_ctx",
  accessToken: "synthetic.access.token.two-ctx-b",
  refreshToken: "synthetic-refresh-token-two-ctx-b",
};

async function seedIncomingContactRequest(page: Page, fromUser: SyntheticUser): Promise<void> {
  await page.evaluate(({ uin, username }) => {
    const contacts = JSON.parse(localStorage.getItem("__iceq_e2e_contacts") ?? "[]") as Array<Record<string, unknown>>;
    contacts.push({ uin, username, avatar_url: "", status: "pending", direction: "incoming" });
    localStorage.setItem("__iceq_e2e_contacts", JSON.stringify(contacts));
    const emit = (window as typeof window & { __iceqE2EQueuePollEnvelope?: (envelope: unknown) => void }).__iceqE2EQueuePollEnvelope;
    emit?.({
      type: "notification",
      id: `contact-request-${uin}`,
      ts: Date.now(),
      payload: { kind: "contact_request", title: "Contact request", body: `${username} sent a request` },
    });
  }, { uin: fromUser.uin, username: fromUser.username });
}

async function seedContactAccepted(page: Page, byUser: SyntheticUser): Promise<void> {
  await page.evaluate(({ uin, username }) => {
    const contacts = JSON.parse(localStorage.getItem("__iceq_e2e_contacts") ?? "[]") as Array<{ uin: number } & Record<string, unknown>>;
    const index = contacts.findIndex((c) => c.uin === uin);
    const updated = { uin, username, avatar_url: "", status: "accepted", direction: "" };
    if (index === -1) contacts.push(updated); else contacts[index] = updated;
    localStorage.setItem("__iceq_e2e_contacts", JSON.stringify(contacts));
    const emit = (window as typeof window & { __iceqE2EQueuePollEnvelope?: (envelope: unknown) => void }).__iceqE2EQueuePollEnvelope;
    emit?.({
      type: "notification",
      id: `contact-accepted-${uin}`,
      ts: Date.now(),
      payload: { kind: "contact_accepted", title: "Contact accepted", body: `${username} accepted your request` },
    });
  }, { uin: byUser.uin, username: byUser.username });
}

// Mobile projects collapse the sidebar (where the contact list and "Add
// contact" button live) behind a hamburger toggle; webkit-ios additionally
// shows a one-time dismissible prompt first. Mirrors contact-notifications.spec.ts.
async function revealSidebarOnMobile(page: Page, projectName: string): Promise<void> {
  if (projectName === "webkit-ios") {
    // Only shown once per fresh load; a reload after it's already been
    // dismissed won't show it again, so this must not block on it.
    await page.getByRole("button", { name: "Got it" }).click({ timeout: 2000 }).catch(() => {});
  }
  if (projectName.endsWith("android") || projectName.endsWith("ios")) {
    await page.getByRole("button", { name: "Toggle menu" }).click();
  }
}

test("a contact request and its acceptance propagate live across two independently authenticated contexts", async ({ browser }, testInfo) => {
  const contextA = await browser.newContext();
  const contextB = await browser.newContext();
  try {
    const pageA = await contextA.newPage();
    const pageB = await contextB.newPage();
    const networkA = await authenticateSynthetic(pageA, USER_A, [USER_A, USER_B]);
    const networkB = await authenticateSynthetic(pageB, USER_B, [USER_A, USER_B]);
    await revealSidebarOnMobile(pageA, testInfo.project.name);
    await revealSidebarOnMobile(pageB, testInfo.project.name);

    // --- A sends a real contact request to B -------------------------------
    await pageA.getByRole("button", { name: "Add contact" }).click();
    await pageA.getByLabel("UIN").fill(String(USER_B.uin));
    await pageA.getByRole("button", { name: "Send request" }).click();
    await expect(pageA.getByRole("status")).toContainText("Contact request sent");
    await expect(pageA.getByRole("region", { name: "Outgoing contact requests" })).toContainText(USER_B.username);

    // --- B sees it live, no reload ------------------------------------------
    await seedIncomingContactRequest(pageB, USER_A);
    await expect(pageB.getByRole("region", { name: "Incoming contact requests" })).toContainText(USER_A.username);
    await expect(pageB.getByRole("button", { name: "Accept" })).toBeVisible();

    // --- Duplicate prevention: A tries to re-add B before B has accepted ---
    // The dialog is still open from the first submission (AddContact.tsx
    // does not auto-close on success), so it's reused directly here.
    await pageA.getByLabel("UIN").fill(String(USER_B.uin));
    await pageA.getByRole("button", { name: "Send request" }).click();
    await expect(pageA.getByRole("alert")).toContainText("Already added");
    await pageA.getByRole("button", { name: "Close add contact" }).click();
    await expect(pageA.getByRole("region", { name: "Outgoing contact requests" })).toContainText("Sent requests · 1");

    // --- B accepts through the real UI + real API call ---------------------
    await pageB.getByRole("button", { name: "Accept" }).click();
    await expect(pageB.getByRole("region", { name: "Contacts" })).toContainText(USER_A.username);
    await expect(pageB.getByRole("button", { name: "Accept" })).toHaveCount(0);
    await expect(pageB.getByRole("region", { name: "Incoming contact requests" })).toHaveCount(0);

    // --- A sees the acceptance live, no reload ------------------------------
    await seedContactAccepted(pageA, USER_B);
    await expect(pageA.getByRole("region", { name: "Contacts" })).toContainText(USER_B.username);
    await expect(pageA.getByRole("region", { name: "Outgoing contact requests" })).toHaveCount(0);

    // --- Reconnection/reconciliation: reload both, state survives ----------
    // The synthetic GET is backed by localStorage (not the poll-queue
    // closure state, which resets on navigation), so this proves the
    // accepted state is durable rather than a transient in-memory artifact.
    await pageA.reload();
    await expect(pageA.getByText(USER_A.username, { exact: false })).toBeVisible();
    await revealSidebarOnMobile(pageA, testInfo.project.name);
    await expect(pageA.getByRole("region", { name: "Contacts" })).toContainText(USER_B.username);

    await pageB.reload();
    await expect(pageB.getByText(USER_B.username, { exact: false })).toBeVisible();
    await revealSidebarOnMobile(pageB, testInfo.project.name);
    await expect(pageB.getByRole("region", { name: "Contacts" })).toContainText(USER_A.username);

    await assertHermeticNetwork(pageA, networkA);
    await assertHermeticNetwork(pageB, networkB);
  } finally {
    await contextA.close();
    await contextB.close();
  }
});
