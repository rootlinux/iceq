import { expect, type Page, type Request, type Route } from "@playwright/test";

export const SYNTHETIC_USER = {
  uin: 700000001,
  username: "synthetic_alice",
  password: "synthetic-password-123",
  accessToken: "synthetic.access.token",
  refreshToken: "synthetic-refresh-token",
};

const FORBIDDEN_BODY_FIELDS = ["privateKey", "access_token", "refresh_token"] as const;

export interface SyntheticNetwork {
  requestBodies: Array<{ url: string; body: string }>;
}

function json(route: Route, body: unknown, status = 200): Promise<void> {
  return route.fulfill({
    status,
    contentType: "application/json",
    body: JSON.stringify(body),
  });
}

export async function installSyntheticAPI(page: Page): Promise<SyntheticNetwork> {
  const requestBodies: SyntheticNetwork["requestBodies"] = [];
  page.on("request", (request: Request) => {
    if (!new URL(request.url()).pathname.startsWith("/api/")) return;
    const body = request.postData();
    if (body !== null) requestBodies.push({ url: request.url(), body });
  });

  await page.route(/^https?:\/\/[^/]+\/api\//, async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    const path = url.pathname;

    if (path === "/api/auth/login" && request.method() === "POST") {
      return json(route, {
        user: { uin: SYNTHETIC_USER.uin, username: SYNTHETIC_USER.username },
        tokens: {
          access_token: SYNTHETIC_USER.accessToken,
          refresh_token: SYNTHETIC_USER.refreshToken,
        },
      });
    }
    if (path === "/api/auth/refresh") return json(route, { error: "no synthetic session" }, 401);
    if (path === "/api/auth/me") return json(route, { uin: SYNTHETIC_USER.uin, username: SYNTHETIC_USER.username });
    if (path === "/api/auth/logout") return json(route, {});
    if (path === "/api/contacts/") return json(route, { contacts: [] });
    if (path === "/api/groups/") return json(route, { groups: [] });
    if (path === `/api/keys/bundle/${SYNTHETIC_USER.uin}`) return json(route, { error: "no synthetic key bundle" }, 404);
    if (path === "/api/keys/prekeys/count") return json(route, { count: 20 });
    if (path === "/api/messages/poll") return json(route, { envelopes: [], cursor: null });
    return json(route, { error: "unhandled synthetic route" }, 404);
  });
  return { requestBodies };
}

export async function authenticateSynthetic(page: Page): Promise<SyntheticNetwork> {
  const network = await installSyntheticAPI(page);
  await page.goto("/login");
  await page.evaluate(async (user) => {
    const { useAuthStore } = await import("/src/store/authStore.ts");
    await useAuthStore.getState().setSession(
      { uin: user.uin, username: user.username },
      user.accessToken,
      user.refreshToken,
    );
  }, SYNTHETIC_USER);
  await expect(page).toHaveURL(/\/app(?:\/|$)/);
  await expect(page.getByText(SYNTHETIC_USER.username, { exact: false })).toBeVisible();
  return network;
}

export async function assertNoSensitiveBody(page: Page, network?: SyntheticNetwork): Promise<void> {
  const html = await page.locator("body").evaluate((body) => body.innerHTML);
  for (const field of FORBIDDEN_BODY_FIELDS) {
    expect(html, `rendered body must not expose ${field}`).not.toContain(field);
  }
  for (const request of network?.requestBodies ?? []) {
    for (const field of FORBIDDEN_BODY_FIELDS) {
      expect(request.body, `${request.url} request body must not contain ${field}`).not.toContain(field);
    }
  }
}

export async function dispatchInstallPrompt(
  page: Page,
  outcome: "accepted" | "dismissed" = "accepted",
): Promise<void> {
  await page.evaluate((choice) => {
    const event = new Event("beforeinstallprompt", { cancelable: true });
    Object.defineProperties(event, {
      prompt: {
        value: async () => {
          (window as typeof window & { __iceqPromptCalled?: boolean }).__iceqPromptCalled = true;
        },
      },
      userChoice: { value: Promise.resolve({ outcome: choice }) },
    });
    window.dispatchEvent(event);
  }, outcome);
}
