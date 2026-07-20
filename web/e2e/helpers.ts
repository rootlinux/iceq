import { expect, type Page, type Request } from "@playwright/test";

export interface SyntheticUser {
  uin: number;
  username: string;
  accessToken: string;
  refreshToken: string;
}

export const SYNTHETIC_USER: SyntheticUser = {
  uin: 700000001,
  username: "synthetic_alice",
  accessToken: "synthetic.access.token",
  refreshToken: "synthetic-refresh-token",
};

const FORBIDDEN_BODY_FIELDS = ["privateKey", "access_token", "refresh_token"] as const;
const PUBLIC_DIRECTORY_KEY = "__iceq_e2e_public_directory";

export interface SyntheticDirectoryEntry {
  identity_key: string;
  signed_pre_key: { id: number; public_key: string; signature: string };
  pre_key?: { id: number; public_key: string };
  registration_id: number;
}
interface BrowserNetworkEvidence {
  apiAttempts: Array<{ path: string; method: string; body: string; handled: boolean }>;
  websocketAttempts: Array<{ url: string; handled: boolean }>;
  unhandled: string[];
}

export interface SyntheticNetwork {
  requestBodies: Array<{ url: string; body: string }>;
  externalRequests: string[];
  externalFailures: string[];
}

declare global {
  interface Window {
    __iceqE2ENetwork: BrowserNetworkEvidence;
    __iceqE2ENativeFetch: typeof fetch;
  }
}

function isProductionTraffic(request: Request): boolean {
  const url = new URL(request.url());
  return url.pathname === "/api" || url.pathname.startsWith("/api/") || url.pathname === "/ws" || url.pathname.startsWith("/ws/");
}

export async function installSyntheticAPI(
  page: Page,
  users: SyntheticUser[] = [SYNTHETIC_USER],
): Promise<SyntheticNetwork> {
  const network: SyntheticNetwork = { requestBodies: [], externalRequests: [], externalFailures: [] };
  page.on("request", (request) => {
    if (!isProductionTraffic(request)) return;
    const path = new URL(request.url()).pathname;
    network.externalRequests.push(`${request.method()} ${path}`);
    const body = request.postData();
    if (body !== null) network.requestBodies.push({ url: request.url(), body });
  });
  page.on("requestfailed", (request) => {
    if (isProductionTraffic(request)) network.externalFailures.push(`${request.method()} ${request.url()}`);
  });

  await page.addInitScript((syntheticUsers) => {
    const evidence: BrowserNetworkEvidence = { apiAttempts: [], websocketAttempts: [], unhandled: [] };
    window.__iceqE2ENetwork = evidence;
    const nativeFetch = window.fetch.bind(window);
    window.__iceqE2ENativeFetch = nativeFetch;

    const respondJSON = (body: unknown, status = 200): Response => new Response(JSON.stringify(body), {
      status,
      headers: { "Content-Type": "application/json" },
    });

    window.fetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const request = new Request(input, init);
      const url = new URL(request.url, window.location.href);
      const isAPI = url.pathname === "/api" || url.pathname.startsWith("/api/");
      const isWS = url.pathname === "/ws" || url.pathname.startsWith("/ws/");
      if (!isAPI && !isWS) return nativeFetch(input, init);

      const body = request.method === "GET" || request.method === "HEAD" ? "" : await request.clone().text();
      const attempt = { path: url.pathname, method: request.method, body, handled: true };
      evidence.apiAttempts.push(attempt);

      if (isWS) {
        attempt.handled = false;
        evidence.unhandled.push(`${request.method} ${url.pathname}`);
        return respondJSON({ error: "unhandled synthetic WebSocket HTTP route" }, 599);
      }

      if (url.pathname === "/api/auth/login" && request.method === "POST") {
        const username = (JSON.parse(body || "{}") as { username?: string }).username;
        const user = syntheticUsers.find((candidate) => candidate.username === username) ?? syntheticUsers[0];
        return respondJSON({
          user: { uin: user.uin, username: user.username },
          tokens: { access_token: user.accessToken, refresh_token: user.refreshToken },
        });
      }
      if (url.pathname === "/api/auth/refresh") return respondJSON({ error: "no synthetic session" }, 401);
      if (url.pathname === "/api/auth/me") {
        const remembered = Number(localStorage.getItem("iceq_account_uin"));
        const user = syntheticUsers.find((candidate) => candidate.uin === remembered) ?? syntheticUsers[0];
        return respondJSON({ uin: user.uin, username: user.username });
      }
      if (url.pathname === "/api/auth/logout") return respondJSON({});
      if (url.pathname === "/api/contacts/" && request.method === "GET") return respondJSON({ contacts: [] });
      if (url.pathname === "/api/groups/" && request.method === "GET") return respondJSON({ groups: [] });
      if (/^\/api\/keys\/bundle\/\d+$/.test(url.pathname) && request.method === "GET") {
        const uin = url.pathname.split("/").at(-1) ?? "";
        const directory = JSON.parse(localStorage.getItem("__iceq_e2e_public_directory") ?? "{}") as Record<string, SyntheticDirectoryEntry>;
        const entry = directory[uin];
        if (entry) return respondJSON(entry);
        return respondJSON({ error: "no synthetic key bundle" }, 404);
      }
      if (url.pathname === "/api/keys/bundle" && request.method === "POST") return respondJSON({});
      if (url.pathname === "/api/keys/prekeys/count" && request.method === "GET") return respondJSON({ count: 20 });
      if (url.pathname === "/api/transport/poll" && request.method === "GET") {
        return new Promise<Response>((_resolve, reject) => {
          request.signal.addEventListener("abort", () => reject(new DOMException("Aborted", "AbortError")), { once: true });
        });
      }

      attempt.handled = false;
      evidence.unhandled.push(`${request.method} ${url.pathname}`);
      return respondJSON({ error: "unhandled synthetic route" }, 599);
    };

    class SyntheticWebSocket extends EventTarget {
      static readonly CONNECTING = 0;
      static readonly OPEN = 1;
      static readonly CLOSING = 2;
      static readonly CLOSED = 3;
      readonly CONNECTING = 0;
      readonly OPEN = 1;
      readonly CLOSING = 2;
      readonly CLOSED = 3;
      readonly url: string;
      readonly protocol = "";
      readonly extensions = "";
      readonly bufferedAmount = 0;
      readonly binaryType = "blob";
      readyState = SyntheticWebSocket.CONNECTING;
      onopen: ((event: Event) => void) | null = null;
      onmessage: ((event: MessageEvent) => void) | null = null;
      onerror: ((event: Event) => void) | null = null;
      onclose: ((event: CloseEvent) => void) | null = null;

      constructor(url: string | URL) {
        super();
        this.url = String(url);
        const target = new URL(this.url, window.location.href);
        const sameOrigin = target.origin === window.location.origin.replace(/^http/, "ws");
        const viteHMR = sameOrigin && target.pathname === "/" && target.searchParams.has("token");
        if (viteHMR) return;
        const handled = sameOrigin && target.pathname === "/ws";
        evidence.websocketAttempts.push({ url: this.url, handled });
        if (!handled) evidence.unhandled.push(`WEBSOCKET ${target.href}`);
      }

      send(): void { /* the synthetic socket intentionally never opens */ }
      close(code = 1000, reason = "synthetic close"): void {
        if (this.readyState === SyntheticWebSocket.CLOSED) return;
        this.readyState = SyntheticWebSocket.CLOSED;
        const event = new CloseEvent("close", { code, reason, wasClean: true });
        this.onclose?.(event);
        this.dispatchEvent(event);
      }
    }

    Object.defineProperty(window, "WebSocket", { configurable: true, writable: true, value: SyntheticWebSocket });
  }, users);

  return network;
}

export async function publishSyntheticDirectory(
  page: Page,
  uin: number,
  entry: SyntheticDirectoryEntry,
): Promise<void> {
  await page.evaluate(({ key, accountUin, directoryEntry }) => {
    const directory = JSON.parse(localStorage.getItem(key) ?? "{}") as Record<string, SyntheticDirectoryEntry>;
    directory[String(accountUin)] = directoryEntry;
    localStorage.setItem(key, JSON.stringify(directory));
  }, { key: PUBLIC_DIRECTORY_KEY, accountUin: uin, directoryEntry: entry });
}

export async function seedSyntheticIdentity(page: Page, user: SyntheticUser): Promise<void> {
  const seeded = await page.evaluate(async (account) => {
    const idb = await import("/src/lib/indexeddb.ts");
    const signal = await import("/src/lib/signal.ts");
    const namespace = { uin: account.uin, deviceId: await idb.loadOrCreateDeviceId() };
    const identity = await signal.generateIdentityKeyPair();
    const registrationId = signal.generateRegistrationId();
    await signal.saveOwnIdentity(identity, registrationId, namespace);
    const bundle = await signal.generatePreKeyBundle(identity, 1, 1, registrationId, namespace);
    return {
      identity_key: bundle.identity_key,
      signed_pre_key: bundle.signed_pre_key,
      pre_key: bundle.one_time_pre_keys[0],
      registration_id: bundle.registration_id,
    };
  }, user);
  await publishSyntheticDirectory(page, user.uin, seeded);
}

export async function assertSignalHealthy(page: Page): Promise<void> {
  await expect.poll(() => page.evaluate(async () => (
    await import("/src/store/signalStore.ts")
  ).useSignalStore.getState().ready)).toBe(true);
  await expect(page.getByRole("alert"), "authenticated synthetic shell must not surface bootstrap errors").toHaveCount(0);
}

export async function authenticateSynthetic(page: Page): Promise<SyntheticNetwork> {
  const network = await installSyntheticAPI(page);
  await page.goto("/login");
  await expect(page.getByRole("heading", { name: "Sign in to IceQ" })).toBeVisible();
  await seedSyntheticIdentity(page, SYNTHETIC_USER);
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
  await assertSignalHealthy(page);
  return network;
}

export async function assertHermeticNetwork(page: Page, network: SyntheticNetwork): Promise<void> {
  const evidence = await page.evaluate(() => window.__iceqE2ENetwork);
  expect(evidence.unhandled, "every production API attempt must match the synthetic allowlist").toEqual([]);
  expect(evidence.apiAttempts.length, "the app must exercise the synthetic API boundary").toBeGreaterThan(0);
  expect(evidence.apiAttempts.every((attempt) => attempt.handled)).toBe(true);
  expect(evidence.websocketAttempts.every((attempt) => attempt.handled)).toBe(true);
  expect(
    network.externalFailures.filter((entry) => !["/api/e2e-cache-probe", "/ws/e2e-cache-probe"].some((path) => entry.endsWith(path))),
    "no non-probe production API or WebSocket request may fail outside the harness",
  ).toEqual([]);
  expect(
    network.externalRequests.filter((entry) => !["GET /api/e2e-cache-probe", "GET /ws/e2e-cache-probe"].includes(entry)),
    "only explicit cache probes may reach the e2e loopback sink",
  ).toEqual([]);
}

export async function nativeCacheProbe(page: Page, paths: string[]): Promise<number[]> {
  return page.evaluate(async (probePaths) => Promise.all(probePaths.map(async (path) => {
    try {
      const response = await window.__iceqE2ENativeFetch(path, { headers: { "X-IceQ-E2E-Cache-Probe": "1" } });
      return response.status;
    } catch {
      return 0;
    }
  })), paths);
}

export async function assertNoSensitiveBody(page: Page, network?: SyntheticNetwork): Promise<void> {
  const html = await page.locator("body").evaluate((body) => body.innerHTML);
  const evidence = await page.evaluate(() => window.__iceqE2ENetwork);
  for (const field of FORBIDDEN_BODY_FIELDS) {
    expect(html, `rendered body must not expose ${field}`).not.toContain(field);
  }
  for (const request of evidence.apiAttempts) {
    for (const field of FORBIDDEN_BODY_FIELDS) {
      expect(request.body, `${request.method} ${request.path} body must not contain ${field}`).not.toContain(field);
    }
  }
  for (const request of network?.requestBodies ?? []) {
    for (const field of FORBIDDEN_BODY_FIELDS) {
      expect(request.body, `${request.url} request body must not contain ${field}`).not.toContain(field);
    }
  }
  if (network) await assertHermeticNetwork(page, network);
  if (/\/app(?:\/|$)/.test(new URL(page.url()).pathname)) await assertSignalHealthy(page);
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
