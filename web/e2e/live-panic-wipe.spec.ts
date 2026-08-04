/**
 * Real-browser E2E: Panic Wipe against the live Docker stack.
 */

import { test, expect, type Page, type Request } from "@playwright/test";

type LivePhase = "bootstrap" | "registration" | "setup" | "app" | "reload" | "unlock" | "wipe" | "post-wipe-relogin";

interface ObservedResponse {
  requestId: number;
  method: string;
  path: string;
  phase: LivePhase;
  status: number;
}

interface LiveDiagnostics {
  applicationErrors: string[];
  failedRequests: ObservedRequestFailure[];
  responses: ObservedResponse[];
}

interface ObservedRequestFailure {
  requestId: number;
  error: string;
  method: string;
  path: string;
  phase: LivePhase;
}

let userCounter = 0;

function nextUser(): { username: string; password: string } {
  userCounter += 1;
  const ts = Date.now().toString(36);
  return {
    username: `e2e${ts}${userCounter}`,
    password: `LivePass1!`,
  };
}

const PASSPHRASE = "BrowserE2ESecurityPhrase1!";
const PANIC_PIN = "4937";
type WipeMode = "pin" | "passphrase";

interface LocalResidue {
  iceqStorageKeys: string[];
  databases: string[];
  cacheNames: string[];
  workerScripts: string[];
}

async function readLocalResidue(page: Page): Promise<LocalResidue> {
  return page.evaluate(async () => {
    const iceqStorageKeys = Object.keys(localStorage)
      .filter((key) => /^(?:iceq_|iceq:|iceq-)/.test(key))
      .sort();
    const databases = indexedDB.databases
      ? (await indexedDB.databases()).flatMap((db) => db.name?.startsWith("iceq") ? [db.name] : []).sort()
      : [];
    const cacheNames = (await caches.keys()).filter((name) => name.startsWith("iceq-static-")).sort();
    const workerScripts = (await navigator.serviceWorker.getRegistrations())
      .flatMap((registration) => {
        const script = registration.active?.scriptURL ?? registration.waiting?.scriptURL ?? registration.installing?.scriptURL;
        return script && new URL(script).pathname === "/sw.js" ? [script] : [];
      })
      .sort();
    return { iceqStorageKeys, databases, cacheNames, workerScripts };
  });
}

async function readMetadataKeys(page: Page): Promise<string[]> {
  return page.evaluate(async () => new Promise<string[]>((resolve, reject) => {
    const open = indexedDB.open("iceq");
    open.onerror = () => reject(open.error ?? new Error("could not open IceQ IndexedDB"));
    open.onsuccess = () => {
      const db = open.result;
      const tx = db.transaction("metadata", "readonly");
      const request = tx.objectStore("metadata").getAllKeys();
      request.onerror = () => { db.close(); reject(request.error ?? new Error("could not read IceQ metadata")); };
      request.onsuccess = () => { db.close(); resolve(request.result.map(String)); };
    };
  }));
}

function collectDiagnostics(page: Page, currentPhase: () => LivePhase): LiveDiagnostics {
  const diagnostics: LiveDiagnostics = { applicationErrors: [], failedRequests: [], responses: [] };
  const requestIds = new WeakMap<Request, number>();
  let nextRequestId = 0;
  const requestId = (request: Request): number => {
    const existing = requestIds.get(request);
    if (existing !== undefined) return existing;
    nextRequestId += 1;
    requestIds.set(request, nextRequestId);
    return nextRequestId;
  };
  page.on("pageerror", (err) => diagnostics.applicationErrors.push(`pageerror: ${err.message}`));
  page.on("console", (msg) => {
    if (msg.type() !== "error") return;
    // Browsers report every non-2xx response as a generic console error. The
    // response listener below audits those by method, path, phase and status;
    // keep this channel for CSP, WASM and JavaScript/runtime failures.
    if (msg.text().startsWith("Failed to load resource:")) return;
    diagnostics.applicationErrors.push(`console-error: ${msg.text()}`);
  });
  page.on("requestfailed", (request) => {
    diagnostics.failedRequests.push({
      requestId: requestId(request),
      error: request.failure()?.errorText ?? "unknown",
      method: request.method(),
      path: new URL(request.url()).pathname,
      phase: currentPhase(),
    });
  });
  page.on("response", (response) => {
    const request = response.request();
    diagnostics.responses.push({
      requestId: requestId(request),
      method: request.method(),
      path: new URL(response.url()).pathname,
      phase: currentPhase(),
      status: response.status(),
    });
  });
  return diagnostics;
}

function isExpectedNavigationCancellation(failure: ObservedRequestFailure): boolean {
  if (!/(?:ERR_ABORTED|cancelled)$/i.test(failure.error)) return false;
  // Long polling is intentionally replaced/cancelled throughout the app
  // lifecycle. This read-only transport request carries no security state.
  if (failure.method === "GET" && failure.path === "/api/transport/poll") return true;
  if (failure.phase !== "reload" && failure.phase !== "wipe") return false;
  if (failure.method === "GET" && (failure.path === "/api/groups/" || failure.path === "/api/contacts/")) return true;
  return failure.method === "GET" && /^\/api\/keys\/bundle\/\d+$/.test(failure.path);
}

function isCompletedNoContentResponse(
  failure: ObservedRequestFailure,
  responses: ObservedResponse[],
): boolean {
  if (!/(?:ERR_ABORTED|cancelled)$/i.test(failure.error)) return false;

  // Chromium can emit requestfailed after it has already received a complete
  // 204 response with no body. Never accept a failed security write merely by
  // route: require the exact method, lifecycle phase and recorded 204 response
  // for the same operation. This preserves the negative signal for genuine
  // upload/enrollment failures.
  const expectedMethod = failure.path === "/api/keys/bundle"
    ? "POST"
    : failure.path === "/api/auth/panic-wipe-public-key" || failure.path === "/api/auth/panic-pin"
      ? "PUT"
      : null;
  const expectedPhase = failure.path === "/api/keys/bundle"
    ? "registration"
    : failure.path === "/api/auth/panic-wipe-public-key"
      ? "setup"
      : failure.path === "/api/auth/panic-pin"
        ? "wipe"
      : null;
  if (expectedMethod === null || failure.method !== expectedMethod || failure.phase !== expectedPhase) return false;

  return responses.some((response) =>
    response.requestId === failure.requestId &&
    response.status === 204 &&
    response.method === failure.method &&
    response.path === failure.path &&
    response.phase === failure.phase,
  );
}

function isExpectedNegativeControl(response: ObservedResponse): boolean {
  // Auth hydration may settle just after the SPA navigates from /login to
  // /register; both phases are still unauthenticated by definition.
  if (response.phase === "bootstrap" || response.phase === "registration") {
    const expectedMissingSession = (
      (response.method === "POST" && response.path === "/api/auth/refresh" && response.status === 422) ||
      (response.method === "GET" && response.path === "/api/auth/me" && response.status === 401) ||
      (response.method === "POST" && response.path === "/api/auth/logout" && response.status === 401)
    );
    if (expectedMissingSession) return true;
  }
  if ((response.phase === "registration" || response.phase === "setup") && response.method === "GET") {
    return /^\/api\/keys\/bundle\/\d+$/.test(response.path) && response.status === 404;
  }
  return (
    response.phase === "post-wipe-relogin" &&
    response.method === "POST" &&
    response.path === "/api/auth/login" &&
    response.status === 401
  );
}

function isExpectedWipeSocketShutdown(error: string): boolean {
  // Chromium reports the server-initiated 4403 close as a console error even
  // though the application receives the close event and completes the wipe
  // lifecycle successfully. Keep this exception exact: every other WebSocket,
  // CSP, WASM or runtime console error must still fail the live test.
  return error === "console-error: WebSocket connection to 'wss://localhost:8443/ws' failed: Close received after close";
}

test.describe("Live Panic Wipe real-browser E2E", () => {
  test("full PIN and passphrase panic-wipe coverage against real APIs", async ({ page, browser, browserName }) => {
    test.setTimeout(240_000);
    // Two real registrations are sufficient to cover both destructive
    // authorization paths without exceeding the intentional three-per-minute
    // anonymous registration limit shared by the rehearsal edge. Chromium
    // covers PIN+wipe-key coexistence; WebKit covers the local vault,
    // challenge-signature and strict CSP path.
    const wipeMode: WipeMode = browserName === "webkit" ? "passphrase" : "pin";
    let phase: LivePhase = "bootstrap";
    const diagnostics = collectDiagnostics(page, () => phase);
    const user = nextUser();

    // ── Step 1: Registration ────────────────────────────────────────
    await page.goto("/login", { waitUntil: "networkidle" });
    await expect
      .poll(
        () => page.evaluate(async () => Boolean((await navigator.serviceWorker.ready).active)),
        { message: `[${browserName}] the real service worker must become active`, timeout: 20_000 },
      )
      .toBe(true);
    await page.locator('a[href="/register"]').first().click();
    await expect(page).toHaveURL(/\/register/, { timeout: 15000 });

    phase = "registration";
    await page.locator("#register-username").fill(user.username);
    await page.locator("#register-password").fill(user.password);
    await page.getByRole("button", { name: /create account|register/i }).click();

    await expect(page).toHaveURL(/\/(setup|app)/, { timeout: 30000 });
    const afterReg = page.url();

    // ── Step 2: Security Setup ──────────────────────────────────────
    if (afterReg.includes("/setup")) {
      phase = "setup";
      const beginSetup = page.getByRole("button", { name: "Begin Setup" });
      const setupPassphrase = page.locator("#setup-passphrase");
      // Registration bootstrap can finish by remounting the setup route just
      // after the first click in WebKit. A real user can simply click again;
      // keep the live test faithful to that recoverable UI state without
      // weakening any security assertion or bypassing setup.
      for (let attempt = 0; attempt < 3 && !(await setupPassphrase.isVisible()); attempt += 1) {
        await beginSetup.click();
        await setupPassphrase.waitFor({ state: "visible", timeout: 5_000 }).catch(() => undefined);
      }
      await expect(setupPassphrase).toBeVisible({ timeout: 15_000 });
      await setupPassphrase.fill(PASSPHRASE);
      await page.locator("#setup-passphrase-confirm").fill(PASSPHRASE);
      await page.getByRole("button", { name: "Continue" }).click();
      await expect(page.getByRole("heading", { name: "Enable Panic Wipe" })).toBeVisible({ timeout: 15000 });
      const metadataKeysBeforeReload = await readMetadataKeys(page);
      const vaultKeysBeforeReload = metadataKeysBeforeReload.filter((key) => /security_vault(?:_salt)?$/.test(key));
      expect(vaultKeysBeforeReload, `vault records missing from metadata keys: ${metadataKeysBeforeReload.join(", ")}`).toHaveLength(2);

      // Reload while setup is incomplete. The persisted vault must require a
      // local-only unlock before wipe-key enrollment can continue.
      phase = "reload";
      await page.reload({ waitUntil: "networkidle" });
      const metadataKeysAfterReload = await readMetadataKeys(page);
      expect(metadataKeysAfterReload.filter((key) => /security_vault(?:_salt)?$/.test(key)), "reload must preserve the same vault records").toEqual(vaultKeysBeforeReload);
      const unlockInput = page.locator("#setup-unlock-passphrase");
      await expect(unlockInput).toBeVisible({ timeout: 15000 });
      phase = "unlock";
      const wrongPassphraseRequests: string[] = [];
      const recordWrongPassphraseRequest = (request: { method(): string; url(): string }): void => {
        wrongPassphraseRequests.push(`${request.method()} ${new URL(request.url()).pathname}`);
      };
      page.on("request", recordWrongPassphraseRequest);
      await unlockInput.fill("WrongPassphrase!!");
      await page.getByRole("button", { name: "Unlock Vault" }).click();
      await expect(page.getByText(/incorrect security passphrase/i)).toBeVisible({ timeout: 10000 });
      await expect(unlockInput).toBeVisible();
      page.off("request", recordWrongPassphraseRequest);
      expect(wrongPassphraseRequests, "wrong local passphrase must not leave the browser").toEqual([]);

      await unlockInput.fill(PASSPHRASE);
      await page.getByRole("button", { name: "Unlock Vault" }).click();
      await expect(page.getByRole("heading", { name: "Enable Panic Wipe" })).toBeVisible({ timeout: 15000 });
      phase = "setup";

      // Wipe key enrollment
      await page.locator("#setup-account-password").fill(user.password);
      await page.getByRole("button", { name: "Enable Panic Wipe" }).click();

      // Recovery package
      await page.getByRole("button", { name: "Generate Recovery Key & Package" }).click();
      await expect(page.getByRole("heading", { name: "Recovery Key & Package" })).toBeVisible({ timeout: 15000 });
      await page.getByRole("button", { name: "I Have Saved Both" }).click();
      // Check the confirmation checkbox
      await page.getByLabel(/I have saved my Recovery Key/).click();
      await page.getByRole("button", { name: "Complete Setup" }).click();
    }

    // ── Step 3: On /app ─────────────────────────────────────────────
    await expect(page).toHaveURL(/\/app/, { timeout: 20000 });
    phase = "app";

    // Open a second passive page in the same browser context. This proves that
    // the UI follows the shared local teardown to /login without requiring a
    // refresh, while the independent context below proves the server close.
    const passivePage = await page.context().newPage();
    const passiveDiagnostics = collectDiagnostics(passivePage, () => phase);
    await passivePage.goto("/app", { waitUntil: "networkidle" });
    await expect(passivePage).toHaveURL(/\/app/, { timeout: 15000 });
    await expect(passivePage.locator('main > header[data-connected="true"]')).toBeVisible({ timeout: 15000 });

    // A genuinely independent browser context does not share cookies,
    // localStorage, IndexedDB or cleanup events with the initiating page. Give
    // it the already-issued access token only long enough to authenticate a
    // passive WebSocket. Its observed close code therefore comes from the
    // server's per-UIN wipe broadcast, not cross-tab storage synchronization.
    const accessToken = await page.evaluate(() => localStorage.getItem("iceq_access_token"));
    expect(accessToken, "the authenticated page must hold an access token").toBeTruthy();
    const independentContext = await browser.newContext({ ignoreHTTPSErrors: true });
    const independentPage = await independentContext.newPage();
    const independentCloseCodes: number[] = [];
    const independentControlTypes: string[] = [];
    await independentPage.exposeFunction("__recordIceQSocketClose", (code: number) => {
      independentCloseCodes.push(code);
    });
    await independentPage.exposeFunction("__recordIceQControl", (type: string) => {
      independentControlTypes.push(type);
    });
    await independentPage.goto("/login", { waitUntil: "domcontentloaded" });
    await independentPage.evaluate(async (token) => {
      await new Promise<void>((resolve, reject) => {
        const ws = new WebSocket("wss://localhost:8443/ws");
        const scope = window as unknown as {
          __iceqPassiveSocket?: WebSocket;
          __recordIceQSocketClose: (code: number) => Promise<void>;
          __recordIceQControl: (type: string) => Promise<void>;
        };
        scope.__iceqPassiveSocket = ws;
        let authenticated = false;
        const timeout = window.setTimeout(() => reject(new Error("passive WebSocket authentication timed out")), 15_000);
        ws.onopen = () => {
          ws.send(JSON.stringify({
            type: "auth",
            id: crypto.randomUUID(),
            ts: Date.now(),
            payload: { access_token: token, presence_enabled: false },
          }));
        };
        ws.onmessage = (event) => {
          const envelope = JSON.parse(String(event.data)) as { type?: string };
          if (envelope.type === "account_wiped") void scope.__recordIceQControl(envelope.type);
          if (envelope.type !== "auth_ok") return;
          authenticated = true;
          window.clearTimeout(timeout);
          resolve();
        };
        ws.onerror = () => {
          if (!authenticated) reject(new Error("passive WebSocket failed before authentication"));
        };
        ws.onclose = (event) => {
          void scope.__recordIceQSocketClose(event.code);
          if (!authenticated) {
            window.clearTimeout(timeout);
            reject(new Error(`passive WebSocket closed before authentication (${event.code})`));
          }
        };
      });
    }, accessToken);

    // ── Step 4: Settings → Panic Wipe ───────────────────────────────
    await page.getByRole("button", { name: "Toggle menu" }).click();
    await page.getByRole("button", { name: "Settings", exact: true }).click();
    await expect(page.getByRole("dialog", { name: "Settings" })).toBeVisible({ timeout: 10000 });

    const settingsDialog = page.getByRole("dialog", { name: "Settings" });
    phase = "wipe";

    if (wipeMode === "pin") {
      // Configure the explicit PIN fallback on an account that already has an
      // enrolled wipe signing key. This is the production coexistence case that
      // previously returned SIGNATURE_REQUIRED and never created a wipe job.
      await settingsDialog.locator("#panic-pin-current-password").fill(user.password);
      await settingsDialog.locator("#panic-pin-new").fill(PANIC_PIN);
      await settingsDialog.getByRole("button", { name: "Save PIN" }).click();
      await expect(settingsDialog.getByText("Panic PIN saved. Your account has not been deleted.")).toBeVisible({ timeout: 15_000 });
    }

    await settingsDialog.getByRole("button", { name: "Permanently delete account" }).click();

    // Panic wipe confirmation dialog
    const panicDialog = page.getByRole("dialog").last();
    await expect(panicDialog).toBeVisible({ timeout: 10000 });
    if (wipeMode === "pin") {
      await page.locator("#panic-wipe-pin").fill(PANIC_PIN);
    } else {
      await panicDialog.getByRole("button", { name: "Security Passphrase" }).click();
      await page.locator("#panic-wipe-passphrase").fill(PASSPHRASE);
    }
    // Click the confirm button ("Permanently delete account") inside the panic dialog
    await panicDialog.getByRole("button", { name: "Permanently delete account" }).click();

    // ── Step 5: Post-wipe redirect to login ─────────────────────────
    await expect(page).toHaveURL(/\/login/, { timeout: 45000 });
    await expect(passivePage).toHaveURL(/\/login/, { timeout: 45000 });
    await expect
      .poll(
        () => independentControlTypes,
        { message: `[${browserName}/${wipeMode}] independent passive session must receive the authenticated wipe control` },
      )
      .toEqual(["account_wiped"]);
    await expect.poll(() => independentCloseCodes.length).toBe(1);
    // WebKit preserves the custom close code through Caddy. Chromium can
    // collapse it to 1006, so the authenticated control frame above is the
    // cross-browser security boundary and 4403 remains defense in depth.
    expect([4403, 1006]).toContain(independentCloseCodes[0]);

    // ── Step 6: Local residue + immediate relogin ───────────────────
    phase = "post-wipe-relogin";
    // The auth state is cleared synchronously, so /login may render before the
    // asynchronous cache, service-worker and IndexedDB cleanup completes. Poll
    // the actual residue instead of treating navigation as the cleanup barrier.
    const expectedResidue: LocalResidue = {
      iceqStorageKeys: ["iceq_logged_out"],
      databases: [],
      cacheNames: [],
      workerScripts: [],
    };
    await expect
      .poll(() => readLocalResidue(page), {
        message: `[${browserName}/${wipeMode}] local panic-wipe cleanup must finish`,
        timeout: 30_000,
      })
      .toEqual(expectedResidue);
    const localResidue = await readLocalResidue(page);
    expect(localResidue.iceqStorageKeys).toEqual(["iceq_logged_out"]);
    expect(localResidue.databases).toEqual([]);
    expect(localResidue.cacheNames).toEqual([]);
    expect(localResidue.workerScripts).toEqual([]);
    await page.locator("#login-username").fill(user.username);
    await page.locator("#login-password").fill(user.password);
    await page.getByRole("button", { name: "Sign in" }).click();

    const invalidCredentials = page.getByText(/username or password is incorrect/i);
    await expect(invalidCredentials).toBeVisible({ timeout: 15000 });
    await expect(invalidCredentials).not.toContainText("401");
    await expect(page).toHaveURL(/\/login/, { timeout: 5000 });

    // ── Step 7: Page error check ────────────────────────────────────
    await page.waitForTimeout(3000);
    const securityWrites = diagnostics.responses.filter((response) =>
      response.status >= 200 && response.status < 300 && (
        (response.method === "POST" && response.path === "/api/keys/bundle") ||
        (response.method === "PUT" && response.path === "/api/auth/panic-wipe-public-key")
      ),
    );
    expect(securityWrites.some((response) => response.method === "POST"), "key bundle publication must succeed").toBe(true);
    expect(securityWrites.some((response) => response.method === "PUT"), "wipe-key enrollment must succeed").toBe(true);
    const unexpectedResponses = diagnostics.responses.filter((response) => response.status >= 400 && !isExpectedNegativeControl(response));
    const unexpectedRequestFailures = diagnostics.failedRequests.filter((failure) =>
      !isExpectedNavigationCancellation(failure) &&
      !isCompletedNoContentResponse(failure, diagnostics.responses),
    );
    const unexpectedApplicationErrors = diagnostics.applicationErrors.filter((error) =>
      !isExpectedWipeSocketShutdown(error),
    );
    const unexpectedPassiveApplicationErrors = passiveDiagnostics.applicationErrors.filter((error) =>
      !isExpectedWipeSocketShutdown(error),
    );
    expect(unexpectedApplicationErrors, `[${browserName}] unexpected application errors`).toEqual([]);
    expect(unexpectedPassiveApplicationErrors, `[${browserName}] unexpected passive-session application errors`).toEqual([]);
    expect(unexpectedRequestFailures, `[${browserName}] unexpected failed requests`).toEqual([]);
    expect(unexpectedResponses, `[${browserName}] unexpected HTTP error responses`).toEqual([]);
    await independentContext.close();
  });
});
