import test from "node:test";
import assert from "node:assert/strict";

test("logout attempts server revocation before clearing every local account state", async () => {
  const values = new Map<string, string>([["iceq_access_token", "token"], ["iceq_privacy_settings", "secret"], ["iceq_account_uin", "7"]]);
  Object.defineProperty(globalThis, "localStorage", { configurable: true, value: {
    get length() { return values.size; }, key(index: number) { return [...values.keys()][index] ?? null; },
    getItem(key: string) { return values.get(key) ?? null; }, setItem(key: string, value: string) { values.set(key, value); },
    removeItem(key: string) { values.delete(key); }, clear() { values.clear(); },
  } });
  Object.defineProperty(globalThis, "sessionStorage", { configurable: true, value: { length: 0, key: () => null, removeItem() {} } });
  Object.defineProperty(globalThis, "caches", { configurable: true, value: undefined });
  let deleteCount = 0;
  Object.defineProperty(globalThis, "indexedDB", { configurable: true, value: { async databases() { return [{ name: "iceq" }]; }, deleteDatabase() {
    const request: Record<string, (() => void) | null> = { onsuccess: null, onerror: null, onblocked: null };
    queueMicrotask(() => { deleteCount += 1; request.onsuccess?.(); });
    return request;
  } } });
  let serverSawLocalState = false;
  let fetchCount = 0;
  let failPanicWipe = false;
  let panicDeleteCountAtCall = -1;
  let logoutAuthorization: string | null = null;
  Object.defineProperty(globalThis, "fetch", { configurable: true, value: async (input: RequestInfo | URL, init?: RequestInit) => {
    fetchCount += 1;
    serverSawLocalState = values.has("iceq_privacy_settings") && deleteCount === 0;
    if (String(input).includes("/api/auth/logout")) logoutAuthorization = new Headers(init?.headers).get("Authorization");
    if (failPanicWipe && String(input).includes("panic-wipe")) { panicDeleteCountAtCall = deleteCount; return new Response("failed", { status: 500 }); }
    return new Response(null, { status: 204 });
  } });

  const { useAuthStore } = await import("../src/store/authStore.ts");
  useAuthStore.setState({ uin: 7, username: "alice", accessToken: "token", isAuthenticated: true, hydrated: true });
  await useAuthStore.getState().logout();

  assert.equal(serverSawLocalState, true);
  assert.equal(logoutAuthorization, "Bearer token");
  assert.equal(deleteCount, 1);
  assert.equal(values.has("iceq_privacy_settings"), false);
  assert.equal(values.get("iceq_logged_out"), "1");
  assert.equal(values.has("iceq_account_uin"), false);
  assert.equal(useAuthStore.getState().isAuthenticated, false);
  const countBeforeHydrate = fetchCount;
  useAuthStore.getState().hydrate();
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.equal(fetchCount, countBeforeHydrate);

  await useAuthStore.getState().setSession({ uin: 7, username: "alice" }, "first", "");
  useAuthStore.setState({ uin: null }); // simulate a reload with only the durable owner marker
  await useAuthStore.getState().setSession({ uin: 8, username: "bob" }, "second", "");
  assert.equal(deleteCount, 2);
  assert.equal(useAuthStore.getState().uin, 8);

  failPanicWipe = true;
  const countBeforePanic = deleteCount;
  await assert.rejects(useAuthStore.getState().panicWipe());
  assert.equal(panicDeleteCountAtCall, countBeforePanic);
  assert.equal(deleteCount, countBeforePanic);
  assert.equal(useAuthStore.getState().isAuthenticated, true);

  Object.defineProperty(globalThis, "fetch", { configurable: true, value: () => new Promise<Response>(() => undefined) });
  useAuthStore.setState({ uin: 8, username: "bob", accessToken: "second", isAuthenticated: true });
  const expiry = useAuthStore.getState().expireSession();
  assert.equal(useAuthStore.getState().isAuthenticated, false);
  assert.equal(useAuthStore.getState().accessToken, null);
  const expiryStarted = Date.now();
  await expiry;
  assert.ok(Date.now() - expiryStarted < 1_500);

  // A hydrate request that resolves after teardown must never resurrect auth.
  let resolveMe!: (response: Response) => void;
  Object.defineProperty(globalThis, "fetch", { configurable: true, value: (input: RequestInfo | URL) => {
    if (String(input).includes("/api/auth/me")) return new Promise<Response>((resolve) => { resolveMe = resolve; });
    return Promise.resolve(new Response(null, { status: 204 }));
  } });
  values.set("iceq_access_token", "late-hydrate-token");
  values.delete("iceq_logged_out");
  useAuthStore.setState({ uin: null, username: null, accessToken: null, isAuthenticated: false, hydrated: false });
  useAuthStore.getState().hydrate();
  await Promise.resolve();
  await useAuthStore.getState().logout();
  resolveMe(new Response(JSON.stringify({ uin: 99, username: "stale" }), {
    status: 200, headers: { "Content-Type": "application/json" },
  }));
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.equal(useAuthStore.getState().isAuthenticated, false);
  assert.equal(useAuthStore.getState().uin, null);
  assert.equal(values.has("iceq_access_token"), false);

  for (const teardown of ["expire", "panic"] as const) {
    let settleLateMe!: (response: Response) => void;
    Object.defineProperty(globalThis, "fetch", { configurable: true, value: (input: RequestInfo | URL) => {
      if (String(input).includes("/api/auth/me")) return new Promise<Response>((resolve) => { settleLateMe = resolve; });
      return Promise.resolve(new Response(null, { status: 204 }));
    } });
    values.set("iceq_access_token", `late-${teardown}`);
    values.delete("iceq_logged_out");
    useAuthStore.setState({ uin: null, username: null, accessToken: null, isAuthenticated: false, hydrated: false });
    useAuthStore.getState().hydrate();
    await Promise.resolve();
    if (teardown === "expire") await useAuthStore.getState().expireSession();
    else await useAuthStore.getState().panicWipe();
    settleLateMe(new Response(JSON.stringify({ uin: 100, username: "stale" }), {
      status: 200, headers: { "Content-Type": "application/json" },
    }));
    await new Promise((resolve) => setTimeout(resolve, 0));
    assert.equal(useAuthStore.getState().isAuthenticated, false);
    assert.equal(useAuthStore.getState().uin, null);
    assert.equal(values.has("iceq_access_token"), false);
  }

  // Expiry teardown is single-flight and its logout 401 must not recurse into
  // refresh/auth-expired dispatch.
  const expiryPaths: string[] = [];
  Object.defineProperty(globalThis, "fetch", { configurable: true, value: async (input: RequestInfo | URL) => {
    expiryPaths.push(String(input));
    return new Response("unauthorized", { status: 401 });
  } });
  useAuthStore.setState({ uin: 7, username: "alice", accessToken: "expired", isAuthenticated: true });
  values.set("iceq_access_token", "expired");
  const firstExpiry = useAuthStore.getState().expireSession();
  const secondExpiry = useAuthStore.getState().expireSession();
  assert.equal(firstExpiry, secondExpiry);
  await Promise.all([firstExpiry, secondExpiry]);
  assert.equal(expiryPaths.filter((path) => path.includes("/api/auth/logout")).length, 1);
  assert.equal(expiryPaths.some((path) => path.includes("/api/auth/refresh")), false);

  // Pending attachment revocation cannot hold durable browser cleanup hostage.
  const { attachmentGrantLifecycle } = await import("../src/lib/attachmentGrantLifecycle.ts");
  const originalRevokeAll = attachmentGrantLifecycle.revokeAll.bind(attachmentGrantLifecycle);
  attachmentGrantLifecycle.revokeAll = () => new Promise<void>(() => undefined);
  try {
    Object.defineProperty(globalThis, "fetch", { configurable: true, value: async () => new Response(null, { status: 204 }) });
    values.set("iceq_access_token", "bounded-logout");
    values.set("iceq_privacy_settings", "secret");
    useAuthStore.setState({ uin: 7, username: "alice", accessToken: "bounded-logout", isAuthenticated: true });
    const logoutStarted = Date.now();
    await useAuthStore.getState().logout();
    assert.ok(Date.now() - logoutStarted < 1_500);
    assert.equal(values.has("iceq_privacy_settings"), false);

    values.set("iceq_access_token", "bounded-panic");
    values.set("iceq_privacy_settings", "secret");
    useAuthStore.setState({ uin: 7, username: "alice", accessToken: "bounded-panic", isAuthenticated: true });
    const panicStarted = Date.now();
    await useAuthStore.getState().panicWipe();
    assert.ok(Date.now() - panicStarted < 1_500);
    assert.equal(values.has("iceq_privacy_settings"), false);
  } finally {
    attachmentGrantLifecycle.revokeAll = originalRevokeAll;
  }

  // A normal logout also bounds a server call that never settles.
  Object.defineProperty(globalThis, "fetch", { configurable: true, value: () => new Promise<Response>(() => undefined) });
  values.set("iceq_access_token", "never-logout");
  values.set("iceq_privacy_settings", "secret");
  useAuthStore.setState({ uin: 7, username: "alice", accessToken: "never-logout", isAuthenticated: true });
  const neverLogoutStarted = Date.now();
  await useAuthStore.getState().logout();
  assert.ok(Date.now() - neverLogoutStarted < 1_500);
  assert.equal(values.has("iceq_privacy_settings"), false);

  // New sessions wait for the active teardown owner and cannot be erased by
  // its late completion.
  async function raceTeardownWithSession(establish: () => Promise<void>, expectedUin: number): Promise<void> {
    let finishDelete!: () => void;
    Object.defineProperty(globalThis, "indexedDB", { configurable: true, value: {
      async databases() { return [{ name: "iceq" }]; },
      deleteDatabase() {
        const request: Record<string, (() => void) | null> = { onsuccess: null, onerror: null, onblocked: null };
        finishDelete = () => request.onsuccess?.();
        return request;
      },
    } });
    const teardown = useAuthStore.getState().logout();
    await new Promise((resolve) => setTimeout(resolve, 0));
    const session = establish();
    await Promise.resolve();
    assert.equal(useAuthStore.getState().isAuthenticated, false);
    finishDelete();
    await Promise.all([teardown, session]);
    assert.equal(useAuthStore.getState().isAuthenticated, true);
    assert.equal(useAuthStore.getState().uin, expectedUin);
  }
  Object.defineProperty(globalThis, "fetch", { configurable: true, value: async (input: RequestInfo | URL) => {
    const path = String(input);
    if (path.includes("/api/auth/login")) return new Response(JSON.stringify({ user: { uin: 21, username: "login" }, tokens: { access_token: "login-token", refresh_token: "" } }), { status: 200, headers: { "Content-Type": "application/json" } });
    if (path.includes("/api/auth/register")) return new Response(JSON.stringify({ user: { uin: 22, username: "register" }, tokens: { access_token: "register-token", refresh_token: "" } }), { status: 200, headers: { "Content-Type": "application/json" } });
    return new Response(null, { status: 204 });
  } });
  await raceTeardownWithSession(() => useAuthStore.getState().login("login", "password"), 21);
  await raceTeardownWithSession(() => useAuthStore.getState().register({ username: "register", password: "password", identityKey: "public" }), 22);
  await raceTeardownWithSession(() => useAuthStore.getState().setSession({ uin: 23, username: "set" }, "set-token", ""), 23);

  // Once the panic endpoint succeeds, a local failure publishes the global
  // persistent retry signal; retrying local cleanup does not call panic again.
  let panicCalls = 0;
  let cleanupEvents = 0;
  let blockedRegisterCalls = 0;
  const eventTarget = new EventTarget();
  eventTarget.addEventListener("iceq:local-cleanup-failed", () => { cleanupEvents += 1; });
  Object.defineProperty(globalThis, "window", { configurable: true, value: eventTarget });
  let blockedLoginCalls = 0;
  Object.defineProperty(globalThis, "fetch", { configurable: true, value: async (input: RequestInfo | URL) => {
    if (String(input).includes("panic-wipe")) panicCalls += 1;
    if (String(input).includes("/api/auth/login")) blockedLoginCalls += 1;
    if (String(input).includes("/api/auth/register")) blockedRegisterCalls += 1;
    return new Response(null, { status: 204 });
  } });
  Object.defineProperty(globalThis, "indexedDB", { configurable: true, value: { deleteDatabase() {
    const request: Record<string, (() => void) | null> = { onsuccess: null, onerror: null, onblocked: null };
    queueMicrotask(() => request.onerror?.());
    return request;
  } } });
  await assert.rejects(useAuthStore.getState().panicWipe());
  assert.equal(panicCalls, 1);
  assert.equal(cleanupEvents, 1);
  assert.equal(values.get("iceq_cleanup_required"), "1");
  assert.deepEqual(JSON.parse(JSON.stringify({ marker: values.get("iceq_cleanup_required") })), { marker: "1" });
  await assert.rejects(useAuthStore.getState().login("must-wait", "password"), /cleanup must be retried/);
  await assert.rejects(useAuthStore.getState().register({ username: "must-wait", password: "password", identityKey: "public" }), /cleanup must be retried/);
  await assert.rejects(useAuthStore.getState().setSession({ uin: 30, username: "must-wait" }, "blocked", ""), /cleanup must be retried/);
  assert.equal(blockedLoginCalls, 0);
  assert.equal(blockedRegisterCalls, 0);
  assert.equal(useAuthStore.getState().isAuthenticated, false);
  Object.defineProperty(globalThis, "indexedDB", { configurable: true, value: undefined });
  await useAuthStore.getState().retryLocalCleanup();
  assert.equal(panicCalls, 1);
  assert.equal(values.has("iceq_cleanup_required"), false);
  Object.defineProperty(globalThis, "fetch", { configurable: true, value: async (input: RequestInfo | URL) => {
    if (String(input).includes("/api/auth/login")) return new Response(JSON.stringify({ user: { uin: 31, username: "after-retry" }, tokens: { access_token: "after-retry-token", refresh_token: "" } }), { status: 200, headers: { "Content-Type": "application/json" } });
    return new Response(null, { status: 204 });
  } });
  await useAuthStore.getState().login("after-retry", "password");
  assert.equal(useAuthStore.getState().uin, 31);
  assert.equal(useAuthStore.getState().isAuthenticated, true);

  // A durable marker alone (as after a reload/crash) blocks network/session
  // restoration, emits the visible failure signal during hydrate, and is
  // removed only by the store-owned retry coordinator.
  values.set("iceq_cleanup_required", "1");
  let durableLoginCalls = 0;
  Object.defineProperty(globalThis, "fetch", { configurable: true, value: async (input: RequestInfo | URL) => {
    if (String(input).includes("/api/auth/login")) durableLoginCalls += 1;
    return new Response(null, { status: 204 });
  } });
  useAuthStore.setState({ uin: 31, username: "after-retry", accessToken: "after-retry-token", isAuthenticated: true, hydrated: false });
  useAuthStore.getState().hydrate();
  await Promise.resolve();
  assert.equal(useAuthStore.getState().isAuthenticated, false);
  assert.ok(cleanupEvents >= 2);
  await assert.rejects(useAuthStore.getState().login("blocked-after-reload", "password"), /cleanup must be retried/);
  assert.equal(durableLoginCalls, 0);
  await useAuthStore.getState().retryLocalCleanup();
  assert.equal(values.has("iceq_cleanup_required"), false);

  async function accountChangeFailure(establish: () => Promise<void>): Promise<void> {
    values.set("iceq_account_uin", "40");
    values.set("iceq_access_token", "old-account");
    useAuthStore.setState({ uin: 40, username: "old", accessToken: "old-account", isAuthenticated: true, hydrated: true });
    Object.defineProperty(globalThis, "indexedDB", { configurable: true, value: { deleteDatabase() {
      const request: Record<string, (() => void) | null> = { onsuccess: null, onerror: null, onblocked: null };
      queueMicrotask(() => request.onerror?.());
      return request;
    } } });
    await assert.rejects(establish());
    assert.equal(values.get("iceq_cleanup_required"), "1");
    assert.equal(useAuthStore.getState().isAuthenticated, false);
    Object.defineProperty(globalThis, "indexedDB", { configurable: true, value: undefined });
    await useAuthStore.getState().retryLocalCleanup();
    assert.equal(values.has("iceq_cleanup_required"), false);
  }
  Object.defineProperty(globalThis, "fetch", { configurable: true, value: async (input: RequestInfo | URL) => {
    const path = String(input);
    if (path.includes("/api/auth/login")) return new Response(JSON.stringify({ user: { uin: 41, username: "new-login" }, tokens: { access_token: "new-login", refresh_token: "" } }), { status: 200, headers: { "Content-Type": "application/json" } });
    if (path.includes("/api/auth/register")) return new Response(JSON.stringify({ user: { uin: 42, username: "new-register" }, tokens: { access_token: "new-register", refresh_token: "" } }), { status: 200, headers: { "Content-Type": "application/json" } });
    return new Response(null, { status: 204 });
  } });
  await accountChangeFailure(() => useAuthStore.getState().login("new-login", "password"));
  await accountChangeFailure(() => useAuthStore.getState().register({ username: "new-register", password: "password", identityKey: "public" }));
  await accountChangeFailure(() => useAuthStore.getState().setSession({ uin: 43, username: "new-set" }, "new-set", ""));

  values.set("iceq_account_uin", "40");
  values.set("iceq_access_token", "hydrate-old");
  Object.defineProperty(globalThis, "indexedDB", { configurable: true, value: { deleteDatabase() {
    const request: Record<string, (() => void) | null> = { onsuccess: null, onerror: null, onblocked: null };
    queueMicrotask(() => request.onerror?.());
    return request;
  } } });
  Object.defineProperty(globalThis, "fetch", { configurable: true, value: async (input: RequestInfo | URL) => {
    if (String(input).includes("/api/auth/me")) return new Response(JSON.stringify({ uin: 44, username: "hydrate-new" }), { status: 200, headers: { "Content-Type": "application/json" } });
    return new Response(null, { status: 204 });
  } });
  useAuthStore.setState({ uin: null, username: null, accessToken: null, isAuthenticated: false, hydrated: false });
  useAuthStore.getState().hydrate();
  await new Promise((resolve) => setTimeout(resolve, 10));
  assert.equal(values.get("iceq_cleanup_required"), "1");
  assert.equal(useAuthStore.getState().isAuthenticated, false);
  Object.defineProperty(globalThis, "indexedDB", { configurable: true, value: undefined });
  await useAuthStore.getState().retryLocalCleanup();

  // A server-originated 4403 path performs the same synchronous demotion and
  // generation invalidation without calling the panic endpoint.
  let settleWipedMe!: (response: Response) => void;
  Object.defineProperty(globalThis, "fetch", { configurable: true, value: (input: RequestInfo | URL) => {
    if (String(input).includes("/api/auth/me")) return new Promise<Response>((resolve) => { settleWipedMe = resolve; });
    return Promise.resolve(new Response(null, { status: 204 }));
  } });
  values.set("iceq_access_token", "server-wipe");
  values.delete("iceq_logged_out");
  useAuthStore.setState({ uin: null, username: null, accessToken: null, isAuthenticated: false, hydrated: false });
  useAuthStore.getState().hydrate();
  await Promise.resolve();
  const serverWipe = useAuthStore.getState().handleServerWipe();
  assert.equal(useAuthStore.getState().isAuthenticated, false);
  settleWipedMe(new Response(JSON.stringify({ uin: 77, username: "stale" }), { status: 200, headers: { "Content-Type": "application/json" } }));
  await serverWipe;
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.equal(useAuthStore.getState().isAuthenticated, false);
  assert.equal(panicCalls, 1);
});
