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
  Object.defineProperty(globalThis, "fetch", { configurable: true, value: async (input: RequestInfo | URL) => {
    fetchCount += 1;
    serverSawLocalState = values.has("iceq_privacy_settings") && deleteCount === 0;
    if (failPanicWipe && String(input).includes("panic-wipe")) { panicDeleteCountAtCall = deleteCount; return new Response("failed", { status: 500 }); }
    return new Response(null, { status: 204 });
  } });

  const { useAuthStore } = await import("../src/store/authStore.ts");
  useAuthStore.setState({ uin: 7, username: "alice", accessToken: "token", isAuthenticated: true, hydrated: true });
  await useAuthStore.getState().logout();

  assert.equal(serverSawLocalState, true);
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
});
