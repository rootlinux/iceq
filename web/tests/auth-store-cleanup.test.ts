import test from "node:test";
import assert from "node:assert/strict";

test("logout attempts server revocation before clearing every local account state", async () => {
  const values = new Map<string, string>([["iceq_access_token", "token"], ["iceq_privacy_settings", "secret"]]);
  Object.defineProperty(globalThis, "localStorage", { configurable: true, value: {
    get length() { return values.size; }, key(index: number) { return [...values.keys()][index] ?? null; },
    getItem(key: string) { return values.get(key) ?? null; }, setItem(key: string, value: string) { values.set(key, value); },
    removeItem(key: string) { values.delete(key); }, clear() { values.clear(); },
  } });
  Object.defineProperty(globalThis, "sessionStorage", { configurable: true, value: { length: 0, key: () => null, removeItem() {} } });
  Object.defineProperty(globalThis, "caches", { configurable: true, value: undefined });
  let deleteCount = 0;
  Object.defineProperty(globalThis, "indexedDB", { configurable: true, value: { deleteDatabase() {
    const request: Record<string, (() => void) | null> = { onsuccess: null, onerror: null, onblocked: null };
    queueMicrotask(() => { deleteCount += 1; request.onsuccess?.(); });
    return request;
  } } });
  let serverSawLocalState = false;
  Object.defineProperty(globalThis, "fetch", { configurable: true, value: async () => {
    serverSawLocalState = values.has("iceq_privacy_settings") && deleteCount === 0;
    return new Response(null, { status: 204 });
  } });

  const { useAuthStore } = await import("../src/store/authStore.ts");
  useAuthStore.setState({ uin: 7, username: "alice", accessToken: "token", isAuthenticated: true, hydrated: true });
  await useAuthStore.getState().logout();

  assert.equal(serverSawLocalState, true);
  assert.equal(deleteCount, 1);
  assert.equal(values.has("iceq_privacy_settings"), false);
  assert.equal(useAuthStore.getState().isAuthenticated, false);

  await useAuthStore.getState().setSession({ uin: 7, username: "alice" }, "first", "");
  useAuthStore.setState({ uin: null }); // simulate a reload with only the durable owner marker
  await useAuthStore.getState().setSession({ uin: 8, username: "bob" }, "second", "");
  assert.equal(deleteCount, 2);
  assert.equal(useAuthStore.getState().uin, 8);
});
