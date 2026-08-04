import test from "node:test";
import assert from "node:assert/strict";

function memoryStorage(): Storage {
  const values = new Map<string, string>();
  return {
    get length() { return values.size; },
    key(index: number) { return [...values.keys()][index] ?? null; },
    getItem(key: string) { return values.get(key) ?? null; },
    setItem(key: string, value: string) { values.set(key, value); },
    removeItem(key: string) { values.delete(key); },
    clear() { values.clear(); },
  };
}

test("server wipe escalates an in-flight logout and erases local IndexedDB", async () => {
  let finishLogoutCleanup!: () => void;
  let unregisterCalls = 0;
  let indexedDBDeletes = 0;
  const registration = {
    active: { scriptURL: "https://iceq.test/sw.js" }, waiting: null, installing: null,
    unregister: () => {
      unregisterCalls += 1;
      if (unregisterCalls > 1) return Promise.resolve(true);
      return new Promise<boolean>((resolve) => { finishLogoutCleanup = () => resolve(true); });
    },
  };

  Object.defineProperties(globalThis, {
    localStorage: { configurable: true, value: memoryStorage() },
    sessionStorage: { configurable: true, value: memoryStorage() },
    caches: { configurable: true, value: undefined },
    navigator: { configurable: true, value: { serviceWorker: { async getRegistrations() { return [registration]; } } } },
    indexedDB: { configurable: true, value: {
      async databases() { return [{ name: "iceq" }]; },
      deleteDatabase() {
        indexedDBDeletes += 1;
        const request: Record<string, (() => void) | null> = { onsuccess: null, onerror: null, onblocked: null };
        queueMicrotask(() => request.onsuccess?.());
        return request;
      },
    } },
    fetch: { configurable: true, value: async () => new Response(null, { status: 204 }) },
  });

  const { useAuthStore } = await import("../src/store/authStore.ts");
  useAuthStore.setState({ uin: 10000001, username: "alice", accessToken: "token", isAuthenticated: true, hydrated: true });

  const logout = useAuthStore.getState().logout();
  await new Promise((resolve) => setTimeout(resolve, 0));
  const serverWipe = useAuthStore.getState().handleServerWipe();
  finishLogoutCleanup();
  await Promise.all([logout, serverWipe]);

  assert.equal(indexedDBDeletes, 1);
  assert.equal(useAuthStore.getState().isAuthenticated, false);
});
