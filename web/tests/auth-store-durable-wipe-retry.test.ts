import test from "node:test";
import assert from "node:assert/strict";

test("cold reload preserves a failed panic-wipe reason until IndexedDB is erased", async () => {
  const values = new Map<string, string>([["iceq_cleanup_required", "panic-wipe"]]);
  const storage: Storage = {
    get length() { return values.size; },
    key(index: number) { return [...values.keys()][index] ?? null; },
    getItem(key: string) { return values.get(key) ?? null; },
    setItem(key: string, value: string) { values.set(key, value); },
    removeItem(key: string) { values.delete(key); },
    clear() { values.clear(); },
  };
  let deletes = 0;
  Object.defineProperties(globalThis, {
    localStorage: { configurable: true, value: storage },
    sessionStorage: { configurable: true, value: storage },
    caches: { configurable: true, value: undefined },
    navigator: { configurable: true, value: { serviceWorker: { async getRegistrations() { return []; } } } },
    indexedDB: { configurable: true, value: {
      async databases() { return [{ name: "iceq" }]; },
      deleteDatabase() {
        deletes += 1;
        const request: Record<string, (() => void) | null> = { onsuccess: null, onerror: null, onblocked: null };
        queueMicrotask(() => request.onsuccess?.());
        return request;
      },
    } },
    fetch: { configurable: true, value: async () => new Response(null, { status: 204 }) },
  });

  const { useAuthStore } = await import("../src/store/authStore.ts");
  useAuthStore.getState().hydrate();
  assert.equal(useAuthStore.getState().isAuthenticated, false);
  await useAuthStore.getState().retryLocalCleanup();

  assert.equal(deletes, 1);
  assert.equal(values.has("iceq_cleanup_required"), false);

  // A delayed benign session-expiry event after a failed destructive pass
  // must upgrade to the durable panic-wipe requirement, never clear it with
  // a cleanup mode that preserves IndexedDB.
  values.set("iceq_cleanup_required", "panic-wipe");
  useAuthStore.getState().hydrate();
  await useAuthStore.getState().expireSession();
  assert.equal(deletes, 2);
  assert.equal(values.has("iceq_cleanup_required"), false);

  // Simulate two tabs: this module retains a weaker logout requirement in
  // memory, then another tab upgrades the shared marker to panic-wipe.
  values.set("iceq_cleanup_required", "logout");
  useAuthStore.getState().hydrate();
  values.set("iceq_cleanup_required", "panic-wipe");
  await useAuthStore.getState().retryLocalCleanup();
  assert.equal(deletes, 3);
  assert.equal(values.has("iceq_cleanup_required"), false);
});
