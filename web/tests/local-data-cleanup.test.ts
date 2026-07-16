import test from "node:test";
import assert from "node:assert/strict";

import {
  LocalCleanupError,
  clearAllIceQLocalData,
  registerMemoryReset,
  trackObjectURL,
} from "../src/lib/localDataCleanup.ts";
import { ICEQ_INDEXEDDB_NAME } from "../src/lib/indexeddb.ts";

function storage(values: Record<string, string>) {
  const entries = new Map(Object.entries(values));
  return {
    entries,
    api: {
      get length() { return entries.size; },
      key(index: number) { return [...entries.keys()][index] ?? null; },
      getItem(key: string) { return entries.get(key) ?? null; },
      setItem(key: string, value: string) { entries.set(key, value); },
      removeItem(key: string) { entries.delete(key); },
      clear() { entries.clear(); },
    } satisfies Storage,
  };
}

test("clears every IceQ-owned browser and registered in-memory state without touching other apps", async () => {
  const local = storage({ iceq_access_token: "secret", iceq_privacy_settings: "{}", other_app: "keep" });
  const session = storage({ "iceq:transport": "secret", unrelated: "keep" });
  const deletedDatabases: string[] = [];
  const deletedCaches: string[] = [];
  const revokedUrls: string[] = [];
  const unregisteredWorkers: string[] = [];
  let resets = 0;

  Object.defineProperties(globalThis, {
    localStorage: { configurable: true, value: local.api },
    sessionStorage: { configurable: true, value: session.api },
    indexedDB: { configurable: true, value: {
      deleteDatabase(name: string) {
        deletedDatabases.push(name);
        const request: Record<string, (() => void) | null> = { onsuccess: null, onerror: null, onblocked: null };
        queueMicrotask(() => request.onsuccess?.());
        return request;
      },
    } },
    caches: { configurable: true, value: {
      async keys() { return ["iceq-static-v3", "iceq-static-v2", "other-cache"]; },
      async delete(name: string) { deletedCaches.push(name); return true; },
    } },
  });
  Object.defineProperty(globalThis.URL, "revokeObjectURL", { configurable: true, value: (url: string) => revokedUrls.push(url) });
  Object.defineProperty(globalThis, "navigator", { configurable: true, value: { serviceWorker: { async getRegistrations() {
    return ["https://iceq.test/sw.js", "https://iceq.test/other-worker.js"].map((scriptURL) => ({
      active: { scriptURL }, waiting: null, installing: null,
      async unregister() { unregisteredWorkers.push(scriptURL); return true; },
    }));
  } } } });

  const unregister = registerMemoryReset(() => { resets += 1; });
  trackObjectURL("blob:iceq-secret");
  await clearAllIceQLocalData("logout");
  await clearAllIceQLocalData("logout");
  unregister();

  assert.deepEqual(deletedDatabases, [ICEQ_INDEXEDDB_NAME, ICEQ_INDEXEDDB_NAME]);
  assert.deepEqual(deletedCaches, ["iceq-static-v3", "iceq-static-v2", "iceq-static-v3", "iceq-static-v2"]);
  assert.deepEqual(revokedUrls, ["blob:iceq-secret"]);
  assert.deepEqual(unregisteredWorkers, ["https://iceq.test/sw.js", "https://iceq.test/sw.js"]);
  assert.equal(resets, 2);
  assert.deepEqual([...local.entries], [["other_app", "keep"]]);
  assert.deepEqual([...session.entries], [["unrelated", "keep"]]);
});

test("rejects a typed aggregate error when mandatory IndexedDB deletion fails", async () => {
  Object.defineProperty(globalThis, "indexedDB", { configurable: true, value: {
    deleteDatabase() {
      const request: Record<string, (() => void) | null> = { onsuccess: null, onerror: null, onblocked: null };
      queueMicrotask(() => request.onerror?.());
      return request;
    },
  } });
  Object.defineProperty(globalThis, "caches", { configurable: true, value: undefined });
  Object.defineProperty(globalThis, "localStorage", { configurable: true, value: undefined });
  Object.defineProperty(globalThis, "sessionStorage", { configurable: true, value: undefined });

  await assert.rejects(
    clearAllIceQLocalData("panic-wipe"),
    (error: unknown) => error instanceof LocalCleanupError && error.failures.some((failure) => failure.area === "indexeddb"),
  );
});

test("aggregates a failing resetter while still running the remaining resetters", async () => {
  Object.defineProperty(globalThis, "indexedDB", { configurable: true, value: undefined });
  let laterReset = false;
  const unregisterFailure = registerMemoryReset(() => { throw new Error("reset failed"); });
  const unregisterLater = registerMemoryReset(() => { laterReset = true; });
  await assert.rejects(clearAllIceQLocalData("auth-expired"), LocalCleanupError);
  unregisterFailure();
  unregisterLater();
  assert.equal(laterReset, true);
});
