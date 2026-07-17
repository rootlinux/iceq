import test from "node:test";
import assert from "node:assert/strict";

import {
  LocalCleanupError,
  clearAllIceQLocalData,
  registerMemoryReset,
  trackObjectURL,
  untrackObjectURL,
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
  const local = storage({ iceq_access_token: "secret", iceq_privacy_settings: "{}", iceq_logged_out: "1", iceq_cleanup_required: "1", other_app: "keep" });
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
      async databases() { return [{ name: ICEQ_INDEXEDDB_NAME }, { name: "iceq-signal" }, { name: "other-db" }]; },
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

  assert.deepEqual(deletedDatabases, [ICEQ_INDEXEDDB_NAME, "iceq-signal", ICEQ_INDEXEDDB_NAME, "iceq-signal"]);
  assert.deepEqual(deletedCaches, ["iceq-static-v3", "iceq-static-v2", "iceq-static-v3", "iceq-static-v2"]);
  assert.deepEqual(revokedUrls, ["blob:iceq-secret"]);
  assert.deepEqual(unregisteredWorkers, ["https://iceq.test/sw.js", "https://iceq.test/sw.js"]);
  assert.equal(resets, 2);
  assert.deepEqual([...local.entries], [["iceq_logged_out", "1"], ["iceq_cleanup_required", "1"], ["other_app", "keep"]]);
  assert.deepEqual([...session.entries], [["unrelated", "keep"]]);
});

test("concurrent cleanup callers share one IndexedDB deletion flight", async () => {
  let deletes = 0;
  let finish: (() => void) | undefined;
  Object.defineProperty(globalThis, "indexedDB", { configurable: true, value: {
    async databases() { return [{ name: ICEQ_INDEXEDDB_NAME }]; },
    deleteDatabase() { deletes += 1; const request: Record<string, (() => void) | null> = { onsuccess: null, onerror: null, onblocked: null }; finish = () => request.onsuccess?.(); return request; },
  } });
  const first = clearAllIceQLocalData("logout");
  const second = clearAllIceQLocalData("auth-expired");
  await new Promise((resolve) => setTimeout(resolve, 0));
  assert.equal(deletes, 1);
  finish?.();
  await Promise.all([first, second]);
});

test("a blocked delete that later succeeds remains one request", async () => {
  let deletes = 0;
  Object.defineProperty(globalThis, "indexedDB", { configurable: true, value: {
    async databases() { return [{ name: ICEQ_INDEXEDDB_NAME }]; },
    deleteDatabase() { deletes += 1; const request: Record<string, (() => void) | null> = { onsuccess: null, onerror: null, onblocked: null }; queueMicrotask(() => { request.onblocked?.(); queueMicrotask(() => request.onsuccess?.()); }); return request; },
  } });
  await Promise.all([clearAllIceQLocalData("panic-wipe"), clearAllIceQLocalData("logout")]);
  assert.equal(deletes, 1);
});

test("untracked object URLs are not revoked by later cleanup", async () => {
  const revoked: string[] = [];
  Object.defineProperty(globalThis.URL, "revokeObjectURL", { configurable: true, value: (url: string) => revoked.push(url) });
  trackObjectURL("blob:finished");
  untrackObjectURL("blob:finished");
  await clearAllIceQLocalData("logout");
  assert.deepEqual(revoked, []);
});

test("a failed object URL revoke remains tracked for cleanup retry", async () => {
  const attempts: string[] = [];
  let fail = true;
  Object.defineProperty(globalThis.URL, "revokeObjectURL", { configurable: true, value: (url: string) => {
    attempts.push(url);
    if (fail) throw new Error("busy");
  } });
  Object.defineProperty(globalThis, "indexedDB", { configurable: true, value: undefined });
  trackObjectURL("blob:retry-me");
  await assert.rejects(clearAllIceQLocalData("panic-wipe"), LocalCleanupError);
  fail = false;
  await clearAllIceQLocalData("panic-wipe");
  assert.deepEqual(attempts, ["blob:retry-me", "blob:retry-me"]);
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
    (error: unknown) => error instanceof LocalCleanupError && error.failures.filter((failure) => failure.area === "indexeddb").length === 4,
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
