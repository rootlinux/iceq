import test from "node:test";
import assert from "node:assert/strict";

import { ICEQ_INDEXEDDB_NAME } from "../src/lib/indexeddb.js";
import { clearLocalState } from "../src/lib/wsCloseCodes.js";

test("clearLocalState removes IceQ localStorage keys and deletes the real IceQ IndexedDB", async () => {
  const removedKeys: string[] = [];
  const deletedDatabases: string[] = [];

  const storage = new Map<string, string>([
    ["iceq_access_token", "token"],
    ["iceq_ios_hint_shown", "1"],
    ["other_app", "keep"],
  ]);

  const localStorageStub = {
    get length() {
      return storage.size;
    },
    key(index: number) {
      return [...storage.keys()][index] ?? null;
    },
    removeItem(key: string) {
      removedKeys.push(key);
      storage.delete(key);
    },
  };

  const indexedDBStub = {
    deleteDatabase(name: string) {
      deletedDatabases.push(name);
      const request: Record<string, (() => void) | null> = { onsuccess: null, onerror: null, onblocked: null };
      queueMicrotask(() => request.onsuccess?.());
      return request;
    },
  };

  Object.defineProperty(globalThis, "localStorage", {
    configurable: true,
    value: localStorageStub,
  });
  Object.defineProperty(globalThis, "indexedDB", {
    configurable: true,
    value: indexedDBStub,
  });

  await Promise.resolve(clearLocalState());

  assert.deepEqual(removedKeys.sort(), ["iceq_access_token", "iceq_ios_hint_shown"]);
  assert.deepEqual(deletedDatabases, [ICEQ_INDEXEDDB_NAME]);
  assert.equal(storage.has("other_app"), true);
});
