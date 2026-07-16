import { ICEQ_INDEXEDDB_NAME } from "./indexeddb";

export type CleanupReason = "logout" | "panic-wipe" | "account-change" | "auth-expired";
export type CleanupFailure = { area: string; cause: unknown };

export class LocalCleanupError extends Error {
  constructor(public readonly failures: CleanupFailure[]) {
    super(`IceQ local cleanup failed in: ${failures.map((failure) => failure.area).join(", ")}`);
    this.name = "LocalCleanupError";
  }
}

const memoryResetters = new Set<() => void>();
const objectUrls = new Set<string>();
const ICEQ_CACHE_PREFIX = "iceq-static-";

export function registerMemoryReset(reset: () => void): () => void {
  memoryResetters.add(reset);
  return () => memoryResetters.delete(reset);
}

export function trackObjectURL(url: string): void {
  objectUrls.add(url);
}

function isIceQStorageKey(key: string): boolean {
  return key.startsWith("iceq_") || key.startsWith("iceq:") || key.startsWith("iceq-");
}

function clearStorage(storage: Storage | undefined): void {
  if (!storage) return;
  for (let index = storage.length - 1; index >= 0; index -= 1) {
    const key = storage.key(index);
    if (key && isIceQStorageKey(key)) storage.removeItem(key);
  }
}

async function deleteIceQDatabase(): Promise<void> {
  if (typeof indexedDB === "undefined") return;
  await new Promise<void>((resolve, reject) => {
    let request: IDBOpenDBRequest;
    try {
      request = indexedDB.deleteDatabase(ICEQ_INDEXEDDB_NAME);
    } catch (error) {
      reject(error);
      return;
    }
    request.onsuccess = () => resolve();
    request.onerror = () => reject(request.error ?? new Error("IndexedDB deletion failed"));
    request.onblocked = () => reject(new Error("IndexedDB deletion was blocked"));
  });
}

export async function clearAllIceQLocalData(_reason: CleanupReason): Promise<void> {
  const failures: CleanupFailure[] = [];
  const capture = async (area: string, operation: () => void | Promise<void>): Promise<void> => {
    try { await operation(); } catch (cause) { failures.push({ area, cause }); }
  };

  for (const reset of memoryResetters) await capture("memory", reset);
  if (typeof URL !== "undefined" && typeof URL.revokeObjectURL === "function") {
    for (const url of objectUrls) await capture("object-urls", () => URL.revokeObjectURL(url));
    objectUrls.clear();
  }
  await capture("local-storage", () => clearStorage(typeof localStorage === "undefined" ? undefined : localStorage));
  await capture("session-storage", () => clearStorage(typeof sessionStorage === "undefined" ? undefined : sessionStorage));
  await capture("service-worker", async () => {
    if (typeof navigator === "undefined" || !navigator.serviceWorker?.getRegistrations) return;
    const registrations = await navigator.serviceWorker.getRegistrations();
    await Promise.all(registrations.filter((registration) => {
      const script = registration.active?.scriptURL ?? registration.waiting?.scriptURL ?? registration.installing?.scriptURL;
      return script ? new URL(script).pathname === "/sw.js" : false;
    }).map(async (registration) => {
      if (!await registration.unregister()) throw new Error("Service worker unregistration failed");
    }));
  });
  await capture("cache-storage", async () => {
    if (typeof caches === "undefined") return;
    const names = await caches.keys();
    await Promise.all(names.filter((name) => name.startsWith(ICEQ_CACHE_PREFIX)).map(async (name) => {
      if (!await caches.delete(name)) throw new Error(`Cache deletion failed: ${name}`);
    }));
  });
  await capture("indexeddb", deleteIceQDatabase);

  if (failures.length > 0) throw new LocalCleanupError(failures);
}
