import { ICEQ_INDEXEDDB_NAME, resetIndexedDBRuntime } from "./indexeddb";

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
export const ICEQ_LOGGED_OUT_MARKER_KEY = "iceq_logged_out";
export const ICEQ_CLEANUP_REQUIRED_MARKER_KEY = "iceq_cleanup_required";
const LEGACY_ICEQ_DATABASES = ["iceq-signal", "iceq-messages", "iceq-keys"] as const;
let cleanupFlight: Promise<void> | null = null;
const outstandingBlockedDatabases = new Set<string>();

export function registerMemoryReset(reset: () => void): () => void {
  memoryResetters.add(reset);
  return () => memoryResetters.delete(reset);
}

export function trackObjectURL(url: string): void {
  objectUrls.add(url);
}

export function untrackObjectURL(url: string): void {
  objectUrls.delete(url);
}

export function resetIceQMemory(): void {
  for (const reset of memoryResetters) {
    try { reset(); } catch { /* durable cleanup reports reset failures on its pass */ }
  }
}

function isIceQStorageKey(key: string): boolean {
  return key.startsWith("iceq_") || key.startsWith("iceq:") || key.startsWith("iceq-");
}

function clearStorage(storage: Storage | undefined, preserved = new Set<string>()): void {
  if (!storage) return;
  for (let index = storage.length - 1; index >= 0; index -= 1) {
    const key = storage.key(index);
    if (key && isIceQStorageKey(key) && !preserved.has(key)) storage.removeItem(key);
  }
}

async function iceQDatabaseNames(): Promise<string[]> {
  const fallback = [ICEQ_INDEXEDDB_NAME, ...LEGACY_ICEQ_DATABASES];
  if (typeof indexedDB === "undefined" || !indexedDB.databases) return fallback;
  try {
    const databases = await indexedDB.databases();
    return [...new Set([ICEQ_INDEXEDDB_NAME, ...databases.flatMap((db) => db.name && (db.name === ICEQ_INDEXEDDB_NAME || db.name.startsWith("iceq-")) ? [db.name] : [])])];
  } catch {
    return fallback;
  }
}

async function deleteIceQDatabase(name: string): Promise<void> {
  if (typeof indexedDB === "undefined") return;
  if (outstandingBlockedDatabases.has(name)) throw new Error(`IndexedDB deletion is still outstanding: ${name}`);
  await new Promise<void>((resolve, reject) => {
    let request: IDBOpenDBRequest;
    try {
      request = indexedDB.deleteDatabase(name);
    } catch (error) {
      reject(error);
      return;
    }
    const timeout = setTimeout(() => { outstandingBlockedDatabases.add(name); reject(new Error("IndexedDB deletion remained blocked")); }, 1_000);
    request.onsuccess = () => { clearTimeout(timeout); outstandingBlockedDatabases.delete(name); resolve(); };
    request.onerror = () => { clearTimeout(timeout); outstandingBlockedDatabases.delete(name); reject(request.error ?? new Error("IndexedDB deletion failed")); };
    request.onblocked = () => { /* keep this single request alive for a bounded grace period */ };
  });
}

export function clearAllIceQLocalData(reason: CleanupReason): Promise<void> {
  // A later reason joins the active cleanup. Every reason has the same durable
  // deletion contract, so overlapping deleteDatabase requests add risk only.
  if (cleanupFlight) return cleanupFlight;
  cleanupFlight = performCleanup(reason).finally(() => { cleanupFlight = null; });
  return cleanupFlight;
}

async function performCleanup(_reason: CleanupReason): Promise<void> {
  const failures: CleanupFailure[] = [];
  const capture = async (area: string, operation: () => void | Promise<void>): Promise<void> => {
    try { await operation(); } catch (cause) { failures.push({ area, cause }); }
  };

  await capture("indexeddb-memory", resetIndexedDBRuntime);
  for (const reset of memoryResetters) await capture("memory", reset);
  if (typeof URL !== "undefined" && typeof URL.revokeObjectURL === "function") {
    for (const url of [...objectUrls]) await capture("object-urls", () => {
      URL.revokeObjectURL(url);
      objectUrls.delete(url);
    });
  }
  await capture("local-storage", () => clearStorage(typeof localStorage === "undefined" ? undefined : localStorage, new Set([ICEQ_LOGGED_OUT_MARKER_KEY, ICEQ_CLEANUP_REQUIRED_MARKER_KEY])));
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
  if (typeof indexedDB !== "undefined") {
    const databaseNames = await iceQDatabaseNames();
    for (const name of databaseNames) await capture("indexeddb", () => deleteIceQDatabase(name));
  }

  if (failures.length > 0) throw new LocalCleanupError(failures);
}
