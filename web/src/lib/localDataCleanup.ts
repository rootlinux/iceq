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
let cleanupFlightReason: CleanupReason | null = null;
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
  if (cleanupFlight) {
    if (reasonErasesCryptoIdentity(reason) && cleanupFlightReason !== null && !reasonErasesCryptoIdentity(cleanupFlightReason)) {
      // A server-confirmed wipe must never inherit a weaker logout/auth-expiry
      // result. Wait for the current browser-resource operations to settle,
      // then run the destructive pass even if the weaker pass failed.
      return trackCleanupFlight(cleanupFlight.catch(() => undefined).then(() => performCleanup(reason)), reason);
    }
    return cleanupFlight;
  }
  return trackCleanupFlight(performCleanup(reason), reason);
}

function trackCleanupFlight(work: Promise<void>, reason: CleanupReason): Promise<void> {
  const tracked = work.finally(() => {
    if (cleanupFlight === tracked) {
      cleanupFlight = null;
      cleanupFlightReason = null;
    }
  });
  cleanupFlight = tracked;
  cleanupFlightReason = reason;
  return tracked;
}

// Reasons that must destructively erase the local Signal identity and
// message cache (the "iceq" IndexedDB database). "auth-expired" and
// "logout" intentionally do NOT appear here: an expired or failed session
// token is not evidence of device compromise, and destroying the only copy
// of a locally-held E2EE identity on every benign session end -- a network
// hiccup during token refresh, a long-idle refresh token finally expiring
// -- would turn an ordinary reliability blip into unrecoverable account
// loss (there is no server-side backup of the private key by design).
// Logging back in on the same device should resume exactly where the user
// left off, the same way Signal/WhatsApp behave. The deliberate "destroy
// this device's access right now" action is panic-wipe (PIN-gated, see
// SecuritySettings); "account-change" wipes so switching to a second
// account on the same device never leaves the previous account's keys
// reachable from the new session.
const REASONS_THAT_ERASE_CRYPTO_IDENTITY: ReadonlySet<CleanupReason> = new Set(["panic-wipe", "account-change"]);

export function reasonErasesCryptoIdentity(reason: CleanupReason): boolean {
  return REASONS_THAT_ERASE_CRYPTO_IDENTITY.has(reason);
}

async function performCleanup(reason: CleanupReason): Promise<void> {
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
      const script = registration.active?.scriptURL ?? registration.waiting?.scriptURL ?? registration.installing?.scriptURL;
      if (await registration.unregister()) return;
      // Another IceQ tab may have unregistered the same worker between the
      // initial enumeration and this call. Treat that as successful only after
      // verifying the target script is actually absent; a still-registered
      // worker remains a mandatory cleanup failure.
      const remaining = await navigator.serviceWorker.getRegistrations();
      const stillRegistered = remaining.some((candidate) => {
        const candidateScript = candidate.active?.scriptURL ?? candidate.waiting?.scriptURL ?? candidate.installing?.scriptURL;
        return script !== undefined && candidateScript === script;
      });
      if (stillRegistered) throw new Error("Service worker unregistration failed");
    }));
  });
  await capture("cache-storage", async () => {
    if (typeof caches === "undefined") return;
    const names = await caches.keys();
    await Promise.all(names.filter((name) => name.startsWith(ICEQ_CACHE_PREFIX)).map(async (name) => {
      if (await caches.delete(name)) return;
      // CacheStorage.delete returns false both on a genuine failure and when a
      // concurrent tab already removed the cache. Re-read the authoritative
      // state so multi-tab panic wipe stays idempotent without weakening the
      // fail-closed behavior for data that remains present.
      if (await caches.has(name)) throw new Error(`Cache deletion failed: ${name}`);
    }));
  });
  if (typeof indexedDB !== "undefined" && reasonErasesCryptoIdentity(reason)) {
    const databaseNames = await iceQDatabaseNames();
    for (const name of databaseNames) await capture("indexeddb", () => deleteIceQDatabase(name));
  }

  if (failures.length > 0) throw new LocalCleanupError(failures);
}
