import { ICEQ_INDEXEDDB_NAME } from "./indexeddb.js";

// wsCloseCodes — central registry for custom WebSocket close codes
// used by the IceQ platform. RFC 6455 reserves 4000-4999 for
// application use; IceQ uses:
//
//   4401  — UNAUTHORIZED. Token missing / invalid / expired. Client
//           should attempt refresh; if refresh fails, redirect to
//           /login.
//   4403  — WIPED. The user was wiped by the panic-wipe addendum.
//           Client MUST clear local state (IndexedDB session state,
//           message cache, localStorage) and redirect to /login.
//           There is no recovery; the account is unrecoverable.
//
// Centralizing the codes here means a single grep finds every
// place in the client that has to handle them. The numbers
// themselves are part of the protocol contract with the
// ws-gateway; do not renumber without coordinating with the
// gateway side.

export const WS_CLOSE_UNAUTHORIZED = 4401;
export const WS_CLOSE_WIPED = 4403;

// onClose is the entry point the WebSocket lifecycle calls when
// the connection drops. We branch on the close code; any code
// outside the 44xx range is treated as a transient disconnect
// and the caller is expected to reconnect with backoff.
//
// The function returns a discriminated union so the caller can
// decide what to do without re-classifying the code.
export type WsCloseAction =
  | { kind: "wiped" }
  | { kind: "unauthorized" }
  | { kind: "transient" };

export function classifyClose(code: number): WsCloseAction {
  switch (code) {
    case WS_CLOSE_WIPED:
      return { kind: "wiped" };
    case WS_CLOSE_UNAUTHORIZED:
      return { kind: "unauthorized" };
    default:
      return { kind: "transient" };
  }
}

// clearLocalState is called on a 4403 (wipe) close. It deletes
// every IceQ-owned key from localStorage and asks the runtime
// to drop the IndexedDB databases that hold Signal session
// state and the message cache.
//
// After this returns, the client should redirect to /login.
// The redirect is the caller's responsibility — this function
// does not navigate so it can be unit-tested without a
// router in scope.
export function clearLocalState(): void {
  // localStorage. Iterate rather than clear() so we leave
  // any non-IceQ keys (e.g. third-party analytics) intact.
  for (let i = localStorage.length - 1; i >= 0; i--) {
    const k = localStorage.key(i);
    if (k && k.startsWith("iceq_")) {
      localStorage.removeItem(k);
    }
  }

  // IndexedDB. The live client store uses the concrete
  // "iceq" database name; delete it directly so wipe
  // works in browsers without indexedDB.databases().
  if (typeof indexedDB !== "undefined") {
    indexedDB.deleteDatabase(ICEQ_INDEXEDDB_NAME);

    // Clean up any older per-feature IceQ DBs left behind
    // by previous client versions when enumeration exists.
    if (indexedDB.databases) {
      void indexedDB
        .databases()
        .then((dbs) => {
          for (const db of dbs) {
            if (db.name && db.name.startsWith("iceq-")) {
              indexedDB.deleteDatabase(db.name);
            }
          }
        })
        .catch(() => {
          // Best-effort cleanup only.
        });
    }
  }
}
