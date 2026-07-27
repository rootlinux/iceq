// src/api/presence.ts
//
// REST client for the presence-service's bulk snapshot endpoint
// (POST /api/presence/bulk, mounted at that path in the Caddyfile).
//
// The real-time presence pipeline (see useWebSocket.ts's "presence"
// case) only delivers DELTA transitions over presence.notify.{uin} --
// a contact who was already online before this client connected never
// generates a transition event, so without this snapshot fetch a
// contact's current status stays unknown ("offline" by the store's
// fallback) until they happen to go offline/online again while this
// client is connected.

import { fetchJSON } from "./client";
import type { PresenceStatus } from "../types/models";

export interface BulkPresenceEntry {
  status: PresenceStatus;
  last_seen: number;
}

export async function getBulkPresence(uins: number[]): Promise<Record<string, BulkPresenceEntry>> {
  if (uins.length === 0) return {};
  return fetchJSON<Record<string, BulkPresenceEntry>>("/api/presence/bulk", {
    method: "POST",
    body: { uins },
  });
}
