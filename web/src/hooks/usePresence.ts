// src/hooks/usePresence.ts
//
// Thin wrapper over the contactStore presence map. Components
// subscribe to just the slice they care about, so a presence
// update for UIN A doesn't re-render a list item for UIN B.

import { useContactStore } from "../store/contactStore";
import type { PresenceState, PresenceStatus } from "../types/models";

const FALLBACK: PresenceState = {
  uin: 0,
  status: "offline",
  last_seen_ts: 0,
};

export function usePresence(uin: number): PresenceState {
  return useContactStore((s) => s.presence[uin] ?? { ...FALLBACK, uin });
}

// Variant: just the status. Cheaper to read in a render
// path that only cares about the color, not the timestamp.
export function usePresenceStatus(uin: number): PresenceStatus {
  return useContactStore((s) => s.presence[uin]?.status ?? "offline");
}
