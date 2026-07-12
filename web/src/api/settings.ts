// SecuritySettings — API client for /api/auth/settings.
//
// The auth-service's settings endpoint returns the documented
// defaults (panic_wipe_enabled=false, panic_wipe_threshold=3) when
// no row exists. We model that as a nullable updated_at: the client
// can tell "user has never saved" (updatedAt == null) from "user
// explicitly turned it off" (updatedAt is a date).
//
// The wipe is opt-in. The defaults are the safe defaults: feature
// off, threshold at a low number for users who choose to enable
// it. A naive client that shows the wrong initial state could
// give the user a false sense of security ("it says ON, must be
// safe") — so the render is explicit about "this is the saved
// value, not the default".

import { fetchJSON } from "./client";

export interface SecuritySettings {
  panic_wipe_enabled: boolean;
  panic_wipe_threshold: number;
  // null when the user has never visited the settings page.
  updated_at: string | null;
}

export interface SettingsUpdate {
  panic_wipe_enabled: boolean;
  panic_wipe_threshold: number;
}

// Thresholds bounded 1..10 to match the DB CHECK constraint and
// the auth-service handler's Validate(). Exported because the
// UI uses the same numbers in the dropdown.
export const MIN_THRESHOLD = 1;
export const MAX_THRESHOLD = 10;
export const DEFAULT_THRESHOLD = 3;

export async function getSettings(): Promise<SecuritySettings> {
  return fetchJSON<SecuritySettings>("/api/auth/settings", { method: "GET" });
}

export async function putSettings(update: SettingsUpdate): Promise<SecuritySettings> {
  return fetchJSON<SecuritySettings>("/api/auth/settings", {
    method: "PUT",
    body: update,
  });
}
