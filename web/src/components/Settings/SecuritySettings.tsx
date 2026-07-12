// SecuritySettings — per-user panic-wipe configuration panel.
//
// UX flow:
//
//   1. On mount, GET /api/auth/settings. Render a loading state
//      while the request is in flight.
//   2. When loaded, render the current state:
//      - toggle off: "Auto-wipe is OFF" + a single "Enable" button
//      - toggle on:  "Auto-wipe is ON — triggers after N attempts"
//                    + a threshold selector + "Save" / "Disable"
//   3. When the user clicks "Enable", open a confirmation modal.
//      The modal text interpolates the chosen threshold so the
//      user sees the exact number they're about to commit to.
//      Buttons: "Enable" (red, destructive) | "Cancel".
//   4. On confirmation, PUT /api/auth/settings with the new
//      values. On success, refresh the local state from the
//      response so the UI shows what the server actually saved.
//   5. On 4xx/5xx, render an inline error and keep the panel in
//      its current state (no implicit revert).
//
// Why a confirmation modal: the wipe is destructive and the user
// may have mis-toggled. The modal gives them a moment to read
// the exact consequence ("after N failed login attempts all your
// messages, contacts, and keys will be permanently deleted and
// unrecoverable") before they commit.
//
// Why the threshold selector is hidden when disabled: the value
// has no effect when the feature is off, so showing a number
// would imply otherwise. The user enables the feature first,
// then picks the threshold.

import { useCallback, useEffect, useState } from "react";
import {
  DEFAULT_THRESHOLD,
  MAX_THRESHOLD,
  MIN_THRESHOLD,
  SecuritySettings as Settings,
  getSettings,
  putSettings,
} from "../../api/settings";
import { loadIdentity } from "../../lib/indexeddb";

type Status =
  | { kind: "loading" }
  | { kind: "loaded"; settings: Settings }
  | { kind: "error"; message: string };

type ConfirmState =
  | { kind: "none" }
  | { kind: "enable"; threshold: number };

type FingerprintStatus =
  | { kind: "loading" }
  | { kind: "ready"; fingerprint: string | null }
  | { kind: "error" };

export function SecuritySettings(): JSX.Element {
  const [status, setStatus] = useState<Status>({ kind: "loading" });
  // Working copy of the threshold. Kept separate from
  // `status.settings.panic_wipe_threshold` so the user can
  // adjust it before clicking Save without us mutating the
  // rendered "currently saved" value.
  const [draftThreshold, setDraftThreshold] = useState<number>(DEFAULT_THRESHOLD);
  const [confirm, setConfirm] = useState<ConfirmState>({ kind: "none" });
  const [fingerprintStatus, setFingerprintStatus] = useState<FingerprintStatus>({
    kind: "loading",
  });
  const [saving, setSaving] = useState(false);

  // Initial fetch.
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const s = await getSettings();
        if (cancelled) return;
        setStatus({ kind: "loaded", settings: s });
        setDraftThreshold(s.panic_wipe_threshold);
      } catch (e) {
        if (cancelled) return;
        setStatus({ kind: "error", message: (e as Error).message });
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const identity = await loadIdentity();
        const fingerprint = identity
          ? await fingerprintIdentityKey(identity.publicKey)
          : null;
        if (cancelled) return;
        setFingerprintStatus({ kind: "ready", fingerprint });
      } catch {
        if (cancelled) return;
        setFingerprintStatus({ kind: "error" });
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const onToggle = useCallback(
    (nextEnabled: boolean) => {
      if (status.kind !== "loaded") return;
      if (nextEnabled) {
        // Open the confirmation modal. We pass the
        // draftThreshold through the modal so the warning
        // text interpolates the chosen number.
        setConfirm({ kind: "enable", threshold: draftThreshold });
      } else {
        // Disable is non-destructive — apply immediately.
        // The user is un-doing an opt-in, not opting in
        // for the first time, so no modal is needed.
        void saveSettings(status.settings.panic_wipe_enabled, draftThreshold, false);
      }
    },
    [status, draftThreshold],
  );

  const onConfirmEnable = useCallback(() => {
    if (confirm.kind !== "enable") return;
    setConfirm({ kind: "none" });
    void saveSettings(true, confirm.threshold, true);
  }, [confirm]);

  const onCancelConfirm = useCallback(() => {
    setConfirm({ kind: "none" });
  }, []);

  const saveSettings = useCallback(
    async (enabled: boolean, threshold: number, _isFirstEnable: boolean) => {
      setSaving(true);
      try {
        const updated = await putSettings({
          panic_wipe_enabled: enabled,
          panic_wipe_threshold: threshold,
        });
        setStatus({ kind: "loaded", settings: updated });
        setDraftThreshold(updated.panic_wipe_threshold);
      } catch (e) {
        // Inline error. Keep the panel in its current
        // state so the user can retry without re-entering
        // values.
        setStatus({
          kind: "error",
          message: (e as Error).message,
        });
      } finally {
        setSaving(false);
      }
    },
    [],
  );

  if (status.kind === "loading") {
    return <div className="iceq-settings-panel">Loading security settings…</div>;
  }

  if (status.kind === "error") {
    return (
      <div className="iceq-settings-panel iceq-settings-error">
        Could not load security settings: {status.message}
      </div>
    );
  }

  const { settings } = status;
  const isEnabled = settings.panic_wipe_enabled;

  return (
    <div className="iceq-settings-panel">
      <h3>Security</h3>

      <div className="iceq-settings-row">
        <label className="iceq-toggle">
          <input
            type="checkbox"
            checked={isEnabled}
            disabled={saving}
            onChange={(e) => onToggle(e.target.checked)}
          />
          <span>Auto-wipe on failed logins</span>
        </label>
      </div>

      {isEnabled && (
        <>
          <div className="iceq-settings-row">
            <label htmlFor="panic-wipe-threshold">
              Threshold (failed attempts before wipe)
            </label>
            <select
              id="panic-wipe-threshold"
              value={draftThreshold}
              disabled={saving}
              onChange={(e) =>
                setDraftThreshold(parseInt(e.target.value, 10) || DEFAULT_THRESHOLD)
              }
            >
              {Array.from(
                { length: MAX_THRESHOLD - MIN_THRESHOLD + 1 },
                (_, i) => i + MIN_THRESHOLD,
              ).map((n) => (
                <option key={n} value={n}>
                  {n}
                </option>
              ))}
            </select>
          </div>

          <div className="iceq-settings-row">
            <button
              type="button"
              disabled={saving || draftThreshold === settings.panic_wipe_threshold}
              onClick={() =>
                saveSettings(true, draftThreshold, false)
              }
            >
              {saving ? "Saving…" : "Save"}
            </button>
          </div>
        </>
      )}

      <div className="iceq-settings-status">
        {isEnabled
          ? `Auto-wipe: ON — triggers after ${settings.panic_wipe_threshold} failed attempts`
          : "Auto-wipe: OFF"}
      </div>

      <div className="iceq-settings-row">
        <div className="iceq-settings-status">
          <strong>Local identity fingerprint</strong>
          <div>{renderFingerprint(fingerprintStatus)}</div>
          <p>
            Compare this fingerprint out-of-band with contacts. This only verifies
            the key stored on this device.
          </p>
        </div>
      </div>

      {confirm.kind === "enable" && (
        <div className="iceq-modal-backdrop" role="dialog" aria-modal="true">
          <div className="iceq-modal">
            <h4>Enable auto-wipe?</h4>
            <p>
              If enabled, after {confirm.threshold} failed login attempts all your
              messages, contacts, and keys will be permanently deleted and
              unrecoverable. This cannot be undone.
            </p>
            <div className="iceq-modal-buttons">
              <button
                type="button"
                className="iceq-btn-destructive"
                onClick={onConfirmEnable}
                disabled={saving}
              >
                Enable
              </button>
              <button
                type="button"
                className="iceq-btn-secondary"
                onClick={onCancelConfirm}
                disabled={saving}
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function renderFingerprint(status: FingerprintStatus): string {
  if (status.kind === "loading") return "Loading...";
  if (status.kind === "error") return "Fingerprint unavailable.";
  return status.fingerprint ?? "No identity key on this device yet.";
}

async function fingerprintIdentityKey(publicKey: string): Promise<string> {
  const digest = new Uint8Array(
    await globalThis.crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(publicKey),
    ),
  );
  const groups: string[] = [];
  for (let i = 0; i < 8; i++) {
    const offset = i * 2;
    const value = ((digest[offset] ?? 0) << 8) | (digest[offset + 1] ?? 0);
    groups.push(value.toString(16).padStart(4, "0"));
  }
  return groups.join(" ").toUpperCase();
}

export default SecuritySettings;
