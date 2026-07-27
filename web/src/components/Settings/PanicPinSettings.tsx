import { useState } from "react";
import type { FormEvent } from "react";
import { ApiError } from "../../api/client";
import { setPanicPin } from "../../api/auth";
import { useI18n } from "../../i18n";

const PIN_PATTERN = /^[0-9]{4}$/;

function getPanicPinErrorMessage(error: unknown, t: ReturnType<typeof useI18n>["t"]): string {
  if (error instanceof ApiError) {
    if (error.code === "INVALID_PASSWORD") return t("security.panicPinWrongPassword");
    if (error.code === "INVALID_PIN") return t("security.panicPinInvalid");
  }
  return t("security.panicPinSaveFailed");
}

export function PanicPinSettings(): JSX.Element {
  const i18n = useI18n();
  const [currentPassword, setCurrentPassword] = useState("");
  const [pin, setPin] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  async function onSubmit(e: FormEvent): Promise<void> {
    e.preventDefault();
    setError(null);
    setSuccess(null);
    if (pin !== "" && !PIN_PATTERN.test(pin)) {
      setError(i18n.t("security.panicPinInvalid"));
      return;
    }
    setBusy(true);
    try {
      await setPanicPin(currentPassword, pin);
      setSuccess(pin === "" ? i18n.t("security.panicPinCleared") : i18n.t("security.panicPinSetSuccess"));
      setCurrentPassword("");
      setPin("");
    } catch (err) {
      setError(getPanicPinErrorMessage(err, i18n.t));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="iceq-settings-row">
      <div className="iceq-settings-status">
        <strong>{i18n.t("security.panicPinTitle")}</strong>
        <p>{i18n.t("security.panicPinHelp")}</p>
        <form onSubmit={(e) => void onSubmit(e)} className="space-y-2">
          <div>
            <label htmlFor="panic-pin-current-password" className="mb-1 block text-xs text-text-2">
              {i18n.t("security.panicPinCurrentPassword")}
            </label>
            <input
              id="panic-pin-current-password"
              type="password"
              autoComplete="current-password"
              className="iceq-input"
              value={currentPassword}
              onChange={(event) => setCurrentPassword(event.target.value)}
              disabled={busy}
              required
            />
          </div>
          <div>
            <label htmlFor="panic-pin-new" className="mb-1 block text-xs text-text-2">
              {i18n.t("security.panicPinNewPin")}
            </label>
            <input
              id="panic-pin-new"
              type="password"
              inputMode="numeric"
              autoComplete="off"
              maxLength={4}
              pattern="[0-9]{4}"
              className="iceq-input"
              value={pin}
              onChange={(event) => setPin(event.target.value.replace(/[^0-9]/g, "").slice(0, 4))}
              disabled={busy}
            />
          </div>
          {error && (
            <div role="alert" className="rounded-md border border-presence-dnd bg-surface p-2 text-sm">
              {error}
            </div>
          )}
          {success && (
            <div role="status" className="rounded-md border border-presence-online bg-surface p-2 text-sm">
              {success}
            </div>
          )}
          <button type="submit" className="iceq-btn-secondary" disabled={busy || currentPassword === ""}>
            {i18n.t("security.panicPinSave")}
          </button>
        </form>
      </div>
    </div>
  );
}

export default PanicPinSettings;
