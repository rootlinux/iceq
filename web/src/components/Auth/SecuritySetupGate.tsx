// src/components/Auth/SecuritySetupGate.tsx
//
// Mandatory first-login security setup wizard. Arctic Signal design.
// Steps: intro → passphrase → unlock → wipekey → recovery → confirm.
//
// Wipekey runs BEFORE recovery so the wipe key exists in IndexedDB by
// the time createRecoveryPackage() gathers the payload — see
// recoveryPackage.ts's gatherRecoveryPayload, which embeds whatever
// wipe key it finds.

import { useState, useEffect, useRef } from "react";
import { useNavigate } from "react-router-dom";
import { useAuthStore } from "../../store/authStore";
import { getActiveCryptoNamespace, hasSecuritySetupCompleted, setSecuritySetupCompleted } from "../../lib/indexeddb";
import { createSecurityPassphrase, hasSecurityPassphrase, isVaultUnlocked, unlockSecurityVault } from "../../lib/securityVault";
import { generateRecoveryKey, createRecoveryPackage } from "../../lib/recoveryPackage";
import {
  loadOrCreateWipeKeyPair,
  storeEncryptedWipePrivateKey,
  reconcileWipeKey,
  clearLocalWipeKey,
  bytesToBase64std,
} from "../../lib/panicWipeKey";
import { uploadWipePublicKey } from "../../api/auth";
import { ApiError } from "../../api/client";
import { useI18n } from "../../i18n";
import { IceQWordmark } from "../Brand/IceQWordmark";
import QRCode from "qrcode";

const MIN_PASSPHRASE_LENGTH = 12;

type SetupStep = "intro" | "passphrase" | "unlock" | "wipekey" | "recovery" | "confirm";

interface SecuritySetupGateProps {
  onSetupComplete?: () => void;
}


export function SecuritySetupGate({ onSetupComplete }: SecuritySetupGateProps): JSX.Element {
  const navigate = useNavigate();
  const uin = useAuthStore((s) => s.uin);
  const i18n = useI18n();
  const [step, setStep] = useState<SetupStep>("intro");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const [passphrase, setPassphrase] = useState("");
  const [passphraseConfirm, setPassphraseConfirm] = useState("");

  const [recoveryKeyB64, setRecoveryKeyB64] = useState("");
  const [recoveryPackage, setRecoveryPackage] = useState("");
  const [recoveryGenerated, setRecoveryGenerated] = useState(false);
  const canvasRef = useRef<HTMLCanvasElement>(null);

  const [savedConfirm, setSavedConfirm] = useState(false);

  const [accountPassword, setAccountPassword] = useState("");
  const [accountPasswordInvalid, setAccountPasswordInvalid] = useState(false);
  const accountPasswordRef = useRef<HTMLInputElement>(null);

  const [unlockPassphrase, setUnlockPassphrase] = useState("");
  const [hasExistingVault, setHasExistingVault] = useState(false);

  useEffect(() => {
    const ns = getActiveCryptoNamespace();
    void hasSecuritySetupCompleted(ns).then(async (done) => {
      if (done) { navigate("/app", { replace: true }); return; }
      if (await hasSecurityPassphrase()) {
        setHasExistingVault(true);
        if (isVaultUnlocked()) {
          setStep("wipekey");
        } else {
          setStep("unlock");
        }
      }
    });
  }, [navigate]);

  useEffect(() => {
    setPassphrase("");
    setPassphraseConfirm("");
    setUnlockPassphrase("");
    setAccountPasswordInvalid(false);
  }, [step]);

  useEffect(() => {
    if (step === "wipekey" && accountPasswordInvalid && !busy) {
      accountPasswordRef.current?.focus();
    }
  }, [step, accountPasswordInvalid, busy]);

  useEffect(() => {
    if (!recoveryKeyB64 || !canvasRef.current) return;
    let cancelled = false;
    void QRCode.toCanvas(canvasRef.current, recoveryKeyB64, { width: 200, margin: 1 }).then(() => {
      // QR rendered successfully.
    }).catch(() => {
      if (!cancelled) setError(i18n.t("setup.recoveryFailed"));
    });
    return () => { cancelled = true; };
  }, [recoveryKeyB64, recoveryGenerated, i18n]);

  async function handleCreatePassphrase(): Promise<void> {
    setError("");
    if (passphrase.length < MIN_PASSPHRASE_LENGTH) { setError(i18n.t("setup.passphraseTooShort")); return; }
    if (passphrase !== passphraseConfirm) { setError(i18n.t("setup.passphraseMismatch")); return; }
    setBusy(true);
    try {
      await createSecurityPassphrase(passphrase);
      setHasExistingVault(true);
      setPassphrase("");
      setPassphraseConfirm("");
      setStep("wipekey");
    } catch (e) {
      setError((e as Error).message || i18n.t("setup.passphraseFailed"));
    } finally {
      setBusy(false);
    }
  }

  async function handleUnlockVault(): Promise<void> {
    setError("");
    setBusy(true);
    try {
      const ok = await unlockSecurityVault(unlockPassphrase);
      setUnlockPassphrase("");
      if (!ok) {
        setError(i18n.t("setup.unlockFailed"));
        return;
      }
      setStep("wipekey");
    } catch {
      setUnlockPassphrase("");
      setError(i18n.t("setup.unlockFailed"));
    } finally {
      setBusy(false);
    }
  }

  async function handleGenerateRecovery(): Promise<void> {
    setError("");
    setBusy(true);
    try {
      const key = generateRecoveryKey();
      const b64 = bytesToBase64url(new Uint8Array(key));
      setRecoveryKeyB64(b64);

      if (uin === null) throw new Error("not authenticated");
      const { loadIdentity } = await import("../../lib/indexeddb");
      const ns = getActiveCryptoNamespace();
      const storedId = await loadIdentity(ns);
      if (!storedId) throw new Error("no local identity");

      const pkg = await createRecoveryPackage(uin, storedId.publicKey, key);
      setRecoveryPackage(pkg);
      setRecoveryGenerated(true);
    } catch {
      setError(i18n.t("setup.recoveryFailed"));
    } finally {
      setBusy(false);
    }
  }

  async function handleEnableWipeKey(): Promise<void> {
    setError("");
    setAccountPasswordInvalid(false);
    setBusy(true);
    try {
      const { publicKeyBytes, encryptedPrivateBlob, isNew } = await loadOrCreateWipeKeyPair();
      if (isNew) {
        await storeEncryptedWipePrivateKey(encryptedPrivateBlob, publicKeyBytes);
      }

      const pubB64 = bytesToBase64std(publicKeyBytes);
      try {
        await uploadWipePublicKey(pubB64, accountPassword || undefined);
      } catch (uploadErr) {
        const reconciliation = await reconcileWipeKey(publicKeyBytes);
        if (reconciliation.status === "match") {
          // Our key is exactly what's enrolled — proceed.
        } else if (reconciliation.status === "mismatch") {
          await clearLocalWipeKey();
          throw new Error(i18n.t("setup.wipeKeyMismatch"));
        } else {
          throw uploadErr;
        }
      }
      setStep("recovery");
    } catch (e) {
      if (e instanceof ApiError && e.code === "INVALID_PASSWORD") {
        setAccountPasswordInvalid(true);
        setError(i18n.t("setup.accountPasswordIncorrect"));
      } else {
        setError((e as Error).message || i18n.t("setup.completeFailed"));
      }
    } finally {
      setAccountPassword("");
      setBusy(false);
    }
  }

  async function handleComplete(): Promise<void> {
    setError("");
    setBusy(true);
    try {
      const ns = getActiveCryptoNamespace();
      await setSecuritySetupCompleted(ns);
      onSetupComplete?.();
      navigate("/app", { replace: true });
    } catch (e) {
      setError((e as Error).message || i18n.t("setup.completeFailed"));
    } finally {
      setPassphrase("");
      setPassphraseConfirm("");
      setBusy(false);
    }
  }

  // ── Step indicator ──────────────────────────────────────────────────
  function renderStepIndicator(current: SetupStep): JSX.Element | null {
    if (current === "unlock") return null; // unlock is a recovery path, not a normal step
    const steps: { key: SetupStep; label: string }[] = [
      { key: "intro", label: i18n.t("setup.title") },
      { key: "passphrase", label: i18n.t("setup.passphraseLabel") },
      { key: "wipekey", label: i18n.t("setup.wipeKeyTitle") },
      { key: "recovery", label: i18n.t("setup.recoveryKeyLabel") },
      { key: "confirm", label: i18n.t("setup.confirmTitle") },
    ];
    const currentIdx = steps.findIndex((s) => s.key === current);

    return (
      <nav className="iceq-steps">
        {steps.map((s, idx) => {
          const isCurrent = s.key === current;
          const isComplete = idx < currentIdx;
          return (
            <div key={s.key} className="flex items-center gap-2">
              <div
                className="iceq-step"
                aria-current={isCurrent ? "step" : undefined}
                data-complete={isComplete ? "true" : undefined}
              >
                <span className="iceq-step-dot">
                  {isComplete ? "✓" : idx + 1}
                </span>
              </div>
              {idx < steps.length - 1 && (
                <div
                  className="iceq-step-connector"
                  data-complete={isComplete ? "true" : undefined}
                />
              )}
            </div>
          );
        })}
      </nav>
    );
  }

  return (
    <div className="abyss-depth grain-overlay flex min-h-full items-start justify-center p-4 pt-8 sm:p-6 sm:pt-12">
      <div className="w-full max-w-setup-card relative">
        {/* ── Aurora glow behind card ────────────────────────────────── */}
        <div
          className="pointer-events-none absolute -inset-8 rounded-3xl opacity-40"
          style={{
            background:
              "radial-gradient(ellipse 60% 50% at 50% 30%, rgba(139,108,255,0.08) 0%, transparent 70%), " +
              "radial-gradient(ellipse 40% 35% at 50% 60%, rgba(89,216,255,0.04) 0%, transparent 70%)",
          }}
        />

        {/* ── Brand header ──────────────────────────────────────────── */}
        <div className="secure-channel mb-6 text-center relative" data-secure="true">
          <IceQWordmark variant="stacked" size="sm" monochrome className="text-frozen mx-auto" />
          <h1 className="mt-2 text-lg font-semibold text-frozen">{i18n.t("setup.title")}</h1>
        </div>

        {/* ── Step indicator ─────────────────────────────────────────── */}
        {step !== "unlock" && renderStepIndicator(step)}

        {/* ── Card ───────────────────────────────────────────────────── */}
        <div className="iceq-panel relative" style={{ maxHeight: "calc(100vh - 12rem)", overflowY: "auto" }}>
          {/* ================================================================
              INTRO
              ================================================================ */}
          {step === "intro" && (
            <>
              <p className="text-sm text-mist">{i18n.t("setup.intro")}</p>

              {!hasExistingVault && (
                <div className="mt-4 space-y-3">
                  <div className="iceq-setup-card">
                    <div className="text-sm font-semibold text-frozen">
                      {i18n.t("setup.loginPasswordLabel")}
                    </div>
                    <p className="mt-1 text-xs text-mist">
                      {i18n.t("setup.loginPasswordDesc")}
                    </p>
                  </div>
                  <div className="iceq-setup-card">
                    <div className="text-sm font-semibold text-frozen">
                      {i18n.t("setup.passphraseLabel")}
                    </div>
                    <p className="mt-1 text-xs text-mist">
                      {i18n.t("setup.passphraseDesc")}
                    </p>
                  </div>
                  <div className="iceq-setup-card">
                    <div className="text-sm font-semibold text-frozen">
                      {i18n.t("setup.recoveryKeyLabel")}
                    </div>
                    <p className="mt-1 text-xs text-mist">
                      {i18n.t("setup.recoveryKeyDesc")}
                    </p>
                  </div>
                </div>
              )}

              {hasExistingVault && (
                <div className="iceq-alert-info mt-4">
                  {i18n.t("setup.vaultAlreadyExists")}
                </div>
              )}

              <div className="iceq-alert-warning mt-4 text-xs">
                {i18n.t("setup.warning")}
              </div>

              <div className="mt-5 space-y-3">
                {!hasExistingVault && (
                  <button
                    type="button"
                    className="iceq-btn-primary w-full"
                    onClick={() => setStep("passphrase")}
                  >
                    {i18n.t("setup.beginSetup")}
                  </button>
                )}
                <button
                  type="button"
                  className="iceq-btn-secondary w-full"
                  onClick={() => navigate("/recovery")}
                >
                  {i18n.t("setup.recoveryAction")}
                </button>
                <p className="text-center text-xs text-mist-dim">
                  {i18n.t("setup.recoveryActionHelp")}
                </p>
              </div>
            </>
          )}

          {/* ================================================================
              PASSPHRASE
              ================================================================ */}
          {step === "passphrase" && (
            <>
              <h2 className="text-xl font-semibold text-frozen">
                {i18n.t("setup.createPassphraseTitle")}
              </h2>
              <p className="mt-2 text-sm text-mist">
                {i18n.t("setup.createPassphraseHelp")}
              </p>

              <div className="mt-4 space-y-3">
                <div>
                  <label htmlFor="setup-passphrase" className="text-label text-mist">
                    {i18n.t("setup.passphraseInput")}
                  </label>
                  <input
                    id="setup-passphrase"
                    type="password"
                    autoComplete="new-password"
                    className="iceq-input mt-1.5"
                    value={passphrase}
                    onChange={(e) => setPassphrase(e.target.value)}
                    disabled={busy}
                  />
                </div>
                <div>
                  <label htmlFor="setup-passphrase-confirm" className="text-label text-mist">
                    {i18n.t("setup.passphraseConfirm")}
                  </label>
                  <input
                    id="setup-passphrase-confirm"
                    type="password"
                    autoComplete="new-password"
                    className="iceq-input mt-1.5"
                    value={passphraseConfirm}
                    onChange={(e) => setPassphraseConfirm(e.target.value)}
                    disabled={busy}
                  />
                </div>
              </div>

              {error && <div role="alert" className="iceq-alert-error mt-3">{error}</div>}

              <div className="mt-5 flex gap-2">
                <button
                  type="button"
                  className="iceq-btn-secondary flex-1"
                  disabled={busy}
                  onClick={() => { setPassphrase(""); setPassphraseConfirm(""); setStep("intro"); }}
                >
                  {i18n.t("setup.back")}
                </button>
                <button
                  type="button"
                  className="iceq-btn-primary flex-1"
                  disabled={busy || !passphrase}
                  onClick={handleCreatePassphrase}
                >
                  {busy ? i18n.t("setup.creating") : i18n.t("setup.continue")}
                </button>
              </div>
            </>
          )}

          {/* ================================================================
              UNLOCK
              ================================================================ */}
          {step === "unlock" && (
            <>
              <h2 className="text-xl font-semibold text-frozen">
                {i18n.t("setup.unlockTitle")}
              </h2>
              <p className="mt-2 text-sm text-mist">
                {i18n.t("setup.unlockHelp")}
              </p>

              <div className="mt-4">
                <label
                  htmlFor="setup-unlock-passphrase"
                  className="text-label text-frozen"
                >
                  {i18n.t("setup.unlockPassphraseLabel")}
                </label>
                <p className="mt-1 text-xs text-mist">
                  {i18n.t("setup.unlockPassphraseHelp")}
                </p>
                <input
                  id="setup-unlock-passphrase"
                  type="password"
                  autoComplete="new-password"
                  className="iceq-input mt-2"
                  value={unlockPassphrase}
                  onChange={(e) => setUnlockPassphrase(e.target.value)}
                  disabled={busy}
                  placeholder={i18n.t("setup.unlockPassphrasePlaceholder")}
                />
              </div>

              {error && <div role="alert" className="iceq-alert-error mt-3">{error}</div>}

              <div className="mt-5 flex gap-2">
                <button
                  type="button"
                  className="iceq-btn-secondary flex-1"
                  disabled={busy}
                  onClick={() => { setUnlockPassphrase(""); setStep("intro"); }}
                >
                  {i18n.t("setup.back")}
                </button>
                <button
                  type="button"
                  className="iceq-btn-primary flex-1"
                  disabled={busy || !unlockPassphrase}
                  onClick={handleUnlockVault}
                >
                  {busy ? i18n.t("setup.unlocking") : i18n.t("setup.unlockAction")}
                </button>
              </div>
            </>
          )}

          {/* ================================================================
              WIPEKEY
              ================================================================ */}
          {step === "wipekey" && (
            <>
              <h2 className="text-xl font-semibold text-frozen">
                {i18n.t("setup.wipeKeyTitle")}
              </h2>
              <p className="mt-2 text-sm text-mist">
                {i18n.t("setup.wipeKeyHelp")}
              </p>

              <div className="mt-4">
                <label
                  htmlFor="setup-account-password"
                  className="text-label text-frozen"
                >
                  {i18n.t("setup.accountPasswordLabel")}
                </label>
                <p className="mt-1 text-xs text-mist">
                  {i18n.t("setup.accountPasswordHelp")}
                </p>
                <input
                  ref={accountPasswordRef}
                  id="setup-account-password"
                  type="password"
                  autoComplete="current-password"
                  className="iceq-input mt-2"
                  value={accountPassword}
                  onChange={(e) => {
                    setAccountPassword(e.target.value);
                    if (accountPasswordInvalid) {
                      setAccountPasswordInvalid(false);
                      setError("");
                    }
                  }}
                  disabled={busy}
                  placeholder={i18n.t("setup.accountPasswordPlaceholder")}
                  aria-invalid={accountPasswordInvalid}
                  aria-describedby={accountPasswordInvalid ? "setup-account-password-error" : undefined}
                />
              </div>

              {error && (
                <div id="setup-account-password-error" role="alert" className="iceq-alert-error mt-3">
                  {error}
                </div>
              )}

              <div className="mt-5 flex gap-2">
                <button
                  type="button"
                  className="iceq-btn-secondary flex-1"
                  disabled={busy}
                  onClick={() => setStep(hasExistingVault ? "unlock" : "passphrase")}
                >
                  {i18n.t("setup.back")}
                </button>
                <button
                  type="button"
                  className="iceq-btn-primary flex-1"
                  disabled={busy || !accountPassword}
                  onClick={handleEnableWipeKey}
                >
                  {busy ? i18n.t("setup.wipeKeyEnabling") : i18n.t("setup.wipeKeyEnable")}
                </button>
              </div>
            </>
          )}

          {/* ================================================================
              RECOVERY
              ================================================================ */}
          {step === "recovery" && (
            <>
              <h2 className="text-xl font-semibold text-frozen">
                {i18n.t("setup.recoveryTitle")}
              </h2>
              <p className="mt-2 text-sm text-mist">
                {i18n.t("setup.recoveryHelp")}
              </p>

              {!recoveryGenerated ? (
                <div className="mt-4">
                  {error && (
                    <div role="alert" className="iceq-alert-error mb-3">{error}</div>
                  )}
                  <button
                    type="button"
                    className="iceq-btn-primary w-full"
                    disabled={busy}
                    onClick={handleGenerateRecovery}
                  >
                    {busy ? (
                      <span className="flex items-center justify-center gap-2">
                        <span className="iceq-spinner" style={{ width: 16, height: 16, borderTopColor: "#050713" }} />
                        {i18n.t("setup.generating")}
                      </span>
                    ) : (
                      i18n.t("setup.generateRecovery")
                    )}
                  </button>
                </div>
              ) : (
                <div className="mt-4 space-y-4">
                  {/* Recovery Key */}
                  <div>
                    <label className="text-label text-frozen">
                      {i18n.t("setup.recoveryKeyLabel2")}
                    </label>
                    <div className="mt-1.5 break-all rounded-lg border border-ice-border bg-deep-ice p-3 text-mono text-sm text-frozen select-all">
                      {recoveryKeyB64}
                    </div>
                    <canvas
                      ref={canvasRef}
                      aria-label={i18n.t("setup.recoveryQrLabel")}
                      role="img"
                      className="mt-2 rounded-lg border border-ice-border"
                      style={{ minHeight: 200, minWidth: 200 }}
                    />
                  </div>

                  {/* Download */}
                  <div>
                    <label className="text-label text-frozen">
                      {i18n.t("setup.downloadPackage")}
                    </label>
                    <button
                      type="button"
                      className="iceq-btn-secondary mt-1.5 w-full"
                      onClick={() => {
                        const blob = new Blob([recoveryPackage], { type: "application/octet-stream" });
                        const url = URL.createObjectURL(blob);
                        const a = document.createElement("a");
                        a.href = url; a.download = "iceq-recovery-v4.iceq"; a.click();
                        URL.revokeObjectURL(url);
                      }}
                    >
                      ↓ {i18n.t("setup.downloadPackage")}
                    </button>
                  </div>
                </div>
              )}

              {recoveryGenerated && (
                <div className="mt-5 flex gap-2">
                  <button
                    type="button"
                    className="iceq-btn-secondary flex-1"
                    disabled={busy}
                    onClick={() => setStep("wipekey")}
                  >
                    {i18n.t("setup.back")}
                  </button>
                  <button
                    type="button"
                    className="iceq-btn-primary flex-1"
                    onClick={() => setStep("confirm")}
                  >
                    {i18n.t("setup.iHaveSaved")}
                  </button>
                </div>
              )}
            </>
          )}

          {/* ================================================================
              CONFIRM
              ================================================================ */}
          {step === "confirm" && (
            <>
              <h2 className="text-xl font-semibold text-frozen">
                {i18n.t("setup.confirmTitle")}
              </h2>
              <p className="mt-2 text-sm text-mist">
                {i18n.t("setup.confirmHelp")}
              </p>

              <div className="mt-4">
                <label className="flex items-start gap-3 text-sm text-frozen cursor-pointer">
                  <input
                    type="checkbox"
                    checked={savedConfirm}
                    onChange={(e) => setSavedConfirm(e.target.checked)}
                    className="mt-0.5 h-4 w-4 rounded-sm border-ice-border bg-deep-ice accent-electric"
                  />
                  <span>{i18n.t("setup.confirmSaved")}</span>
                </label>
              </div>

              {error && (
                <div role="alert" className="iceq-alert-error mt-3">{error}</div>
              )}

              <div className="mt-5 flex gap-2">
                <button
                  type="button"
                  className="iceq-btn-secondary flex-1"
                  disabled={busy}
                  onClick={() => setStep("recovery")}
                >
                  {i18n.t("setup.back")}
                </button>
                <button
                  type="button"
                  className="iceq-btn-primary flex-1"
                  disabled={busy || !savedConfirm}
                  onClick={handleComplete}
                >
                  {busy ? i18n.t("setup.completing") : i18n.t("setup.completeSetup")}
                </button>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}

function bytesToBase64url(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]!);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
