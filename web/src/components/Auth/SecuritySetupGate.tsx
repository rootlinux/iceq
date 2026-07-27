import { useState, useEffect, useRef } from "react";
import { useNavigate } from "react-router-dom";
import { useAuthStore } from "../../store/authStore";
import { getActiveCryptoNamespace, hasSecuritySetupCompleted, setSecuritySetupCompleted } from "../../lib/indexeddb";
import { createSecurityPassphrase } from "../../lib/securityVault";
import { generateRecoveryKey, createRecoveryPackage } from "../../lib/recoveryPackage";
import { generateWipeKeyPair, storeEncryptedWipePrivateKey } from "../../lib/panicWipeKey";
import { uploadWipePublicKey } from "../../api/auth";
import { useI18n } from "../../i18n";
import QRCode from "qrcode";

const MIN_PASSPHRASE_LENGTH = 12;

type SetupStep = "intro" | "passphrase" | "recovery" | "confirm";

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

  // Account password for reauthentication during initial wipe-key enrollment.
  // Kept in component memory only; cleared immediately after the upload request.
  // This is NOT the Security Passphrase — it is the login password used to
  // authenticate to the auth-service.
  const [accountPassword, setAccountPassword] = useState("");

  useEffect(() => {
    const ns = getActiveCryptoNamespace();
    void hasSecuritySetupCompleted(ns).then((done) => {
      if (done) navigate("/app", { replace: true });
    });
  }, [navigate]);

  // Render QR code after the canvas mounts, not during state update.
  useEffect(() => {
    if (!recoveryKeyB64 || !canvasRef.current) return;
    let cancelled = false;
    void QRCode.toCanvas(canvasRef.current, recoveryKeyB64, { width: 200, margin: 1 }).then(() => {
      // QR rendered successfully.
    }).catch(() => {
      if (!cancelled) setError(i18n.t("setup.recoveryFailed"));
    });
    return () => { cancelled = true; };
  }, [recoveryKeyB64, i18n]);

  async function handleCreatePassphrase(): Promise<void> {
    setError("");
    if (passphrase.length < MIN_PASSPHRASE_LENGTH) { setError(i18n.t("setup.passphraseTooShort")); return; }
    if (passphrase !== passphraseConfirm) { setError(i18n.t("setup.passphraseMismatch")); return; }
    setBusy(true);
    try {
      await createSecurityPassphrase(passphrase);
      setStep("recovery");
    } catch (e) {
      setError((e as Error).message || i18n.t("setup.passphraseFailed"));
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
      // QR rendering is handled by the useEffect watching recoveryKeyB64 + canvasRef.
    } catch {
      setError(i18n.t("setup.recoveryFailed"));
    } finally {
      setBusy(false);
    }
  }

  async function handleComplete(): Promise<void> {
    setError("");
    setBusy(true);
    try {
      const ns = getActiveCryptoNamespace();
      const { publicKeyBytes, encryptedPrivateBlob } = await generateWipeKeyPair();
      await storeEncryptedWipePrivateKey(encryptedPrivateBlob);

      const pubB64 = bytesToBase64std(publicKeyBytes);
      await uploadWipePublicKey(pubB64, accountPassword || undefined);
      await setSecuritySetupCompleted(ns);
      // Signal App that setup is complete so it can update routing state
      // without waiting for the next IndexedDB poll.
      onSetupComplete?.();
      navigate("/app", { replace: true });
    } catch (e) {
      setError((e as Error).message || i18n.t("setup.completeFailed"));
    } finally {
      // Always clear sensitive material from component memory, even on failure.
      setAccountPassword("");
      setPassphrase("");
      setPassphraseConfirm("");
      setBusy(false);
    }
  }

  return (
    <div className="flex h-full items-center justify-center bg-bg p-4">
      <div className="w-full max-w-lg rounded-lg border border-border bg-surface-2 p-6 shadow-lg" style={{ maxHeight: "calc(100vh - 2rem)", overflowY: "auto" }}>
        {step === "intro" && (
          <>
            <h2 className="text-xl font-semibold text-text">{i18n.t("setup.title")}</h2>
            <p className="mt-3 text-sm text-text-2">{i18n.t("setup.intro")}</p>
            <div className="mt-4 space-y-3 text-sm text-text-2">
              <div>
                <strong className="text-text">{i18n.t("setup.loginPasswordLabel")}</strong>{" "}
                {i18n.t("setup.loginPasswordDesc")}
              </div>
              <div>
                <strong className="text-text">{i18n.t("setup.passphraseLabel")}</strong>{" "}
                {i18n.t("setup.passphraseDesc")}
              </div>
              <div>
                <strong className="text-text">{i18n.t("setup.recoveryKeyLabel")}</strong>{" "}
                {i18n.t("setup.recoveryKeyDesc")}
              </div>
            </div>
            <p className="mt-4 text-xs text-text-2">{i18n.t("setup.warning")}</p>
            <div className="mt-6 space-y-3">
              <button type="button" className="iceq-btn-primary w-full" onClick={() => setStep("passphrase")}>
                {i18n.t("setup.beginSetup")}
              </button>
              <button
                type="button"
                className="iceq-btn-secondary w-full text-sm"
                onClick={() => navigate("/recovery")}
              >
                {i18n.t("setup.recoveryAction")}
              </button>
              <p className="text-xs text-text-2 text-center">{i18n.t("setup.recoveryActionHelp")}</p>
            </div>
          </>
        )}

        {step === "passphrase" && (
          <>
            <h2 className="text-xl font-semibold text-text">{i18n.t("setup.createPassphraseTitle")}</h2>
            <p className="mt-2 text-sm text-text-2">{i18n.t("setup.createPassphraseHelp")}</p>
            <div className="mt-4 space-y-3">
              <div>
                <label htmlFor="setup-passphrase" className="mb-1 block text-xs text-text-2">{i18n.t("setup.passphraseInput")}</label>
                <input id="setup-passphrase" type="password" autoComplete="new-password" className="iceq-input w-full"
                  value={passphrase} onChange={(e) => setPassphrase(e.target.value)} disabled={busy} />
              </div>
              <div>
                <label htmlFor="setup-passphrase-confirm" className="mb-1 block text-xs text-text-2">{i18n.t("setup.passphraseConfirm")}</label>
                <input id="setup-passphrase-confirm" type="password" autoComplete="new-password" className="iceq-input w-full"
                  value={passphraseConfirm} onChange={(e) => setPassphraseConfirm(e.target.value)} disabled={busy} />
              </div>
            </div>
            {error && <div role="alert" className="mt-3 text-sm text-danger">{error}</div>}
            <div className="mt-5 flex gap-2">
              <button type="button" className="iceq-btn-secondary flex-1" disabled={busy} onClick={() => setStep("intro")}>{i18n.t("setup.back")}</button>
              <button type="button" className="iceq-btn-primary flex-1" disabled={busy || !passphrase} onClick={handleCreatePassphrase}>
                {busy ? i18n.t("setup.creating") : i18n.t("setup.continue")}
              </button>
            </div>
          </>
        )}

        {step === "recovery" && (
          <>
            <h2 className="text-xl font-semibold text-text">{i18n.t("setup.recoveryTitle")}</h2>
            <p className="mt-2 text-sm text-text-2">{i18n.t("setup.recoveryHelp")}</p>
            {!recoveryGenerated ? (
              <div className="mt-4">
                {error && <div role="alert" className="mb-3 text-sm text-danger">{error}</div>}
                <button type="button" className="iceq-btn-primary w-full" disabled={busy} onClick={handleGenerateRecovery}>
                  {busy ? i18n.t("setup.generating") : i18n.t("setup.generateRecovery")}
                </button>
              </div>
            ) : (
              <div className="mt-4 space-y-3">
                <div>
                  <label className="mb-1 block text-xs font-semibold text-text">{i18n.t("setup.recoveryKeyLabel2")}</label>
                  <div className="break-all rounded border border-border bg-bg p-2 text-sm font-mono text-text select-all">
                    {recoveryKeyB64}
                  </div>
                  <canvas ref={canvasRef} className="mt-2 border border-border rounded" />
                </div>
                <div>
                  <label className="mb-1 block text-xs font-semibold text-text">{i18n.t("setup.downloadPackage")}</label>
                  <button type="button" className="iceq-btn-secondary w-full text-xs" onClick={() => {
                    const blob = new Blob([recoveryPackage], { type: "application/octet-stream" });
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement("a");
                    a.href = url; a.download = "iceq-recovery-v3.iceq"; a.click();
                    URL.revokeObjectURL(url);
                  }}>
                    {i18n.t("setup.downloadPackage")}
                  </button>
                </div>
              </div>
            )}
            {recoveryGenerated && (
              <div className="mt-5 flex gap-2">
                <button type="button" className="iceq-btn-secondary flex-1" disabled={busy} onClick={() => setStep("passphrase")}>{i18n.t("setup.back")}</button>
                <button type="button" className="iceq-btn-primary flex-1" onClick={() => setStep("confirm")}>{i18n.t("setup.iHaveSaved")}</button>
              </div>
            )}
          </>
        )}

        {step === "confirm" && (
          <>
            <h2 className="text-xl font-semibold text-text">{i18n.t("setup.confirmTitle")}</h2>
            <p className="mt-2 text-sm text-text-2">{i18n.t("setup.confirmHelp")}</p>
            <div className="mt-4 space-y-3">
              <div>
                <label htmlFor="setup-account-password" className="mb-1 block text-xs font-semibold text-text">
                  {i18n.t("setup.accountPasswordLabel")}
                </label>
                <p className="mb-1 text-xs text-text-2">{i18n.t("setup.accountPasswordHelp")}</p>
                <input
                  id="setup-account-password"
                  type="password"
                  autoComplete="current-password"
                  className="iceq-input w-full"
                  value={accountPassword}
                  onChange={(e) => setAccountPassword(e.target.value)}
                  disabled={busy}
                  placeholder={i18n.t("setup.accountPasswordPlaceholder")}
                />
              </div>
              <div className="space-y-2 text-sm text-text-2">
                <label className="flex items-start gap-2">
                  <input type="checkbox" checked={savedConfirm} onChange={(e) => setSavedConfirm(e.target.checked)} className="mt-0.5" />
                  <span>{i18n.t("setup.confirmSaved")}</span>
                </label>
              </div>
            </div>
            {error && <div role="alert" className="mt-3 text-sm text-danger">{error}</div>}
            <div className="mt-5 flex gap-2">
              <button type="button" className="iceq-btn-secondary flex-1" disabled={busy} onClick={() => setStep("recovery")}>{i18n.t("setup.back")}</button>
              <button type="button" className="iceq-btn-primary flex-1" disabled={busy || !savedConfirm || !accountPassword} onClick={handleComplete}>
                {busy ? i18n.t("setup.completing") : i18n.t("setup.completeSetup")}
              </button>
            </div>
          </>
        )}
      </div>
    </div>
  );
}

function bytesToBase64url(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]!);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function bytesToBase64std(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]!);
  return btoa(binary);
}
