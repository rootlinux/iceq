import { useState, useEffect, useRef } from "react";
import { useNavigate } from "react-router-dom";
import { useAuthStore } from "../../store/authStore";
import { getActiveCryptoNamespace, hasSecuritySetupCompleted, setSecuritySetupCompleted } from "../../lib/indexeddb";
import { createSecurityPassphrase, hasSecurityPassphrase } from "../../lib/securityVault";
import { generateRecoveryKey, createRecoveryPackage } from "../../lib/recoveryPackage";
import {
  loadOrCreateWipeKeyPair,
  storeEncryptedWipePrivateKey,
  reconcileWipeKey,
  clearLocalWipeKey,
  bytesToBase64std,
} from "../../lib/panicWipeKey";
import { uploadWipePublicKey } from "../../api/auth";
import { useI18n } from "../../i18n";
import QRCode from "qrcode";

const MIN_PASSPHRASE_LENGTH = 12;

// Step order matters: "wipekey" runs BEFORE "recovery" so the wipe key
// already exists in IndexedDB by the time createRecoveryPackage() gathers
// the payload -- see recoveryPackage.ts's gatherRecoveryPayload, which
// embeds whatever wipe key it finds. Generating the recovery package
// before the wipe key existed (the original order) meant a recovered
// device could never restore it.
type SetupStep = "intro" | "passphrase" | "wipekey" | "recovery" | "confirm";

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
    void hasSecuritySetupCompleted(ns).then(async (done) => {
      if (done) { navigate("/app", { replace: true }); return; }
      // A vault can already exist without setup being marked complete:
      // RecoveryImportScreen creates one so a recovered wipe key (if the
      // package had one) can be re-encrypted immediately. If the package
      // had no wipe key, this device still needs to enable one -- but
      // asking for a SECOND, different passphrase here would orphan the
      // one just created. Skip straight to "wipekey".
      if (await hasSecurityPassphrase()) setStep("wipekey");
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
      setStep("wipekey");
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

  // Enables Panic Wipe: generates (or reuses, if a prior attempt's
  // response was lost -- see loadOrCreateWipeKeyPair) an Ed25519 wipe key
  // and enrolls its public half server-side. Runs BEFORE the recovery
  // step so that when handleGenerateRecovery builds the recovery package,
  // the wipe key already exists to embed -- see the SetupStep comment.
  async function handleEnableWipeKey(): Promise<void> {
    setError("");
    setBusy(true);
    try {
      // Load-or-create implements the retry-safe enrollment pattern:
      // if a prior attempt generated a key but the server response was lost,
      // we reuse the same key instead of generating a new one.
      const { publicKeyBytes, encryptedPrivateBlob, isNew } = await loadOrCreateWipeKeyPair();
      if (isNew) {
        await storeEncryptedWipePrivateKey(encryptedPrivateBlob, publicKeyBytes);
      }

      const pubB64 = bytesToBase64std(publicKeyBytes);
      try {
        await uploadWipePublicKey(pubB64, accountPassword || undefined);
      } catch (uploadErr) {
        // The upload's own success/failure is not trusted on its own --
        // ask the server what it actually has enrolled and act on that,
        // not on the HTTP status code. A 409 (or, before the server-side
        // compare-before-rotate fix, even a 401) can mean "this exact key
        // already landed and the response was lost" just as easily as it
        // can mean something genuinely failed.
        const reconciliation = await reconcileWipeKey(publicKeyBytes);
        if (reconciliation.status === "match") {
          // Our key is exactly what's enrolled -- the earlier failure was
          // cosmetic (lost response, duplicate submit). Proceed.
        } else if (reconciliation.status === "mismatch") {
          // A different key is enrolled -- most likely this device lost a
          // concurrent first-enrollment race. This local key is orphaned:
          // keeping it would let every future retry resubmit it and hit
          // the same mismatch. Rotating to make it current would require
          // a signature from whichever key IS enrolled, which this device
          // never had -- so this is a real failure, not something to
          // paper over.
          await clearLocalWipeKey();
          throw new Error(i18n.t("setup.wipeKeyMismatch"));
        } else {
          // server-has-no-key: the reconcile confirms this was a real
          // failure, not a lost-response false negative. The local key is
          // preserved so a retry reuses it instead of generating yet
          // another one.
          throw uploadErr;
        }
      }
      setStep("recovery");
    } catch (e) {
      setError((e as Error).message || i18n.t("setup.completeFailed"));
    } finally {
      // Always clear sensitive material from component memory, even on failure.
      setAccountPassword("");
      setBusy(false);
    }
  }

  // Final step: the wipe key and recovery package already exist. Just
  // mark setup complete and route into the app.
  async function handleComplete(): Promise<void> {
    setError("");
    setBusy(true);
    try {
      const ns = getActiveCryptoNamespace();
      await setSecuritySetupCompleted(ns);
      // Signal App that setup is complete so it can update routing state
      // without waiting for the next IndexedDB poll.
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

        {step === "wipekey" && (
          <>
            <h2 className="text-xl font-semibold text-text">{i18n.t("setup.wipeKeyTitle")}</h2>
            <p className="mt-2 text-sm text-text-2">{i18n.t("setup.wipeKeyHelp")}</p>
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
            </div>
            {error && <div role="alert" className="mt-3 text-sm text-danger">{error}</div>}
            <div className="mt-5 flex gap-2">
              <button type="button" className="iceq-btn-secondary flex-1" disabled={busy} onClick={() => setStep("passphrase")}>{i18n.t("setup.back")}</button>
              <button type="button" className="iceq-btn-primary flex-1" disabled={busy || !accountPassword} onClick={handleEnableWipeKey}>
                {busy ? i18n.t("setup.wipeKeyEnabling") : i18n.t("setup.wipeKeyEnable")}
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
                    a.href = url; a.download = "iceq-recovery-v4.iceq"; a.click();
                    URL.revokeObjectURL(url);
                  }}>
                    {i18n.t("setup.downloadPackage")}
                  </button>
                </div>
              </div>
            )}
            {recoveryGenerated && (
              <div className="mt-5 flex gap-2">
                <button type="button" className="iceq-btn-secondary flex-1" disabled={busy} onClick={() => setStep("wipekey")}>{i18n.t("setup.back")}</button>
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
              <button type="button" className="iceq-btn-primary flex-1" disabled={busy || !savedConfirm} onClick={handleComplete}>
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
