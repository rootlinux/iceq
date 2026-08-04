// src/components/Auth/RecoveryImportScreen.tsx
//
// Recovery package import screen — Arctic Signal design.
// Restores encryption identity from a previously saved .iceq package
// and Recovery Key. Preserves all existing security logic.

import { useState, useRef, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { importRecoveryPackage } from "../../lib/recoveryPackage";
import {
  getActiveCryptoNamespace,
  loadIdentity,
  loadPendingRecoveryProvisioning,
  clearPendingRecoveryProvisioning,
  setSecuritySetupCompleted,
  type CryptoNamespace,
} from "../../lib/indexeddb";
import { createSecurityPassphrase, hasSecurityPassphrase } from "../../lib/securityVault";
import { importRecoveredWipeKey } from "../../lib/panicWipeKey";
import { useI18n } from "../../i18n";
import { IceQWordmark } from "../Brand/IceQWordmark";
import { useAuthStore } from "../../store/authStore";
import { fetchBundle } from "../../api/keys";
import { provisionRecoveryPrekeys, IdentityKeyMismatchError } from "../../lib/signalBootstrap";
import { deriveIdentityPublicKey } from "../../lib/signal";

const MIN_PASSPHRASE_LENGTH = 12;

type ImportState = "passphrase" | "input" | "importing" | "provisioning" | "done" | "error";

interface RecoveryImportScreenProps {
  onRecoveryComplete?: () => void;
}

export function RecoveryImportScreen({ onRecoveryComplete }: RecoveryImportScreenProps): JSX.Element {
  const navigate = useNavigate();
  const i18n = useI18n();
  const selfUin = useAuthStore((s) => s.uin);
  const [state, setState] = useState<ImportState>("passphrase");
  const [error, setError] = useState("");
  const [passphrase, setPassphrase] = useState("");
  const [passphraseConfirm, setPassphraseConfirm] = useState("");
  const [recoveryKeyB64, setRecoveryKeyB64] = useState("");
  const [packageContent, setPackageContent] = useState("");
  const fileInputRef = useRef<HTMLInputElement>(null);
  const identityImported = useRef(false);
  const provisioningNs = useRef<CryptoNamespace | null>(null);
  const mountCheckDone = useRef(false);
  const pendingWipeKey = useRef<{ publicKey: string; privateKeyPkcs8: string } | null>(null);
  const wipeKeyRestored = useRef(false);

  useEffect(() => {
    if (mountCheckDone.current) return;
    mountCheckDone.current = true;

    void (async () => {
      const restoredPending = await tryRestorePendingProvisioning();
      if (restoredPending) return;
      if (await hasSecurityPassphrase()) setState("input");
    })();

    async function tryRestorePendingProvisioning(): Promise<boolean> {
      if (selfUin === null) return false;
      let ns: CryptoNamespace;
      try { ns = getActiveCryptoNamespace(); } catch { return false; }
      if (ns.uin !== selfUin) return false;

      const pending = await loadPendingRecoveryProvisioning(ns);
      if (!pending) return false;

      const stored = await loadIdentity(pending.namespace);
      if (!stored) {
        await clearPendingRecoveryProvisioning(ns);
        return false;
      }

      let derivedPublic: string;
      try { derivedPublic = await deriveIdentityPublicKey(stored.privateKey); } catch {
        await clearPendingRecoveryProvisioning(ns);
        return false;
      }

      if (derivedPublic !== pending.identityFingerprint) {
        await clearPendingRecoveryProvisioning(ns);
        return false;
      }

      provisioningNs.current = pending.namespace;
      identityImported.current = true;
      setState("error");
      setError(i18n.t("recovery.provisioningPending"));
      return true;
    }
  }, [selfUin, i18n]);

  async function handleCreatePassphrase(): Promise<void> {
    setError("");
    if (passphrase.length < MIN_PASSPHRASE_LENGTH) { setError(i18n.t("setup.passphraseTooShort")); return; }
    if (passphrase !== passphraseConfirm) { setError(i18n.t("setup.passphraseMismatch")); return; }
    try {
      await createSecurityPassphrase(passphrase);
      setState("input");
    } catch (e) {
      setError((e as Error).message || i18n.t("setup.passphraseFailed"));
    } finally {
      setPassphrase("");
      setPassphraseConfirm("");
    }
  }

  async function restorePendingWipeKey(): Promise<void> {
    if (wipeKeyRestored.current || !pendingWipeKey.current) return;
    const { publicKey, privateKeyPkcs8 } = pendingWipeKey.current;
    await importRecoveredWipeKey(base64urlToBytes(publicKey), base64urlToBytes(privateKeyPkcs8));
    wipeKeyRestored.current = true;
  }

  async function finishRecovery(ns: CryptoNamespace): Promise<void> {
    if (wipeKeyRestored.current) {
      await setSecuritySetupCompleted(ns);
      onRecoveryComplete?.();
    }
    setState("done");
  }

  async function handleFileSelect(e: React.ChangeEvent<HTMLInputElement>): Promise<void> {
    const file = e.target.files?.[0];
    if (!file) return;
    try {
      const text = await file.text();
      setPackageContent(text.trim());
    } catch {
      setError(i18n.t("recovery.fileReadFailed"));
    }
  }

  async function handleImport(): Promise<void> {
    setError("");
    if (!packageContent) { setError(i18n.t("recovery.noPackage")); return; }
    if (!recoveryKeyB64) { setError(i18n.t("recovery.noKey")); return; }

    setState("importing");

    try {
      let keyBytes: Uint8Array;
      try { keyBytes = base64urlToBytes(recoveryKeyB64); } catch {
        throw new Error(i18n.t("recovery.invalidKey"));
      }
      if (keyBytes.length !== 32) throw new Error(i18n.t("recovery.invalidKeyLength"));
      if (selfUin === null) throw new Error(i18n.t("recovery.importFailed"));

      const bundle = await fetchBundle(selfUin);
      const ns = getActiveCryptoNamespace();
      provisioningNs.current = ns;

      const payload = await importRecoveryPackage(packageContent, selfUin, bundle.identity_key, keyBytes);
      identityImported.current = true;
      pendingWipeKey.current = payload.wipeKey ?? null;

      await restorePendingWipeKey();

      setState("provisioning");
      try {
        await provisionRecoveryPrekeys(ns);
      } catch (provErr) {
        if (provErr instanceof IdentityKeyMismatchError) {
          throw new Error(i18n.t("recovery.identityMismatch"));
        }
        throw new Error(i18n.t("recovery.provisioningFailed"));
      }

      await finishRecovery(ns);
    } catch (e) {
      setState("error");
      setError((e as Error).message || i18n.t("recovery.importFailed"));
    }
  }

  async function handleRetryProvisioning(): Promise<void> {
    setError("");
    const ns = provisioningNs.current;
    if (selfUin === null || !ns) {
      setError(i18n.t("recovery.importFailed"));
      return;
    }
    setState("provisioning");
    try {
      await restorePendingWipeKey();
      await provisionRecoveryPrekeys(ns);
      await finishRecovery(ns);
    } catch (provErr) {
      setState("error");
      if (provErr instanceof IdentityKeyMismatchError) {
        setError(i18n.t("recovery.identityMismatch"));
      } else {
        setError(i18n.t("recovery.provisioningFailed"));
      }
    }
  }

  function base64urlToBytes(s: string): Uint8Array {
    let b64 = s.replace(/-/g, "+").replace(/_/g, "/");
    while (b64.length % 4 !== 0) b64 += "=";
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
  }

  const renderHeader = (title: string) => (
    <div className="secure-channel mb-6 text-center" data-secure="true">
      <IceQWordmark variant="stacked" size="sm" monochrome className="text-frozen mx-auto" />
      <h1 className="mt-2 text-lg font-semibold text-frozen">{title}</h1>
    </div>
  );

  const pageBg = "abyss-depth grain-overlay flex min-h-full items-center justify-center p-4";

  const isBusy = state === "importing" || state === "provisioning";

  // ── DONE state ──────────────────────────────────────────────────────
  if (state === "done") {
    return (
      <div className={pageBg}>
        <div className="w-full max-w-modal-sm text-center">
          {renderHeader(i18n.t("recovery.title"))}
          <div className="iceq-panel">
            <div className="iceq-empty">
              <div className="iceq-empty-icon">
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
              </div>
              <div className="iceq-empty-title">{i18n.t("recovery.importSuccess")}</div>
              <p className="iceq-empty-text mt-1">{i18n.t("recovery.importSuccessHelp")}</p>
            </div>
            <button
              type="button"
              className="iceq-btn-primary mt-4 w-full"
              onClick={() => navigate("/app", { replace: true })}
            >
              {i18n.t("recovery.continueToApp")}
            </button>
          </div>
        </div>
      </div>
    );
  }

  // ── PASSPHRASE state ────────────────────────────────────────────────
  if (state === "passphrase") {
    return (
      <div className={pageBg}>
        <div className="w-full max-w-auth-form">
          {renderHeader(i18n.t("recovery.title"))}
          <div className="iceq-panel space-y-4">
            <h2 className="text-xl font-semibold text-frozen">
              {i18n.t("setup.createPassphraseTitle")}
            </h2>
            <p className="text-sm text-mist">{i18n.t("setup.createPassphraseHelp")}</p>

            <div className="space-y-3">
              <div>
                <label htmlFor="recovery-passphrase" className="text-label text-mist">
                  {i18n.t("setup.passphraseInput")}
                </label>
                <input
                  id="recovery-passphrase"
                  type="password"
                  autoComplete="new-password"
                  className="iceq-input mt-1.5"
                  value={passphrase}
                  onChange={(e) => setPassphrase(e.target.value)}
                />
              </div>
              <div>
                <label htmlFor="recovery-passphrase-confirm" className="text-label text-mist">
                  {i18n.t("setup.passphraseConfirm")}
                </label>
                <input
                  id="recovery-passphrase-confirm"
                  type="password"
                  autoComplete="new-password"
                  className="iceq-input mt-1.5"
                  value={passphraseConfirm}
                  onChange={(e) => setPassphraseConfirm(e.target.value)}
                />
              </div>
            </div>

            {error && <div role="alert" className="iceq-alert-error">{error}</div>}

            <div className="flex gap-2">
              <button
                type="button"
                className="iceq-btn-secondary flex-1"
                onClick={() => navigate("/app", { replace: true })}
              >
                {i18n.t("common.cancel")}
              </button>
              <button
                type="button"
                className="iceq-btn-primary flex-1"
                disabled={!passphrase}
                onClick={() => void handleCreatePassphrase()}
              >
                {i18n.t("setup.continue")}
              </button>
            </div>
          </div>
        </div>
      </div>
    );
  }

  // ── INPUT / IMPORTING / PROVISIONING / ERROR states ─────────────────
  return (
    <div className={pageBg}>
      <div className="w-full max-w-auth-form">
        {renderHeader(i18n.t("recovery.title"))}
        <div className="iceq-panel space-y-4">
          <p className="text-sm text-mist">{i18n.t("recovery.help")}</p>

          <div className="iceq-alert-warning text-xs">
            {i18n.t("recovery.wrongAccountWarning")}
          </div>

          {state === "provisioning" ? (
            <div className="flex flex-col items-center gap-3 py-6">
              <span className="iceq-spinner" />
              <p className="text-sm text-mist">{i18n.t("recovery.provisioning")}</p>
            </div>
          ) : (
            <div className="space-y-3">
              <div>
                <label htmlFor="recovery-package-file" className="text-label text-frozen">
                  {i18n.t("recovery.packageLabel")}
                </label>
                <input
                  id="recovery-package-file"
                  ref={fileInputRef}
                  type="file"
                  accept=".iceq"
                  className="iceq-input mt-1.5"
                  onChange={(e) => void handleFileSelect(e)}
                  disabled={isBusy}
                />
                {packageContent && (
                  <p className="mt-1 text-xs text-secure-mint">{i18n.t("recovery.packageLoaded")}</p>
                )}
              </div>

              <div>
                <label htmlFor="recovery-key" className="text-label text-frozen">
                  {i18n.t("recovery.keyLabel")}
                </label>
                <input
                  id="recovery-key"
                  type="text"
                  autoComplete="off"
                  className="iceq-input mt-1.5 text-mono"
                  value={recoveryKeyB64}
                  onChange={(e) => setRecoveryKeyB64(e.target.value.trim())}
                  disabled={isBusy}
                  placeholder={i18n.t("recovery.keyPlaceholder")}
                />
              </div>
            </div>
          )}

          {error && <div role="alert" className="iceq-alert-error">{error}</div>}

          <div className="flex gap-2">
            <button
              type="button"
              className="iceq-btn-secondary flex-1"
              disabled={isBusy}
              onClick={() => navigate("/app", { replace: true })}
            >
              {i18n.t("common.cancel")}
            </button>
            {state === "error" && identityImported.current ? (
              <button
                type="button"
                className="iceq-btn-primary flex-1"
                onClick={() => void handleRetryProvisioning()}
              >
                {i18n.t("recovery.retryProvisioning")}
              </button>
            ) : (
              <button
                type="button"
                className="iceq-btn-primary flex-1"
                disabled={isBusy || !packageContent || !recoveryKeyB64}
                onClick={() => void handleImport()}
              >
                {state === "importing" ? (
                  <span className="flex items-center justify-center gap-2">
                    <span className="iceq-spinner" style={{ width: 16, height: 16, borderTopColor: "#050713" }} />
                    {i18n.t("recovery.importing")}
                  </span>
                ) : (
                  i18n.t("recovery.importAction")
                )}
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

export default RecoveryImportScreen;
