import { useState, useRef, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { importRecoveryPackage } from "../../lib/recoveryPackage";
import {
  getActiveCryptoNamespace,
  loadIdentity,
  loadPendingRecoveryProvisioning,
  clearPendingRecoveryProvisioning,
  type CryptoNamespace,
} from "../../lib/indexeddb";
import { useI18n } from "../../i18n";
import { useAuthStore } from "../../store/authStore";
import { fetchBundle } from "../../api/keys";
import { provisionRecoveryPrekeys, IdentityKeyMismatchError } from "../../lib/signalBootstrap";
import { deriveIdentityPublicKey } from "../../lib/signal";

type ImportState = "input" | "importing" | "provisioning" | "done" | "error";

export function RecoveryImportScreen(): JSX.Element {
  const navigate = useNavigate();
  const i18n = useI18n();
  const selfUin = useAuthStore((s) => s.uin);
  const [state, setState] = useState<ImportState>("input");
  const [error, setError] = useState("");
  const [recoveryKeyB64, setRecoveryKeyB64] = useState("");
  const [packageContent, setPackageContent] = useState("");
  const fileInputRef = useRef<HTMLInputElement>(null);
  // Tracks whether the identity was successfully imported so we can
  // retry only provisioning (not the full import which would fail
  // because the identity already exists in IndexedDB).
  const identityImported = useRef(false);
  // The active namespace captured before import. Used for provisioning
  // so we never invent or hardcode a namespace — the identity was
  // imported into this exact namespace by importRecoveryPackage.
  const provisioningNs = useRef<CryptoNamespace | null>(null);
  // Tracks whether the mount-time pending-record check has completed.
  const mountCheckDone = useRef(false);

  // On mount, check for a pending recovery provisioning record from a
  // previous session that was interrupted (e.g. page reload). If one
  // exists with a matching identity fingerprint, restore the UI into
  // resumable provisioning state so the user can retry without
  // re-importing the recovery package.
  //
  // Pending records are scoped by account/device namespace — a
  // mismatched authenticated account cannot observe or delete another
  // account's recoverable pending state.
  useEffect(() => {
    if (mountCheckDone.current) return;
    mountCheckDone.current = true;

    void (async () => {
      if (selfUin === null) return;

      // Obtain the active crypto namespace. If no namespace is set,
      // there cannot be a pending record for this device — skip.
      let ns: CryptoNamespace;
      try {
        ns = getActiveCryptoNamespace();
      } catch {
        return;
      }

      // Validate UIN matches the authenticated session before reading.
      // The key includes UIN, so a mismatched account would already
      // get null — but we defensively verify here.
      if (ns.uin !== selfUin) return;

      const pending = await loadPendingRecoveryProvisioning(ns);
      if (!pending) return;

      // Validate that the recovered identity still exists in IndexedDB.
      const stored = await loadIdentity(pending.namespace);
      if (!stored) {
        // Identity was deleted (e.g. IndexedDB cleared). Clear the
        // stale pending record — the caller must re-import.
        await clearPendingRecoveryProvisioning(ns);
        return;
      }

      // Validate identity fingerprint matches the pending record.
      let derivedPublic: string;
      try {
        derivedPublic = await deriveIdentityPublicKey(stored.privateKey);
      } catch {
        await clearPendingRecoveryProvisioning(ns);
        return;
      }

      if (derivedPublic !== pending.identityFingerprint) {
        // Identity changed — stale pending record for a different key.
        await clearPendingRecoveryProvisioning(ns);
        return;
      }

      // All validations passed. Restore the UI into resumable
      // provisioning state. The pending record contains the exact
      // prekey bundle to retry.
      provisioningNs.current = pending.namespace;
      identityImported.current = true;
      setState("error"); // Show the retry UI
      setError(i18n.t("recovery.provisioningPending"));
    })();
  }, [selfUin, i18n]);

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
    if (!packageContent) {
      setError(i18n.t("recovery.noPackage"));
      return;
    }
    if (!recoveryKeyB64) {
      setError(i18n.t("recovery.noKey"));
      return;
    }

    setState("importing");

    try {
      // Decode the recovery key from base64url.
      let keyBytes: Uint8Array;
      try {
        keyBytes = base64urlToBytes(recoveryKeyB64);
      } catch {
        throw new Error(i18n.t("recovery.invalidKey"));
      }

      if (keyBytes.length !== 32) {
        throw new Error(i18n.t("recovery.invalidKeyLength"));
      }

      if (selfUin === null) {
        throw new Error(i18n.t("recovery.importFailed"));
      }

      // Fetch the account's currently published public identity from the
      // key-directory endpoint.
      const bundle = await fetchBundle(selfUin);

      // Capture the active namespace BEFORE importing. The identity
      // will be stored under this namespace by importRecoveryPackage.
      // We pass the same namespace to provisionRecoveryPrekeys so the
      // prekeys are generated and stored in the correct namespace.
      const ns = getActiveCryptoNamespace();
      provisioningNs.current = ns;

      // Import the recovery package. This validates:
      //   - v3 format with AAD-authenticated header
      //   - UIN and server identity match (header AAD)
      //   - Decryption integrity
      //   - Derived public key matches payload identity AND server directory
      //   - No existing identity in target namespace
      //   - Atomic IndexedDB write (all-or-nothing)
      //
      // Private identity material is NEVER uploaded to the server.
      await importRecoveryPackage(packageContent, selfUin, bundle.identity_key, keyBytes);
      identityImported.current = true;

      // Identity is now restored in IndexedDB. The server still has the
      // OLD device's prekey bundle. We must explicitly provision fresh
      // prekeys for this device before reporting recovery as complete.
      //
      // provisionRecoveryPrekeys:
      //   1. Confirms derived public identity matches server directory
      //   2. Generates fresh signed prekey + one-time prekeys
      //   3. Persists private halves locally BEFORE publishing
      //   4. Uploads the new bundle (same identity_key, new prekeys)
      //   5. Fails closed on identity mismatch (uploads nothing)
      //
      // If provisioning fails, the staged keys are already in IndexedDB.
      // The user can retry — keys are NOT regenerated on each attempt.
      setState("provisioning");
      try {
        await provisionRecoveryPrekeys(ns);
      } catch (provErr) {
        if (provErr instanceof IdentityKeyMismatchError) {
          throw new Error(i18n.t("recovery.identityMismatch"));
        }
        throw new Error(i18n.t("recovery.provisioningFailed"));
      }

      setState("done");
    } catch (e) {
      setState("error");
      setError((e as Error).message || i18n.t("recovery.importFailed"));
    }
  }

  // Retry only the provisioning step — the identity is already in
  // IndexedDB and the staged prekeys are persisted. We do NOT regenerate
  // keys; we retry the exact same bundle upload. The pending record
  // (if it exists) ensures the same bundle is reused even after a page
  // reload.
  async function handleRetryProvisioning(): Promise<void> {
    setError("");
    const ns = provisioningNs.current;
    if (selfUin === null || !ns) {
      setError(i18n.t("recovery.importFailed"));
      return;
    }
    setState("provisioning");
    try {
      await provisionRecoveryPrekeys(ns);
      setState("done");
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

  if (state === "done") {
    return (
      <div className="flex h-full items-center justify-center bg-bg p-4">
        <div className="w-full max-w-md rounded-lg border border-border bg-surface-2 p-6 text-center shadow-lg">
          <h2 className="text-xl font-semibold text-text">{i18n.t("recovery.importSuccess")}</h2>
          <p className="mt-3 text-sm text-text-2">{i18n.t("recovery.importSuccessHelp")}</p>
          <button
            type="button"
            className="iceq-btn-primary mt-4 w-full"
            onClick={() => {
              // Identity restored + fresh prekeys provisioned.
              // Navigate to /app. If security setup hasn't been completed
              // on this device, the App router will redirect to /setup.
              navigate("/app", { replace: true });
            }}
          >
            {i18n.t("recovery.continueToApp")}
          </button>
        </div>
      </div>
    );
  }

  const isBusy = state === "importing" || state === "provisioning";

  return (
    <div className="flex h-full items-center justify-center bg-bg p-4">
      <div className="w-full max-w-md rounded-lg border border-border bg-surface-2 p-6 shadow-lg">
        <h2 className="text-xl font-semibold text-text">{i18n.t("recovery.title")}</h2>
        <p className="mt-2 text-sm text-text-2">{i18n.t("recovery.help")}</p>

        <div className="mt-2 rounded border border-warning/30 bg-warning/10 p-2 text-xs text-text-2">
          {i18n.t("recovery.wrongAccountWarning")}
        </div>

        {state === "provisioning" ? (
          <div className="mt-4 py-6 text-center">
            <p className="text-sm text-text-2">{i18n.t("recovery.provisioning")}</p>
          </div>
        ) : (
          <>
            <div className="mt-4 space-y-3">
              <div>
                <label htmlFor="recovery-package-file" className="mb-1 block text-xs font-semibold text-text">
                  {i18n.t("recovery.packageLabel")}
                </label>
                <input
                  id="recovery-package-file"
                  ref={fileInputRef}
                  type="file"
                  accept=".iceq"
                  className="iceq-input w-full text-xs"
                  onChange={(e) => void handleFileSelect(e)}
                  disabled={isBusy}
                />
                {packageContent && (
                  <p className="mt-1 text-xs text-text-2">{i18n.t("recovery.packageLoaded")}</p>
                )}
              </div>

              <div>
                <label htmlFor="recovery-key" className="mb-1 block text-xs font-semibold text-text">
                  {i18n.t("recovery.keyLabel")}
                </label>
                <input
                  id="recovery-key"
                  type="text"
                  autoComplete="off"
                  className="iceq-input w-full font-mono text-sm"
                  value={recoveryKeyB64}
                  onChange={(e) => setRecoveryKeyB64(e.target.value.trim())}
                  disabled={isBusy}
                  placeholder={i18n.t("recovery.keyPlaceholder")}
                />
              </div>
            </div>
          </>
        )}

        {error && <div role="alert" className="mt-3 text-sm text-danger">{error}</div>}

        <div className="mt-5 flex gap-2">
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
              {state === "importing" ? i18n.t("recovery.importing") : i18n.t("recovery.importAction")}
            </button>
          )}
        </div>
      </div>
    </div>
  );
}

export default RecoveryImportScreen;
