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
import { useAuthStore } from "../../store/authStore";
import { fetchBundle } from "../../api/keys";
import { provisionRecoveryPrekeys, IdentityKeyMismatchError } from "../../lib/signalBootstrap";
import { deriveIdentityPublicKey } from "../../lib/signal";

const MIN_PASSPHRASE_LENGTH = 12;

// "passphrase" runs BEFORE "input"/"importing" so a security vault exists
// on THIS device by the time a recovered wipe key (if the package has one
// -- see recoveryPackage.ts's Task #11 wipeKey field) needs to be
// re-encrypted and persisted. The recovered key is only ever held as raw
// bytes in memory for the moment between decrypting the package and
// wrapping it with this device's own vault key -- never written to
// IndexedDB unencrypted.
type ImportState = "passphrase" | "input" | "importing" | "provisioning" | "done" | "error";

export function RecoveryImportScreen(): JSX.Element {
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
  // The recovered wipe key (if the package had one), held only long
  // enough to re-encrypt it with this device's own vault key -- see
  // restorePendingWipeKey. Cleared once restored so a retry never
  // re-does it, and simply absent (not an error) if a page reload wiped
  // in-memory state before restoration completed -- see the comment on
  // handleRetryProvisioning.
  const pendingWipeKey = useRef<{ publicKey: string; privateKeyPkcs8: string } | null>(null);
  const wipeKeyRestored = useRef(false);

  // On mount: first check for a pending recovery provisioning record from
  // a previous session that was interrupted (e.g. page reload). If one
  // exists with a matching identity fingerprint, restore the UI into
  // resumable provisioning state so the user can retry without
  // re-importing the recovery package.
  //
  // Pending records are scoped by account/device namespace — a
  // mismatched authenticated account cannot observe or delete another
  // account's recoverable pending state.
  //
  // If there's no pending record, this is either a fresh visit or a
  // retry from before a vault existed. Either way, skip straight past
  // the passphrase step when a vault already exists (e.g. the user
  // already completed it earlier in this same session) rather than
  // asking them to set a new one and silently orphaning the first.
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

      // Obtain the active crypto namespace. If no namespace is set,
      // there cannot be a pending record for this device — skip.
      let ns: CryptoNamespace;
      try {
        ns = getActiveCryptoNamespace();
      } catch {
        return false;
      }

      // Validate UIN matches the authenticated session before reading.
      // The key includes UIN, so a mismatched account would already
      // get null — but we defensively verify here.
      if (ns.uin !== selfUin) return false;

      const pending = await loadPendingRecoveryProvisioning(ns);
      if (!pending) return false;

      // Validate that the recovered identity still exists in IndexedDB.
      const stored = await loadIdentity(pending.namespace);
      if (!stored) {
        // Identity was deleted (e.g. IndexedDB cleared). Clear the
        // stale pending record — the caller must re-import.
        await clearPendingRecoveryProvisioning(ns);
        return false;
      }

      // Validate identity fingerprint matches the pending record.
      let derivedPublic: string;
      try {
        derivedPublic = await deriveIdentityPublicKey(stored.privateKey);
      } catch {
        await clearPendingRecoveryProvisioning(ns);
        return false;
      }

      if (derivedPublic !== pending.identityFingerprint) {
        // Identity changed — stale pending record for a different key.
        await clearPendingRecoveryProvisioning(ns);
        return false;
      }

      // All validations passed. Restore the UI into resumable
      // provisioning state. The pending record contains the exact
      // prekey bundle to retry.
      provisioningNs.current = pending.namespace;
      identityImported.current = true;
      setState("error"); // Show the retry UI
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

  // Re-encrypts the wipe key recovered from the package (if any) with
  // this device's own vault key. No-ops if there's nothing pending
  // (no wipe key in the package) or it was already restored (retry after
  // a later step failed). See the pendingWipeKey/wipeKeyRestored comment
  // above for what happens if a reload wipes this in-memory state before
  // it runs -- graceful fallback, not a hard failure.
  async function restorePendingWipeKey(): Promise<void> {
    if (wipeKeyRestored.current || !pendingWipeKey.current) return;
    const { publicKey, privateKeyPkcs8 } = pendingWipeKey.current;
    await importRecoveredWipeKey(base64urlToBytes(publicKey), base64urlToBytes(privateKeyPkcs8));
    wipeKeyRestored.current = true;
  }

  // Identity, peer trust, vault, and (if the package had one) the wipe
  // key are all restored at this point. Only mark setup fully complete
  // when the wipe key was ALSO restored -- otherwise this device still
  // needs to go through SecuritySetupGate's "wipekey" step to enable
  // panic wipe (it skips straight past "passphrase" since a vault
  // already exists -- see SecuritySetupGate's mount check).
  async function finishRecovery(ns: CryptoNamespace): Promise<void> {
    if (wipeKeyRestored.current) {
      await setSecuritySetupCompleted(ns);
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
      //   - v3 or v4 format with AAD-authenticated header (v4 adds an
      //     optional wipe key -- see payload.wipeKey below)
      //   - UIN and server identity match (header AAD)
      //   - Decryption integrity
      //   - Derived public key matches payload identity AND server directory
      //   - No existing identity in target namespace
      //   - Atomic IndexedDB write (all-or-nothing)
      //
      // Private identity material is NEVER uploaded to the server.
      const payload = await importRecoveryPackage(packageContent, selfUin, bundle.identity_key, keyBytes);
      identityImported.current = true;
      pendingWipeKey.current = payload.wipeKey ?? null;

      // If the package carried a wipe key (Task #11: the source device
      // had one enrolled at export time), restore it now that the vault
      // exists -- see restorePendingWipeKey. Absent for older v3
      // packages or if the source device hadn't enabled panic wipe yet;
      // either way this device falls back to enrolling a fresh one later
      // via SecuritySetupGate, same as before this restoration existed.
      await restorePendingWipeKey();

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

      await finishRecovery(ns);
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
      // Retry wipe-key restoration first, in case that's what failed
      // last time (or a reload interrupted it before provisioning ever
      // started) -- restorePendingWipeKey no-ops if it already succeeded
      // or there was never a wipe key to restore.
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
              // Identity, peer trust, vault, and fresh prekeys are
              // restored. If the package also had a wipe key,
              // finishRecovery already marked setup complete and /app
              // will NOT redirect to /setup. Otherwise (older v3 package,
              // or the source device hadn't enabled panic wipe), the App
              // router redirects to /setup, which skips straight past the
              // passphrase step (a vault already exists) to "wipekey".
              navigate("/app", { replace: true });
            }}
          >
            {i18n.t("recovery.continueToApp")}
          </button>
        </div>
      </div>
    );
  }

  if (state === "passphrase") {
    return (
      <div className="flex h-full items-center justify-center bg-bg p-4">
        <div className="w-full max-w-md rounded-lg border border-border bg-surface-2 p-6 shadow-lg">
          <h2 className="text-xl font-semibold text-text">{i18n.t("setup.createPassphraseTitle")}</h2>
          <p className="mt-2 text-sm text-text-2">{i18n.t("setup.createPassphraseHelp")}</p>
          <div className="mt-4 space-y-3">
            <div>
              <label htmlFor="recovery-passphrase" className="mb-1 block text-xs text-text-2">
                {i18n.t("setup.passphraseInput")}
              </label>
              <input
                id="recovery-passphrase"
                type="password"
                autoComplete="new-password"
                className="iceq-input w-full"
                value={passphrase}
                onChange={(e) => setPassphrase(e.target.value)}
              />
            </div>
            <div>
              <label htmlFor="recovery-passphrase-confirm" className="mb-1 block text-xs text-text-2">
                {i18n.t("setup.passphraseConfirm")}
              </label>
              <input
                id="recovery-passphrase-confirm"
                type="password"
                autoComplete="new-password"
                className="iceq-input w-full"
                value={passphraseConfirm}
                onChange={(e) => setPassphraseConfirm(e.target.value)}
              />
            </div>
          </div>
          {error && <div role="alert" className="mt-3 text-sm text-danger">{error}</div>}
          <div className="mt-5 flex gap-2">
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
