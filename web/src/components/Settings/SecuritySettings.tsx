import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { getActiveCryptoNamespace, loadIdentity } from "../../lib/indexeddb";
import { SafetyQr } from "./SafetyQr";
import { fetchBundle } from "../../api/keys";
import { computeSafetyNumber } from "../../lib/safetyFingerprint";
import { acceptPeerIdentity, assessPeerIdentity, verifyPeerIdentity } from "../../lib/identityTrust";
import { useAuthStore } from "../../store/authStore";
import { verifySignedPreKeyBundle } from "../../lib/signal";
import { PrivacySettings } from "./PrivacySettings";
import { PanicPinSettings } from "./PanicPinSettings";
import { useI18n } from "../../i18n";
import { runConfirmedPanicWipe } from "../../lib/panicWipeAction";
import { ApiError } from "../../api/client";
import { unlockSecurityVault, lockSecurityVault } from "../../lib/securityVault";
import { loadAndDecryptWipePrivateKey, signWipeChallenge } from "../../lib/panicWipeKey";
import { panicWipeWithSignature, requestWipeChallenge } from "../../api/auth";

type FingerprintStatus =
  | { kind: "loading" }
  | { kind: "ready"; fingerprint: string | null }
  | { kind: "error" };

type PanicWipeMode = "idle" | "pin" | "passphrase";

export function SecuritySettings(): JSX.Element {
  const i18n = useI18n();
  const navigate = useNavigate();
  const selfUin = useAuthStore((state) => state.uin);
  const storePanicWipe = useAuthStore((state) => state.panicWipe);
  const [panicBusy, setPanicBusy] = useState(false);
  const [panicError, setPanicError] = useState<string | null>(null);
  const [panicConfirmOpen, setPanicConfirmOpen] = useState(false);
  const [panicPinInput, setPanicPinInput] = useState("");
  const [panicPassphraseInput, setPanicPassphraseInput] = useState("");
  const [panicMode, setPanicMode] = useState<PanicWipeMode>("idle");
  const [fingerprintStatus, setFingerprintStatus] = useState<FingerprintStatus>({
    kind: "loading",
  });
  const [peerUin, setPeerUin] = useState("");
  const [peerSafety, setPeerSafety] = useState<{ uin: number; identityKey: string; number: string; changed: boolean; verified: boolean } | null>(null);
  const [peerError, setPeerError] = useState<string | null>(null);

  const inspectPeer = async (): Promise<void> => {
    const parsed = Number(peerUin);
    if (!Number.isSafeInteger(parsed) || parsed <= 0 || selfUin === null) {
      setPeerError(i18n.t("security.invalidUin")); return;
    }
    try {
      const [local, remote] = await Promise.all([loadIdentity(getActiveCryptoNamespace()), fetchBundle(parsed)]);
      if (!local) throw new Error(i18n.t("security.localUnavailable"));
      await verifySignedPreKeyBundle(remote);
      const assessment = await assessPeerIdentity(parsed, remote.identity_key,getActiveCryptoNamespace());
      const number = await computeSafetyNumber(
        { uin: selfUin, identityKey: local.publicKey },
        { uin: parsed, identityKey: remote.identity_key },
      );
      setPeerSafety({ uin: parsed, identityKey: remote.identity_key, number, changed: !assessment.sendAllowed, verified: assessment.record.verified && assessment.record.fingerprint === remote.identity_key });
      setPeerError(null);
    } catch (error) { setPeerSafety(null); setPeerError((error as Error).message); }
  };

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const identity = await loadIdentity(getActiveCryptoNamespace());
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

  async function handlePassphraseWipe(): Promise<void> {
    setPanicError(null);
    setPanicBusy(true);
    try {
      const unlocked = await unlockSecurityVault(panicPassphraseInput);
      if (!unlocked) {
        setPanicError(i18n.t("security.panicWipeWrongPin"));
        return;
      }

      const privateKey = await loadAndDecryptWipePrivateKey();
      if (!privateKey) {
        setPanicError(i18n.t("security.panicWipeFailed"));
        return;
      }

      const challengeResp = await requestWipeChallenge();
      const challengeBytes = new Uint8Array(
        Uint8Array.from(atob(challengeResp.challenge), c => c.charCodeAt(0))
      );

      const sigBytes = await signWipeChallenge(challengeBytes, privateKey);
      const sigB64 = btoa(String.fromCharCode(...sigBytes));

      await panicWipeWithSignature(challengeResp.challenge_id, sigB64);

      // Server accepted the wipe (202). Trigger destructive local cleanup:
      // lock vault, clear tokens, destroy IndexedDB, clear caches, reset
      // memory, redirect to login. Await the teardown so we know whether
      // local cleanup succeeded.
      lockSecurityVault();
      try {
        await useAuthStore.getState().handleServerWipe();
        // Local cleanup succeeded — clear the dialog.
        setPanicConfirmOpen(false);
      } catch {
        // Local cleanup failed. The fail-closed cleanup-required marker is
        // already set by startSessionTeardown. Keep the dialog open so the
        // user sees the error banner; do not report the wipe as completed.
        setPanicError(i18n.t("cleanup.failed"));
        // Keep panicConfirmOpen = true so the user can retry.
      }
    } catch (e) {
      lockSecurityVault();
      if (e instanceof ApiError) {
        if (e.code === "INVALID_SIGNATURE") setPanicError(i18n.t("security.panicWipeWrongPin"));
        else if (e.code === "SIGNATURE_REQUIRED") setPanicError(i18n.t("security.panicWipeWrongPin"));
        else setPanicError(i18n.t("security.panicWipeFailed"));
      } else {
        setPanicError(i18n.t("security.panicWipeFailed"));
      }
    } finally {
      setPanicBusy(false);
      setPanicPassphraseInput("");
    }
  }

  async function handlePinWipe(): Promise<void> {
    try {
      await runConfirmedPanicWipe(() => true, storePanicWipe, panicPinInput);
      setPanicConfirmOpen(false);
    } catch (e: unknown) {
      if (e instanceof ApiError && e.code === "INVALID_PIN") {
        setPanicError(i18n.t("security.panicWipeWrongPin"));
      } else {
        setPanicError(i18n.t("security.panicWipeFailed"));
      }
    }
  }

  function openPanicWipe(): void {
    setPanicError(null);
    setPanicPinInput("");
    setPanicPassphraseInput("");
    setPanicMode("pin");
    setPanicConfirmOpen(true);
  }

  return (
    <div className="iceq-settings-panel">
      <h3>{i18n.t("security.title")}</h3>

      <PrivacySettings />
      {fingerprintStatus.kind === "ready" && fingerprintStatus.fingerprint && (
        <SafetyQr fingerprint={fingerprintStatus.fingerprint} />
      )}
      <div className="iceq-settings-row">
        <div className="iceq-settings-status">
          <strong>{i18n.t("security.verifyContact")}</strong>
          <input aria-label={i18n.t("security.contactUin")} inputMode="numeric" value={peerUin} onChange={(event) => setPeerUin(event.target.value)} />
          <button type="button" onClick={() => void inspectPeer()}>{i18n.t("security.loadSafety")}</button>
          {peerError && <div role="alert">{peerError}</div>}
          {peerSafety && (
            <div>
              <div>{peerSafety.number}</div>
              <SafetyQr fingerprint={peerSafety.number} />
              {peerSafety.changed && <div role="alert">{i18n.t("security.identityChanged")}</div>}
              {peerSafety.changed && <button type="button" onClick={async () => { await acceptPeerIdentity(peerSafety.uin, peerSafety.identityKey,getActiveCryptoNamespace()); await inspectPeer(); }}>{i18n.t("security.acceptIdentity")}</button>}
              {!peerSafety.verified && !peerSafety.changed && <button type="button" onClick={async () => { await verifyPeerIdentity(peerSafety.uin, peerSafety.identityKey,getActiveCryptoNamespace()); await inspectPeer(); }}>{i18n.t("security.markVerified")}</button>}
              {peerSafety.verified && <div role="status">{i18n.t("security.verified")}</div>}
            </div>
          )}
        </div>
      </div>

      <PanicPinSettings />

      <div className="iceq-settings-row">
        <div className="iceq-settings-status">
          <strong>{i18n.t("security.panicWipeTitle")}</strong>
          <p>{i18n.t("security.panicWipeWarning")}</p>
          <button type="button" disabled={panicBusy} onClick={openPanicWipe}>
            {i18n.t("security.panicWipeAction")}
          </button>
          {panicError === i18n.t("security.panicWipeFailed") && <div role="alert">{panicError}</div>}
        </div>
      </div>

      {panicConfirmOpen && (
        <div
          className="iceq-modal-backdrop"
          role="dialog"
          aria-modal="true"
          aria-labelledby="panic-wipe-confirm-title"
          onClick={() => !panicBusy && setPanicConfirmOpen(false)}
        >
          <div className="iceq-modal" onClick={(e) => e.stopPropagation()}>
            <h2 id="panic-wipe-confirm-title" className="text-lg font-semibold text-text">
              {i18n.t("security.panicWipeAction")}
            </h2>
            <p className="mt-1 text-sm text-text-2">{i18n.t("security.panicWipeConfirm")}</p>

            <div className="mt-3 flex gap-2">
              <button
                type="button"
                className={panicMode === "pin" ? "iceq-btn-primary text-xs" : "iceq-btn-secondary text-xs"}
                onClick={() => setPanicMode("pin")}
              >
                {i18n.t("security.panicWipeEnterPin")}
              </button>
              <button
                type="button"
                className={panicMode === "passphrase" ? "iceq-btn-primary text-xs" : "iceq-btn-secondary text-xs"}
                onClick={() => setPanicMode("passphrase")}
              >
                {i18n.t("setup.passphraseLabel")}
              </button>
            </div>

            {panicMode === "pin" && (
              <div className="mt-3">
                <label htmlFor="panic-wipe-pin" className="mb-1 block text-xs text-text-2">
                  {i18n.t("security.panicWipeEnterPin")}
                </label>
                <input
                  id="panic-wipe-pin"
                  type="password"
                  inputMode="numeric"
                  autoComplete="off"
                  maxLength={4}
                  pattern="[0-9]{4}"
                  className="iceq-input"
                  value={panicPinInput}
                  onChange={(event) => setPanicPinInput(event.target.value.replace(/[^0-9]/g, "").slice(0, 4))}
                  disabled={panicBusy}
                />
                <p className="mt-1 text-xs text-text-2">{i18n.t("security.panicWipeEnterPinHelp")}</p>
              </div>
            )}

            {panicMode === "passphrase" && (
              <div className="mt-3">
                <label htmlFor="panic-wipe-passphrase" className="mb-1 block text-xs text-text-2">
                  {i18n.t("setup.passphraseInput")}
                </label>
                <input
                  id="panic-wipe-passphrase"
                  type="password"
                  autoComplete="off"
                  className="iceq-input"
                  value={panicPassphraseInput}
                  onChange={(event) => setPanicPassphraseInput(event.target.value)}
                  disabled={panicBusy}
                />
                <p className="mt-1 text-xs text-text-2">{i18n.t("setup.createPassphraseHelp")}</p>
              </div>
            )}

            {panicError && <div role="alert" className="mt-2 text-sm">{panicError}</div>}

            <div className="iceq-modal-buttons">
              <button type="button" className="iceq-btn-secondary" disabled={panicBusy} onClick={() => setPanicConfirmOpen(false)}>
                {i18n.t("security.panicWipeCancel")}
              </button>
              <button
                type="button"
                className="iceq-btn-primary"
                disabled={panicBusy}
                onClick={() => {
                  setPanicBusy(true);
                  setPanicError(null);
                  if (panicMode === "passphrase") {
                    void handlePassphraseWipe();
                  } else {
                    void (async () => {
                      await handlePinWipe();
                      setPanicBusy(false);
                    })();
                  }
                }}
              >
                {i18n.t("security.panicWipeAction")}
              </button>
            </div>
          </div>
        </div>
      )}

      <div className="iceq-settings-row">
        <div className="iceq-settings-status">
          <strong>{i18n.t("recovery.title")}</strong>
          <p>{i18n.t("recovery.help")}</p>
          <button type="button" onClick={() => navigate("/recovery")}>
            {i18n.t("recovery.importAction")}
          </button>
        </div>
      </div>

      <div className="iceq-settings-row">
        <div className="iceq-settings-status">
          <strong>{i18n.t("security.localFingerprint")}</strong>
          <div>{renderFingerprint(fingerprintStatus, i18n.t)}</div>
          <p>{i18n.t("security.fingerprintHelp")}</p>
        </div>
      </div>

    </div>
  );
}

function renderFingerprint(status: FingerprintStatus, translate: ReturnType<typeof useI18n>["t"]): string {
  if (status.kind === "loading") return translate("security.fingerprintLoading");
  if (status.kind === "error") return translate("security.fingerprintUnavailable");
  return status.fingerprint ?? translate("security.noIdentity");
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
