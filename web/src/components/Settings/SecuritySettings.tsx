// src/components/Settings/SecuritySettings.tsx
//
// Security settings panel — Arctic Signal design.
// Privacy toggles, identity fingerprint, peer verification,
// panic PIN, panic wipe, recovery import.

import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useDialogFocus } from "../../hooks/useDialogFocus";
import { getActiveCryptoNamespace, loadIdentity } from "../../lib/indexeddb";
import { SafetyQr } from "./SafetyQr";
import {
  inspectPeerSafety,
  PEER_SAFETY_LOCAL_IDENTITY_UNAVAILABLE,
  type PeerSafetyInspection,
} from "../../lib/peerSafetyInspection";
import { acceptPeerIdentity, verifyPeerIdentity } from "../../lib/identityTrust";
import { useAuthStore } from "../../store/authStore";
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
  const panicTriggerRef = useRef<HTMLButtonElement>(null);
  const panicDialogRef = useDialogFocus(panicConfirmOpen, () => setPanicConfirmOpen(false), panicTriggerRef);
  const [fingerprintStatus, setFingerprintStatus] = useState<FingerprintStatus>({ kind: "loading" });
  const [peerUin, setPeerUin] = useState("");
  const [peerSafety, setPeerSafety] = useState<PeerSafetyInspection | null>(null);
  const [peerError, setPeerError] = useState<string | null>(null);

  const inspectPeer = async (): Promise<void> => {
    const parsed = Number(peerUin);
    if (!Number.isSafeInteger(parsed) || parsed <= 0 || selfUin === null) {
      setPeerError(i18n.t("security.invalidUin")); return;
    }
    try {
      setPeerSafety(await inspectPeerSafety(selfUin, parsed, getActiveCryptoNamespace()));
      setPeerError(null);
    } catch (error) {
      setPeerSafety(null);
      const message = (error as Error).message;
      setPeerError(message === PEER_SAFETY_LOCAL_IDENTITY_UNAVAILABLE ? i18n.t("security.localUnavailable") : message);
    }
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
    return () => { cancelled = true; };
  }, []);

  async function handlePassphraseWipe(): Promise<void> {
    setPanicError(null);
    setPanicBusy(true);
    try {
      const unlocked = await unlockSecurityVault(panicPassphraseInput);
      if (!unlocked) { setPanicError(i18n.t("security.panicWipeWrongPin")); return; }

      const privateKey = await loadAndDecryptWipePrivateKey();
      if (!privateKey) { setPanicError(i18n.t("security.panicWipeFailed")); return; }

      const challengeResp = await requestWipeChallenge();
      const challengeBytes = new Uint8Array(
        Uint8Array.from(atob(challengeResp.challenge), c => c.charCodeAt(0))
      );
      const sigBytes = await signWipeChallenge(challengeBytes, privateKey);
      const sigB64 = btoa(String.fromCharCode(...sigBytes));
      await panicWipeWithSignature(challengeResp.challenge_id, sigB64);

      lockSecurityVault();
      try {
        await useAuthStore.getState().handleServerWipe();
        setPanicConfirmOpen(false);
        navigate("/login", { replace: true });
      } catch {
        setPanicError(i18n.t("cleanup.failed"));
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
      navigate("/login", { replace: true });
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
      {/* ── Privacy ────────────────────────────────────────────────── */}
      <PrivacySettings />

      {/* ── Safety QR ──────────────────────────────────────────────── */}
      {fingerprintStatus.kind === "ready" && fingerprintStatus.fingerprint && (
        <div className="iceq-settings-section">
          <SafetyQr fingerprint={fingerprintStatus.fingerprint} />
        </div>
      )}

      {/* ── Verify a contact ───────────────────────────────────────── */}
      <div className="iceq-settings-section">
        <h3 className="text-sm font-semibold text-frozen">{i18n.t("security.verifyContact")}</h3>
        <div className="flex gap-2">
          <input
            aria-label={i18n.t("security.contactUin")}
            inputMode="numeric"
            className="iceq-input flex-1 text-xs"
            value={peerUin}
            onChange={(event) => setPeerUin(event.target.value)}
            placeholder={i18n.t("contacts.uinExample")}
          />
          <button type="button" className="iceq-btn-secondary text-xs" onClick={() => void inspectPeer()}>
            {i18n.t("security.loadSafety")}
          </button>
        </div>
        {peerError && <div role="alert" className="text-xs text-destructive">{peerError}</div>}
        {peerSafety && (
          <div className="mt-2 space-y-2">
            <div className="break-all rounded border border-ice-border bg-deep-ice p-2 text-mono text-xs text-frozen select-all">
              {peerSafety.number}
            </div>
            <SafetyQr fingerprint={peerSafety.number} />
            {peerSafety.changed && (
              <div role="alert" className="iceq-alert-warning text-xs">{i18n.t("security.identityChanged")}</div>
            )}
            {peerSafety.changed && (
              <button type="button" className="iceq-btn-secondary text-xs w-full" onClick={async () => {
                await acceptPeerIdentity(peerSafety.uin, peerSafety.identityKey, getActiveCryptoNamespace());
                await inspectPeer();
              }}>
                {i18n.t("security.acceptIdentity")}
              </button>
            )}
            {!peerSafety.verified && !peerSafety.changed && (
              <button type="button" className="iceq-btn-primary text-xs w-full" onClick={async () => {
                await verifyPeerIdentity(peerSafety.uin, peerSafety.identityKey, getActiveCryptoNamespace());
                await inspectPeer();
              }}>
                {i18n.t("security.markVerified")}
              </button>
            )}
            {peerSafety.verified && (
              <div role="status" className="iceq-alert-success text-xs flex items-center gap-1.5">
                <svg width="14" height="14" viewBox="0 0 14 14" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><polyline points="2.5 7 5.5 10 11.5 4"/></svg>
                {i18n.t("security.verified")}
              </div>
            )}
          </div>
        )}
      </div>

      {/* ── Panic PIN ──────────────────────────────────────────────── */}
      <PanicPinSettings />

      {/* ── Panic Wipe ─────────────────────────────────────────────── */}
      <div className="iceq-settings-section border-destructive/30">
        <h3 className="text-sm font-semibold text-destructive">{i18n.t("security.panicWipeTitle")}</h3>
        <p className="text-xs text-mist">{i18n.t("security.panicWipeWarning")}</p>
        <button
          type="button"
          ref={panicTriggerRef}
          className="iceq-btn-destructive mt-2"
          disabled={panicBusy}
          onClick={openPanicWipe}
        >
          {i18n.t("security.panicWipeAction")}
        </button>
        {panicError === i18n.t("security.panicWipeFailed") && (
          <div role="alert" className="mt-2 text-xs text-destructive">{panicError}</div>
        )}
      </div>

      {/* ── Recovery import ────────────────────────────────────────── */}
      <div className="iceq-settings-section">
        <h3 className="text-sm font-semibold text-frozen">{i18n.t("recovery.title")}</h3>
        <p className="text-xs text-mist">{i18n.t("recovery.help")}</p>
        <button type="button" className="iceq-btn-secondary mt-2" onClick={() => navigate("/recovery")}>
          {i18n.t("recovery.importAction")}
        </button>
      </div>

      {/* ── Local fingerprint ──────────────────────────────────────── */}
      <div className="iceq-settings-section">
        <h3 className="text-sm font-semibold text-frozen">{i18n.t("security.localFingerprint")}</h3>
        <div className="break-all rounded border border-ice-border bg-deep-ice p-2 text-mono text-xs text-frozen select-all">
          {renderFingerprint(fingerprintStatus, i18n.t)}
        </div>
        <p className="mt-1 text-xs text-mist-dim">{i18n.t("security.fingerprintHelp")}</p>
      </div>

      {/* ── Panic Wipe Confirmation Modal ──────────────────────────── */}
      {panicConfirmOpen && (
        <div
          className="iceq-modal-backdrop"
          role="dialog"
          aria-modal="true"
          aria-labelledby="panic-wipe-confirm-title"
          ref={panicDialogRef}
          onClick={() => !panicBusy && setPanicConfirmOpen(false)}
        >
          <div className="iceq-modal" onClick={(e) => e.stopPropagation()}>
            <h2 id="panic-wipe-confirm-title" className="text-lg font-semibold text-destructive">
              {i18n.t("security.panicWipeAction")}
            </h2>
            <p className="mt-1 text-sm text-mist">{i18n.t("security.panicWipeConfirm")}</p>

            {/* Auth mode tabs */}
            <div className="iceq-tabs mt-3">
              <button
                type="button"
                className={`iceq-tab ${panicMode === "pin" ? "iceq-tab--active" : ""}`}
                onClick={() => setPanicMode("pin")}
              >
                {i18n.t("security.panicWipeEnterPin")}
              </button>
              <button
                type="button"
                className={`iceq-tab ${panicMode === "passphrase" ? "iceq-tab--active" : ""}`}
                onClick={() => setPanicMode("passphrase")}
              >
                {i18n.t("setup.passphraseLabel")}
              </button>
            </div>

            {panicMode === "pin" && (
              <div className="mt-3">
                <label htmlFor="panic-wipe-pin" className="text-label text-mist">
                  {i18n.t("security.panicWipeEnterPin")}
                </label>
                <input
                  id="panic-wipe-pin"
                  type="password"
                  inputMode="numeric"
                  autoComplete="off"
                  maxLength={4}
                  pattern="[0-9]{4}"
                  className="iceq-input mt-1"
                  value={panicPinInput}
                  onChange={(event) => setPanicPinInput(event.target.value.replace(/[^0-9]/g, "").slice(0, 4))}
                  disabled={panicBusy}
                />
                <p className="mt-1 text-xs text-mist-dim">{i18n.t("security.panicWipeEnterPinHelp")}</p>
              </div>
            )}

            {panicMode === "passphrase" && (
              <div className="mt-3">
                <label htmlFor="panic-wipe-passphrase" className="text-label text-mist">
                  {i18n.t("setup.passphraseInput")}
                </label>
                <input
                  id="panic-wipe-passphrase"
                  type="password"
                  autoComplete="off"
                  className="iceq-input mt-1"
                  value={panicPassphraseInput}
                  onChange={(event) => setPanicPassphraseInput(event.target.value)}
                  disabled={panicBusy}
                />
                <p className="mt-1 text-xs text-mist-dim">{i18n.t("setup.createPassphraseHelp")}</p>
              </div>
            )}

            {panicError && (
              <div role="alert" className="iceq-alert-error mt-3 text-xs">{panicError}</div>
            )}

            <div className="iceq-modal-buttons">
              <button
                type="button"
                className="iceq-btn-secondary"
                disabled={panicBusy}
                onClick={() => setPanicConfirmOpen(false)}
              >
                {i18n.t("security.panicWipeCancel")}
              </button>
              <button
                type="button"
                className="iceq-btn-destructive"
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
    await globalThis.crypto.subtle.digest("SHA-256", new TextEncoder().encode(publicKey)),
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
