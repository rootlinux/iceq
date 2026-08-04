// src/components/Chat/SafetyNumberVerifyModal.tsx
//
// In-chat peer safety number verification — Arctic Signal design.
// Reuses the same engine as SecuritySettings.

import { useCallback, useEffect, useRef, useState } from "react";
import { getActiveCryptoNamespace } from "../../lib/indexeddb";
import {
  inspectPeerSafety,
  PEER_SAFETY_LOCAL_IDENTITY_UNAVAILABLE,
  type PeerSafetyInspection,
} from "../../lib/peerSafetyInspection";
import { acceptPeerIdentity, verifyPeerIdentity } from "../../lib/identityTrust";
import { SafetyQr } from "../Settings/SafetyQr";
import { useDialogFocus } from "../../hooks/useDialogFocus";
import { useI18n } from "../../i18n";

interface Props {
  selfUin: number;
  peerUin: number;
  peerLabel: string;
  onClose: () => void;
}

type State =
  | { kind: "loading" }
  | { kind: "ready"; safety: PeerSafetyInspection }
  | { kind: "error"; message: string };

export function SafetyNumberVerifyModal({ selfUin, peerUin, peerLabel, onClose }: Props): JSX.Element {
  const i18n = useI18n();
  const [state, setState] = useState<State>({ kind: "loading" });
  const returnFocusRef = useRef<HTMLElement>(null);
  const dialogRef = useDialogFocus(true, onClose, returnFocusRef);

  const reload = useCallback(async () => {
    setState({ kind: "loading" });
    try {
      const safety = await inspectPeerSafety(selfUin, peerUin, getActiveCryptoNamespace());
      setState({ kind: "ready", safety });
    } catch (error) {
      const message = (error as Error).message;
      setState({
        kind: "error",
        message:
          message === PEER_SAFETY_LOCAL_IDENTITY_UNAVAILABLE ? i18n.t("security.localUnavailable") : message,
      });
    }
  }, [selfUin, peerUin, i18n]);

  useEffect(() => {
    void reload();
  }, [reload]);

  return (
    <div className="iceq-modal-backdrop" role="dialog" aria-modal="true" aria-labelledby="safety-verify-title" ref={dialogRef}>
      <div className="iceq-modal max-w-modal-lg">
        <div className="mb-4 flex items-start justify-between gap-4">
          <h2 id="safety-verify-title" className="text-lg font-semibold text-frozen">
            {i18n.t("security.verifySafetyNumber")} — {peerLabel}
          </h2>
          <button
            type="button"
            className="iceq-btn-icon"
            aria-label={i18n.t("common.close")}
            onClick={onClose}
            ref={returnFocusRef as React.RefObject<HTMLButtonElement>}
          >
            <svg width="18" height="18" viewBox="0 0 18 18" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round">
              <line x1="4" y1="4" x2="14" y2="14" /><line x1="14" y1="4" x2="4" y2="14" />
            </svg>
          </button>
        </div>

        {state.kind === "loading" && (
          <div className="flex items-center justify-center gap-2 py-6 text-sm text-mist">
            <span className="iceq-spinner" />
            {i18n.t("security.fingerprintLoading")}
          </div>
        )}

        {state.kind === "error" && (
          <div role="alert" className="iceq-alert-error">{state.message}</div>
        )}

        {state.kind === "ready" && (
          <div className="space-y-4">
            <div className="break-all rounded-md border border-ice-border bg-deep-ice p-3 text-mono text-sm text-frozen tracking-wide select-all">
              {state.safety.number}
            </div>

            <SafetyQr fingerprint={state.safety.number} />

            {state.safety.changed && (
              <>
                <div role="alert" className="iceq-alert-warning">
                  {i18n.t("security.identityChanged")}
                </div>
                <button
                  type="button"
                  className="iceq-btn-secondary w-full"
                  onClick={() => {
                    void acceptPeerIdentity(peerUin, state.safety.identityKey, getActiveCryptoNamespace()).then(reload);
                  }}
                >
                  {i18n.t("security.acceptIdentity")}
                </button>
              </>
            )}

            {!state.safety.verified && !state.safety.changed && (
              <button
                type="button"
                className="iceq-btn-primary w-full"
                onClick={() => {
                  void verifyPeerIdentity(peerUin, state.safety.identityKey, getActiveCryptoNamespace()).then(reload);
                }}
              >
                {i18n.t("security.markVerified")}
              </button>
            )}

            {state.safety.verified && (
              <div role="status" className="iceq-alert-success flex items-center gap-2">
                <svg width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><polyline points="3 8 6.5 11.5 13 5"/></svg>
                {i18n.t("security.verified")}
              </div>
            )}
          </div>
        )}

        <div className="iceq-modal-buttons">
          <button type="button" className="iceq-btn-secondary" onClick={onClose}>
            {i18n.t("common.close")}
          </button>
        </div>
      </div>
    </div>
  );
}

export default SafetyNumberVerifyModal;
