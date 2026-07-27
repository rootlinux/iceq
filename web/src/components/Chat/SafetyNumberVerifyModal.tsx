// src/components/Chat/SafetyNumberVerifyModal.tsx
//
// In-chat entry point for verifying a peer's safety number. Reuses
// exactly the same tested engine SecuritySettings.tsx's "Verify a
// contact" flow uses (lib/peerSafetyInspection.ts -> identityTrust.ts
// TOFU pinning + safetyFingerprint.ts's combined safety number +
// Settings/SafetyQr.tsx's QR compare). This component only adds
// discoverability: launching the same flow pre-scoped to the peer
// already open in the conversation, instead of requiring their UIN
// to be typed into Settings. No new crypto or storage code, and no
// separate "verified" store -- verification state lives only in
// identityTrust.ts's STORE_PEER_TRUST, same as Settings.

import { useCallback, useEffect, useState } from "react";
import { getActiveCryptoNamespace } from "../../lib/indexeddb";
import {
  inspectPeerSafety,
  PEER_SAFETY_LOCAL_IDENTITY_UNAVAILABLE,
  type PeerSafetyInspection,
} from "../../lib/peerSafetyInspection";
import { acceptPeerIdentity, verifyPeerIdentity } from "../../lib/identityTrust";
import { SafetyQr } from "../Settings/SafetyQr";
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
    <div className="iceq-modal-backdrop" role="dialog" aria-modal="true">
      <div className="iceq-modal max-w-lg">
        <h4>
          {i18n.t("security.verifySafetyNumber")} — {peerLabel}
        </h4>

        {state.kind === "loading" && (
          <p className="iceq-settings-status">{i18n.t("security.fingerprintLoading")}</p>
        )}

        {state.kind === "error" && (
          <p className="iceq-settings-status" role="alert">
            {state.message}
          </p>
        )}

        {state.kind === "ready" && (
          <>
            <div className="iceq-card mt-3 break-all font-mono text-sm tracking-wide">
              {state.safety.number}
            </div>
            <SafetyQr fingerprint={state.safety.number} />

            {state.safety.changed && (
              <div role="alert">{i18n.t("security.identityChanged")}</div>
            )}
            {state.safety.changed && (
              <button
                type="button"
                className="iceq-btn-secondary"
                onClick={() => {
                  void acceptPeerIdentity(peerUin, state.safety.identityKey, getActiveCryptoNamespace()).then(
                    reload,
                  );
                }}
              >
                {i18n.t("security.acceptIdentity")}
              </button>
            )}
            {!state.safety.verified && !state.safety.changed && (
              <button
                type="button"
                className="iceq-btn-primary"
                onClick={() => {
                  void verifyPeerIdentity(peerUin, state.safety.identityKey, getActiveCryptoNamespace()).then(
                    reload,
                  );
                }}
              >
                {i18n.t("security.markVerified")}
              </button>
            )}
            {state.safety.verified && <div role="status">{i18n.t("security.verified")}</div>}
          </>
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
