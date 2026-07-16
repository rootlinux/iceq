import { useEffect, useState } from "react";
import { loadIdentity } from "../../lib/indexeddb";
import { SafetyQr } from "./SafetyQr";
import { fetchBundle } from "../../api/keys";
import { computeSafetyNumber } from "../../lib/safetyFingerprint";
import { acceptPeerIdentity, assessPeerIdentity, verifyPeerIdentity } from "../../lib/identityTrust";
import { useAuthStore } from "../../store/authStore";
import { verifySignedPreKeyBundle } from "../../lib/signal";
import { PrivacySettings } from "./PrivacySettings";
import { useI18n } from "../../i18n";

type FingerprintStatus =
  | { kind: "loading" }
  | { kind: "ready"; fingerprint: string | null }
  | { kind: "error" };

export function SecuritySettings(): JSX.Element {
  const i18n = useI18n();
  const selfUin = useAuthStore((state) => state.uin);
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
      const [local, remote] = await Promise.all([loadIdentity(), fetchBundle(parsed)]);
      if (!local) throw new Error(i18n.t("security.localUnavailable"));
      await verifySignedPreKeyBundle(remote);
      const assessment = await assessPeerIdentity(parsed, remote.identity_key);
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
        const identity = await loadIdentity();
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
              {peerSafety.changed && <button type="button" onClick={async () => { await acceptPeerIdentity(peerSafety.uin, peerSafety.identityKey); await inspectPeer(); }}>{i18n.t("security.acceptIdentity")}</button>}
              {!peerSafety.verified && !peerSafety.changed && <button type="button" onClick={async () => { await verifyPeerIdentity(peerSafety.uin, peerSafety.identityKey); await inspectPeer(); }}>{i18n.t("security.markVerified")}</button>}
              {peerSafety.verified && <div role="status">{i18n.t("security.verified")}</div>}
            </div>
          )}
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
