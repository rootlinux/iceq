import { loadPeerTrust, resetPeerSignalState, savePeerTrust, type StoredPeerTrust } from "./indexeddb";

const RAW_KEY_BYTES = 32;

export interface PeerTrustAssessment {
  status: "trusted" | "changed";
  sendAllowed: boolean;
  record: StoredPeerTrust;
}

export async function assessPeerIdentity(peerUin: number, fingerprint: string): Promise<PeerTrustAssessment> {
  validate(peerUin, fingerprint);
  const existing = await loadPeerTrust(peerUin);
  if (!existing) {
    const now = Date.now();
    const record: StoredPeerTrust = { version: 1, peerUin, fingerprint, verified: false, firstSeenAt: now, updatedAt: now };
    await savePeerTrust(record);
    return { status: "trusted", sendAllowed: true, record };
  }
  if (existing.fingerprint !== fingerprint) {
    const blocked = { ...existing, pendingFingerprint: fingerprint, updatedAt: Date.now() };
    await savePeerTrust(blocked);
    return { status: "changed", sendAllowed: false, record: blocked };
  }
  return { status: "trusted", sendAllowed: true, record: existing };
}

export async function acceptPeerIdentity(peerUin: number, fingerprint: string): Promise<void> {
  validate(peerUin, fingerprint);
  const existing = await loadPeerTrust(peerUin);
  const now = Date.now();
  await savePeerTrust({ version: 1, peerUin, fingerprint, verified: false, firstSeenAt: existing?.firstSeenAt ?? now, updatedAt: now });
  await resetPeerSignalState(peerUin);
}

export async function verifyPeerIdentity(peerUin: number, fingerprint: string): Promise<void> {
  const assessment = await assessPeerIdentity(peerUin, fingerprint);
  if (!assessment.sendAllowed) throw new Error("peer identity changed; accept it before verification");
  await savePeerTrust({ ...assessment.record, verified: true, updatedAt: Date.now() });
}

export const getPeerTrust = loadPeerTrust;

export async function isPeerSendAllowed(peerUin: number): Promise<boolean> {
  const trust = await loadPeerTrust(peerUin);
  return !trust?.pendingFingerprint;
}

function validate(peerUin: number, fingerprint: string): void {
  if (!Number.isSafeInteger(peerUin) || peerUin <= 0) throw new Error("invalid peer UIN");
  if (byteLength(fingerprint) !== RAW_KEY_BYTES) throw new Error("invalid public identity fingerprint");
}

function byteLength(value: string): number {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) return -1;
  try {
    const pad = "=".repeat((4 - value.length % 4) % 4);
    return atob(value.replace(/-/g, "+").replace(/_/g, "/") + pad).length;
  } catch { return -1; }
}
