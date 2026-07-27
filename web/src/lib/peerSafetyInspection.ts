// src/lib/peerSafetyInspection.ts
//
// Composes the existing, independently-tested peer-verification
// primitives -- identityTrust.ts's TOFU pinning, safetyFingerprint.ts's
// combined safety number, signal.ts's signed-prekey verification --
// into the single fetch-verify-assess sequence both SecuritySettings
// and the in-chat verification modal need. This is the only place
// that composes them; neither caller re-implements the sequence.
//
// Dependency-injected (see signalBootstrap.ts's ensureOwnBundle for
// the same pattern) so the sequence is unit-testable without a real
// backend or WebCrypto signature material.

import { loadIdentity, type CryptoNamespace } from "./indexeddb";
import { fetchBundle, type RemotePreKeyBundle } from "../api/keys";
import { computeSafetyNumber, type SafetyIdentity } from "./safetyFingerprint";
import { assessPeerIdentity } from "./identityTrust";
import { verifySignedPreKeyBundle } from "./signal";

export interface PeerSafetyInspection {
  uin: number;
  identityKey: string;
  number: string;
  changed: boolean;
  verified: boolean;
}

// Thrown when the LOCAL device has no identity key yet -- distinct
// from anything fetchBundle/verifySignedPreKeyBundle might throw, so
// callers can show a translated message for this one expected case
// and fall back to the raw error message for anything else.
export const PEER_SAFETY_LOCAL_IDENTITY_UNAVAILABLE = "local-identity-unavailable";

export interface InspectPeerSafetyDeps {
  loadIdentity: (ns: CryptoNamespace) => ReturnType<typeof loadIdentity>;
  fetchBundle: (uin: number) => Promise<RemotePreKeyBundle>;
  verifySignedPreKeyBundle: (
    remote: Pick<RemotePreKeyBundle, "identity_key" | "signed_pre_key">,
  ) => Promise<true>;
  assessPeerIdentity: typeof assessPeerIdentity;
  computeSafetyNumber: (a: SafetyIdentity, b: SafetyIdentity) => Promise<string>;
}

const defaultDeps: InspectPeerSafetyDeps = {
  loadIdentity,
  fetchBundle,
  verifySignedPreKeyBundle,
  assessPeerIdentity,
  computeSafetyNumber,
};

// inspectPeerSafety -- fetch a peer's current key bundle, verify its
// signed prekey, run it through TOFU assessment, and compute the
// combined safety number. `verified` is only true when the stored
// trust record's verified flag AND its pinned fingerprint both match
// the identity key just fetched -- a verification recorded against
// an old key must not read as "verified" once the key has changed.
export async function inspectPeerSafety(
  selfUin: number,
  peerUin: number,
  ns: CryptoNamespace,
  deps: InspectPeerSafetyDeps = defaultDeps,
): Promise<PeerSafetyInspection> {
  const [local, remote] = await Promise.all([deps.loadIdentity(ns), deps.fetchBundle(peerUin)]);
  if (!local) throw new Error(PEER_SAFETY_LOCAL_IDENTITY_UNAVAILABLE);
  await deps.verifySignedPreKeyBundle(remote);
  const assessment = await deps.assessPeerIdentity(peerUin, remote.identity_key, ns);
  const number = await deps.computeSafetyNumber(
    { uin: selfUin, identityKey: local.publicKey },
    { uin: peerUin, identityKey: remote.identity_key },
  );
  return {
    uin: peerUin,
    identityKey: remote.identity_key,
    number,
    changed: !assessment.sendAllowed,
    verified: assessment.record.verified && assessment.record.fingerprint === remote.identity_key,
  };
}
