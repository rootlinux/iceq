// src/api/keys.ts
//
// Prekey-bundle API. Two endpoints:
//
//   POST /api/keys/bundle       — upload own bundle
//   POST /api/keys/prekeys      — top up one-time prekeys
//   GET  /api/keys/prekeys/count — unused server-side prekey count
//   GET  /api/keys/bundle/:uin   — fetch a peer's bundle
//                                  (used by Signal X3DH)
//
// Privacy note: the bundle contains public-key material only.
// The private half of every key lives in IndexedDB; the
// server never sees it.

import { fetchJSON, fetchWithAuth } from "./client";

export interface SignedPreKeyUpload {
  id: number;
  public_key: string;
  // The server verifies the signature against the identity
  // key in the same bundle, so the client must produce a
  // valid signature. The Signal bindings do this internally
  // when the bundle is built; the value here is the
  // base64url-encoded signature bytes.
  signature: string;
}

export interface OneTimePreKeyUpload {
  id: number;
  public_key: string;
}

export interface PreKeyBundleUpload {
  identity_key: string;
  signed_pre_key: SignedPreKeyUpload;
  one_time_pre_keys: OneTimePreKeyUpload[];
  registration_id: number;
}

export async function uploadBundle(bundle: PreKeyBundleUpload, signal?: AbortSignal): Promise<void> {
  await fetchWithAuth("/api/keys/bundle", { method: "POST", body: bundle, signal });
}

export async function addPreKeys(prekeys: OneTimePreKeyUpload[], signal?: AbortSignal): Promise<{ accepted: number }> {
  await fetchWithAuth("/api/keys/prekeys", {
    method: "POST",
    body: { prekeys },
    signal,
  });
  return { accepted: prekeys.length };
}

export async function getPrekeyCount(signal?: AbortSignal): Promise<number> {
  const resp = await fetchJSON<{ count: number }>("/api/keys/prekeys/count", { method: "GET", signal });
  return resp.count;
}

export interface RemotePreKeyBundle {
  identity_key: string;
  signed_pre_key: { id: number; public_key: string; signature: string };
  pre_key?: { id: number; public_key: string };
  registration_id: number;
}

export async function fetchBundle(uin: number, signal?: AbortSignal): Promise<RemotePreKeyBundle> {
  return fetchJSON<RemotePreKeyBundle>(`/api/keys/bundle/${encodeURIComponent(String(uin))}`, {
    method: "GET",
    signal,
  });
}
