// src/api/auth.ts
//
// Auth flow. The client-side entry points are:
//
//   register(input)        — create a new user. Returns
//                            { user, tokens } on success.
//   login(input)           — exchange username/password for
//                            tokens.
//   refresh()              — public; the client.ts wrapper calls this on 401.
//                            The refresh token is an HttpOnly cookie.
//   logout()               — invalidate the server-side session; client always
//                            clears local state regardless of
//                            the server response.
//   me()                   — fetch the authenticated user's
//                            profile.
//
// All typed end-to-end. The IdentityKey is a base64url string
// produced by signal.generateIdentityKeyPair() on the client.

import { fetchJSON, fetchWithAuth } from "./client";

export interface RegisterInput {
  username: string;
  password: string;
  identity_key: string; // b64url public key
}

export interface LoginInput {
  username: string;
  password: string;
}

export interface AuthTokens {
  access_token: string;
  refresh_token: string;
  // Token lifetimes in seconds. Optional; the server may
  // omit them and the client just uses a fixed
  // 14-minute refresh cadence.
  expires_in?: number;
}

export interface UserPublic {
  uin: number;
  username: string;
  created_at?: string;
}

export interface AuthResponse {
  user: UserPublic;
  tokens: AuthTokens;
}

export async function register(input: RegisterInput): Promise<AuthResponse> {
  return fetchJSON<AuthResponse>("/api/auth/register", {
    method: "POST",
    body: input,
    noAuth: true,
  });
}

export async function login(input: LoginInput): Promise<AuthResponse> {
  return fetchJSON<AuthResponse>("/api/auth/login", {
    method: "POST",
    body: input,
    noAuth: true,
  });
}

export async function refresh(): Promise<AuthTokens> {
	return fetchJSON<AuthTokens>("/api/auth/refresh", {
		method: "POST",
		body: {},
		noAuth: true,
		skipRefresh: true,
	});
}

export async function logout(signal?: AbortSignal, accessToken?: string | null): Promise<void> {
	await fetchWithAuth("/api/auth/logout", {
		method: "POST",
		body: {},
		skipRefresh: true,
		signal,
		...(accessToken ? { headers: { Authorization: `Bearer ${accessToken}` } } : {}),
	});
}

export async function panicWipe(pin?: string): Promise<void> {
  await fetchWithAuth("/api/auth/panic-wipe", { method: "POST", body: { pin: pin ?? "" } });
}

export async function panicWipeWithSignature(challengeID: string, signature: string): Promise<void> {
  await fetchWithAuth("/api/auth/panic-wipe", { method: "POST", body: { challenge_id: challengeID, signature } });
}

export async function uploadWipePublicKey(publicKey: string, password?: string): Promise<void> {
  await fetchWithAuth("/api/auth/panic-wipe-public-key", {
    method: "PUT",
    body: { public_key: publicKey, password: password ?? "" },
  });
}

// getWipePublicKey -- the account's currently-enrolled wipe public key, or
// null if none is enrolled yet. Used by lib/panicWipeKey.ts's
// reconcileWipeKey to verify local wipe-key state against the server after
// an ambiguous enrollment/rotation outcome, rather than guessing from an
// HTTP status code.
export async function getWipePublicKey(): Promise<{ public_key: string | null }> {
  return fetchJSON("/api/auth/panic-wipe-public-key");
}

export async function requestWipeChallenge(): Promise<{ challenge_id: string; challenge: string }> {
  return fetchJSON("/api/auth/panic-wipe-challenge", { method: "POST" });
}

// setPanicPin sets (pin non-empty) or clears (pin === "") the panic-wipe
// PIN. The server re-verifies currentPassword before writing -- changing
// this security setting requires the same re-authentication bar as any
// other one.
export async function setPanicPin(currentPassword: string, pin: string): Promise<void> {
  await fetchWithAuth("/api/auth/panic-pin", {
    method: "PUT",
    body: { current_password: currentPassword, pin },
  });
}

export async function me(signal?: AbortSignal): Promise<UserPublic> {
  return fetchJSON<UserPublic>("/api/auth/me", { method: "GET", signal });
}

export interface CryptoBinding {
  uin: number;
  identity_key: string;
}

/** Returns the authenticated user's public identity key for
 *  ambiguous registration recovery. Self-only — never accepts
 *  a target UIN and never exposes private material. */
export async function cryptoBinding(signal?: AbortSignal): Promise<CryptoBinding> {
  return fetchJSON<CryptoBinding>("/api/auth/crypto-binding", { method: "GET", signal });
}
