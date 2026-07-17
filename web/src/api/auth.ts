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

export async function logout(signal?: AbortSignal): Promise<void> {
	await fetchWithAuth("/api/auth/logout", {
		method: "POST",
		body: {},
		skipRefresh: true,
		signal,
	});
}

export async function panicWipe(): Promise<void> {
  await fetchWithAuth("/api/auth/panic-wipe", { method: "POST", body: {} });
}

export async function me(): Promise<UserPublic> {
  return fetchJSON<UserPublic>("/api/auth/me", { method: "GET" });
}
