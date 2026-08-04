// src/store/authStore.ts
//
// Auth state. The store is the source of truth for
// "is the user logged in" and "what's their UIN/username".
//
// Persistence:
//   - accessToken is kept for REST Authorization and WebSocket auth.
//     The refresh token is an HttpOnly cookie and never enters JS.
//   - The Identity private key NEVER enters this store. It
//     lives in IndexedDB (lib/indexeddb.ts) and is only ever
//     touched by the Signal bindings.

import { create } from "zustand";
import { tokenStore } from "../api/client";
import * as authApi from "../api/auth";
import type { UserPublic } from "../api/auth";
import { attachmentGrantLifecycle } from "../lib/attachmentGrantLifecycle";
import { clearAllIceQLocalData, ICEQ_CLEANUP_REQUIRED_MARKER_KEY, ICEQ_LOGGED_OUT_MARKER_KEY, reasonErasesCryptoIdentity, registerMemoryReset, resetIceQMemory, type CleanupReason } from "../lib/localDataCleanup";
import { lockSecurityVault } from "../lib/securityVault";

const ACCOUNT_UIN_KEY = "iceq_account_uin";

interface AuthState {
  uin: number | null;
  username: string | null;
  accessToken: string | null;
  refreshToken: string | null;
  isAuthenticated: boolean;
  // Hydration flag. The App component gates rendering on
  // `hydrated` so the first paint shows a spinner, not a
  // flash-of-login.
  hydrated: boolean;

  // Actions
  hydrate: () => void;
  login: (username: string, password: string) => Promise<void>;
  register: (input: { username: string; password: string; identityKey: string }) => Promise<void>;
  logout: () => Promise<void>;
  panicWipe: (pin?: string) => Promise<void>;
  handleServerWipe: () => Promise<void>;
  retryLocalCleanup: () => Promise<void>;
  expireSession: () => Promise<void>;
  setSession: (user: UserPublic, access: string, refresh: string) => Promise<void>;
}

const EMPTY_AUTH = { uin: null, username: null, accessToken: null, refreshToken: null, isAuthenticated: false } as const;
const ATTACHMENT_REVOKE_GRACE_MS = 1_000;
let authLifecycleGeneration = 0;
let teardownFlight: Promise<void> | null = null;
let teardownFlightReason: CleanupReason | null = null;
let cleanupRequired: CleanupReason | null = null;
let cleanupRetryFlight: Promise<void> | null = null;

function beginSessionTeardown(): void {
	authLifecycleGeneration += 1;
}

function generationIsCurrent(generation: number): boolean {
	return generation === authLifecycleGeneration;
}

function assertGenerationCurrent(generation: number): void {
	if (!generationIsCurrent(generation)) throw new Error("authentication operation was superseded by session teardown");
}

async function revokeAttachmentsBounded(): Promise<void> {
	await new Promise<void>((resolve) => {
		const timeout = setTimeout(resolve, ATTACHMENT_REVOKE_GRACE_MS);
		void attachmentGrantLifecycle.revokeAll().catch(() => undefined).finally(() => {
			clearTimeout(timeout);
			resolve();
		});
	});
}

async function cleanSession(reason: CleanupReason, revokeAttachments = true): Promise<void> {
  // Durable local deletion must not depend on a remote grant revoke that may
  // never settle. Start both, then give the best-effort remote cleanup only a
  // bounded grace period before returning.
  const revokeFlight = revokeAttachments ? revokeAttachmentsBounded() : Promise.resolve();
  tokenStore.clear();
  try {
    await clearAllIceQLocalData(reason);
  } finally {
    await revokeFlight;
  }
}

function priorAccountUin(): number | null {
  if (typeof localStorage === "undefined") return null;
  const value = Number(localStorage.getItem(ACCOUNT_UIN_KEY));
  return Number.isSafeInteger(value) && value > 0 ? value : null;
}

function rememberAccountUin(uin: number): void {
  localStorage.setItem(ACCOUNT_UIN_KEY, String(uin));
}

async function observeLogoutBounded(accessToken: string | null): Promise<void> {
  await new Promise<void>((resolve) => {
    const controller = new AbortController();
    const timeout = setTimeout(() => {
      controller.abort();
      resolve();
    }, 1_000);
    void authApi.logout(controller.signal, accessToken).catch(() => undefined).finally(() => {
      clearTimeout(timeout);
      resolve();
    });
  });
}

function reportCleanupFailure(error: unknown): void {
	if (typeof window !== "undefined") {
		window.dispatchEvent(new CustomEvent("iceq:local-cleanup-failed", { detail: error }));
	}
}

function durableCleanupReason(): CleanupReason | null {
	if (typeof localStorage === "undefined") return null;
	const value = localStorage.getItem(ICEQ_CLEANUP_REQUIRED_MARKER_KEY);
	if (value === null) return null;
	if (value === "logout" || value === "auth-expired" || value === "account-change" || value === "panic-wipe") return value;
	// Legacy builds stored only "1", losing whether the failed pass was
	// destructive. Never risk clearing that marker with a non-destructive
	// retry while private material may remain from a real panic wipe.
	return "panic-wipe";
}

function hasDurableCleanupRequirement(): boolean {
	return durableCleanupReason() !== null;
}

function cleanupStrength(reason: CleanupReason): number {
	return reasonErasesCryptoIdentity(reason) ? 2 : 1;
}

function strongestOutstandingCleanup(): CleanupReason | null {
	const durable = durableCleanupReason();
	if (cleanupRequired === null) return durable;
	if (durable === null) return cleanupRequired;
	return cleanupStrength(durable) > cleanupStrength(cleanupRequired) ? durable : cleanupRequired;
}

function strongestRequiredCleanup(requested: CleanupReason): CleanupReason {
	const outstanding = strongestOutstandingCleanup();
	return outstanding !== null && cleanupStrength(outstanding) > cleanupStrength(requested) ? outstanding : requested;
}

function markCleanupRequired(reason: CleanupReason, error: unknown): void {
	const strongest = strongestRequiredCleanup(reason);
	cleanupRequired = strongest;
	if (typeof localStorage !== "undefined") localStorage.setItem(ICEQ_CLEANUP_REQUIRED_MARKER_KEY, strongest);
	reportCleanupFailure(error);
}

function clearCleanupRequirement(completedReason: CleanupReason): void {
	const outstanding = strongestOutstandingCleanup();
	if (outstanding !== null && cleanupStrength(outstanding) > cleanupStrength(completedReason)) return;
	cleanupRequired = null;
	if (typeof localStorage !== "undefined") localStorage.removeItem(ICEQ_CLEANUP_REQUIRED_MARKER_KEY);
}

async function runTrackedCleanup(requestedReason: CleanupReason): Promise<void> {
	const reason = strongestRequiredCleanup(requestedReason);
	try {
		await cleanSession(reason);
		clearCleanupRequirement(reason);
	} catch (error) {
		markCleanupRequired(reason, error);
		throw error;
	}
}

async function waitForTeardown(): Promise<void> {
	if (teardownFlight) await teardownFlight;
	if (cleanupRequired || hasDurableCleanupRequirement()) throw new Error("local cleanup must be retried before starting a new session");
}

function startSessionTeardown(reason: CleanupReason, logoutServer: boolean, set: (state: Partial<AuthState>) => void): Promise<void> {
	if (teardownFlight) {
		if (reasonErasesCryptoIdentity(reason) && teardownFlightReason !== null && !reasonErasesCryptoIdentity(teardownFlightReason)) {
			// A genuine server wipe outranks a benign logout/auth-expiry already
			// in progress. Preserve single-flight ordering, but require a second,
			// destructive cleanup pass before the wipe handler may resolve.
			return trackTeardownFlight(teardownFlight.catch(() => undefined).then(() => runTrackedCleanup(reason)), reason);
		}
		return teardownFlight;
	}
	const accessToken = tokenStore.accessToken;
	beginSessionTeardown();
	tokenStore.clear();
	resetIceQMemory();
	lockSecurityVault();
	set(EMPTY_AUTH);
	const ownerGeneration = authLifecycleGeneration;
	return trackTeardownFlight((async () => {
		if (logoutServer) await observeLogoutBounded(accessToken);
		try {
			await runTrackedCleanup(reason);
		} catch (error) {
			throw error;
		} finally {
			if (generationIsCurrent(ownerGeneration)) {
				set(EMPTY_AUTH);
				localStorage.setItem(ICEQ_LOGGED_OUT_MARKER_KEY, "1");
			}
		}
	})(), reason);
}

function trackTeardownFlight(work: Promise<void>, reason: CleanupReason): Promise<void> {
	const tracked = work.finally(() => {
		if (teardownFlight === tracked) {
			teardownFlight = null;
			teardownFlightReason = null;
		}
	});
	teardownFlight = tracked;
	teardownFlightReason = reason;
	return tracked;
}

export const useAuthStore = create<AuthState>((set) => ({
  uin: null,
  username: null,
  accessToken: null,
  refreshToken: null,
  isAuthenticated: false,
  hydrated: false,

	hydrate: () => {
		if (hasDurableCleanupRequirement()) {
			cleanupRequired = strongestOutstandingCleanup() ?? "panic-wipe";
			tokenStore.clear();
			resetIceQMemory();
			set({ ...EMPTY_AUTH, hydrated: true });
			queueMicrotask(() => reportCleanupFailure(new Error("local cleanup must be retried before restoring a session")));
			return;
		}
		const generation = authLifecycleGeneration;
		// Read the short-lived access token from localStorage on first load. The user
		// object is unknown until the next /me round-trip; we
		// optimistically set isAuthenticated = true so the chat
		// shell can render while /me is in flight. If /me fails
		// the api/client refresh-on-401 will demote us.
		const access = tokenStore.accessToken;
		if (access) {
			set({ accessToken: access, refreshToken: null, isAuthenticated: true, hydrated: true });
			// Kick off a /me to populate username/uin.
			authApi
				.me()
        .then(async (u) => {
          if (!generationIsCurrent(generation)) return;
          const previousUin = useAuthStore.getState().uin ?? priorAccountUin();
          if (previousUin !== null && previousUin !== u.uin) {
            tokenStore.clear();
            resetIceQMemory();
            set({ ...EMPTY_AUTH, hydrated: true });
            await runTrackedCleanup("account-change");
            if (!generationIsCurrent(generation)) return;
            tokenStore.set(access);
          }
          if (!generationIsCurrent(generation)) return;
          rememberAccountUin(u.uin);
          set({ uin: u.uin, username: u.username, accessToken: access, isAuthenticated: true, hydrated: true });
        })
        .catch(() => {
          if (!generationIsCurrent(generation)) return;
          // /me failed; the refresh-on-401 path in api/client
          // will have already routed us back to /login if
          // appropriate. Nothing more to do here.
        });
		} else if (localStorage.getItem(ICEQ_LOGGED_OUT_MARKER_KEY) === "1") {
			set({ hydrated: true });
		} else {
			void authApi
				.refresh()
				.then((tokens) => {
					if (!generationIsCurrent(generation)) return null;
					tokenStore.set(tokens.access_token);
					set({ accessToken: tokens.access_token, refreshToken: null, isAuthenticated: true, hydrated: true });
					return authApi.me();
				})
				.then(async (u) => {
					if (!u || !generationIsCurrent(generation)) return;
					const access = tokenStore.accessToken;
					const previousUin = useAuthStore.getState().uin ?? priorAccountUin();
					if (previousUin !== null && previousUin !== u.uin) {
						tokenStore.clear();
						resetIceQMemory();
						set({ ...EMPTY_AUTH, hydrated: true });
						await runTrackedCleanup("account-change");
						if (!generationIsCurrent(generation)) return;
						if (access) tokenStore.set(access);
					}
					if (!generationIsCurrent(generation)) return;
					rememberAccountUin(u.uin);
					set({ uin: u.uin, username: u.username, accessToken: access, isAuthenticated: true, hydrated: true });
				})
				.catch(() => {
					if (!generationIsCurrent(generation)) return;
					tokenStore.clear();
					set({ hydrated: true });
				});
		}
	},

	login: async (username, password) => {
		await waitForTeardown();
		const generation = authLifecycleGeneration;
		const resp = await authApi.login({ username, password });
		assertGenerationCurrent(generation);
		const previousUin = useAuthStore.getState().uin ?? priorAccountUin();
		if (previousUin !== null && previousUin !== resp.user.uin) await runTrackedCleanup("account-change");
		assertGenerationCurrent(generation);
		authLifecycleGeneration += 1;
		tokenStore.set(resp.tokens.access_token, resp.tokens.refresh_token);
		localStorage.removeItem(ICEQ_LOGGED_OUT_MARKER_KEY);
		rememberAccountUin(resp.user.uin);
		set({
			uin: resp.user.uin,
			username: resp.user.username,
			accessToken: resp.tokens.access_token,
			refreshToken: null,
			isAuthenticated: true,
		});
	},

	register: async (input) => {
		await waitForTeardown();
		const generation = authLifecycleGeneration;
		const resp = await authApi.register({
      username: input.username,
      password: input.password,
      identity_key: input.identityKey,
		});
		assertGenerationCurrent(generation);
		const previousUin = useAuthStore.getState().uin ?? priorAccountUin();
		if (previousUin !== null && previousUin !== resp.user.uin) await runTrackedCleanup("account-change");
		assertGenerationCurrent(generation);
		authLifecycleGeneration += 1;
		tokenStore.set(resp.tokens.access_token, resp.tokens.refresh_token);
		localStorage.removeItem(ICEQ_LOGGED_OUT_MARKER_KEY);
		rememberAccountUin(resp.user.uin);
		set({
			uin: resp.user.uin,
			username: resp.user.username,
			accessToken: resp.tokens.access_token,
			refreshToken: null,
			isAuthenticated: true,
		});
	},

	logout: async () => {
		return startSessionTeardown("logout", true, set);
	},

	panicWipe: async (pin) => {
		await authApi.panicWipe(pin);
		return startSessionTeardown("panic-wipe", false, set);
	},

	handleServerWipe: () => startSessionTeardown("panic-wipe", false, set),

	retryLocalCleanup: () => {
		if (!cleanupRequired && !hasDurableCleanupRequirement()) return Promise.resolve();
		if (cleanupRetryFlight) return cleanupRetryFlight;
		const reason = cleanupRequired ?? durableCleanupReason() ?? "panic-wipe";
		cleanupRetryFlight = runTrackedCleanup(reason).finally(() => { cleanupRetryFlight = null; });
		return cleanupRetryFlight;
	},

	expireSession: () => {
		return startSessionTeardown("auth-expired", true, set);
	},

	setSession: async (user, access, refresh) => {
		await waitForTeardown();
		const generation = authLifecycleGeneration;
		const previousUin = useAuthStore.getState().uin ?? priorAccountUin();
		if (previousUin !== null && previousUin !== user.uin) await runTrackedCleanup("account-change");
		assertGenerationCurrent(generation);
		authLifecycleGeneration += 1;
		tokenStore.set(access, refresh);
		localStorage.removeItem(ICEQ_LOGGED_OUT_MARKER_KEY);
		rememberAccountUin(user.uin);
    set({
			uin: user.uin,
			username: user.username,
			accessToken: access,
			refreshToken: null,
			isAuthenticated: true,
		});
	},
}));

registerMemoryReset(() => useAuthStore.setState(EMPTY_AUTH));

// ----------------------------------------------------------------------------
// Selector helpers. Components should subscribe to the slice
// they care about to avoid re-renders on unrelated state.
// ----------------------------------------------------------------------------
export const selectIsAuthed = (s: AuthState): boolean => s.isAuthenticated;
export const selectUin = (s: AuthState): number | null => s.uin;
export const selectUsername = (s: AuthState): string | null => s.username;
