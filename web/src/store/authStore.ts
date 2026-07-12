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

const LOGGED_OUT_MARKER_KEY = "iceq_logged_out";

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
  setSession: (user: UserPublic, access: string, refresh: string) => void;
}

export const useAuthStore = create<AuthState>((set) => ({
  uin: null,
  username: null,
  accessToken: null,
  refreshToken: null,
  isAuthenticated: false,
  hydrated: false,

	hydrate: () => {
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
        .then((u) => {
          set({ uin: u.uin, username: u.username });
        })
        .catch(() => {
          // /me failed; the refresh-on-401 path in api/client
          // will have already routed us back to /login if
          // appropriate. Nothing more to do here.
        });
		} else if (localStorage.getItem(LOGGED_OUT_MARKER_KEY) === "1") {
			set({ hydrated: true });
		} else {
			void authApi
				.refresh()
				.then((tokens) => {
					tokenStore.set(tokens.access_token);
					set({ accessToken: tokens.access_token, refreshToken: null, isAuthenticated: true, hydrated: true });
					return authApi.me();
				})
				.then((u) => {
					set({ uin: u.uin, username: u.username });
				})
				.catch(() => {
					tokenStore.clear();
					set({ hydrated: true });
				});
		}
	},

	login: async (username, password) => {
		const resp = await authApi.login({ username, password });
		localStorage.removeItem(LOGGED_OUT_MARKER_KEY);
		tokenStore.set(resp.tokens.access_token, resp.tokens.refresh_token);
		set({
			uin: resp.user.uin,
			username: resp.user.username,
			accessToken: resp.tokens.access_token,
			refreshToken: null,
			isAuthenticated: true,
		});
	},

	register: async (input) => {
		const resp = await authApi.register({
      username: input.username,
      password: input.password,
      identity_key: input.identityKey,
		});
		localStorage.removeItem(LOGGED_OUT_MARKER_KEY);
		tokenStore.set(resp.tokens.access_token, resp.tokens.refresh_token);
		set({
			uin: resp.user.uin,
			username: resp.user.username,
			accessToken: resp.tokens.access_token,
			refreshToken: null,
			isAuthenticated: true,
		});
	},

	logout: async () => {
		// Always clear local state, even if the server call
		// fails. A partial-logout is worse than a full one
		// (the user thinks they're logged out but the server
		// still has a live refresh token).
		try {
			await authApi.logout();
		} catch {
			// best-effort
		} finally {
			localStorage.setItem(LOGGED_OUT_MARKER_KEY, "1");
			tokenStore.clear();
			set({
				uin: null,
				username: null,
				accessToken: null,
				refreshToken: null,
				isAuthenticated: false,
			});
		}
	},

	setSession: (user, access, refresh) => {
		localStorage.removeItem(LOGGED_OUT_MARKER_KEY);
		tokenStore.set(access, refresh);
    set({
			uin: user.uin,
			username: user.username,
			accessToken: access,
			refreshToken: null,
			isAuthenticated: true,
		});
	},
}));

// ----------------------------------------------------------------------------
// Selector helpers. Components should subscribe to the slice
// they care about to avoid re-renders on unrelated state.
// ----------------------------------------------------------------------------
export const selectIsAuthed = (s: AuthState): boolean => s.isAuthenticated;
export const selectUin = (s: AuthState): number | null => s.uin;
export const selectUsername = (s: AuthState): string | null => s.username;
