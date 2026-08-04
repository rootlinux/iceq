// src/api/client.ts
//
// Base fetch wrapper. Three responsibilities:
//
//   1. Inject the short-lived access token from localStorage. Every
//      authenticated call goes through this so we never have to
//      remember to set the header by hand.
//
//   2. Translate 401 into a single cookie-backed refresh-and-retry.
//      The refresh token is HttpOnly; JS never reads it.
//
//   3. Decode JSON safely. Errors include the response body
//      (truncated) so the dev console shows the server's
//      diagnosis.

const ACCESS_TOKEN_KEY = "iceq_access_token";
const REFRESH_TOKEN_KEY = "iceq_refresh_token";
const CSRF_HEADER_NAME = "X-IceQ-CSRF";
const CSRF_HEADER_VALUE = "1";

// ----------------------------------------------------------------------------
// ApiError — typed errors so callers can switch on cause without
// parsing message strings. We keep the HTTP status on every
// error so a UI layer can show "rate-limited, retry in N seconds".
// ----------------------------------------------------------------------------
export class ApiError extends Error {
  constructor(
    message: string,
    public readonly status: number,
    public readonly code?: string,
    public readonly body?: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

export class ApiAuthError extends ApiError {
  constructor(message: string, status: number, code?: string, body?: string) {
    super(message, status, code, body);
    this.name = "ApiAuthError";
  }
}

export class ApiNetworkError extends ApiError {
  constructor(message: string) {
    super(message, 0);
    this.name = "ApiNetworkError";
  }
}

// ----------------------------------------------------------------------------
// Refresh coordination. A burst of 401s — e.g. after the page
// has been open for a while and the access token just expired —
// would otherwise fire N parallel refresh calls. The first
// starts the refresh; everyone else awaits the same promise.
// ----------------------------------------------------------------------------
let inflightRefresh: Promise<boolean> | null = null;

async function attemptRefresh(): Promise<boolean> {
	if (inflightRefresh) return inflightRefresh;
	inflightRefresh = (async () => {
		try {
			const resp = await fetch("/api/auth/refresh", {
				method: "POST",
				headers: { "Content-Type": "application/json", [CSRF_HEADER_NAME]: CSRF_HEADER_VALUE },
				credentials: "same-origin",
				body: JSON.stringify({}),
			});
			if (!resp.ok) return false;
			const j = (await resp.json()) as { access_token: string; refresh_token?: string };
			localStorage.setItem(ACCESS_TOKEN_KEY, j.access_token);
			localStorage.removeItem(REFRESH_TOKEN_KEY);
			return true;
    } catch {
      return false;
    } finally {
      // Defer clearing the in-flight ref until microtask
      // drain so any callers that grabbed it during the
      // refresh see the resolved value.
      setTimeout(() => {
        inflightRefresh = null;
      }, 0);
    }
  })();
  return inflightRefresh;
}

function clearStoredTokensAndNotify(): void {
  localStorage.removeItem(ACCESS_TOKEN_KEY);
  localStorage.removeItem(REFRESH_TOKEN_KEY);
  window.dispatchEvent(new CustomEvent("iceq:auth-expired"));
}

export async function refreshSession(): Promise<boolean> {
  const ok = await attemptRefresh();
  if (!ok) {
    clearStoredTokensAndNotify();
  }
  return ok;
}

type UnauthorizedDisposition = "refreshable" | "terminal" | "endpoint-specific";

async function classifyUnauthorized(resp: Response): Promise<UnauthorizedDisposition> {
  try {
    const payload = await resp.clone().json() as { code?: unknown };
    if (typeof payload.code !== "string") return "refreshable";
    // Refresh only conditions that a valid refresh cookie can actually
    // recover. Revoked, malformed, or wrong-type access tokens are terminal:
    // minting a replacement for them would undermine server-side revocation.
    if (payload.code === "AUTH_MISSING_BEARER" || payload.code === "TOKEN_EXPIRED") {
      return "refreshable";
    }
    if (payload.code === "TOKEN_REVOKED" || payload.code === "TOKEN_INVALID" || payload.code === "TOKEN_WRONG_TYPE") {
      return "terminal";
    }
    return "endpoint-specific";
  } catch {
    // Preserve compatibility with an older or non-JSON auth boundary: a
    // bare 401 may still mean that the access token expired.
    return "refreshable";
  }
}

// ----------------------------------------------------------------------------
// fetchWithAuth — the public wrapper. `retried` is the internal
// flag that prevents an infinite refresh loop: the second leg
// uses the freshly-minted access token and surfaces a 401
// directly if the server still rejects it.
// ----------------------------------------------------------------------------
export interface FetchOptions {
  method?: "GET" | "POST" | "PUT" | "DELETE" | "PATCH";
  body?: unknown;
  headers?: Record<string, string>;
  // Skip the Authorization header — used for register/login
  // where there is no token yet.
  noAuth?: boolean;
  // Skip the auto-refresh-on-401 path. Used by the refresh
  // call itself to avoid recursion.
  skipRefresh?: boolean;
  // Abort signal so a component unmount can cancel the
  // request.
  signal?: AbortSignal;
}

export async function fetchWithAuth(path: string, opts: FetchOptions = {}, retried = false): Promise<Response> {
	const method = opts.method ?? (opts.body !== undefined ? "POST" : "GET");
  const headers: Record<string, string> = {
    Accept: "application/json",
    ...(opts.headers ?? {}),
  };
  if (opts.body !== undefined) {
    headers["Content-Type"] = "application/json";
  }
	if (requiresCSRF(method)) {
		headers[CSRF_HEADER_NAME] = CSRF_HEADER_VALUE;
	}
  if (!opts.noAuth) {
    const token = localStorage.getItem(ACCESS_TOKEN_KEY);
    if (token) headers["Authorization"] = `Bearer ${token}`;
  }

  let resp: Response;
	try {
		resp = await fetch(path, {
			method,
			headers,
			body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
			credentials: "same-origin",
			signal: opts.signal,
		});
  } catch (e) {
    if ((e as { name?: string }).name === "AbortError") throw e;
    throw new ApiNetworkError((e as Error).message);
  }

  if (resp.status === 401 && !opts.noAuth) {
    const disposition = await classifyUnauthorized(resp);
    if (disposition === "terminal") {
      clearStoredTokensAndNotify();
    } else if (disposition === "refreshable") {
      if (!opts.skipRefresh && !retried) {
        const ok = await refreshSession();
        if (ok) {
          return fetchWithAuth(path, opts, true);
        }
        throw new ApiAuthError("unauthorized", 401);
      }
      // A fresh retry that is still unauthorized cannot be recovered by
      // refreshing again. End the local session instead of looping or leaving
      // a dead bearer token in place.
      clearStoredTokensAndNotify();
    }
  }

  if (!resp.ok) {
    const text = await resp.text().catch(() => "");
    let code: string | undefined;
    try {
      const parsed = JSON.parse(text) as { code?: string; error?: string };
      code = parsed.code;
    } catch {
      // body wasn't JSON; ignore
    }
    throw new ApiError(`${resp.status} ${resp.statusText}`, resp.status, code, text.slice(0, 500));
  }
  return resp;
}

function requiresCSRF(method: string): boolean {
	return method !== "GET" && method !== "HEAD" && method !== "OPTIONS";
}

// ----------------------------------------------------------------------------
// Convenience JSON helper. Returns the parsed body.
// ----------------------------------------------------------------------------
export async function fetchJSON<T>(path: string, opts: FetchOptions = {}): Promise<T> {
  const resp = await fetchWithAuth(path, opts);
  return (await resp.json()) as T;
}

// ----------------------------------------------------------------------------
// Token storage helpers. Re-exported so the auth-store can
// read/write the same keys without importing localStorage
// directly in two places.
// ----------------------------------------------------------------------------
export const tokenStore = {
  get accessToken(): string | null {
    return localStorage.getItem(ACCESS_TOKEN_KEY);
  },
	get refreshToken(): string | null {
		return null;
	},
	set(access: string, _refresh?: string): void {
		localStorage.setItem(ACCESS_TOKEN_KEY, access);
		localStorage.removeItem(REFRESH_TOKEN_KEY);
	},
  clear(): void {
    localStorage.removeItem(ACCESS_TOKEN_KEY);
    localStorage.removeItem(REFRESH_TOKEN_KEY);
  },
};
