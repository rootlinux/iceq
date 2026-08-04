import assert from "node:assert/strict";
import test from "node:test";
import { ApiError, fetchWithAuth } from "../src/api/client";

class MemoryStorage {
  private readonly values = new Map<string, string>([["iceq_access_token", "expired-access-token"]]);

  getItem(key: string): string | null {
    return this.values.get(key) ?? null;
  }

  setItem(key: string, value: string): void {
    this.values.set(key, value);
  }

  removeItem(key: string): void {
    this.values.delete(key);
  }
}

async function withMockedClient(
  mockFetch: (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>,
  run: (storage: MemoryStorage) => Promise<void>,
): Promise<void> {
  const originalFetch = globalThis.fetch;
  const originalStorage = Object.getOwnPropertyDescriptor(globalThis, "localStorage");
  const originalWindow = Object.getOwnPropertyDescriptor(globalThis, "window");
  const storage = new MemoryStorage();

  Object.defineProperty(globalThis, "localStorage", { configurable: true, value: storage });
  Object.defineProperty(globalThis, "window", { configurable: true, value: new EventTarget() });
  globalThis.fetch = mockFetch as typeof fetch;

  try {
    await run(storage);
  } finally {
    globalThis.fetch = originalFetch;
    if (originalStorage) Object.defineProperty(globalThis, "localStorage", originalStorage);
    else Reflect.deleteProperty(globalThis, "localStorage");
    if (originalWindow) Object.defineProperty(globalThis, "window", originalWindow);
    else Reflect.deleteProperty(globalThis, "window");
    // attemptRefresh deliberately retains its settled promise until the next
    // task, so let that cleanup run before another behavioral case starts.
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
}

test("an endpoint-specific INVALID_PASSWORD response does not rotate the authenticated session", async () => {
  const calls: string[] = [];

  await withMockedClient(async (input) => {
    const path = String(input);
    calls.push(path);
    if (path === "/api/auth/refresh") {
      return new Response(JSON.stringify({ access_token: "new-access-token" }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }
    return new Response(JSON.stringify({ error: "incorrect password", code: "INVALID_PASSWORD" }), {
      status: 401,
      headers: { "Content-Type": "application/json" },
    });
  }, async () => {
    await assert.rejects(
      fetchWithAuth("/api/auth/panic-wipe-public-key", {
        method: "PUT",
        body: { public_key: "public-key", password: "wrong-password" },
      }),
      (error: unknown) => error instanceof ApiError
        && error.status === 401
        && error.code === "INVALID_PASSWORD",
    );
    assert.deepEqual(calls, ["/api/auth/panic-wipe-public-key"]);
  });
});

test("TOKEN_EXPIRED refreshes once and retries with the replacement access token", async () => {
  const calls: Array<{ path: string; authorization: string | null }> = [];
  let resourceAttempts = 0;

  await withMockedClient(async (input, init) => {
    const path = String(input);
    const headers = new Headers(init?.headers);
    calls.push({ path, authorization: headers.get("Authorization") });
    if (path === "/api/auth/refresh") {
      return new Response(JSON.stringify({ access_token: "replacement-access-token" }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }
    resourceAttempts += 1;
    if (resourceAttempts === 1) {
      return new Response(JSON.stringify({ error: "expired", code: "TOKEN_EXPIRED" }), {
        status: 401,
        headers: { "Content-Type": "application/json" },
      });
    }
    return new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  }, async (storage) => {
    const response = await fetchWithAuth("/api/auth/me");
    assert.equal(response.status, 200);
    assert.deepEqual(calls, [
      { path: "/api/auth/me", authorization: "Bearer expired-access-token" },
      { path: "/api/auth/refresh", authorization: null },
      { path: "/api/auth/me", authorization: "Bearer replacement-access-token" },
    ]);
    assert.equal(storage.getItem("iceq_access_token"), "replacement-access-token");
  });
});

test("TOKEN_REVOKED is terminal and never mints a replacement token", async () => {
  const calls: string[] = [];
  let expiryEvents = 0;

  await withMockedClient(async (input) => {
    const path = String(input);
    calls.push(path);
    return new Response(JSON.stringify({ error: "revoked", code: "TOKEN_REVOKED" }), {
      status: 401,
      headers: { "Content-Type": "application/json" },
    });
  }, async (storage) => {
    window.addEventListener("iceq:auth-expired", () => { expiryEvents += 1; });
    await assert.rejects(
      fetchWithAuth("/api/auth/me"),
      (error: unknown) => error instanceof ApiError
        && error.status === 401
        && error.code === "TOKEN_REVOKED",
    );
    assert.deepEqual(calls, ["/api/auth/me"]);
    assert.equal(storage.getItem("iceq_access_token"), null);
    assert.equal(expiryEvents, 1);
  });
});

test("a legacy code-less 401 keeps the refresh compatibility path", async () => {
  const calls: string[] = [];
  let resourceAttempts = 0;

  await withMockedClient(async (input) => {
    const path = String(input);
    calls.push(path);
    if (path === "/api/auth/refresh") {
      return new Response(JSON.stringify({ access_token: "replacement-access-token" }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }
    resourceAttempts += 1;
    return resourceAttempts === 1
      ? new Response("unauthorized", { status: 401 })
      : new Response(JSON.stringify({ ok: true }), { status: 200 });
  }, async () => {
    const response = await fetchWithAuth("/api/auth/me");
    assert.equal(response.status, 200);
    assert.deepEqual(calls, ["/api/auth/me", "/api/auth/refresh", "/api/auth/me"]);
  });
});

test("a replacement token rejected as expired ends the session without a refresh loop", async () => {
  const calls: string[] = [];
  let expiryEvents = 0;

  await withMockedClient(async (input) => {
    const path = String(input);
    calls.push(path);
    if (path === "/api/auth/refresh") {
      return new Response(JSON.stringify({ access_token: "replacement-access-token" }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }
    return new Response(JSON.stringify({ error: "expired", code: "TOKEN_EXPIRED" }), {
      status: 401,
      headers: { "Content-Type": "application/json" },
    });
  }, async (storage) => {
    window.addEventListener("iceq:auth-expired", () => { expiryEvents += 1; });
    await assert.rejects(
      fetchWithAuth("/api/auth/me"),
      (error: unknown) => error instanceof ApiError
        && error.status === 401
        && error.code === "TOKEN_EXPIRED",
    );
    assert.deepEqual(calls, ["/api/auth/me", "/api/auth/refresh", "/api/auth/me"]);
    assert.equal(storage.getItem("iceq_access_token"), null);
    assert.equal(expiryEvents, 1);
  });
});
