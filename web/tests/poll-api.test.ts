import assert from "node:assert/strict";
import test from "node:test";

import { pollEnvelopes } from "../src/api/poll.ts";

test("poll uses bounded query and forwards abort signal", async () => {
  const original = globalThis.fetch;
  const originalStorage = Object.getOwnPropertyDescriptor(globalThis, "localStorage");
  Object.defineProperty(globalThis, "localStorage", { configurable: true, value: { getItem: () => "token" } });
  const controller = new AbortController();
  let seen = ""; let signal: AbortSignal | undefined;
  globalThis.fetch = (async (input, init) => {
    seen = String(input); signal = init?.signal;
    return new Response(JSON.stringify({ cursor: "next", envelopes: [] }), { status: 200, headers: { "content-type": "application/json" } });
  }) as typeof fetch;
  try {
    const out = await pollEnvelopes("opaque cursor", controller.signal);
    assert.match(seen, /\/api\/transport\/poll\?/);
    assert.match(seen, /cursor=opaque\+cursor/);
    assert.equal(signal, controller.signal);
    assert.equal(out.cursor, "next");
  } finally {
    globalThis.fetch = original;
    if (originalStorage) Object.defineProperty(globalThis, "localStorage", originalStorage);
    else Reflect.deleteProperty(globalThis, "localStorage");
  }
});
