import assert from "node:assert/strict";
import test from "node:test";

import { TransportInbox, markEnvelopeRetryable } from "../src/hooks/useMessageTransport.ts";

const raw = (id: string) => JSON.stringify({ type: "message", id, ts: 1, payload: { ciphertext: "opaque" } });

test("WS and poll use one parser/callback and suppress duplicate envelope IDs", () => {
  const delivered: string[] = [];
  const inbox = new TransportInbox((env, source) => delivered.push(`${source}:${env.id}`), 3);
  assert.equal(inbox.consume(raw("one"), "ws"), true);
  assert.equal(inbox.consume(raw("one"), "poll"), false);
  assert.equal(inbox.consume(raw("two"), "poll"), true);
  assert.deepEqual(delivered, ["ws:one", "poll:two"]);
});

test("HTTP fallback failure marks the matching optimistic message retryable", () => {
  const state = { "dm:7:42": [{ id: "client-1", state: "sending" }, { id: "other", state: "sending" }] };
  const next = markEnvelopeRetryable(state, { type:"message", id:"wire", ts:1, payload:{client_id:"client-1"} } as never);
  assert.equal(next["dm:7:42"]?.[0]?.state, "failed");
  assert.equal(next["dm:7:42"]?.[1]?.state, "sending");
});

test("invalid envelopes never reach transport callbacks", () => {
  let calls = 0;
  const inbox = new TransportInbox(() => { calls += 1; });
  assert.equal(inbox.consume("not-json", "poll"), false);
  assert.equal(calls, 0);
});

test("dedupe memory is bounded and evicts oldest IDs", () => {
  const delivered: string[] = [];
  const inbox = new TransportInbox((env) => delivered.push(env.id), 2);
  inbox.consume(raw("one"), "ws"); inbox.consume(raw("two"), "poll"); inbox.consume(raw("three"), "poll");
  assert.equal(inbox.consume(raw("one"), "ws"), true);
  assert.deepEqual(delivered, ["one", "two", "three", "one"]);
});
