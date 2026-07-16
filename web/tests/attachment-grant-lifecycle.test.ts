import assert from "node:assert/strict";
import test from "node:test";
import { AttachmentGrantLifecycle } from "../src/lib/attachmentGrantLifecycle.ts";

function harness() {
  const grants: string[] = [], revokes: string[] = [];
  const exhausted: Array<{ messageId: string; attempts: number; reason: string }> = [];
  let timeout: (() => void) | undefined;
  let revokeFailures = 0;
  const lifecycle = new AttachmentGrantLifecycle({
    grant: async (key, uin) => { grants.push(`${key}:${uin}`); },
    revoke: async (key, uin) => {
      revokes.push(`${key}:${uin}`);
      if (revokeFailures-- > 0) throw new Error("transient secret-bearing failure");
    },
    setTimer: (fn) => { timeout = fn; return 1; },
    clearTimer: () => {}, timeoutMs: 10,
    retryDelaysMs: [0, 0],
    sleep: async () => {},
    onExhausted: (event) => { exhausted.push(event); },
  });
  return {
    lifecycle, grants, revokes, exhausted,
    failNextRevokes: (count: number) => { revokeFailures = count; },
    fireTimeout: () => timeout?.(),
  };
}

test("persisted ack retains grant and later close does not revoke", async () => {
  const h = harness();
  await h.lifecycle.prepare("m1", "object", 200);
  h.lifecycle.ack("m1", "persisted");
  await h.lifecycle.revokeAll();
  assert.deepEqual(h.revokes, []);
});

test("terminal nack revokes pending grant", async () => {
  const h = harness(); await h.lifecycle.prepare("m1", "object", 200);
  await h.lifecycle.fail("m1"); assert.deepEqual(h.revokes, ["object:200"]);
});

test("close or logout revokes every pending grant", async () => {
  const h = harness(); await h.lifecycle.prepare("m1", "a", 200); await h.lifecycle.prepare("m2", "b", 300);
  await h.lifecycle.revokeAll(); assert.deepEqual(h.revokes.sort(), ["a:200", "b:300"]);
});

test("timeout revokes pending grant", async () => {
  const h = harness(); await h.lifecycle.prepare("m1", "object", 200); h.fireTimeout(); await Promise.resolve(); await Promise.resolve();
  assert.deepEqual(h.revokes, ["object:200"]);
});

test("local send failure revokes but successful delivered ack retains", async () => {
  const failed = harness(); await failed.lifecycle.prepare("m1", "object", 200); await failed.lifecycle.fail("m1");
  assert.deepEqual(failed.revokes, ["object:200"]);
  const ok = harness(); await ok.lifecycle.prepare("m2", "object", 200); ok.lifecycle.ack("m2", "delivered"); await ok.lifecycle.revokeAll();
  assert.deepEqual(ok.revokes, []);
});

test("transient revoke failure retries once and then removes the pending grant", async () => {
  const h = harness(); h.failNextRevokes(1); await h.lifecycle.prepare("m1", "object", 200);
  await h.lifecycle.fail("m1");
  assert.deepEqual(h.revokes, ["object:200", "object:200"]);
  assert.deepEqual(h.exhausted, []);
  await h.lifecycle.revokeAll();
  assert.equal(h.revokes.length, 2);
});

test("repeated revoke failure remains recoverable after exhaustion and revokeAll retries it", async () => {
  const h = harness(); h.failNextRevokes(3); await h.lifecycle.prepare("m1", "object", 200);
  await h.lifecycle.fail("m1");
  assert.equal(h.revokes.length, 3);
  assert.deepEqual(h.exhausted, [{ messageId: "m1", attempts: 3, reason: "revoke_exhausted" }]);
  await h.lifecycle.revokeAll();
  assert.equal(h.revokes.length, 4);
  await h.lifecycle.revokeAll();
  assert.equal(h.revokes.length, 4);
});

test("concurrent revoke requests are idempotent and share one in-flight operation", async () => {
  let release!: () => void;
  const revokes: string[] = [];
  const lifecycle = new AttachmentGrantLifecycle({
    grant: async () => {},
    revoke: async (key) => { revokes.push(key); await new Promise<void>((resolve) => { release = resolve; }); },
    retryDelaysMs: [], timeoutMs: 1000,
  });
  await lifecycle.prepare("m1", "object", 200);
  const first = lifecycle.fail("m1"); const second = lifecycle.fail("m1");
  await Promise.resolve(); assert.deepEqual(revokes, ["object"]);
  release(); await Promise.all([first, second]);
  assert.deepEqual(revokes, ["object"]);
});

test("ack racing an in-flight revoke restores the grant and does not retry revoke", async () => {
  let release!: () => void;
  const grants: string[] = [], revokes: string[] = [];
  const lifecycle = new AttachmentGrantLifecycle({
    grant: async (key) => { grants.push(key); },
    revoke: async (key) => { revokes.push(key); await new Promise<void>((resolve) => { release = resolve; }); },
    retryDelaysMs: [0, 0], sleep: async () => {}, timeoutMs: 1000,
  });
  await lifecycle.prepare("m1", "object", 200);
  const failure = lifecycle.fail("m1"); await Promise.resolve();
  lifecycle.ack("m1", "persisted"); release(); await failure;
  assert.deepEqual(revokes, ["object"]);
  assert.deepEqual(grants, ["object", "object"]);
  await lifecycle.revokeAll(); assert.deepEqual(revokes, ["object"]);
});
