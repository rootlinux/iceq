import assert from "node:assert/strict";
import test from "node:test";
import { AttachmentGrantLifecycle } from "../src/lib/attachmentGrantLifecycle.ts";

function harness() {
  const grants: string[] = [], revokes: string[] = [];
  let timeout: (() => void) | undefined;
  const lifecycle = new AttachmentGrantLifecycle({
    grant: async (key, uin) => { grants.push(`${key}:${uin}`); },
    revoke: async (key, uin) => { revokes.push(`${key}:${uin}`); },
    setTimer: (fn) => { timeout = fn; return 1; },
    clearTimer: () => {}, timeoutMs: 10,
  });
  return { lifecycle, grants, revokes, fireTimeout: () => timeout?.() };
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
