import test from "node:test";
import assert from "node:assert/strict";
import { runConfirmedPanicWipe } from "../src/lib/panicWipeAction.ts";

test("panic wipe does not call the server when confirmation is declined", async () => {
  let calls = 0;
  await runConfirmedPanicWipe(() => false, async () => { calls += 1; });
  assert.equal(calls, 0);
});

test("confirmed panic wipe exposes server failure for an authenticated retry", async () => {
  let calls = 0;
  await assert.rejects(runConfirmedPanicWipe(() => true, async () => { calls += 1; throw new Error("server failed"); }));
  assert.equal(calls, 1);
});
