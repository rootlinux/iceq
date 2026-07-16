import assert from "node:assert/strict";
import test from "node:test";
import "fake-indexeddb/auto";
import { saveGroupCryptoState, loadGroupCryptoState, pruneObsoleteGroupEpochs } from "../src/lib/groupCryptoStore";

test("group state is versioned and keyed by group, epoch, and sender", async () => {
  indexedDB.deleteDatabase("iceq");
  const record = { version: 1 as const, kind: "receiver" as const, group_id: "g", epoch: 3, sender_uin: 9, updated_at: 100, state: { secret: "opaque" } };
  await saveGroupCryptoState(record);
  assert.deepEqual(await loadGroupCryptoState("g", 3, 9, "receiver"), record);
  assert.equal(await loadGroupCryptoState("g", 4, 9, "receiver"), null);
});

test("obsolete epochs are removed after decrypt-only grace", async () => {
  const old = Date.now() - 10_000;
  await saveGroupCryptoState({ version: 1, kind: "receiver", group_id: "prune", epoch: 1, sender_uin: 1, updated_at: old, state: {} });
  await saveGroupCryptoState({ version: 1, kind: "receiver", group_id: "prune", epoch: 2, sender_uin: 1, updated_at: Date.now(), state: {} });
  await pruneObsoleteGroupEpochs("prune", 2, 1_000);
  assert.equal(await loadGroupCryptoState("prune", 1, 1, "receiver"), null);
  assert.ok(await loadGroupCryptoState("prune", 2, 1, "receiver"));
});
