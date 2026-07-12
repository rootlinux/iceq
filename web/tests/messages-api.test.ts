import test from "node:test";
import assert from "node:assert/strict";

import { buildHistoryDMPath } from "../src/api/messages.js";
import { conversationIdForPair } from "../src/types/models.js";

test("buildHistoryDMPath targets the history endpoint with canonical conversation_id", () => {
  const conversationId = conversationIdForPair(42, 7);

  assert.equal(conversationId, "dm:7:42");
  assert.equal(
    buildHistoryDMPath(conversationId, 50),
    "/api/messages/history?conversation_id=dm%3A7%3A42&limit=50",
  );
});

test("buildHistoryDMPath appends the pagination cursor when present", () => {
  assert.equal(
    buildHistoryDMPath("dm:7:42", 20, "2026-06-11T10:00:00Z"),
    "/api/messages/history?conversation_id=dm%3A7%3A42&limit=20&before=2026-06-11T10%3A00%3A00Z",
  );
});
