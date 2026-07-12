import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));
const wsSource = readFileSync(resolve(__dirname, "../src/hooks/useWebSocket.ts"), "utf8");

test("persisted acknowledgements settle optimistic outgoing messages", () => {
  assert.match(wsSource, /p\.state === "persisted"/);
  assert.match(wsSource, /markDelivered\(p\.message_id, convId\)/);
});
