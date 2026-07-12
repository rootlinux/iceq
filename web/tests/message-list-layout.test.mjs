import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));
const messageListSource = readFileSync(
  resolve(__dirname, "../src/components/Chat/MessageList.tsx"),
  "utf8",
);
const chatWindowSource = readFileSync(
  resolve(__dirname, "../src/components/Chat/ChatWindow.tsx"),
  "utf8",
);

test("message list fills the chat pane and stacks messages from the bottom", () => {
  assert.match(chatWindowSource, /className="[^"]*\bmin-h-0\b[^"]*\bflex-1\b/);
  assert.match(messageListSource, /className="[^"]*\bflex\b[^"]*\bmin-h-0\b[^"]*\bflex-1\b[^"]*\bflex-col\b/);
  assert.match(messageListSource, /className="[^"]*\bmt-auto\b[^"]*\bspace-y-2\b/);
  assert.doesNotMatch(messageListSource, /justify-center/);
});

test("message list scrolls an explicit bottom anchor into view on render changes", () => {
  assert.match(messageListSource, /bottomRef/);
  assert.match(messageListSource, /scrollIntoView\(\{ block: "end" \}\)/);
});
