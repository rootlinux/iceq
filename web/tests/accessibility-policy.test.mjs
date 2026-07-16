import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const read = (path) => readFileSync(resolve(root, path), "utf8");

test("settings dialogs manage focus, Escape, and focus return", () => {
  const sidebar = read("src/components/Layout/Sidebar.tsx");
  assert.match(sidebar, /useDialogFocus/);
  assert.match(sidebar, /settingsTriggerRef/);
  assert.match(sidebar, /onKeyDown/);
});

test("connection errors are announced and message state has visible text", () => {
  const layout = read("src/components/Layout/MainLayout.tsx");
  const item = read("src/components/Chat/MessageItem.tsx");
  assert.match(layout, /aria-live=["']assertive["']/);
  assert.match(item, /message-state-text/);
});

test("global styles include visible focus, touch targets, and reduced motion", () => {
  const css = read("src/index.css");
  assert.match(css, /:focus-visible/);
  assert.match(css, /min-height:\s*44px/);
  assert.match(css, /prefers-reduced-motion:\s*reduce/);
});

