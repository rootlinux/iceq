import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createDialogStack, cycleDialogFocus, focusInitialTarget, handleDialogEscape, restoreDialogFocus } from "../src/hooks/dialogFocus.ts";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const read = (path) => readFileSync(resolve(root, path), "utf8");

test("settings dialogs manage focus, Escape, and focus return", () => {
  const sidebar = read("src/components/Layout/Sidebar.tsx");
  assert.match(sidebar, /useDialogFocus/);
  assert.match(sidebar, /settingsTriggerRef/);
  assert.match(sidebar, /settingsDialogRef/);
});

test("all dialog surfaces use managed dialog focus", () => {
  for (const path of ["src/components/Contacts/AddContact.tsx", "src/components/Groups/GroupList.tsx", "src/components/Layout/Sidebar.tsx"]) {
    assert.match(read(path), /useDialogFocus/, `${path} lacks managed focus`);
  }
});

test("closed mobile sidebar is translated offscreen and cannot cover the menu trigger", () => {
  const sidebar = read("src/components/Layout/Sidebar.tsx");
  const layout = read("src/components/Layout/MainLayout.tsx");
  assert.match(sidebar, /open \? "translate-x-0" : "-translate-x-full"/);
  assert.match(sidebar, /md:translate-x-0/);
  assert.match(sidebar, /setAttribute\("inert", ""\)/);
  assert.match(sidebar, /removeAttribute\("inert"\)/);
  assert.match(sidebar, /aria-hidden=/);
  assert.match(layout, /sidebarToggleRef/);
  assert.match(layout, /sidebarToggleRef\.current\?\.focus\(\)/);
});

test("mobile menu toggle owns the drawer and opening naturally focuses its close control", () => {
  const sidebar = read("src/components/Layout/Sidebar.tsx");
  const layout = read("src/components/Layout/MainLayout.tsx");
  assert.match(sidebar, /id="primary-navigation-drawer"/);
  assert.match(layout, /aria-controls="primary-navigation-drawer"/);
  assert.match(layout, /aria-expanded=\{sidebarOpen\}/);
  assert.match(sidebar, /closeButtonRef/);
  assert.match(sidebar, /closeButtonRef\.current\?\.focus\(\)/);
});

test("dialog keyboard helper wraps Tab in both directions", () => {
  const first = { focusCalls: 0, focus() { this.focusCalls += 1; } };
  const last = { focusCalls: 0, focus() { this.focusCalls += 1; } };
  assert.equal(cycleDialogFocus([first, last], first, true), true);
  assert.equal(last.focusCalls, 1);
  assert.equal(cycleDialogFocus([first, last], last, false), true);
  assert.equal(first.focusCalls, 1);
  assert.equal(cycleDialogFocus([first, last], first, false), false);
});

test("dialog behavior focuses the preferred control, closes on Escape, and restores opener", () => {
  const preferred = { focusCalls: 0, focus() { this.focusCalls += 1; } };
  const fallback = { focusCalls: 0, focus() { this.focusCalls += 1; } };
  focusInitialTarget(preferred, fallback);
  assert.equal(preferred.focusCalls, 1);
  let closes = 0;
  assert.equal(handleDialogEscape("Escape", () => { closes += 1; }), true);
  assert.equal(handleDialogEscape("Enter", () => { closes += 1; }), false);
  assert.equal(closes, 1);
  restoreDialogFocus(fallback);
  assert.equal(fallback.focusCalls, 1);
});

test("nested dialog stack lets only the topmost trap and close, then restores the parent", () => {
  const stack = createDialogStack();
  const parent = stack.push();
  const inner = stack.push();
  assert.equal(stack.isTop(parent), false);
  assert.equal(stack.isTop(inner), true);
  stack.remove(inner);
  assert.equal(stack.isTop(parent), true);
  stack.remove(inner);
  assert.equal(stack.isTop(parent), true, "duplicate StrictMode cleanup is harmless");
  stack.remove(parent);
  assert.equal(stack.isTop(parent), false);
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
