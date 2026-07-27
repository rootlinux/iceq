import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const layout = readFileSync(resolve(root, "src/components/Layout/MainLayout.tsx"), "utf8");
const app = readFileSync(resolve(root, "src/App.tsx"), "utf8");
const main = readFileSync(resolve(root, "src/main.tsx"), "utf8");
const iosHint = readFileSync(resolve(root, "src/components/PWA/IOSInstallHint.tsx"), "utf8");

test("authenticated layout mounts the PWA install prompts", () => {
  assert.match(
    layout,
    /import\s+\{\s*InstallPrompt\s*\}\s+from\s+["']\.\.\/PWA\/InstallPrompt["'];/,
  );
  assert.match(
    layout,
    /import\s+\{\s*IOSInstallHint\s*\}\s+from\s+["']\.\.\/PWA\/IOSInstallHint["'];/,
  );
  assert.match(layout, /<InstallPrompt\s*\/>/);
  assert.match(layout, /<IOSInstallHint\s+visible=\{selfUin\s*!==\s*null\}\s*\/>/);
});

test("install prompt capture starts before React renders while UI stays in the authenticated route", () => {
  assert.match(main, /initializeInstallPromptCapture\(\)/);
  assert.ok(
    main.indexOf("initializeInstallPromptCapture()") < main.indexOf("ReactDOM.createRoot"),
    "capture must start before React mounts",
  );
  assert.match(
    app,
    /path=["']\/app\/\*["'][\s\S]*<MainLayout>/,
  );
  assert.doesNotMatch(app, /path=["']\/(?:login|register)["'][\s\S]{0,200}<InstallPrompt/);
});

test("iOS install hint uses the shared accessible dialog lifecycle", () => {
  assert.match(iosHint, /useDialogFocus/);
  assert.match(iosHint, /role=["']dialog["']/);
  assert.match(iosHint, /aria-modal=["']true["']/);
  assert.match(iosHint, /aria-labelledby=["']ios-install-hint-title["']/);
  assert.match(iosHint, /id=["']ios-install-hint-title["']/);
});
