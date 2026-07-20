import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const layout = readFileSync(resolve(root, "src/components/Layout/MainLayout.tsx"), "utf8");

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
