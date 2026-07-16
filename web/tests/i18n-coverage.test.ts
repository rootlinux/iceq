import assert from "node:assert/strict";
import test from "node:test";
import { en } from "../src/i18n/en.ts";
import { tr } from "../src/i18n/tr.ts";
import { createI18n, localeStorageKey, resolveLocale } from "../src/i18n/index.ts";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";

test("Turkish catalog covers exactly every English message key", () => {
  assert.deepEqual(Object.keys(tr).sort(), Object.keys(en).sort());
});

test("locale resolution uses explicit choice, browser preference, then English fallback", () => {
  assert.equal(resolveLocale("tr", ["en-US"]), "tr");
  assert.equal(resolveLocale(null, ["tr-TR", "en-US"]), "tr");
  assert.equal(resolveLocale("unsupported", ["de-DE"]), "en");
});

test("runtime translation falls back to English and only persists the locale code", () => {
  const writes: Array<[string, string]> = [];
  const i18n = createI18n({
    browserLanguages: ["tr-TR"],
    storage: { getItem: () => null, setItem: (key, value) => writes.push([key, value]) },
  });
  assert.equal(i18n.t("auth.signInTitle"), tr["auth.signInTitle"]);
  i18n.setLocale("en");
  assert.deepEqual(writes, [[localeStorageKey, "en"]]);
  assert.doesNotMatch(JSON.stringify(writes), /message|conversation|uin|username|identifier/i);
});

test("migrated components do not regress to raw catalog copy", () => {
  const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
  const migrated = ["src/App.tsx", "src/components/Auth/LoginForm.tsx", "src/components/Auth/RegisterForm.tsx", "src/components/Chat/ChatShell.tsx", "src/components/Layout/MainLayout.tsx", "src/components/Layout/Sidebar.tsx"];
  migrated.push("src/components/Settings/SecuritySettings.tsx");
  const violations: string[] = [];
  for (const path of migrated) {
    const source = readFileSync(resolve(root, path), "utf8");
    const file = ts.createSourceFile(path, source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
    const visit = (node: ts.Node): void => {
      if (ts.isJsxText(node) && /[A-Za-z]{2}/.test(node.text.trim()) && node.text.trim() !== "IceQ") violations.push(`${path}: JSX text ${node.text.trim()}`);
      if (ts.isJsxAttribute(node) && node.initializer && ts.isStringLiteral(node.initializer) && /^(aria-label|placeholder|title)$/.test(node.name.getText()) && /[A-Za-z]{2}/.test(node.initializer.text)) violations.push(`${path}: ${node.name.getText()}=${node.initializer.text}`);
      if (ts.isStringLiteral(node) && node.parent && ts.isConditionalExpression(node.parent) && isInsideJsx(node) && /^[A-Z][A-Za-z ]/.test(node.text)) violations.push(`${path}: conditional copy ${node.text}`);
      ts.forEachChild(node, visit);
    };
    visit(file);
  }
  assert.deepEqual(violations, []);
});

function isInsideJsx(node: ts.Node): boolean {
  for (let parent = node.parent; parent; parent = parent.parent) if (ts.isJsxExpression(parent) || ts.isJsxElement(parent)) return true;
  return false;
}
