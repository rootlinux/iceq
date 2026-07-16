import assert from "node:assert/strict";
import test from "node:test";
import { en } from "../src/i18n/en.ts";
import { tr } from "../src/i18n/tr.ts";
import { createI18n, localeStorageKey, resolveLocale } from "../src/i18n/index.ts";
import { readFileSync, readdirSync } from "node:fs";
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
  const migrated = allTsx(resolve(root, "src/components")).map((path) => path.slice(root.length + 1));
  const violations: string[] = [];
  for (const path of migrated) {
    const source = readFileSync(resolve(root, path), "utf8");
    const file = ts.createSourceFile(path, source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
    const visit = (node: ts.Node): void => {
      if (ts.isJsxText(node) && /[A-Za-z]{2}/.test(node.text.trim()) && node.text.trim() !== "IceQ") violations.push(`${path}: JSX text ${node.text.trim()}`);
      if (ts.isJsxAttribute(node) && node.initializer && ts.isStringLiteralLike(node.initializer) && /^(aria-label|placeholder|title)$/.test(node.name.getText()) && /[A-Za-z]{2}/.test(node.initializer.text)) violations.push(`${path}: ${node.name.getText()}=${node.initializer.text}`);
      if (ts.isJsxAttribute(node) && node.initializer && ts.isJsxExpression(node.initializer) && node.initializer.expression && /^(aria-label|placeholder|title)$/.test(node.name.getText())) collectRenderedCopy(node.initializer.expression, path, violations);
      if (ts.isJsxExpression(node) && !ts.isJsxAttribute(node.parent) && node.expression) collectRenderedCopy(node.expression, path, violations);
      if (ts.isCallExpression(node) && ts.isIdentifier(node.expression) && /^set[A-Za-z]*(Error|Success)$/.test(node.expression.text)) {
        const value = node.arguments[0];
        if (value && (ts.isStringLiteral(value) || ts.isNoSubstitutionTemplateLiteral(value)) && /[A-Za-z]{2}/.test(value.text)) violations.push(`${path}: static UI state ${value.text}`);
      }
      ts.forEachChild(node, visit);
    };
    visit(file);
  }
  assert.deepEqual(violations, []);
});

function allTsx(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => entry.isDirectory() ? allTsx(resolve(dir, entry.name)) : entry.name.endsWith(".tsx") ? [resolve(dir, entry.name)] : []);
}

function collectRenderedCopy(node: ts.Expression, path: string, violations: string[]): void {
  if ((ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) && /[A-Za-z]{2}/.test(node.text) && node.text !== "IceQ") violations.push(`${path}: rendered copy ${node.text}`);
  else if (ts.isTemplateExpression(node) && /[A-Za-z]{2}/.test(node.head.text + node.templateSpans.map((span) => span.literal.text).join(""))) violations.push(`${path}: rendered template copy`);
  else if (ts.isConditionalExpression(node)) { collectRenderedCopy(node.whenTrue, path, violations); collectRenderedCopy(node.whenFalse, path, violations); }
  else if (ts.isBinaryExpression(node) && (node.operatorToken.kind === ts.SyntaxKind.AmpersandAmpersandToken || node.operatorToken.kind === ts.SyntaxKind.QuestionQuestionToken)) collectRenderedCopy(node.right, path, violations);
  else if (ts.isParenthesizedExpression(node)) collectRenderedCopy(node.expression, path, violations);
}
