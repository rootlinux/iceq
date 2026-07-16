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

test("restricted storage falls back and locale updates remain live", () => {
  let notifications = 0;
  const i18n = createI18n({ browserLanguages: ["tr-TR"], storage: { getItem: () => { throw new Error("denied"); }, setItem: () => { throw new Error("denied"); } } });
  i18n.subscribe(() => { notifications += 1; });
  assert.equal(i18n.locale, "tr");
  assert.doesNotThrow(() => i18n.setLocale("en"));
  assert.equal(i18n.locale, "en");
  assert.equal(notifications, 1);
});

test("migrated components do not regress to raw catalog copy", () => {
  const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
  const migrated = allTsx(resolve(root, "src/components")).map((path) => path.slice(root.length + 1));
  const violations: string[] = [];
  for (const path of migrated) {
    const source = readFileSync(resolve(root, path), "utf8");
    violations.push(...inspectSource(path, source));
  }
  assert.deepEqual(violations, []);
});

function inspectSource(path: string, source: string): string[] {
  const file = ts.createSourceFile(path, source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
  const violations: string[] = [];
  const bindings = new Map<string, ts.Expression>();
  const functions = new Map<string, ts.FunctionDeclaration>();
  const index = (node: ts.Node): void => {
    if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.initializer) bindings.set(node.name.text, node.initializer);
    if (ts.isFunctionDeclaration(node) && node.name) functions.set(node.name.text, node);
    ts.forEachChild(node, index);
  };
  index(file);
  const visit = (node: ts.Node): void => {
      if (ts.isJsxText(node) && /[A-Za-z]{2}/.test(node.text.trim()) && node.text.trim() !== "IceQ") violations.push(`${path}: JSX text ${node.text.trim()}`);
      if (ts.isJsxAttribute(node) && node.initializer && ts.isStringLiteralLike(node.initializer) && /^(aria-label|placeholder|title)$/.test(node.name.getText()) && /[A-Za-z]{2}/.test(node.initializer.text)) violations.push(`${path}: ${node.name.getText()}=${node.initializer.text}`);
      if (ts.isJsxAttribute(node) && node.initializer && ts.isJsxExpression(node.initializer) && node.initializer.expression && /^(aria-label|placeholder|title)$/.test(node.name.getText())) collectRenderedCopy(node.initializer.expression, path, violations, bindings, functions);
      if (ts.isJsxExpression(node) && !ts.isJsxAttribute(node.parent) && node.expression) collectRenderedCopy(node.expression, path, violations, bindings, functions);
      if (ts.isCallExpression(node) && ts.isIdentifier(node.expression) && /^set[A-Za-z]*(Error|Success)$/.test(node.expression.text)) {
        const value = node.arguments[0];
        if (value && (ts.isStringLiteral(value) || ts.isNoSubstitutionTemplateLiteral(value)) && /[A-Za-z]{2}/.test(value.text)) violations.push(`${path}: static UI state ${value.text}`);
      }
      ts.forEachChild(node, visit);
  };
  visit(file);
  return violations;
}

test("raw-copy guard follows local dataflow instead of allowing indirection", () => {
  const fixture = `
    const label = "Delete account";
    const copy = { retry: "Try again" };
    const labels = ["Remove device"];
    function warning() { return "Danger zone"; }
    export function Fixture({ error }: { error?: string }) {
      return <><button>{label}</button><p>{error || copy.retry}</p><span>{labels[0]}</span><b>{warning()}</b></>;
    }`;
  const violations = inspectSource("fixture.tsx", fixture);
  for (const expected of ["Delete account", "Try again", "Remove device", "Danger zone"]) assert.ok(violations.some((value) => value.includes(expected)), expected);
});

function allTsx(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => entry.isDirectory() ? allTsx(resolve(dir, entry.name)) : entry.name.endsWith(".tsx") ? [resolve(dir, entry.name)] : []);
}

function collectRenderedCopy(node: ts.Expression, path: string, violations: string[], bindings: Map<string, ts.Expression>, functions: Map<string, ts.FunctionDeclaration>, seen = new Set<ts.Node>()): void {
  if (seen.has(node)) return;
  seen.add(node);
  if ((ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) && /[A-Za-z]{2}/.test(node.text) && node.text !== "IceQ") violations.push(`${path}: rendered copy ${node.text}`);
  else if (ts.isTemplateExpression(node) && /[A-Za-z]{2}/.test(node.head.text + node.templateSpans.map((span) => span.literal.text).join(""))) violations.push(`${path}: rendered template copy`);
  else if (ts.isConditionalExpression(node)) { collectRenderedCopy(node.whenTrue, path, violations, bindings, functions, seen); collectRenderedCopy(node.whenFalse, path, violations, bindings, functions, seen); }
  else if (ts.isBinaryExpression(node) && [ts.SyntaxKind.AmpersandAmpersandToken, ts.SyntaxKind.QuestionQuestionToken, ts.SyntaxKind.BarBarToken].includes(node.operatorToken.kind)) collectRenderedCopy(node.right, path, violations, bindings, functions, seen);
  else if (ts.isParenthesizedExpression(node)) collectRenderedCopy(node.expression, path, violations, bindings, functions, seen);
  else if (ts.isIdentifier(node)) { const value = bindings.get(node.text); if (value) collectRenderedCopy(value, path, violations, bindings, functions, seen); }
  else if (ts.isPropertyAccessExpression(node) && ts.isIdentifier(node.expression)) {
    const object = bindings.get(node.expression.text);
    if (object && ts.isObjectLiteralExpression(object)) {
      const property = object.properties.find((item): item is ts.PropertyAssignment => ts.isPropertyAssignment(item) && item.name.getText().replace(/["']/g, "") === node.name.text);
      if (property) collectRenderedCopy(property.initializer, path, violations, bindings, functions, seen);
    }
  } else if (ts.isElementAccessExpression(node) && ts.isIdentifier(node.expression) && node.argumentExpression && ts.isNumericLiteral(node.argumentExpression)) {
    const array = bindings.get(node.expression.text);
    const item = array && ts.isArrayLiteralExpression(array) ? array.elements[Number(node.argumentExpression.text)] : undefined;
    if (item && ts.isExpression(item)) collectRenderedCopy(item, path, violations, bindings, functions, seen);
  } else if (ts.isCallExpression(node) && ts.isIdentifier(node.expression) && node.arguments.length === 0) {
    const fn = functions.get(node.expression.text);
    if (fn && fn.parameters.length === 0 && fn.body) {
      const returned = fn.body.statements.find(ts.isReturnStatement)?.expression;
      if (returned) collectRenderedCopy(returned, path, violations, bindings, functions, seen);
    }
    const arrow = bindings.get(node.expression.text);
    if (arrow && ts.isArrowFunction(arrow) && arrow.parameters.length === 0 && !ts.isBlock(arrow.body)) collectRenderedCopy(arrow.body, path, violations, bindings, functions, seen);
  }
}
