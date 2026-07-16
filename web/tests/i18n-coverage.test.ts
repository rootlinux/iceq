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

test("raw-copy guard resolves nearest lexical binding without cross-function collisions", () => {
  const fixtures = [
    `function A(){ const label='Delete account'; return <button>{label}</button>; } function B(){ const label=t('safe.key'); return <button>{label}</button>; }`,
    `function B(){ const label=t('safe.key'); return <button>{label}</button>; } function A(){ const label='Delete account'; return <button>{label}</button>; }`,
    `function A(){ const label='Delete account'; { const label=t('safe.key'); void <button>{label}</button>; } return <button>{label}</button>; }`,
    `const label=t('safe.key'); function A(){ const label='Delete account'; function B(){ const label=t('safe.key'); return <button>{label}</button>; } return <button>{label}</button>; }`,
  ];
  for (const [index, fixture] of fixtures.entries()) {
    const violations = inspectSource(`scope-${index}.tsx`, fixture);
    assert.equal(violations.filter((value) => value.includes("Delete account")).length, 1, JSON.stringify(violations));
    assert.equal(violations.some((value) => value.includes("safe.key")), false, JSON.stringify(violations));
  }
});

function allTsx(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => entry.isDirectory() ? allTsx(resolve(dir, entry.name)) : entry.name.endsWith(".tsx") ? [resolve(dir, entry.name)] : []);
}

function collectRenderedCopy(node: ts.Expression, path: string, violations: string[], seen = new Set<ts.Node>()): void {
  if (seen.has(node)) return;
  seen.add(node);
  if ((ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) && /[A-Za-z]{2}/.test(node.text) && node.text !== "IceQ") violations.push(`${path}: rendered copy ${node.text}`);
  else if (ts.isTemplateExpression(node) && /[A-Za-z]{2}/.test(node.head.text + node.templateSpans.map((span) => span.literal.text).join(""))) violations.push(`${path}: rendered template copy`);
  else if (ts.isConditionalExpression(node)) { collectRenderedCopy(node.whenTrue, path, violations, seen); collectRenderedCopy(node.whenFalse, path, violations, seen); }
  else if (ts.isBinaryExpression(node) && [ts.SyntaxKind.AmpersandAmpersandToken, ts.SyntaxKind.QuestionQuestionToken, ts.SyntaxKind.BarBarToken].includes(node.operatorToken.kind)) collectRenderedCopy(node.right, path, violations, seen);
  else if (ts.isParenthesizedExpression(node)) collectRenderedCopy(node.expression, path, violations, seen);
  else if (ts.isIdentifier(node)) {
    const declaration = resolveLexicalDeclaration(node.text, node);
    if (declaration && ts.isVariableDeclaration(declaration) && declaration.initializer) collectRenderedCopy(declaration.initializer, path, violations, seen);
  }
  else if (ts.isPropertyAccessExpression(node) && ts.isIdentifier(node.expression)) {
    const declaration = resolveLexicalDeclaration(node.expression.text, node);
    const object = declaration && ts.isVariableDeclaration(declaration) ? declaration.initializer : undefined;
    if (object && ts.isObjectLiteralExpression(object)) {
      const property = object.properties.find((item): item is ts.PropertyAssignment => ts.isPropertyAssignment(item) && item.name.getText().replace(/["']/g, "") === node.name.text);
      if (property) collectRenderedCopy(property.initializer, path, violations, seen);
    }
  } else if (ts.isElementAccessExpression(node) && ts.isIdentifier(node.expression) && node.argumentExpression && ts.isNumericLiteral(node.argumentExpression)) {
    const declaration = resolveLexicalDeclaration(node.expression.text, node);
    const array = declaration && ts.isVariableDeclaration(declaration) ? declaration.initializer : undefined;
    const item = array && ts.isArrayLiteralExpression(array) ? array.elements[Number(node.argumentExpression.text)] : undefined;
    if (item && ts.isExpression(item)) collectRenderedCopy(item, path, violations, seen);
  } else if (ts.isCallExpression(node) && ts.isIdentifier(node.expression) && node.arguments.length === 0) {
    const declaration = resolveLexicalDeclaration(node.expression.text, node);
    const fn = declaration && ts.isFunctionDeclaration(declaration) ? declaration : undefined;
    if (fn && fn.parameters.length === 0 && fn.body) {
      const returned = fn.body.statements.find(ts.isReturnStatement)?.expression;
      if (returned) collectRenderedCopy(returned, path, violations, seen);
    }
    const arrow = declaration && ts.isVariableDeclaration(declaration) ? declaration.initializer : undefined;
    if (arrow && ts.isArrowFunction(arrow) && arrow.parameters.length === 0 && !ts.isBlock(arrow.body)) collectRenderedCopy(arrow.body, path, violations, seen);
  }
}

type LexicalDeclaration = ts.VariableDeclaration | ts.FunctionDeclaration | ts.ParameterDeclaration;

function resolveLexicalDeclaration(name: string, usage: ts.Node): LexicalDeclaration | undefined {
  for (let scope: ts.Node | undefined = usage.parent; scope; scope = scope.parent) {
    if (ts.isFunctionLike(scope)) {
      const parameter = scope.parameters.find((item) => ts.isIdentifier(item.name) && item.name.text === name);
      if (parameter) return parameter;
    }
    if (!ts.isBlock(scope) && !ts.isSourceFile(scope)) continue;
    let best: LexicalDeclaration | undefined;
    for (const statement of scope.statements) {
      if (statement.pos > usage.pos) break;
      if (ts.isVariableStatement(statement)) {
        for (const declaration of statement.declarationList.declarations) {
          if (ts.isIdentifier(declaration.name) && declaration.name.text === name && declaration.pos <= usage.pos) best = declaration;
        }
      } else if (ts.isFunctionDeclaration(statement) && statement.name?.text === name) {
        best = statement;
      }
    }
    if (best) return best;
  }
  return undefined;
}
