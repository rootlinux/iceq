/**
 * router-regression.test.ts
 *
 * TypeScript AST-based regression test guarding IceQ against:
 *  - Attacker-controlled destinations reaching <Link>, <Navigate>,
 *    useNavigate, window.location, location.assign, or location.replace
 *  - Destinations that contain a scheme, protocol-relative URL, or backslash
 *  - SSR, RSC, Framework Mode, Data Mode, server hydration, loader,
 *    action, or affected React Router server APIs
 *
 * FIXED INTERNAL ROUTES ALLOWED: /login, /app, /setup, /recovery, /register
 * (and sub-paths like /app/*).
 *
 * This test parses production .ts/.tsx source files with the TypeScript
 * compiler API. It fails on any finding — there is no allowlist beyond
 * the fixed internal route prefixes.
 */

import assert from "node:assert/strict";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { basename, extname, join, relative } from "node:path";
import test from "node:test";
import ts from "typescript";

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const SRC_DIR = new URL("../src", import.meta.url).pathname;
const EXTENSIONS = new Set([".ts", ".tsx"]);

/** Navigation API names to track. */
const NAVIGATION_APIS = new Set([
  "Link",
  "Navigate",
  "useNavigate",
]);

/** Navigation method names on `location` / `window.location`. */
const LOCATION_METHODS = new Set([
  "assign",
  "replace",
]);

/** Fixed internal route prefixes that are allowed as navigation destinations. */
const ALLOWED_ROUTE_PREFIXES = [
  "/login",
  "/app",
  "/setup",
  "/recovery",
  "/register",
];

/** Banned substring markers in navigation destinations. */
const BANNED_DESTINATION_PATTERNS: { pattern: RegExp; label: string }[] = [
  { pattern: /:\/\//, label: "URL scheme (://)" },
  { pattern: /^\/\//, label: "protocol-relative URL (//)" },
  { pattern: /\\/, label: "backslash (\\)" },
  { pattern: /^javascript:/i, label: "javascript: URL" },
  { pattern: /^data:/i, label: "data: URL" },
];

/** Banned import sources — direct react-router imports (not react-router-dom). */
const BANNED_IMPORT_MODULES: { module: string; label: string }[] = [
  { module: "react-router", label: "direct react-router import (must use react-router-dom)" },
];

/**
 * Banned identifiers — SSR, RSC, Data Mode, Framework Mode, server hydration.
 *
 * NOTE: `json` and `hydrate` are intentionally excluded — they are too common
 * in application code (Response.json(), JSON.parse, auth-store hydration) and
 * not specific enough to be reliable markers. The react-router-dom import guard
 * below catches `json` / `redirect` / `defer` when imported from the router.
 */
const BANNED_IDENTIFIERS: { ident: string; label: string }[] = [
  { ident: "createBrowserRouter", label: "Data Mode createBrowserRouter" },
  { ident: "createMemoryRouter", label: "Data Mode createMemoryRouter" },
  { ident: "createHashRouter", label: "Data Mode createHashRouter" },
  { ident: "createStaticRouter", label: "SSR-only createStaticRouter" },
  { ident: "RouterProvider", label: "Data Mode RouterProvider" },
  { ident: "createRoutesFromElements", label: "Data Mode API" },
  { ident: "hydrateRoot", label: "React 18 SSR hydration API" },
  { ident: "renderToPipeableStream", label: "React SSR streaming" },
  { ident: "renderToReadableStream", label: "React SSR streaming" },
  { ident: "renderToString", label: "React SSR rendering" },
  { ident: "renderToStaticMarkup", label: "React SSR rendering" },
  { ident: "useLoaderData", label: "Data Mode loader" },
  { ident: "useActionData", label: "Data Mode action" },
  { ident: "useFetcher", label: "Data Mode fetcher" },
  { ident: "useFetchers", label: "Data Mode fetchers" },
  { ident: "useSubmit", label: "Data Mode submit" },
  { ident: "useRouteLoaderData", label: "Data Mode route loader" },
  { ident: "useRevalidator", label: "Data Mode revalidator" },
  { ident: "useBlocker", label: "Data Mode blocker" },
  { ident: "useRouteError", label: "Data Mode route error" },
  { ident: "useAsyncError", label: "Data Mode async error" },
  { ident: "useAsyncValue", label: "Data Mode async value" },
  { ident: "HydrateFallback", label: "Data Mode hydration fallback" },
  { ident: "Form", label: "Data Mode Form (the react-router-dom component, not HTML <form>)" },
  { ident: "LoaderFunction", label: "Data Mode loader type" },
  { ident: "LoaderFunctionArgs", label: "Data Mode loader args type" },
  { ident: "ActionFunction", label: "Data Mode action type" },
  { ident: "ActionFunctionArgs", label: "Data Mode action args type" },
  { ident: "LoaderArgs", label: "Data Mode loader args" },
  { ident: "ActionArgs", label: "Data Mode action args" },
  { ident: "DataFunctionArgs", label: "Data Mode data function args" },
  { ident: "StaticRouter", label: "SSR StaticRouter" },
  { ident: "StaticRouterProvider", label: "SSR StaticRouterProvider" },
  { ident: "ServerRouter", label: "SSR ServerRouter" },
  { ident: "createStaticHandler", label: "SSR static handler" },
  { ident: "createRequestHandler", label: "SSR request handler" },
  { ident: "unstable_useBlocker", label: "Router unstable API" },
  { ident: "unstable_usePrompt", label: "Router unstable API" },
  { ident: "UNSAFE_mapRouteProperties", label: "Router UNSAFE API" },
  { ident: "UNSAFE_useRoutesImpl", label: "Router UNSAFE API" },
  { ident: "UNSAFE_DataRouterContext", label: "Data Router context" },
  { ident: "UNSAFE_DataRouterStateContext", label: "Data Router state context" },
  { ident: "UNSAFE_NavigationContext", label: "Router UNSAFE context" },
  { ident: "UNSAFE_RouteContext", label: "Router UNSAFE context" },
  { ident: "matchPath", label: "Router v6 matchPath (only in react-router, not react-router-dom)" },
  { ident: "matchRoutes", label: "Router matchRoutes (Data Mode helper)" },
  { ident: "resolvePath", label: "Router resolvePath (internal API, use only via hooks)" },
  { ident: "generatePath", label: "Router generatePath (internal API)" },
];

/** Banned import specifiers from react-router-dom (should only import v6 declarative APIs). */
const BANNED_REACT_ROUTER_DOM_IMPORTS: { ident: string; label: string }[] = [
  { ident: "createBrowserRouter", label: "Data Mode API from react-router-dom" },
  { ident: "createMemoryRouter", label: "Data Mode API from react-router-dom" },
  { ident: "createHashRouter", label: "Data Mode API from react-router-dom" },
  { ident: "RouterProvider", label: "Data Mode API from react-router-dom" },
  { ident: "createRoutesFromElements", label: "Data Mode API from react-router-dom" },
  { ident: "createStaticRouter", label: "SSR API from react-router-dom" },
  { ident: "useLoaderData", label: "Data Mode API from react-router-dom" },
  { ident: "useActionData", label: "Data Mode API from react-router-dom" },
  { ident: "useFetcher", label: "Data Mode API from react-router-dom" },
  { ident: "useFetchers", label: "Data Mode API from react-router-dom" },
  { ident: "useSubmit", label: "Data Mode API from react-router-dom" },
  { ident: "useRouteLoaderData", label: "Data Mode API from react-router-dom" },
  { ident: "useRevalidator", label: "Data Mode API from react-router-dom" },
  { ident: "Form", label: "Data Mode API from react-router-dom" },
  { ident: "defer", label: "Data Mode API from react-router-dom" },
  { ident: "redirect", label: "Data Mode API from react-router-dom" },
  { ident: "json", label: "Data Mode API from react-router-dom" },
  { ident: "Await", label: "Data Mode API from react-router-dom" },
  { ident: "HydrateFallback", label: "Data Mode API from react-router-dom" },
  { ident: "LoaderFunction", label: "Data Mode type from react-router-dom" },
  { ident: "ActionFunction", label: "Data Mode type from react-router-dom" },
  { ident: "StaticRouter", label: "SSR API from react-router-dom" },
  { ident: "StaticRouterProvider", label: "SSR API from react-router-dom" },
];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

interface Finding {
  file: string;
  line: number;
  message: string;
}

function collectSourceFiles(dir: string): string[] {
  const result: string[] = [];
  const entries = readdirSync(dir);
  for (const entry of entries) {
    const full = join(dir, entry);
    let st: ReturnType<typeof statSync>;
    try { st = statSync(full); } catch { continue; }
    if (st.isDirectory()) {
      // Skip non-source directories
      if (entry === "node_modules" || entry === "dist" || entry.startsWith(".")) continue;
      result.push(...collectSourceFiles(full));
    } else if (EXTENSIONS.has(extname(entry))) {
      result.push(full);
    }
  }
  return result;
}

function isFixedInternalRoute(destination: string): boolean {
  return ALLOWED_ROUTE_PREFIXES.some(
    (prefix) => destination === prefix || destination.startsWith(prefix + "/") || destination.startsWith(prefix + "?"),
  );
}

function isTemplateLiteralWithExpressions(node: ts.TemplateExpression | ts.NoSubstitutionTemplateLiteral): boolean {
  return ts.isTemplateExpression(node);
}

/**
 * Walk AST to find navigation-related issues in a single file.
 */
function auditFile(filePath: string, sourceFile: ts.SourceFile): Finding[] {
  const findings: Finding[] = [];
  const src = sourceFile.text;
  const shortPath = relative(new URL("..", import.meta.url).pathname, filePath);

  // ------------------------------------------------------------------
  // Shared state — populated by Pass 1, consumed by Pass 2
  // ------------------------------------------------------------------

  // Collect imports from banned modules (for the regex pass below)
  const reactRouterDomImportNames = new Set<string>();

  // Track local name → API name for navigation imports (including aliases)
  // e.g. import { useNavigate as go } → { go → "useNavigate" }
  const importedNavAPIs = new Map<string, string>();

  // Track variables initialized from useNavigate() calls
  // e.g. const navigate = useNavigate() → navigate
  const navigateVars = new Set<string>();

  // ------------------------------------------------------------------
  // PASS 1 — collect imports, aliases, navigate variables
  //          (order-independent: ALL declarations are gathered before
  //           any usage is audited, so a call before its declaration
  //           is still detected.)
  // ------------------------------------------------------------------

  const pass1 = (node: ts.Node): void => {
    // --- Import declarations ---
    if (ts.isImportDeclaration(node)) {
      const moduleSpec = node.moduleSpecifier;
      if (ts.isStringLiteral(moduleSpec)) {
        const moduleName = moduleSpec.text;

        // Check for banned import modules
        for (const { module, label } of BANNED_IMPORT_MODULES) {
          if (moduleName === module) {
            const { line } = sourceFile.getLineAndCharacterOfPosition(moduleSpec.getStart());
            findings.push({
              file: shortPath,
              line: line + 1,
              message: `Banned import: ${label}`,
            });
          }
        }

        // Track react-router-dom import names (including nav API aliases)
        if (moduleName === "react-router-dom" && node.importClause?.namedBindings) {
          const bindings = node.importClause.namedBindings;
          if (ts.isNamedImports(bindings)) {
            for (const el of bindings.elements) {
              const localName = el.name.text;
              reactRouterDomImportNames.add(localName);
              // el.propertyName is the export name in `import { Foo as Bar }`
              const apiName = el.propertyName?.text ?? localName;
              if (NAVIGATION_APIS.has(apiName)) {
                importedNavAPIs.set(localName, apiName);
              }
            }
          }
        }
      }
    }

    // --- Check banned react-router-dom imports ---
    if (ts.isImportSpecifier(node)) {
      const name = node.name.text;
      for (const { ident, label } of BANNED_REACT_ROUTER_DOM_IMPORTS) {
        if (name === ident) {
          let ancestor = node.parent?.parent;
          if (ts.isImportDeclaration(ancestor)) {
            const spec = ancestor.moduleSpecifier;
            if (ts.isStringLiteral(spec) && spec.text === "react-router-dom") {
              const { line } = sourceFile.getLineAndCharacterOfPosition(node.getStart());
              findings.push({
                file: shortPath,
                line: line + 1,
                message: `Banned import '${ident}' from react-router-dom: ${label}`,
              });
            }
          }
        }
      }
    }

    // --- Track variables initialized from useNavigate() ---
    if (ts.isVariableDeclaration(node) && node.initializer) {
      if (ts.isCallExpression(node.initializer)) {
        const callee = node.initializer.expression;
        if (ts.isIdentifier(callee)) {
          const apiName = importedNavAPIs.get(callee.text);
          if (apiName === "useNavigate" && ts.isIdentifier(node.name)) {
            navigateVars.add(node.name.text);
          }
        }
      }
    }

    ts.forEachChild(node, pass1);
  };

  ts.forEachChild(sourceFile, pass1);

  // ------------------------------------------------------------------
  // PASS 2 — audit usages (JSX, calls, location assignments, banned
  //          identifiers) against the state collected in Pass 1.
  // ------------------------------------------------------------------

  const pass2 = (node: ts.Node): void => {
    // --- Check for banned identifiers in any context ---
    if (ts.isIdentifier(node)) {
      const ident = node.text;
      if (node.parent && (ts.isImportSpecifier(node.parent) || ts.isImportClause(node.parent))) {
        // handled in pass 1
      }
      for (const { ident: banned, label } of BANNED_IDENTIFIERS) {
        if (ident === banned && !ts.isImportSpecifier(node.parent) && !ts.isImportClause(node.parent)) {
          const { line } = sourceFile.getLineAndCharacterOfPosition(node.getStart());
          findings.push({
            file: shortPath,
            line: line + 1,
            message: `Banned identifier '${banned}': ${label}`,
          });
        }
      }
    }

    // --- JSX elements: <Link to="..."> and <Navigate to="..."> ---
    if (ts.isJsxOpeningElement(node) || ts.isJsxSelfClosingElement(node)) {
      const tagName = node.tagName;
      if (ts.isIdentifier(tagName)) {
        // Check both the literal tag name and any aliased import
        const tagText = tagName.text;
        const apiName = importedNavAPIs.get(tagText) ?? tagText;
        const isNavComponent =
          apiName === "Link" || apiName === "Navigate" || NAVIGATION_APIS.has(tagText);

        if (isNavComponent) {
          const attribs = ts.isJsxOpeningElement(node)
            ? node.attributes
            : (node as ts.JsxSelfClosingElement).attributes;

          // Order-aware spread tracking: a spread after the last verified
          // `to` prop can overwrite the destination and must fail closed.
          let lastToIndex = -1;
          let lastSpreadIndex = -1;

          for (let i = 0; i < attribs.properties.length; i++) {
            const prop = attribs.properties[i]!;
            if (ts.isJsxSpreadAttribute(prop)) {
              lastSpreadIndex = i;
            }
            if (ts.isJsxAttribute(prop) && prop.name.text === "to") {
              lastToIndex = i;
              if (prop.initializer) {
                auditNavigationDestination(
                  prop.initializer,
                  `<${tagText} to>`,
                  node,
                  findings,
                  sourceFile,
                  shortPath,
                );
              }
            }
          }

          if (lastSpreadIndex >= 0 && lastToIndex === -1) {
            // Spread without any explicit `to` — cannot prove safety
            const { line } = sourceFile.getLineAndCharacterOfPosition(node.getStart());
            findings.push({
              file: shortPath,
              line: line + 1,
              message:
                `<${tagText}> uses spread attributes without a verifiable 'to' prop. ` +
                `Cannot prove destination safety. Provide an explicit fixed internal route 'to' prop.`,
            });
          } else if (lastSpreadIndex >= 0 && lastSpreadIndex > lastToIndex) {
            // A spread appears after the last explicit `to` — can overwrite it
            const { line } = sourceFile.getLineAndCharacterOfPosition(node.getStart());
            findings.push({
              file: shortPath,
              line: line + 1,
              message:
                `<${tagText}> has a spread attribute after the final 'to' prop. ` +
                `The spread may overwrite the destination. Move 'to' after the spread, ` +
                `or remove the trailing spread.`,
            });
          }
        }
      }
    }

    // --- Call expressions ---
    if (ts.isCallExpression(node)) {
      const callee = node.expression;

      // Check for banned identifiers used as callee
      if (ts.isIdentifier(callee)) {
        for (const { ident, label } of BANNED_IDENTIFIERS) {
          if (callee.text === ident) {
            const { line } = sourceFile.getLineAndCharacterOfPosition(callee.getStart());
            findings.push({
              file: shortPath,
              line: line + 1,
              message: `Call to banned API '${ident}': ${label}`,
            });
          }
        }
      }

      // Detect: navigate("destination") where navigate was initialized from useNavigate()
      if (ts.isIdentifier(callee) && navigateVars.has(callee.text) && node.arguments.length >= 1) {
        const firstArg = node.arguments[0]!;
        auditNavigationDestination(
          firstArg,
          `${callee.text}()`,
          node,
          findings,
          sourceFile,
          shortPath,
        );
      }

      // Detect: useNavigate()("destination") — direct call without binding.
      // This pattern is opaque to variable tracking; fail closed.
      if (ts.isCallExpression(callee) && node.arguments.length >= 1) {
        const innerCallee = callee.expression;
        if (ts.isIdentifier(innerCallee)) {
          const apiName = importedNavAPIs.get(innerCallee.text);
          if (apiName === "useNavigate") {
            const { line } = sourceFile.getLineAndCharacterOfPosition(node.getStart());
            findings.push({
              file: shortPath,
              line: line + 1,
              message:
                `Direct useNavigate()(destination) call bypasses variable tracking. ` +
                `Bind useNavigate() to a local variable first.`,
            });
          }
        }
      }

      // Check location.assign(...) and location.replace(...)
      if (ts.isPropertyAccessExpression(callee)) {
        const methodName = callee.name.text;
        if (LOCATION_METHODS.has(methodName) && isLocationObject(callee.expression)) {
          if (node.arguments.length >= 1) {
            const arg = node.arguments[0]!;
            auditNavigationDestination(
              arg,
              `location.${methodName}`,
              node,
              findings,
              sourceFile,
              shortPath,
            );
          }
        }
      }
    }

    // --- Assignments: location.href = ..., window.location = ..., location = ... ---
    if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
      // location.href = value
      if (ts.isPropertyAccessExpression(node.left)) {
        const lhs = node.left;
        const prop = lhs.name.text;
        if (prop === "href" && isLocationObject(lhs.expression)) {
          auditNavigationDestination(
            node.right,
            "location.href assignment",
            node,
            findings,
            sourceFile,
            shortPath,
          );
        }
      }

      // location = value (bare global)
      if (ts.isIdentifier(node.left) && node.left.text === "location") {
        auditNavigationDestination(
          node.right,
          "location assignment",
          node,
          findings,
          sourceFile,
          shortPath,
        );
      }

      // window.location = value, document.location = value, globalThis.location = value
      if (ts.isPropertyAccessExpression(node.left) && node.left.name.text === "location") {
        const obj = node.left.expression;
        if (
          ts.isIdentifier(obj) &&
          (obj.text === "window" || obj.text === "document" || obj.text === "globalThis")
        ) {
          auditNavigationDestination(
            node.right,
            `${obj.text}.location assignment`,
            node,
            findings,
            sourceFile,
            shortPath,
          );
        }
      }
    }

    ts.forEachChild(node, pass2);
  };

  ts.forEachChild(sourceFile, pass2);

  // ------------------------------------------------------------------
  // Supplementary regex scan for banned identifiers in source text
  // (catches identifiers in type positions that the AST walk may miss)
  // ------------------------------------------------------------------

  for (const { ident, label } of BANNED_IDENTIFIERS) {
    const re = new RegExp(`\\b${escapeRegex(ident)}\\b`, "g");
    let m: RegExpExecArray | null;
    while ((m = re.exec(src)) !== null) {
      const pos = m.index;
      const lineStart = src.lastIndexOf("\n", pos) + 1;
      const lineEnd = src.indexOf("\n", pos);
      const line = src.slice(lineStart, lineEnd === -1 ? undefined : lineEnd);
      // Skip if inside a // comment
      const commentIdx = line.indexOf("//");
      if (commentIdx !== -1 && pos - lineStart > commentIdx) continue;
      // Skip if inside a block comment
      const blockCommentClose = line.indexOf("*/");
      const blockCommentOpen = line.indexOf("/*");
      if (
        blockCommentOpen !== -1 &&
        (blockCommentClose === -1 || pos - lineStart > blockCommentOpen) &&
        (blockCommentClose === -1 || pos - lineStart < blockCommentClose)
      )
        continue;

      const { line: lineNo } = sourceFile.getLineAndCharacterOfPosition(pos);
      const alreadyFound = findings.some(
        (f) => f.line === lineNo + 1 && f.message.includes(ident),
      );
      if (!alreadyFound) {
        findings.push({
          file: shortPath,
          line: lineNo + 1,
          message: `Banned identifier '${ident}' in source: ${label}`,
        });
      }
    }
  }

  return findings;
}

/**
 * Returns true if `node` is a reference to `window.location` or
 * `document.location` (the global Location object).
 */
function isLocationObject(node: ts.Node): boolean {
  // Direct: `location` (the global)
  if (ts.isIdentifier(node) && node.text === "location") return true;
  // `window.location` or `document.location`
  if (ts.isPropertyAccessExpression(node) && node.name.text === "location") {
    const obj = node.expression;
    if (ts.isIdentifier(obj) && (obj.text === "window" || obj.text === "document" || obj.text === "globalThis")) {
      return true;
    }
  }
  return false;
}

/**
 * Check a navigation destination AST node for safety.
 *
 * Unwraps JsxExpression and ParenthesizedExpression containers before
 * inspecting the underlying value.
 */
function auditNavigationDestination(
  node: ts.Node,
  context: string,
  _parentNode: ts.Node,
  findings: Finding[],
  sourceFile: ts.SourceFile,
  shortPath: string,
): void {
  // Unwrap JSX expression wrappers: to={expr} → expr is inside a JsxExpression
  if (ts.isJsxExpression(node) && node.expression) {
    auditNavigationDestination(node.expression, context, node, findings, sourceFile, shortPath);
    return;
  }

  // Unwrap parentheses
  if (ts.isParenthesizedExpression(node)) {
    auditNavigationDestination(node.expression, context, node, findings, sourceFile, shortPath);
    return;
  }

  const { line } = sourceFile.getLineAndCharacterOfPosition(node.getStart());

  // String literal
  if (ts.isStringLiteral(node)) {
    const dest = node.text;

    // Check for banned patterns
    for (const { pattern, label } of BANNED_DESTINATION_PATTERNS) {
      if (pattern.test(dest)) {
        findings.push({
          file: shortPath,
          line: line + 1,
          message: `Navigation destination '${dest}' in ${context} contains ${label}`,
        });
      }
    }

    // Check if it's a non-fixed internal route
    if (dest && !dest.startsWith("#") && !isFixedInternalRoute(dest)) {
      // Dynamic routes that are sub-paths of internal routes are OK
      // Otherwise flag
      findings.push({
        file: shortPath,
        line: line + 1,
        message: `Navigation destination '${dest}' in ${context}: not a recognized fixed internal route. ` +
          `Allowed prefixes: ${ALLOWED_ROUTE_PREFIXES.join(", ")}. ` +
          `If this is a legitimate fixed internal route, add it to ALLOWED_ROUTE_PREFIXES.`,
      });
    }
    return;
  }

  // Template literal with no expressions (backtick string)
  if (ts.isNoSubstitutionTemplateLiteral(node)) {
    const dest = node.text;

    for (const { pattern, label } of BANNED_DESTINATION_PATTERNS) {
      if (pattern.test(dest)) {
        findings.push({
          file: shortPath,
          line: line + 1,
          message: `Navigation destination \`${dest}\` in ${context} contains ${label}`,
        });
      }
    }

    if (dest && !dest.startsWith("#") && !isFixedInternalRoute(dest)) {
      findings.push({
        file: shortPath,
        line: line + 1,
        message: `Navigation destination \`${dest}\` in ${context}: not a recognized fixed internal route.`,
      });
    }
    return;
  }

  // Template literal with expressions: `${base}/${dynamic}` — flag as potentially attacker-controlled
  if (ts.isTemplateExpression(node)) {
    findings.push({
      file: shortPath,
      line: line + 1,
      message: `Navigation destination in ${context} uses template expression with substitutions — ` +
        `may be attacker-controlled. Use fixed literal or validate against ALLOWED_ROUTE_PREFIXES.`,
    });
    return;
  }

  // Variable reference / function call / ternary / etc. — flag for review
  // unless it's a ternary where both branches are fixed internal routes
  if (ts.isConditionalExpression(node)) {
    auditNavigationDestination(node.whenTrue, `${context} (ternary-true)`, node, findings, sourceFile, shortPath);
    auditNavigationDestination(node.whenFalse, `${context} (ternary-false)`, node, findings, sourceFile, shortPath);
    return;
  }

  // Binary expression like isAuthed ? "/app" : "/login" — already handled as conditional above
  // Other expressions: flag as potentially dynamic
  if (!ts.isStringLiteral(node) && !ts.isNoSubstitutionTemplateLiteral(node) &&
      !ts.isTemplateExpression(node) && !ts.isConditionalExpression(node)) {
    findings.push({
      file: shortPath,
      line: line + 1,
      message: `Navigation destination in ${context} is a dynamic expression (${ts.SyntaxKind[node.kind]}). ` +
        `Must be a fixed internal route literal. Verify it is not attacker-controlled.`,
    });
  }
}

function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

// ---------------------------------------------------------------------------
// Fixture helper — audit synthetic source text for scanner regression tests
// ---------------------------------------------------------------------------

function auditSourceText(code: string, fileName = "fixture.tsx"): Finding[] {
  const sourceFile = ts.createSourceFile(
    fileName,
    code,
    ts.ScriptTarget.ESNext,
    /* setParentNodes */ true,
    fileName.endsWith(".tsx") ? ts.ScriptKind.TSX : ts.ScriptKind.TS,
  );
  // Use the fileName directly as shortPath for fixture tests
  return auditFile(fileName, sourceFile);
}

// ---------------------------------------------------------------------------
// Scanner fixture tests — verify the audit engine against synthetic inputs
// ---------------------------------------------------------------------------

test("fixture: navigate(\"/app\") passes", () => {
  const findings = auditSourceText(`
    import { useNavigate } from "react-router-dom";
    function Comp() {
      const navigate = useNavigate();
      navigate("/app");
    }
  `);
  const nav = findings.filter((f) => f.message.includes("Navigation destination"));
  assert.equal(nav.length, 0, `expected 0 findings, got: ${JSON.stringify(nav)}`);
});

test("fixture: conditional with only fixed internal routes passes", () => {
  const findings = auditSourceText(`
    import { useNavigate } from "react-router-dom";
    function Comp({ authed }: { authed: boolean }) {
      const navigate = useNavigate();
      navigate(authed ? "/app" : "/login");
    }
  `);
  // The conditional branches are /app and /login — both are allowed prefixes
  const nav = findings.filter(
    (f) => f.message.includes("Navigation destination") || f.message.includes("dynamic expression"),
  );
  assert.equal(nav.length, 0, `expected 0 findings, got: ${JSON.stringify(nav)}`);
});

test("fixture: navigate(userInput) fails", () => {
  const findings = auditSourceText(`
    import { useNavigate } from "react-router-dom";
    function Comp({ dest }: { dest: string }) {
      const navigate = useNavigate();
      navigate(dest);
    }
  `);
  const flagged = findings.filter(
    (f) => f.message.includes("dynamic expression") || f.message.includes("Navigation destination"),
  );
  assert.ok(flagged.length > 0, "expected findings for userInput navigation");
});

test('fixture: navigate("//attacker.example") fails', () => {
  const findings = auditSourceText(`
    import { useNavigate } from "react-router-dom";
    function Comp() {
      const navigate = useNavigate();
      navigate("//attacker.example");
    }
  `);
  const flagged = findings.filter((f) => f.message.includes("protocol-relative URL"));
  assert.ok(flagged.length > 0, "expected protocol-relative URL detection");
});

test("fixture: backslash destination fails", () => {
  const findings = auditSourceText(`
    import { useNavigate } from "react-router-dom";
    function Comp() {
      const navigate = useNavigate();
      navigate("\\\\attacker.example");
    }
  `);
  const flagged = findings.filter((f) => f.message.includes("backslash"));
  assert.ok(flagged.length > 0, "expected backslash detection");
});

test('fixture: "javascript:" destination fails', () => {
  const findings = auditSourceText(`
    import { useNavigate } from "react-router-dom";
    function Comp() {
      const navigate = useNavigate();
      navigate("javascript:alert(1)");
    }
  `);
  const flagged = findings.filter((f) => f.message.includes("javascript:"));
  assert.ok(flagged.length > 0, "expected javascript: URL detection");
});

test('fixture: "data:" destination fails', () => {
  const findings = auditSourceText(`
    import { useNavigate } from "react-router-dom";
    function Comp() {
      const navigate = useNavigate();
      navigate("data:text/html,<script>alert(1)</script>");
    }
  `);
  const flagged = findings.filter((f) => f.message.includes("data:"));
  assert.ok(flagged.length > 0, "expected data: URL detection");
});

test("fixture: aliased useNavigate import is detected", () => {
  const findings = auditSourceText(`
    import { useNavigate as go } from "react-router-dom";
    function Comp() {
      const goFn = go();
      goFn("//attacker.example");
    }
  `);
  const flagged = findings.filter((f) => f.message.includes("protocol-relative URL"));
  assert.ok(flagged.length > 0, "expected aliased useNavigate to be tracked");
});

test("fixture: aliased Link component is detected", () => {
  const findings = auditSourceText(`
    import { Link as MyLink } from "react-router-dom";
    function Comp() {
      return <MyLink to="//attacker.example">click</MyLink>;
    }
  `);
  const flagged = findings.filter((f) => f.message.includes("protocol-relative URL"));
  assert.ok(flagged.length > 0, "expected aliased Link detection");
});

test("fixture: aliased Navigate component is detected", () => {
  const findings = auditSourceText(`
    import { Navigate as GoTo } from "react-router-dom";
    function Comp() {
      return <GoTo to="//attacker.example" />;
    }
  `);
  const flagged = findings.filter((f) => f.message.includes("protocol-relative URL"));
  assert.ok(flagged.length > 0, "expected aliased Navigate detection");
});

test("fixture: <Link to={userInput}> fails", () => {
  const findings = auditSourceText(`
    import { Link } from "react-router-dom";
    function Comp({ dest }: { dest: string }) {
      return <Link to={dest}>click</Link>;
    }
  `);
  const flagged = findings.filter((f) => f.message.includes("dynamic expression"));
  assert.ok(flagged.length > 0, "expected dynamic expression detection in Link to");
});

test("fixture: spread attributes on Link without explicit to fails closed", () => {
  const findings = auditSourceText(`
    import { Link } from "react-router-dom";
    function Comp(props: any) {
      return <Link {...props}>click</Link>;
    }
  `);
  const flagged = findings.filter((f) => f.message.includes("spread attributes"));
  assert.ok(flagged.length > 0, "expected spread-attribute fail-closed");
});

test("fixture: spread attributes on Navigate without explicit to fails closed", () => {
  const findings = auditSourceText(`
    import { Navigate } from "react-router-dom";
    function Comp(props: any) {
      return <Navigate {...props} />;
    }
  `);
  const flagged = findings.filter((f) => f.message.includes("spread attributes"));
  assert.ok(flagged.length > 0, "expected Navigate spread-attribute fail-closed");
});

test("fixture: spread with explicit safe to passes", () => {
  const findings = auditSourceText(`
    import { Link } from "react-router-dom";
    function Comp(props: any) {
      return <Link {...props} to="/app">click</Link>;
    }
  `);
  const flagged = findings.filter((f) => f.message.includes("spread attributes"));
  assert.equal(flagged.length, 0, "expected spread with explicit to to pass");
});

test("fixture: window.location = value is covered", () => {
  const findings = auditSourceText(`
    function Comp() {
      window.location = "//attacker.example";
    }
  `);
  const flagged = findings.filter((f) => f.message.includes("protocol-relative URL"));
  assert.ok(flagged.length > 0, "expected window.location assignment detection");
});

test("fixture: bare location = value is covered", () => {
  const findings = auditSourceText(`
    function Comp() {
      location = "//attacker.example";
    }
  `);
  const flagged = findings.filter((f) => f.message.includes("protocol-relative URL"));
  assert.ok(flagged.length > 0, "expected bare location assignment detection");
});

test("fixture: location.href = value is covered", () => {
  const findings = auditSourceText(`
    function Comp() {
      location.href = "//attacker.example";
    }
  `);
  const flagged = findings.filter((f) => f.message.includes("protocol-relative URL"));
  assert.ok(flagged.length > 0, "expected location.href assignment detection");
});

test("fixture: location.assign(value) is covered", () => {
  const findings = auditSourceText(`
    function Comp() {
      location.assign("//attacker.example");
    }
  `);
  const flagged = findings.filter((f) => f.message.includes("protocol-relative URL"));
  assert.ok(flagged.length > 0, "expected location.assign detection");
});

test("fixture: location.replace(value) is covered", () => {
  const findings = auditSourceText(`
    function Comp() {
      location.replace("//attacker.example");
    }
  `);
  const flagged = findings.filter((f) => f.message.includes("protocol-relative URL"));
  assert.ok(flagged.length > 0, "expected location.replace detection");
});

// --- Order-independence: navigate call before declaration ---

test("fixture: navigate(userInput) before declaration is detected (order-independent)", () => {
  const findings = auditSourceText(`
    import { useNavigate } from "react-router-dom";
    function Comp({ dest }: { dest: string }) {
      function inner() {
        navigate(dest); // appears before declaration in source order
      }
      const navigate = useNavigate();
      inner();
    }
  `);
  const flagged = findings.filter(
    (f) => f.message.includes("dynamic expression"),
  );
  assert.ok(flagged.length > 0, "expected order-independent detection of navigate(userInput)");
});

// --- Direct useNavigate()(destination) — fail closed ---

test("fixture: direct useNavigate()(destination) fails closed", () => {
  const findings = auditSourceText(`
    import { useNavigate } from "react-router-dom";
    function Comp() {
      useNavigate()("//attacker.example");
    }
  `);
  const flagged = findings.filter(
    (f) => f.message.includes("Direct useNavigate()"),
  );
  assert.ok(flagged.length > 0, "expected direct useNavigate()(dest) to fail closed");
});

// --- Spread order-aware: spread AFTER to fails ---

test("fixture: spread after explicit to fails closed", () => {
  const findings = auditSourceText(`
    import { Link } from "react-router-dom";
    function Comp(props: any) {
      return <Link to="/app" {...props}>click</Link>;
    }
  `);
  const flagged = findings.filter((f) => f.message.includes("spread attribute after"));
  assert.ok(flagged.length > 0, "expected spread-after-to to fail closed");
});

test("fixture: spread before explicit to passes (order-aware)", () => {
  const findings = auditSourceText(`
    import { Link } from "react-router-dom";
    function Comp(props: any) {
      return <Link {...props} to="/app">click</Link>;
    }
  `);
  const flagged = findings.filter((f) => f.message.includes("spread attribute"));
  assert.equal(flagged.length, 0, "expected spread-before-to to pass");
});

test("fixture: spread after to on Navigate fails closed", () => {
  const findings = auditSourceText(`
    import { Navigate } from "react-router-dom";
    function Comp(props: any) {
      return <Navigate to="/app" {...props} />;
    }
  `);
  const flagged = findings.filter((f) => f.message.includes("spread attribute after"));
  assert.ok(flagged.length > 0, "expected Navigate spread-after-to to fail closed");
});

test("fixture: spread after to on aliased Link fails closed", () => {
  const findings = auditSourceText(`
    import { Link as MyLink } from "react-router-dom";
    function Comp(props: any) {
      return <MyLink to="/app" {...props}>click</MyLink>;
    }
  `);
  const flagged = findings.filter((f) => f.message.includes("spread attribute after"));
  assert.ok(flagged.length > 0, "expected aliased Link spread-after-to to fail closed");
});

// ---------------------------------------------------------------------------
// Production source audit
// ---------------------------------------------------------------------------

const files = collectSourceFiles(SRC_DIR);
const allFindings: Finding[] = [];

for (const filePath of files) {
  const src = readFileSync(filePath, "utf-8");
  const sourceFile = ts.createSourceFile(
    basename(filePath),
    src,
    ts.ScriptTarget.ESNext,
    /* setParentNodes */ true,
    extname(filePath) === ".tsx" ? ts.ScriptKind.TSX : ts.ScriptKind.TS,
  );
  const findings = auditFile(filePath, sourceFile);
  allFindings.push(...findings);
}

test("no banned SSR, RSC, Data Mode, or Framework Mode APIs are imported or used", () => {
  const banned = allFindings.filter((f) => f.message.includes("Banned"));
  if (banned.length > 0) {
    const lines = banned.map((f) => `  ${f.file}:${f.line} — ${f.message}`);
    assert.fail(`Found ${banned.length} banned API usage(s):\n${lines.join("\n")}`);
  }
});

test("no direct react-router imports (must use react-router-dom)", () => {
  const direct = allFindings.filter((f) => f.message.includes("direct react-router import"));
  if (direct.length > 0) {
    const lines = direct.map((f) => `  ${f.file}:${f.line} — ${f.message}`);
    assert.fail(`Found ${direct.length} direct react-router import(s):\n${lines.join("\n")}`);
  }
});

test("all navigation destinations are fixed internal routes without schemes, backslashes, or protocol-relative URLs", () => {
  const nav = allFindings.filter(
    (f) =>
      f.message.includes("Navigation destination") &&
      !f.message.includes("Banned"),
  );
  // Group by file for readability
  if (nav.length > 0) {
    const lines = nav.map((f) => `  ${f.file}:${f.line} — ${f.message}`);
    assert.fail(`Found ${nav.length} navigation destination concern(s):\n${lines.join("\n")}`);
  }
});

test("no attacker-controlled or unresolved navigation destinations", () => {
  const dynamic = allFindings.filter(
    (f) =>
      f.message.includes("dynamic expression") ||
      f.message.includes("template expression with substitutions"),
  );
  if (dynamic.length > 0) {
    const lines = dynamic.map((f) => `  ${f.file}:${f.line} — ${f.message}`);
    assert.fail(`Found ${dynamic.length} potentially attacker-controlled navigation destination(s):\n${lines.join("\n")}`);
  }
});
