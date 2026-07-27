#!/usr/bin/env node --import tsx

/**
 * audit-policy.mts — Narrow npm audit gate for IceQ web.
 *
 * Parses `npm audit --json` and allows ONLY the three reviewed GHSA advisories
 * while react-router + react-router-dom remain exactly 6.30.4.
 *
 * Fail-closed: any parse failure, missing audit, high/critical advisory,
 * unknown advisory, unparseable advisory URL, version-pin drift, or change in
 * accepted-advisory count produces a non-zero exit.
 *
 * Expiry: 2026-10-27. After this date this script fails unconditionally
 * so the exception is not silently carried forward.
 *
 * Usage:
 *   node --import tsx web/scripts/audit-policy.mts            # all dependencies
 *   node --import tsx web/scripts/audit-policy.mts --production  # --omit=dev
 */

import { execSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const EXPIRY_DATE = "2026-10-27";
const REQUIRED_ROUTER_VERSION = "6.30.4";
const REQUIRED_REACT_MAJOR = 18;

/**
 * The exact set of GHSA advisory identifiers temporarily accepted.
 * If this list changes (additions, removals, or count drift), the gate fails.
 */
const ACCEPTED_ADVISORIES: ReadonlySet<string> = new Set([
  "GHSA-wrjc-x8rr-h8h6", // Open redirect via backslash — fixed internal routes only
  "GHSA-jjmj-jmhj-qwj2", // Open redirect leading to XSS — fixed internal routes only
  "GHSA-337j-9hxr-rhxg", // deserializeErrors SSR — client-only BrowserRouter, not applicable
]);

/**
 * Human-readable rationale recorded in output.
 */
const RATIONALE = [
  "GHSA-337j-9hxr-rhxg affects Framework/Data Mode applications performing",
  "  manual SSR hydration. IceQ uses client-only BrowserRouter declarative",
  "  mode and does not use the affected SSR path.",
  "",
  "GHSA-wrjc-x8rr-h8h6 and GHSA-jjmj-jmhj-qwj2 require attacker-controlled",
  "  destinations to reach Link, Navigate, or useNavigate. Current IceQ",
  "  production navigation destinations are fixed internal routes.",
  "",
  "Acceptance is conditional on react-router + react-router-dom staying at",
  "  exactly 6.30.4 and React staying at 18.x, guarded by CI regression checks.",
].join("\n");

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface AuditAdvisory {
  url: string;
  severity: string;
  title: string;
}

interface AuditVia {
  source: number;
  url: string;
  title: string;
  severity: string;
}

interface AuditVuln {
  name: string;
  severity: "critical" | "high" | "moderate" | "low";
  isDirect: boolean;
  via: (string | AuditVia)[];
}

interface AuditReport {
  auditReportVersion: number;
  vulnerabilities: Record<string, AuditVuln>;
  metadata: {
    vulnerabilities: {
      info: number;
      low: number;
      moderate: number;
      high: number;
      critical: number;
      total: number;
    };
  };
}

interface AdvisoryInfo {
  title: string;
  severity: string;
  pkg: string;
}

interface PolicyPass {
  pass: true;
  foundGHSAs: Map<string, AdvisoryInfo>;
  routerVersion: string;
}

interface PolicyFail {
  pass: false;
  reason: string;
}

type PolicyResult = PolicyPass | PolicyFail;

// ---------------------------------------------------------------------------
// Pure policy evaluation — testable without npm or network
// ---------------------------------------------------------------------------

function extractGHSA(url: string): string | null {
  const m = url.match(/(GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})/i);
  return m ? m[1] : null;
}

/**
 * Evaluate an npm audit report against the policy.
 *
 * Pure function — does not touch the filesystem or network.
 * Pass `now` for deterministic expiry testing.
 */
export function evaluatePolicy(
  report: AuditReport,
  opts?: {
    now?: Date;
    acceptedAdvisories?: ReadonlySet<string>;
    requiredRouterVersion?: string;
    requiredReactMajor?: number;
    expiryDate?: string;
  },
): PolicyResult {
  const now = opts?.now ?? new Date();
  const accepted = opts?.acceptedAdvisories ?? ACCEPTED_ADVISORIES;
  const requiredRouter = opts?.requiredRouterVersion ?? REQUIRED_ROUTER_VERSION;
  const requiredReactMajor = opts?.requiredReactMajor ?? REQUIRED_REACT_MAJOR;
  const expiryDate = opts?.expiryDate ?? EXPIRY_DATE;

  // --- Expiry check ---
  const expiry = new Date(expiryDate);
  if (now >= expiry) {
    return {
      pass: false,
      reason: `Temporary audit exception expired on ${expiryDate}. Re-evaluate the React Router migration and update the policy or pin.`,
    };
  }

  // --- Validate report structure ---
  if (!report || typeof report !== "object") {
    return { pass: false, reason: "Parsed audit report is not an object." };
  }

  const meta = report.metadata?.vulnerabilities;
  if (!meta) {
    return { pass: false, reason: "Audit report missing metadata.vulnerabilities." };
  }

  // --- Reject high / critical ---
  if (meta.high > 0 || meta.critical > 0) {
    return {
      pass: false,
      reason: `Found ${meta.high} high and ${meta.critical} critical vulnerabilities. These are not covered by the temporary exception.`,
    };
  }

  // --- Collect all advisory GHSA IDs ---
  const vulns = report.vulnerabilities ?? {};
  const foundGHSAs = new Map<string, AdvisoryInfo>();
  const unparseable: string[] = [];

  for (const [pkgName, vuln] of Object.entries(vulns)) {
    for (const via of vuln.via) {
      if (typeof via === "string") continue; // transitive dependency chain reference
      const url = via.url ?? "";
      const ghsa = extractGHSA(url);
      if (!ghsa) {
        // Fail closed: every leaf advisory must have a parseable GHSA identifier
        unparseable.push(
          `  (no parseable GHSA) ${via.severity ?? vuln.severity} — ${via.title ?? url} [in ${pkgName}]`,
        );
        continue;
      }
      foundGHSAs.set(ghsa, {
        title: via.title ?? url,
        severity: via.severity ?? vuln.severity,
        pkg: pkgName,
      });
    }
  }

  if (unparseable.length > 0) {
    return {
      pass: false,
      reason:
        `Found ${unparseable.length} advisory/advisories without a parseable GHSA identifier:\n` +
        unparseable.join("\n") +
        `\n\nEvery leaf advisory must be mapped to a known GHSA. Update extractGHSA or review the advisory URL format.`,
    };
  }

  // --- Verify every found advisory is accepted ---
  const unknown: string[] = [];
  for (const [ghsa, info] of foundGHSAs) {
    if (!accepted.has(ghsa)) {
      unknown.push(`  ${ghsa} (${info.severity}) — ${info.title} [in ${info.pkg}]`);
    }
  }

  if (unknown.length > 0) {
    return {
      pass: false,
      reason:
        `Found ${unknown.length} advisory/advisories NOT in the accepted list:\n` +
        unknown.join("\n") +
        `\n\nThese must be reviewed and either added to the policy or resolved.`,
    };
  }

  // --- Verify accepted advisory count matches found count (no silent drops) ---
  if (foundGHSAs.size !== accepted.size) {
    const acceptedButNotFound = [...accepted].filter((a) => !foundGHSAs.has(a));
    return {
      pass: false,
      reason:
        `Advisory count mismatch: accepted ${accepted.size}, found ${foundGHSAs.size}. ` +
        `Accepted but not in report: ${acceptedButNotFound.join(", ") || "(none)"}. ` +
        `This may mean a previously-accepted advisory was patched — verify and update the policy.`,
    };
  }

  return {
    pass: true,
    foundGHSAs,
    routerVersion: requiredRouter,
  };
}

// ---------------------------------------------------------------------------
// Pure version-policy evaluation — testable without npm or network
// ---------------------------------------------------------------------------

export interface VersionInput {
  react: string | null;
  reactDom: string | null;
  reactRouter: string | null;
  reactRouterDom: string | null;
  reactDepSpec: string | null;
  reactDomDepSpec: string | null;
}

export interface VersionFail {
  pass: false;
  reason: string;
}

export interface VersionPass {
  pass: true;
}

export type VersionResult = VersionPass | VersionFail;

/**
 * Evaluate installed package versions and dependency specifications against
 * the Router audit exception policy.
 *
 * Pure function — all values are injected. Pass `null` for any value that
 * could not be resolved.
 */
export function evaluateVersions(
  input: VersionInput,
  opts?: {
    requiredRouterVersion?: string;
    requiredReactMajor?: number;
  },
): VersionResult {
  const requiredRouter = opts?.requiredRouterVersion ?? REQUIRED_ROUTER_VERSION;
  const requiredReactMajor = opts?.requiredReactMajor ?? REQUIRED_REACT_MAJOR;

  // --- Resolve installed versions ---
  function checkInstalled(
    label: string,
    version: string | null,
    expectedMajorOrExact: number | string,
    isExact: boolean,
  ): string | null {
    if (!version) return `${label}: cannot resolve installed version.`;
    if (isExact) {
      if (version !== expectedMajorOrExact) {
        return `${label}: installed ${version}, required exactly ${expectedMajorOrExact}.`;
      }
    } else {
      const major = parseInt(version.split(".")[0]!, 10);
      if (major !== expectedMajorOrExact) {
        return `${label}: installed ${version} (major ${major}), required major ${expectedMajorOrExact}.x.`;
      }
    }
    return null;
  }

  // --- Check dep spec cannot resolve to a higher major ---
  function checkDepSpec(
    label: string,
    spec: string | null,
    maxMajor: number,
  ): string | null {
    if (!spec) return `${label}: cannot read dependency specification from package.json.`;
    // Extract major from caret/tilde/exact spec, e.g. "^18.3.1" → 18, "~18.3.1" → 18, "18.3.1" → 18
    const m = spec.match(/^[\^~]?(\d+)\./);
    if (!m) return `${label}: cannot parse major version from spec "${spec}".`;
    const specMajor = parseInt(m[1]!, 10);
    if (specMajor > maxMajor) {
      return `${label}: spec "${spec}" resolves to major ${specMajor}, which exceeds maximum allowed major ${maxMajor}.`;
    }
    // Also reject specs that are clearly for the wrong major via range syntax
    if (spec.startsWith("^") && specMajor !== maxMajor) {
      return `${label}: spec "${spec}" resolves to ${specMajor}.x, required ${maxMajor}.x.`;
    }
    return null;
  }

  const checks: string[] = [];

  const r = checkInstalled("react", input.react, requiredReactMajor, false);
  if (r) checks.push(r);

  const rd = checkInstalled("react-dom", input.reactDom, requiredReactMajor, false);
  if (rd) checks.push(rd);

  const rr = checkInstalled("react-router", input.reactRouter, requiredRouter, true);
  if (rr) checks.push(rr);

  const rrd = checkInstalled("react-router-dom", input.reactRouterDom, requiredRouter, true);
  if (rrd) checks.push(rrd);

  const rdSpec = checkDepSpec("react", input.reactDepSpec, requiredReactMajor);
  if (rdSpec) checks.push(rdSpec);

  const rddSpec = checkDepSpec("react-dom", input.reactDomDepSpec, requiredReactMajor);
  if (rddSpec) checks.push(rddSpec);

  if (checks.length > 0) {
    return { pass: false, reason: checks.join("\n") };
  }

  return { pass: true };
}

function fail(reason: string): never {
  process.stderr.write(`\n[AUDIT-POLICY] FAIL: ${reason}\n\n`);
  process.exit(1);
}

function daysUntil(target: Date): number {
  return Math.max(0, Math.ceil((target.getTime() - Date.now()) / 86_400_000));
}

function resolvePackageVersion(pkgName: string, cwd: string): string | null {
  try {
    const pkgJson = execSync(
      `node -e "process.stdout.write(require('${pkgName}/package.json').version)"`,
      {
        cwd,
        encoding: "utf-8",
        stdio: ["ignore", "pipe", "pipe"],
      },
    );
    return pkgJson.trim() || null;
  } catch {
    return null;
  }
}

/**
 * Run npm audit and return the raw JSON output.
 * Exported for testing.
 */
export function runNpmAudit(cwd: string, production: boolean): string {
  const auditArgs = ["audit", "--json"];
  if (production) auditArgs.push("--omit=dev");

  let raw: string;
  try {
    raw = execSync("npm " + auditArgs.join(" "), {
      cwd,
      encoding: "utf-8",
      maxBuffer: 10 * 1024 * 1024,
      stdio: ["ignore", "pipe", "pipe"],
    });
  } catch (err) {
    const e = err as { stdout?: string; stderr?: string; status?: number };
    if (e.stdout) {
      raw = e.stdout;
    } else {
      throw new Error(
        `npm audit failed to produce output (status ${e.status ?? "unknown"}). ` +
          `stderr: ${e.stderr ?? "(none)"}`,
      );
    }
  }

  if (!raw || raw.trim().length === 0) {
    throw new Error("npm audit returned empty output.");
  }

  return raw;
}

// ---------------------------------------------------------------------------
// Main — only executes when run directly (not imported for testing)
// ---------------------------------------------------------------------------

const isMain = process.argv[1] && import.meta.url.endsWith(
  process.argv[1].replace(/^\.\//, ""),
);

if (isMain) {
  const production = process.argv.includes("--production");
  const cwd = new URL("..", import.meta.url).pathname;

  // --- Run npm audit ---
  let raw: string;
  try {
    raw = runNpmAudit(cwd, production);
  } catch (err) {
    fail(err instanceof Error ? err.message : "npm audit execution failed.");
  }

  // --- Parse ---
  let report: AuditReport;
  try {
    report = JSON.parse(raw) as AuditReport;
  } catch {
    fail("npm audit returned malformed JSON. Cannot parse audit report.");
  }

  // --- Evaluate policy ---
  const result = evaluatePolicy(report);

  if (!result.pass) {
    fail(result.reason);
  }

  // --- Verify installed versions and dependency specs ---

  let pkgJsonDeps: Record<string, string> = {};
  try {
    const rawPkg = readFileSync(join(cwd, "package.json"), "utf-8");
    pkgJsonDeps = (JSON.parse(rawPkg) as { dependencies?: Record<string, string> }).dependencies ?? {};
  } catch {
    fail("Cannot read package.json for dependency specification verification.");
  }

  const versionResult = evaluateVersions({
    react: resolvePackageVersion("react", cwd),
    reactDom: resolvePackageVersion("react-dom", cwd),
    reactRouter: resolvePackageVersion("react-router", cwd),
    reactRouterDom: resolvePackageVersion("react-router-dom", cwd),
    reactDepSpec: pkgJsonDeps["react"] ?? null,
    reactDomDepSpec: pkgJsonDeps["react-dom"] ?? null,
  });

  if (!versionResult.pass) {
    fail(
      `Version policy violation:\n${versionResult.reason}\n` +
        `The temporary audit exception is valid only at the pinned versions.`,
    );
  }

  // --- Success ---
  const mode = production ? "production" : "all";
  const expiryDate = new Date(EXPIRY_DATE);
  process.stdout.write(
    [
      "",
      "[AUDIT-POLICY] PASS",
      `  Mode:      ${mode} dependencies`,
      `  Expiry:    ${EXPIRY_DATE} (${daysUntil(expiryDate)} days remaining)`,
      `  React:     react@${resolvePackageVersion("react", cwd)!}, react-dom@${resolvePackageVersion("react-dom", cwd)!}`,
      `  Router:    react-router@${resolvePackageVersion("react-router", cwd)!}, react-router-dom@${resolvePackageVersion("react-router-dom", cwd)!}`,
      `  Accepted:  ${result.foundGHSAs.size} advisory/advisories`,
    ].join("\n") + "\n",
  );

  for (const [ghsa, info] of result.foundGHSAs) {
    process.stdout.write(`    ${ghsa} — ${info.title}\n`);
  }

  process.stdout.write(`\n  Rationale:\n${RATIONALE.replace(/^/gm, "    ")}\n\n`);

  process.exit(0);
}
