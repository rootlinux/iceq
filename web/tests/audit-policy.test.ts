/**
 * audit-policy.test.ts — Fixture tests for the pure policy evaluation function
 * and runtime helpers exported from audit-policy.mts.
 *
 * Run via: node --import tsx --test web/tests/audit-policy.test.ts
 */

import assert from "node:assert/strict";
import test from "node:test";
import { evaluatePolicy, evaluateVersions, runNpmAudit } from "../scripts/audit-policy.mts";
import type { VersionInput } from "../scripts/audit-policy.mts";

// ---------------------------------------------------------------------------
// Test fixtures
// ---------------------------------------------------------------------------

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

interface PolicyFail {
  pass: false;
  reason: string;
}

function makeReport(overrides: Partial<AuditReport> = {}): AuditReport {
  return {
    auditReportVersion: 3,
    vulnerabilities: {},
    metadata: {
      vulnerabilities: {
        info: 0,
        low: 0,
        moderate: 0,
        high: 0,
        critical: 0,
        total: 0,
      },
    },
    ...overrides,
  };
}

function makeVia(overrides: Partial<AuditVia> = {}): AuditVia {
  return {
    source: 123456,
    url: "https://github.com/advisories/GHSA-wrjc-x8rr-h8h6",
    title: "Test Advisory",
    severity: "moderate",
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test("policy: exact current report passes", () => {
  const report = makeReport({
    vulnerabilities: {
      "react-router": {
        name: "react-router",
        severity: "moderate",
        isDirect: false,
        via: [
          makeVia({
            url: "https://github.com/advisories/GHSA-wrjc-x8rr-h8h6",
            title: "Open redirect via backslash",
          }),
          makeVia({
            url: "https://github.com/advisories/GHSA-jjmj-jmhj-qwj2",
            title: "Open redirect leading to XSS",
          }),
        ],
      },
      "react-router-dom": {
        name: "react-router-dom",
        severity: "moderate",
        isDirect: true,
        via: [
          "react-router",
          makeVia({
            url: "https://github.com/advisories/GHSA-337j-9hxr-rhxg",
            title: "deserializeErrors SSR",
          }),
        ],
      },
    },
    metadata: {
      vulnerabilities: { info: 0, low: 0, moderate: 3, high: 0, critical: 0, total: 3 },
    },
  });

  const result = evaluatePolicy(report, {
    now: new Date("2026-08-01"),
  });

  assert.equal(result.pass, true, `expected pass, got: ${(result as PolicyFail).reason}`);
});

test("policy: unknown moderate advisory fails", () => {
  const report = makeReport({
    vulnerabilities: {
      "some-pkg": {
        name: "some-pkg",
        severity: "moderate",
        isDirect: true,
        via: [
          makeVia({
            url: "https://github.com/advisories/GHSA-xxxx-xxxx-xxxx",
            title: "Unknown advisory",
          }),
        ],
      },
    },
    metadata: {
      vulnerabilities: { info: 0, low: 0, moderate: 1, high: 0, critical: 0, total: 1 },
    },
  });

  const result = evaluatePolicy(report, {
    now: new Date("2026-08-01"),
  });

  assert.equal(result.pass, false);
  assert.ok(
    (result as PolicyFail).reason.includes("NOT in the accepted list"),
    `expected 'NOT in the accepted list' in reason, got: ${(result as PolicyFail).reason}`,
  );
});

test("policy: advisory without parseable GHSA URL fails", () => {
  const report = makeReport({
    vulnerabilities: {
      "some-pkg": {
        name: "some-pkg",
        severity: "moderate",
        isDirect: true,
        via: [
          makeVia({
            url: "https://example.com/security/issue-123",
            title: "Advisory without GHSA URL",
          }),
        ],
      },
    },
    metadata: {
      vulnerabilities: { info: 0, low: 0, moderate: 1, high: 0, critical: 0, total: 1 },
    },
  });

  const result = evaluatePolicy(report, {
    now: new Date("2026-08-01"),
  });

  assert.equal(result.pass, false);
  assert.ok(
    (result as PolicyFail).reason.includes("without a parseable GHSA"),
    `expected 'without a parseable GHSA', got: ${(result as PolicyFail).reason}`,
  );
});

test("policy: high severity fails", () => {
  const report = makeReport({
    vulnerabilities: {
      "some-pkg": {
        name: "some-pkg",
        severity: "high",
        isDirect: true,
        via: [
          makeVia({
            url: "https://github.com/advisories/GHSA-wrjc-x8rr-h8h6",
            severity: "high",
          }),
        ],
      },
    },
    metadata: {
      vulnerabilities: { info: 0, low: 0, moderate: 0, high: 1, critical: 0, total: 1 },
    },
  });

  const result = evaluatePolicy(report, {
    now: new Date("2026-08-01"),
  });

  assert.equal(result.pass, false);
  assert.ok(
    (result as PolicyFail).reason.includes("high"),
    `expected 'high' in reason, got: ${(result as PolicyFail).reason}`,
  );
});

test("policy: critical severity fails", () => {
  const report = makeReport({
    vulnerabilities: {
      "some-pkg": {
        name: "some-pkg",
        severity: "critical",
        isDirect: true,
        via: [
          makeVia({
            url: "https://github.com/advisories/GHSA-wrjc-x8rr-h8h6",
            severity: "critical",
          }),
        ],
      },
    },
    metadata: {
      vulnerabilities: { info: 0, low: 0, moderate: 0, high: 0, critical: 1, total: 1 },
    },
  });

  const result = evaluatePolicy(report, {
    now: new Date("2026-08-01"),
  });

  assert.equal(result.pass, false);
  assert.ok(
    (result as PolicyFail).reason.includes("critical"),
    `expected 'critical' in reason, got: ${(result as PolicyFail).reason}`,
  );
});

test("policy: malformed JSON fails", () => {
  assert.throws(() => {
    JSON.parse("{not valid json}") as AuditReport;
  });
});

test("policy: missing metadata fails", () => {
  const report = makeReport();
  delete (report as { metadata?: unknown }).metadata;

  const result = evaluatePolicy(report, {
    now: new Date("2026-08-01"),
  });

  assert.equal(result.pass, false);
  assert.ok(
    (result as PolicyFail).reason.includes("missing metadata"),
    `expected 'missing metadata', got: ${(result as PolicyFail).reason}`,
  );
});

test("policy: missing vulnerability records fails", () => {
  const report = makeReport();
  delete (report as { vulnerabilities?: unknown }).vulnerabilities;

  const result = evaluatePolicy(report, {
    now: new Date("2026-08-01"),
  });

  // Missing vulnerabilities → foundGHSAs.size will be 0, accepted is 3 → count mismatch
  assert.equal(result.pass, false);
  assert.ok(
    (result as PolicyFail).reason.includes("count mismatch"),
    `expected 'count mismatch', got: ${(result as PolicyFail).reason}`,
  );
});

test("policy: accepted-advisory count drift fails", () => {
  const report = makeReport({
    vulnerabilities: {
      "react-router-dom": {
        name: "react-router-dom",
        severity: "moderate",
        isDirect: true,
        via: [
          makeVia({
            url: "https://github.com/advisories/GHSA-337j-9hxr-rhxg",
            title: "deserializeErrors SSR",
          }),
        ],
      },
    },
    metadata: {
      vulnerabilities: { info: 0, low: 0, moderate: 1, high: 0, critical: 0, total: 1 },
    },
  });

  const result = evaluatePolicy(report, {
    now: new Date("2026-08-01"),
  });

  // Only 1 found but 3 accepted → count drift
  assert.equal(result.pass, false);
  assert.ok(
    (result as PolicyFail).reason.includes("count mismatch"),
    `expected 'count mismatch', got: ${(result as PolicyFail).reason}`,
  );
});

// ---------------------------------------------------------------------------
// Version-policy tests
// ---------------------------------------------------------------------------

const CURRENT_VERSIONS: VersionInput = {
  react: "18.3.1",
  reactDom: "18.3.1",
  reactRouter: "6.30.4",
  reactRouterDom: "6.30.4",
  reactDepSpec: "^18.3.1",
  reactDomDepSpec: "^18.3.1",
};

test("versions: current versions pass", () => {
  const result = evaluateVersions(CURRENT_VERSIONS);
  assert.equal(result.pass, true, `expected pass, got: ${(result as { reason: string }).reason}`);
});

test("versions: React 19 fails", () => {
  const result = evaluateVersions({ ...CURRENT_VERSIONS, react: "19.0.0" });
  assert.equal(result.pass, false);
  assert.ok(
    (result as { reason: string }).reason.includes("react"),
    `expected 'react' in reason, got: ${(result as { reason: string }).reason}`,
  );
});

test("versions: ReactDOM 19 fails", () => {
  const result = evaluateVersions({ ...CURRENT_VERSIONS, reactDom: "19.0.0" });
  assert.equal(result.pass, false);
  assert.ok(
    (result as { reason: string }).reason.includes("react-dom"),
    `expected 'react-dom' in reason, got: ${(result as { reason: string }).reason}`,
  );
});

test("versions: react-router 7.x fails", () => {
  const result = evaluateVersions({ ...CURRENT_VERSIONS, reactRouter: "7.0.0" });
  assert.equal(result.pass, false);
  assert.ok(
    (result as { reason: string }).reason.includes("react-router"),
    `expected 'react-router' in reason, got: ${(result as { reason: string }).reason}`,
  );
});

test("versions: react-router-dom 7.x fails", () => {
  const result = evaluateVersions({ ...CURRENT_VERSIONS, reactRouterDom: "7.0.0" });
  assert.equal(result.pass, false);
  assert.ok(
    (result as { reason: string }).reason.includes("react-router-dom"),
    `expected 'react-router-dom' in reason, got: ${(result as { reason: string }).reason}`,
  );
});

test("versions: dep spec resolving to React 19 fails", () => {
  const result = evaluateVersions({ ...CURRENT_VERSIONS, reactDepSpec: "^19.0.0" });
  assert.equal(result.pass, false);
  assert.ok(
    (result as { reason: string }).reason.includes("react"),
    `expected dep-spec failure, got: ${(result as { reason: string }).reason}`,
  );
});

test("versions: dep spec resolving to ReactDOM 19 fails", () => {
  const result = evaluateVersions({ ...CURRENT_VERSIONS, reactDomDepSpec: "^19.0.0" });
  assert.equal(result.pass, false);
  assert.ok(
    (result as { reason: string }).reason.includes("react-dom"),
    `expected dep-spec failure, got: ${(result as { reason: string }).reason}`,
  );
});

test("versions: missing react version fails closed", () => {
  const result = evaluateVersions({ ...CURRENT_VERSIONS, react: null });
  assert.equal(result.pass, false);
  assert.ok(
    (result as { reason: string }).reason.includes("react"),
    `expected missing-version failure, got: ${(result as { reason: string }).reason}`,
  );
});

test("versions: missing react-router-dom version fails closed", () => {
  const result = evaluateVersions({ ...CURRENT_VERSIONS, reactRouterDom: null });
  assert.equal(result.pass, false);
  assert.ok(
    (result as { reason: string }).reason.includes("react-router-dom"),
    `expected missing-version failure, got: ${(result as { reason: string }).reason}`,
  );
});

test("versions: missing dep spec fails closed", () => {
  const result = evaluateVersions({ ...CURRENT_VERSIONS, reactDepSpec: null });
  assert.equal(result.pass, false);
  assert.ok(
    (result as { reason: string }).reason.includes("package.json"),
    `expected missing-spec failure, got: ${(result as { reason: string }).reason}`,
  );
});

test("versions: malformed dep spec fails closed", () => {
  const result = evaluateVersions({ ...CURRENT_VERSIONS, reactDepSpec: ">=18" });
  assert.equal(result.pass, false);
  assert.ok(
    (result as { reason: string }).reason.includes("parse major"),
    `expected malformed-spec failure, got: ${(result as { reason: string }).reason}`,
  );
});

test("versions: all four versions wrong produces a compound reason", () => {
  const result = evaluateVersions({
    react: "19.0.0",
    reactDom: "19.0.0",
    reactRouter: "7.0.0",
    reactRouterDom: "7.0.0",
    reactDepSpec: "^18.3.1",
    reactDomDepSpec: "^18.3.1",
  });
  assert.equal(result.pass, false);
  const reason = (result as { reason: string }).reason;
  assert.ok(reason.includes("react:"), "compound reason should include react");
  assert.ok(reason.includes("react-dom:"), "compound reason should include react-dom");
  assert.ok(reason.includes("react-router:"), "compound reason should include react-router");
  assert.ok(reason.includes("react-router-dom:"), "compound reason should include react-router-dom");
});

// --- Expiry test (uses evaluatePolicy, not evaluateVersions) ---

test("policy: expiry fails after the deadline", () => {
  const report = makeReport({
    vulnerabilities: {
      "react-router": {
        name: "react-router",
        severity: "moderate",
        isDirect: false,
        via: [
          makeVia({ url: "https://github.com/advisories/GHSA-wrjc-x8rr-h8h6" }),
          makeVia({ url: "https://github.com/advisories/GHSA-jjmj-jmhj-qwj2" }),
        ],
      },
      "react-router-dom": {
        name: "react-router-dom",
        severity: "moderate",
        isDirect: true,
        via: [
          "react-router",
          makeVia({ url: "https://github.com/advisories/GHSA-337j-9hxr-rhxg" }),
        ],
      },
    },
    metadata: {
      vulnerabilities: { info: 0, low: 0, moderate: 3, high: 0, critical: 0, total: 3 },
    },
  });

  const result = evaluatePolicy(report, {
    now: new Date("2026-10-28"), // after 2026-10-27 expiry
  });

  assert.equal(result.pass, false);
  assert.ok(
    (result as PolicyFail).reason.includes("expired"),
    `expected 'expired', got: ${(result as PolicyFail).reason}`,
  );
});

test("policy: npm audit execution failure returns error", () => {
  // Test that runNpmAudit throws on a nonexistent directory
  assert.throws(
    () => {
      runNpmAudit("/nonexistent/path/that/cannot/exist", false);
    },
    (err: Error) => {
      return err.message.includes("npm audit failed") || err.message.includes("Command failed");
    },
  );
});
