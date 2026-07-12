import test from "node:test";
import assert from "node:assert/strict";

import { isIOSSafariInstallHintEligible } from "../src/components/PWA/IOSInstallHint.js";

test("detects iPadOS Safari in desktop mode for the install hint", () => {
  assert.equal(
    isIOSSafariInstallHintEligible({
      userAgent:
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
      platform: "MacIntel",
      maxTouchPoints: 5,
    }),
    true,
  );
});

test("rejects iOS Chrome for the install hint", () => {
  assert.equal(
    isIOSSafariInstallHintEligible({
      userAgent:
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/125.0.6422.73 Mobile/15E148 Safari/604.1",
      platform: "iPhone",
      maxTouchPoints: 5,
    }),
    false,
  );
});
