import test from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";

import { computeSafetyNumber } from "../src/lib/safetyFingerprint.ts";

Object.defineProperty(globalThis, "crypto", {
  value: webcrypto,
  configurable: true,
});

const aliceIdentity = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const bobIdentity = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";

test("computeSafetyNumber is stable and independent of caller ordering", async () => {
  const fromAlice = await computeSafetyNumber(
    { uin: 7, identityKey: aliceIdentity },
    { uin: 42, identityKey: bobIdentity },
  );
  const fromBob = await computeSafetyNumber(
    { uin: 42, identityKey: bobIdentity },
    { uin: 7, identityKey: aliceIdentity },
  );

  assert.equal(fromAlice, fromBob);
  assert.match(fromAlice, /^\d{5}( \d{5}){11}$/);
});

test("computeSafetyNumber changes when an identity key changes", async () => {
  const first = await computeSafetyNumber(
    { uin: 7, identityKey: aliceIdentity },
    { uin: 42, identityKey: bobIdentity },
  );
  const second = await computeSafetyNumber(
    { uin: 7, identityKey: aliceIdentity },
    { uin: 42, identityKey: "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI" },
  );

  assert.notEqual(first, second);
});
