import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

test("protobuf parser used by the security boundary is an exact direct dependency", () => {
  const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
  assert.equal(pkg.dependencies["@privacyresearch/libsignal-protocol-protobuf-ts"], "0.0.9");
});
