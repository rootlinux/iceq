import test from "node:test";
import assert from "node:assert/strict";

import {
  createSafetyQrPayload,
  decodeSafetyQrPixels,
  createSafetyQrPixels,
  renderSafetyQrSvg,
  assertQrUploadBounds,
} from "../src/components/Settings/SafetyQr.tsx";

test("renders a locally generated scannable QR and decodes its pixels locally", async () => {
  const payload = createSafetyQrPayload("12345 67890 54321 09876");
  const svg = await renderSafetyQrSvg(payload);
  assert.match(svg, /^<svg/);
  assert.doesNotMatch(svg, /(?:href|src)="https?:\/\//);

  const matrix = createSafetyQrPixels(payload);
  assert.equal(decodeSafetyQrPixels(matrix.data, matrix.width, matrix.height), payload);
});

test("rejects oversized QR uploads and decoded pixel bombs before canvas allocation", () => {
  assert.throws(() => assertQrUploadBounds(2_000_001, 100, 100), /too large/i);
  assert.throws(() => assertQrUploadBounds(1_000, 5000, 100), /dimensions/i);
  assert.throws(() => assertQrUploadBounds(1_000, 3000, 3000), /pixels/i);
  assert.doesNotThrow(() => assertQrUploadBounds(1_000, 1024, 1024));
});
