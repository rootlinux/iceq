import test from "node:test";
import assert from "node:assert/strict";

import {
  createSafetyQrPayload,
  decodeSafetyQrPixels,
  createSafetyQrPixels,
  renderSafetyQrSvg,
} from "../src/components/Settings/SafetyQr.tsx";

test("renders a locally generated scannable QR and decodes its pixels locally", async () => {
  const payload = createSafetyQrPayload("12345 67890 54321 09876");
  const svg = await renderSafetyQrSvg(payload);
  assert.match(svg, /^<svg/);
  assert.doesNotMatch(svg, /(?:href|src)="https?:\/\//);

  const matrix = createSafetyQrPixels(payload);
  assert.equal(decodeSafetyQrPixels(matrix.data, matrix.width, matrix.height), payload);
});
