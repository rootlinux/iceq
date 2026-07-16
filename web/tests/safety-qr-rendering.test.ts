import test from "node:test";
import assert from "node:assert/strict";

import {
  createSafetyQrPayload,
  decodeSafetyQrPixels,
  createSafetyQrPixels,
  renderSafetyQrSvg,
  assertQrUploadBounds,
  decodeValidatedQrBitmap,
} from "../src/components/Settings/SafetyQr.tsx";

test("renders a locally generated scannable QR and decodes its pixels locally", async () => {
  const payload = createSafetyQrPayload("12345 67890 54321 09876");
  const svg = await renderSafetyQrSvg(payload);
  assert.match(svg, /^<svg/);
  assert.doesNotMatch(svg, /(?:href|src)="https?:\/\//);

  const matrix = createSafetyQrPixels(payload);
  assert.equal(decodeSafetyQrPixels(matrix.data, matrix.width, matrix.height), payload);
});

test("rejects a tiny PNG declaring bomb dimensions before image decoding", async () => {
  const png = new Uint8Array(24);
  png.set([137, 80, 78, 71, 13, 10, 26, 10]);
  png.set([0, 0, 0, 13, 73, 72, 68, 82], 8);
  new DataView(png.buffer).setUint32(16, 5000); new DataView(png.buffer).setUint32(20, 100);
  let decoderCalled = false;
  await assert.rejects(
    () => decodeValidatedQrBitmap(new Blob([png], { type: "image/png" }), async () => { decoderCalled = true; throw new Error("must not run"); }),
    /dimensions/i,
  );
  assert.equal(decoderCalled, false);
});

test("rejects SVG and malformed image headers before decoding", async () => {
  let decoderCalled = false;
  for (const blob of [new Blob(["<svg/>"] , { type: "image/svg+xml" }), new Blob(["not-png"], { type: "image/png" })]) {
    await assert.rejects(() => decodeValidatedQrBitmap(blob, async () => { decoderCalled = true; throw new Error("must not run"); }), /unsupported|malformed/i);
  }
  assert.equal(decoderCalled, false);
});

test("rejects oversized QR uploads and decoded pixel bombs before canvas allocation", () => {
  assert.throws(() => assertQrUploadBounds(2_000_001, 100, 100), /too large/i);
  assert.throws(() => assertQrUploadBounds(1_000, 5000, 100), /dimensions/i);
  assert.throws(() => assertQrUploadBounds(1_000, 3000, 3000), /pixels/i);
  assert.doesNotThrow(() => assertQrUploadBounds(1_000, 1024, 1024));
});
