// src/components/Settings/SafetyQr.tsx
//
// Safety QR code component — Arctic Signal design.
// QR generation, accessible payload, scan/compare.

import { useEffect, useState } from "react";
import QRCode from "qrcode";
import jsQR from "jsqr";
import { useI18n } from "../../i18n";

export interface SafetyQrPayload { version: 1; fingerprint: string }

const MAX_QR_UPLOAD_BYTES = 2_000_000;
const MAX_QR_DIMENSION = 4096;
const MAX_QR_PIXELS = 4_194_304;
const MAX_QR_CANVAS_DIMENSION = 1024;

export function createSafetyQrPayload(fingerprint: string): string {
  const canonical = fingerprint.replace(/\s/g, "").toUpperCase();
  if (!/^[A-Z0-9]{10,120}$/.test(canonical)) throw new Error("invalid safety fingerprint");
  return JSON.stringify({ version: 1, fingerprint: canonical } satisfies SafetyQrPayload);
}

export function parseSafetyQrPayload(raw: string): SafetyQrPayload {
  const value = JSON.parse(raw) as Record<string, unknown>;
  if (!value || Object.keys(value).sort().join(",") !== "fingerprint,version"
      || value.version !== 1 || typeof value.fingerprint !== "string"
      || !/^[A-Z0-9]{10,120}$/.test(value.fingerprint)) {
    throw new Error("invalid safety QR payload");
  }
  return { version: 1, fingerprint: value.fingerprint };
}

export async function renderSafetyQrSvg(payload: string): Promise<string> {
  parseSafetyQrPayload(payload);
  return QRCode.toString(payload, { type: "svg", errorCorrectionLevel: "M", margin: 4, color: { dark: "#000000", light: "#ffffff" } });
}

export function decodeSafetyQrPixels(data: Uint8ClampedArray, width: number, height: number): string {
  const decoded = jsQR(data, width, height, { inversionAttempts: "dontInvert" });
  if (!decoded) throw new Error("No QR code found in image");
  parseSafetyQrPayload(decoded.data);
  return decoded.data;
}

export function createSafetyQrPixels(payload: string): { data: Uint8ClampedArray; width: number; height: number } {
  parseSafetyQrPayload(payload);
  const qr = QRCode.create(payload, { errorCorrectionLevel: "M" });
  const quiet = 4; const scale = 8; const modules = qr.modules.size;
  const width = (modules + quiet * 2) * scale;
  const data = new Uint8ClampedArray(width * width * 4).fill(255);
  for (let y = 0; y < modules; y++) for (let x = 0; x < modules; x++) {
    if (!qr.modules.get(x, y)) continue;
    for (let yy = (y + quiet) * scale; yy < (y + quiet + 1) * scale; yy++) for (let xx = (x + quiet) * scale; xx < (x + quiet + 1) * scale; xx++) {
      const offset = (yy * width + xx) * 4;
      data[offset] = data[offset + 1] = data[offset + 2] = 0; data[offset + 3] = 255;
    }
  }
  return { data, width, height: width };
}

export function assertQrUploadBounds(bytes: number, width: number, height: number): void {
  if (!Number.isSafeInteger(bytes) || bytes < 0 || bytes > MAX_QR_UPLOAD_BYTES) throw new Error("QR image is too large");
  if (!Number.isSafeInteger(width) || !Number.isSafeInteger(height) || width < 1 || height < 1
      || width > MAX_QR_DIMENSION || height > MAX_QR_DIMENSION) throw new Error("QR image dimensions are invalid");
  if (width * height > MAX_QR_PIXELS) throw new Error("QR image has too many pixels");
}

export async function decodeValidatedQrBitmap(
  file: Blob,
  decoder: (blob: Blob) => Promise<ImageBitmap> = (blob) => createImageBitmap(blob),
): Promise<ImageBitmap> {
  assertQrUploadBounds(file.size, 1, 1);
  const header = new Uint8Array(await file.arrayBuffer());
  const dimensions = parseSupportedImageDimensions(header);
  assertQrUploadBounds(file.size, dimensions.width, dimensions.height);
  return decoder(file);
}

function parseSupportedImageDimensions(bytes: Uint8Array): { width: number; height: number } {
  const png = [137, 80, 78, 71, 13, 10, 26, 10];
  if (png.every((value, index) => bytes[index] === value)) {
    if (bytes.length < 24 || String.fromCharCode(...bytes.slice(12, 16)) !== "IHDR") throw new Error("malformed PNG header");
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    return { width: view.getUint32(16), height: view.getUint32(20) };
  }
  if (bytes[0] === 0xff && bytes[1] === 0xd8) {
    let offset = 2;
    const sof = new Set([0xc0, 0xc1, 0xc2, 0xc3, 0xc5, 0xc6, 0xc7, 0xc9, 0xca, 0xcb, 0xcd, 0xce, 0xcf]);
    while (offset + 4 <= bytes.length) {
      if (bytes[offset] !== 0xff) throw new Error("malformed JPEG header");
      while (bytes[offset] === 0xff) offset++;
      const marker = bytes[offset++]!;
      if (marker === 0xd9 || marker === 0xda) break;
      if (offset + 2 > bytes.length) break;
      const length = (bytes[offset]! << 8) | bytes[offset + 1]!;
      if (length < 2 || offset + length > bytes.length) throw new Error("malformed JPEG header");
      if (sof.has(marker)) {
        if (length < 7) throw new Error("malformed JPEG dimensions");
        return { height: (bytes[offset + 3]! << 8) | bytes[offset + 4]!, width: (bytes[offset + 5]! << 8) | bytes[offset + 6]! };
      }
      offset += length;
    }
    throw new Error("malformed JPEG header");
  }
  throw new Error("unsupported QR image format; use PNG or JPEG");
}

export function SafetyQr({ fingerprint }: { fingerprint: string }): JSX.Element {
  const i18n = useI18n();
  const [comparison, setComparison] = useState<"idle" | "match" | "mismatch" | "invalid">("idle");
  const [svg, setSvg] = useState("");

  const payload = createSafetyQrPayload(fingerprint);

  useEffect(() => {
    let active = true;
    void renderSafetyQrSvg(payload).then((value) => { if (active) setSvg(value); });
    return () => { active = false; };
  }, [payload]);

  const compare = (raw: string): void => {
    try {
      const scanned = parseSafetyQrPayload(raw);
      setComparison(scanned.fingerprint === fingerprint.replace(/\s/g, "").toUpperCase() ? "match" : "mismatch");
    } catch { setComparison(raw ? "invalid" : "idle"); }
  };

  const decodeImage = async (file: File): Promise<void> => {
    let bitmap: ImageBitmap | null = null;
    try {
      bitmap = await decodeValidatedQrBitmap(file);
      const ratio = Math.min(1, MAX_QR_CANVAS_DIMENSION / Math.max(bitmap.width, bitmap.height));
      const canvas = document.createElement("canvas");
      canvas.width = Math.max(1, Math.round(bitmap.width * ratio));
      canvas.height = Math.max(1, Math.round(bitmap.height * ratio));
      const context = canvas.getContext("2d", { willReadFrequently: true });
      if (!context) throw new Error("Image decoding is unavailable");
      context.drawImage(bitmap, 0, 0, canvas.width, canvas.height);
      const pixels = context.getImageData(0, 0, canvas.width, canvas.height);
      compare(decodeSafetyQrPixels(pixels.data, pixels.width, pixels.height));
    } catch { setComparison("invalid"); } finally { bitmap?.close(); }
  };

  return (
    <div className="space-y-3">
      <h4 className="text-sm font-semibold text-frozen">{i18n.t("safety.title")}</h4>

      {svg && (
        <img
          aria-label={i18n.t("safety.yourQr")}
          src={`data:image/svg+xml,${encodeURIComponent(svg)}`}
          alt="Safety QR"
          className="rounded-md border border-ice-border"
        />
      )}

      <details className="text-xs">
        <summary className="cursor-pointer text-mist hover:text-frozen transition-colors">
          {i18n.t("safety.accessiblePayload")}
        </summary>
        <textarea
          readOnly
          aria-label={i18n.t("safety.yourPayload")}
          className="iceq-input mt-1.5 text-mono text-xs"
          value={payload}
          rows={2}
        />
      </details>

      <div>
        <label className="text-xs text-mist">
          {i18n.t("safety.scanImage")}
          <input
            aria-label={i18n.t("safety.contactImage")}
            type="file"
            accept="image/*"
            className="iceq-input mt-1 text-xs"
            onChange={(event) => {
              const file = event.currentTarget.files?.[0];
              if (file) void decodeImage(file);
            }}
          />
        </label>
      </div>

      <div>
        <label className="text-xs text-mist">
          {i18n.t("safety.comparePayload")}
          <textarea
            aria-label={i18n.t("safety.contactPayload")}
            className="iceq-input mt-1 text-mono text-xs"
            rows={2}
            onChange={(event) => compare(event.target.value)}
          />
        </label>
      </div>

      {comparison !== "idle" && (
        <div role="status" className={
          comparison === "match" ? "iceq-alert-success text-xs" :
          comparison === "mismatch" ? "iceq-alert-error text-xs" :
          "iceq-alert-warning text-xs"
        }>
          {comparison === "match"
            ? i18n.t("safety.match")
            : comparison === "mismatch"
              ? i18n.t("safety.mismatch")
              : i18n.t("safety.invalid")}
        </div>
      )}
    </div>
  );
}
