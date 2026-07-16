import { useEffect, useState } from "react";
import QRCode from "qrcode";
import jsQR from "jsqr";

export interface SafetyQrPayload { version: 1; fingerprint: string }

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

export function SafetyQr({ fingerprint }: { fingerprint: string }): JSX.Element {
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
    const bitmap = await createImageBitmap(file);
    try {
      const canvas = document.createElement("canvas");
      canvas.width = bitmap.width; canvas.height = bitmap.height;
      const context = canvas.getContext("2d", { willReadFrequently: true });
      if (!context) throw new Error("Image decoding is unavailable");
      context.drawImage(bitmap, 0, 0);
      const pixels = context.getImageData(0, 0, bitmap.width, bitmap.height);
      compare(decodeSafetyQrPixels(pixels.data, pixels.width, pixels.height));
    } catch { setComparison("invalid"); } finally { bitmap.close(); }
  };
  return (
    <div className="iceq-settings-status">
      <strong>Safety QR</strong>
      {svg && <div aria-label="Your scannable safety QR code" role="img" dangerouslySetInnerHTML={{ __html: svg }} />}
      <details><summary>Accessible text payload</summary><textarea readOnly aria-label="Your safety QR payload" value={payload} rows={3} /></details>
      <label>Scan from image<input aria-label="Contact safety QR image" type="file" accept="image/*" onChange={(event) => { const file = event.currentTarget.files?.[0]; if (file) void decodeImage(file); }} /></label>
      <label>
        Or compare accessible text payload
        <textarea aria-label="Contact safety QR payload" rows={3} onChange={(event) => {
          compare(event.target.value);
        }} />
      </label>
      {comparison !== "idle" && <div role="status">{comparison === "match" ? "Fingerprints match" : comparison === "mismatch" ? "Fingerprint mismatch — do not send" : "Invalid safety payload"}</div>}
    </div>
  );
}
