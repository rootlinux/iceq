import { useState } from "react";

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

export function SafetyQr({ fingerprint }: { fingerprint: string }): JSX.Element {
  const [comparison, setComparison] = useState<"idle" | "match" | "mismatch" | "invalid">("idle");
  const payload = createSafetyQrPayload(fingerprint);
  return (
    <div className="iceq-settings-status">
      <strong>Safety QR payload</strong>
      <textarea readOnly aria-label="Your safety QR payload" value={payload} rows={3} />
      <label>
        Compare contact QR payload
        <textarea aria-label="Contact safety QR payload" rows={3} onChange={(event) => {
          try {
            const scanned = parseSafetyQrPayload(event.target.value);
            setComparison(scanned.fingerprint === fingerprint.replace(/\s/g, "").toUpperCase() ? "match" : "mismatch");
          } catch { setComparison(event.target.value ? "invalid" : "idle"); }
        }} />
      </label>
      {comparison !== "idle" && <div role="status">{comparison === "match" ? "Fingerprints match" : comparison === "mismatch" ? "Fingerprint mismatch — do not send" : "Invalid safety payload"}</div>}
    </div>
  );
}
