export interface SafetyIdentity {
  uin: number;
  identityKey: string;
}

const SAFETY_VERSION = "iceq-safety-number-v1";
const RAW_X25519_PUBLIC_KEY_LENGTH = 32;

export async function computeSafetyNumber(a: SafetyIdentity, b: SafetyIdentity): Promise<string> {
  validateSafetyIdentity(a);
  validateSafetyIdentity(b);

  const ordered = [a, b].sort((x, y) => {
    if (x.uin !== y.uin) return x.uin - y.uin;
    return x.identityKey.localeCompare(y.identityKey);
  }) as [SafetyIdentity, SafetyIdentity];
  const [left, right] = ordered;
  const input = `${SAFETY_VERSION}\n${left.uin}:${left.identityKey}\n${right.uin}:${right.identityKey}`;
  const digest = new Uint8Array(await globalThis.crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(input),
  ));

  const groups: string[] = [];
  for (let i = 0; i < 12; i++) {
    const offset = (i * 4) % digest.length;
    const value = (
      ((digest[offset] ?? 0) << 24)
      | ((digest[(offset + 1) % digest.length] ?? 0) << 16)
      | ((digest[(offset + 2) % digest.length] ?? 0) << 8)
      | (digest[(offset + 3) % digest.length] ?? 0)
    ) >>> 0;
    groups.push(String(value % 100000).padStart(5, "0"));
  }
  return groups.join(" ");
}

function validateSafetyIdentity(identity: SafetyIdentity): void {
  if (!Number.isSafeInteger(identity.uin) || identity.uin <= 0) {
    throw new Error("uin must be a positive safe integer");
  }
  if (b64UrlByteLength(identity.identityKey) !== RAW_X25519_PUBLIC_KEY_LENGTH) {
    throw new Error("identityKey must be a base64url-encoded 32-byte X25519 public key");
  }
}

function b64UrlToArrayBuffer(s: string): ArrayBuffer {
  const pad = "=".repeat((4 - (s.length % 4)) % 4);
  const b = atob(s.replace(/-/g, "+").replace(/_/g, "/") + pad);
  const out = new Uint8Array(b.length);
  for (let i = 0; i < b.length; i++) out[i] = b.charCodeAt(i);
  return out.buffer;
}

function b64UrlByteLength(s: string): number {
  if (!/^[A-Za-z0-9_-]+$/.test(s)) return -1;
  try {
    return b64UrlToArrayBuffer(s).byteLength;
  } catch {
    return -1;
  }
}
