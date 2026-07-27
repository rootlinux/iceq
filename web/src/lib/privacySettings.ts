export interface PrivacySettings {
  presence: boolean;
  typing: boolean;
  deliveryReceipts: boolean;
  readReceipts: boolean;
}
export type PrivacySignal = keyof PrivacySettings;
export const defaultPrivacySettings: PrivacySettings = {
  presence: false,
  typing: false,
  deliveryReceipts: true,
  readReceipts: false,
};
const KEY = "iceq_privacy_settings";
const EXPIRY_KEY = "iceq_disappearing_seconds";
export function loadPrivacySettings(): PrivacySettings {
  try { return { ...defaultPrivacySettings, ...JSON.parse(localStorage.getItem(KEY) ?? "{}") as Partial<PrivacySettings> }; }
  catch { return { ...defaultPrivacySettings }; }
}
export function savePrivacySettings(value: PrivacySettings): void {
  localStorage.setItem(KEY, JSON.stringify(value));
  globalThis.dispatchEvent?.(new CustomEvent("iceq:privacy-changed"));
}
export function permitsPrivacySignal(signal: PrivacySignal, value = loadPrivacySettings()): boolean { return value[signal]; }
export function shouldProcessPrivacyEnvelope(type: string, state?: string, value = loadPrivacySettings()): boolean {
  if (type === "presence") return value.presence;
  if (type === "typing") return value.typing;
  if (type === "read") return value.readReceipts;
  if (type === "ack" && state === "delivered") return value.deliveryReceipts;
  if (type === "ack" && state === "read") return value.readReceipts;
  return true;
}
// IceQ does not offer indefinite server-side message retention: the server
// always enforces a bounded TTL (see backend/message-service/store), and the
// client only chooses how short that window is. DEFAULT_DISAPPEARING_SECONDS
// must match the server's defaultMessageTTL so the UI reflects reality even
// before the user picks a shorter option.
export const DEFAULT_DISAPPEARING_SECONDS = 86400; // 1 day
export const ALLOWED_DISAPPEARING_SECONDS = [3600, 86400, 259200, 604800]; // 1h, 1d, 3d, 7d (server max)

export function loadDisappearingSeconds(): number {
  const n = Number(localStorage.getItem(EXPIRY_KEY) ?? DEFAULT_DISAPPEARING_SECONDS);
  return ALLOWED_DISAPPEARING_SECONDS.includes(n) ? n : DEFAULT_DISAPPEARING_SECONDS;
}
export function saveDisappearingSeconds(seconds: number): void {
  if (!ALLOWED_DISAPPEARING_SECONDS.includes(seconds)) throw new Error("unsupported disappearing duration");
  localStorage.setItem(EXPIRY_KEY, String(seconds));
}
