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
export function savePrivacySettings(value: PrivacySettings): void { localStorage.setItem(KEY, JSON.stringify(value)); }
export function permitsPrivacySignal(signal: PrivacySignal, value = loadPrivacySettings()): boolean { return value[signal]; }
export function loadDisappearingSeconds(): number {
  const n = Number(localStorage.getItem(EXPIRY_KEY) ?? 0);
  return [0, 3600, 86400, 604800, 2592000].includes(n) ? n : 0;
}
export function saveDisappearingSeconds(seconds: number): void {
  if (![0, 3600, 86400, 604800, 2592000].includes(seconds)) throw new Error("unsupported disappearing duration");
  localStorage.setItem(EXPIRY_KEY, String(seconds));
}
