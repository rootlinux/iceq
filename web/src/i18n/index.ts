import { useSyncExternalStore } from "react";
import { en, type MessageKey } from "./en";
import { tr } from "./tr";

export type Locale = "en" | "tr";
type StorageLike = Pick<Storage, "getItem" | "setItem">;
const catalogs: Record<Locale, Record<MessageKey, string>> = { en, tr };
export const localeStorageKey = "iceq.locale";

export function resolveLocale(stored: string | null, browserLanguages: readonly string[]): Locale {
  if (stored === "en" || stored === "tr") return stored;
  const browserLocale = browserLanguages.find((value) => /^(en|tr)(-|$)/i.test(value));
  return browserLocale?.toLowerCase().startsWith("tr") ? "tr" : "en";
}

export function createI18n(options: { storage?: StorageLike; browserLanguages?: readonly string[] } = {}) {
  const storage = options.storage;
  let storedLocale: string | null = null;
  try { storedLocale = storage?.getItem(localeStorageKey) ?? null; } catch { /* restricted storage: use browser locale */ }
  let locale = resolveLocale(storedLocale, options.browserLanguages ?? []);
  const listeners = new Set<() => void>();
  return {
    get locale(): Locale { return locale; },
    t(key: MessageKey, values: Record<string, string | number> = {}): string {
      return (catalogs[locale][key] ?? en[key]).replace(/\{(\w+)\}/g, (token, name: string) => values[name] === undefined ? token : String(values[name]));
    },
    setLocale(next: Locale): void {
      if (next === locale) return;
      locale = next;
      try { storage?.setItem(localeStorageKey, next); } catch { /* best-effort persistence */ }
      if (typeof document !== "undefined") document.documentElement.lang = next;
      listeners.forEach((listener) => listener());
    },
    subscribe(listener: () => void): () => void { listeners.add(listener); return () => listeners.delete(listener); },
    snapshot(): Locale { return locale; },
  };
}

const runtime = createI18n({
  storage: typeof localStorage === "undefined" ? undefined : localStorage,
  browserLanguages: typeof navigator === "undefined" ? [] : navigator.languages,
});
if (typeof document !== "undefined") document.documentElement.lang = runtime.locale;

export function useI18n() {
  useSyncExternalStore(runtime.subscribe, runtime.snapshot, runtime.snapshot);
  return runtime;
}

export const t = (key: MessageKey): string => runtime.t(key);
