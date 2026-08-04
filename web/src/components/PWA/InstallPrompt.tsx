// src/components/PWA/InstallPrompt.tsx
//
// Android Chrome "Add to Home Screen" banner — Arctic Signal design.

import { useEffect, useState } from "react";
import { useI18n } from "../../i18n";
import { installPromptLifecycle, type BeforeInstallPromptEvent } from "../../lib/installPromptLifecycle";

export async function handleInstallPrompt(
  prompt: () => Promise<unknown>,
  report: (message: string) => void = (message) => console.warn(message),
): Promise<void> {
  try {
    await prompt();
  } catch {
    report("PWA install prompt failed");
  }
}

export function InstallPrompt(): JSX.Element | null {
  const i18n = useI18n();
  const [deferredPrompt, setDeferredPrompt] =
    useState<BeforeInstallPromptEvent | null>(() => installPromptLifecycle.current());

  useEffect(() => {
    return installPromptLifecycle.subscribe(setDeferredPrompt);
  }, []);

  if (!deferredPrompt) return null;

  return (
    <div className="fixed inset-x-0 bottom-0 z-[9999] flex items-center gap-3 border-t border-ice-border bg-cobalt px-4 py-2.5">
      <img
        src="/icons/icon-192.png"
        alt="IceQ"
        className="h-6 w-6 shrink-0 rounded-sm"
      />
      <span className="flex-1 text-sm text-frozen">
        {i18n.t("pwa.addHome")}
      </span>
      <button
        type="button"
        className="iceq-btn-primary text-xs"
        onClick={() => { void installPromptLifecycle.prompt(); }}
      >
        {i18n.t("pwa.install")}
      </button>
      <button
        type="button"
        className="iceq-btn-icon"
        aria-label={i18n.t("pwa.dismiss")}
        onClick={() => installPromptLifecycle.dismiss()}
      >
        <svg width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round">
          <line x1="4" y1="4" x2="12" y2="12"/><line x1="12" y1="4" x2="4" y2="12"/>
        </svg>
      </button>
    </div>
  );
}
