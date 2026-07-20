// Android Chrome "Add to Home Screen" install banner.
// Uses the beforeinstallprompt API — only fires on Android Chrome
// when PWA criteria are met and the app isn't already installed.

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

  const handleInstall = (): void => {
    void handleInstallPrompt(() => installPromptLifecycle.prompt());
  };

  const handleDismiss = (): void => {
    installPromptLifecycle.dismiss();
  };

  return (
    <div
      style={{
        position: "fixed",
        bottom: 0,
        left: 0,
        right: 0,
        zIndex: 9999,
        background: "#141414",
        borderTop: "1px solid #2a2a2a",
        display: "flex",
        alignItems: "center",
        padding: "10px 16px",
        gap: "12px",
      }}
    >
      <img
        src="/icons/icon-192.png"
        alt="IceQ"
        style={{ width: 24, height: 24, borderRadius: 4, flexShrink: 0 }}
      />
      <span style={{ flex: 1, fontSize: 14, color: "#e5e5e5" }}>
        {i18n.t("pwa.addHome")}
      </span>
      <button
        onClick={handleInstall}
        style={{
          background: "#00b4d8",
          color: "#0a0a0a",
          border: "none",
          borderRadius: 6,
          padding: "6px 14px",
          fontWeight: 600,
          fontSize: 13,
          cursor: "pointer",
        }}
      >
        {i18n.t("pwa.install")}
      </button>
      <button
        onClick={handleDismiss}
        aria-label={i18n.t("pwa.dismiss")}
        style={{
          background: "none",
          border: "none",
          color: "#888",
          fontSize: 18,
          cursor: "pointer",
          padding: "0 4px",
        }}
      >
        ×
      </button>
    </div>
  );
}
