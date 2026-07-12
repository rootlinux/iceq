// Android Chrome "Add to Home Screen" install banner.
// Uses the beforeinstallprompt API — only fires on Android Chrome
// when PWA criteria are met and the app isn't already installed.

import { useEffect, useState } from "react";

const DISMISS_KEY = "iceq_install_dismissed";
const DISMISS_TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7 days

interface BeforeInstallPromptEvent extends Event {
  prompt: () => Promise<void>;
  userChoice: Promise<{ outcome: "accepted" | "dismissed" }>;
}

function isDismissed(): boolean {
  const ts = localStorage.getItem(DISMISS_KEY);
  if (!ts) return false;
  return Date.now() - Number(ts) < DISMISS_TTL_MS;
}

export function InstallPrompt(): JSX.Element | null {
  const [deferredPrompt, setDeferredPrompt] =
    useState<BeforeInstallPromptEvent | null>(null);

  useEffect(() => {
    const handler = (e: Event): void => {
      e.preventDefault();
      if (!isDismissed()) {
        setDeferredPrompt(e as BeforeInstallPromptEvent);
      }
    };
    window.addEventListener("beforeinstallprompt", handler);
    return () => window.removeEventListener("beforeinstallprompt", handler);
  }, []);

  if (!deferredPrompt) return null;

  const handleInstall = async (): Promise<void> => {
    await deferredPrompt.prompt();
    await deferredPrompt.userChoice;
    setDeferredPrompt(null);
  };

  const handleDismiss = (): void => {
    localStorage.setItem(DISMISS_KEY, String(Date.now()));
    setDeferredPrompt(null);
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
        Add IceQ to your home screen
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
        Install
      </button>
      <button
        onClick={handleDismiss}
        aria-label="Dismiss"
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
