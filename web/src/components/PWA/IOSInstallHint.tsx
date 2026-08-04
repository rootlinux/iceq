// src/components/PWA/IOSInstallHint.tsx
//
// iOS Safari install hint (bottom sheet) — Arctic Signal design.

import { useCallback, useEffect, useRef, useState } from "react";
import { useI18n } from "../../i18n";
import { useDialogFocus } from "../../hooks/useDialogFocus";

const HINT_KEY = "iceq_ios_hint_shown";

interface InstallHintNavigator {
  userAgent: string;
  platform?: string;
  maxTouchPoints?: number;
}

export function isIOSSafariInstallHintEligible(navigatorLike: InstallHintNavigator): boolean {
  const userAgent = navigatorLike.userAgent;
  const platform = navigatorLike.platform ?? "";
  const maxTouchPoints = navigatorLike.maxTouchPoints ?? 0;
  const isIOSDevice =
    /iPad|iPhone|iPod/.test(userAgent) ||
    (platform === "MacIntel" && maxTouchPoints > 1);
  if (!isIOSDevice) return false;
  return /Safari/i.test(userAgent) && !/(CriOS|FxiOS|EdgiOS|OPiOS|OPT\/)/i.test(userAgent);
}

function isIOS(): boolean {
  return isIOSSafariInstallHintEligible(navigator);
}

function isStandalone(): boolean {
  return Boolean((navigator as { standalone?: boolean }).standalone);
}

interface IOSInstallHintProps {
  visible: boolean;
}

export function IOSInstallHint({ visible }: IOSInstallHintProps): JSX.Element | null {
  const i18n = useI18n();
  const [show, setShow] = useState(false);
  const returnFocusRef = useRef<HTMLElement | null>(null);
  const dismissButtonRef = useRef<HTMLButtonElement>(null);

  const handleGotIt = useCallback((): void => {
    localStorage.setItem(HINT_KEY, "1");
    setShow(false);
  }, []);

  const dialogRef = useDialogFocus(show, handleGotIt, returnFocusRef, dismissButtonRef);

  useEffect(() => {
    if (visible && isIOS() && !isStandalone() && !localStorage.getItem(HINT_KEY)) {
      returnFocusRef.current = document.activeElement as HTMLElement | null;
      setShow(true);
    }
  }, [visible]);

  if (!show) return null;

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="ios-install-hint-title"
      className="fixed inset-0 z-[10000] flex items-end justify-center"
      style={{ background: "rgba(8, 13, 24, 0.75)", backdropFilter: "blur(4px)" }}
      onClick={handleGotIt}
    >
      <div
        ref={dialogRef}
        className="w-full max-w-modal-sm rounded-t-2xl border-t border-ice-border bg-cobalt px-5 pb-9 pt-6"
        onClick={(e) => e.stopPropagation()}
      >
        <h2
          id="ios-install-hint-title"
          className="text-lg font-semibold text-frozen"
        >
          {i18n.t("pwa.installIceq")}
        </h2>
        <p className="mt-3 text-sm leading-relaxed text-mist">
          {i18n.t("pwa.iosHelp")}
        </p>
        <button
          ref={dismissButtonRef}
          type="button"
          className="iceq-btn-primary mt-5 w-full"
          onClick={handleGotIt}
        >
          {i18n.t("pwa.gotIt")}
        </button>
      </div>
    </div>
  );
}
