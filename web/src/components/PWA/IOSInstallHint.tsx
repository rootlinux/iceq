// iOS Safari install hint — shown once after first login on
// iOS devices that haven't installed the PWA.
// iOS Safari doesn't support beforeinstallprompt, so we show
// manual instructions instead.

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

  if (!isIOSDevice) {
    return false;
  }

  return /Safari/i.test(userAgent) && !/(CriOS|FxiOS|EdgiOS|OPiOS|OPT\/)/i.test(userAgent);
}

function isIOS(): boolean {
  return isIOSSafariInstallHintEligible(navigator);
}

function isStandalone(): boolean {
  return Boolean((navigator as { standalone?: boolean }).standalone);
}

interface IOSInstallHintProps {
  /** Pass true once the user has successfully logged in */
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
    if (
      visible &&
      isIOS() &&
      !isStandalone() &&
      !localStorage.getItem(HINT_KEY)
    ) {
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
      style={{
        position: "fixed",
        inset: 0,
        zIndex: 10000,
        background: "rgba(0,0,0,0.7)",
        display: "flex",
        alignItems: "flex-end",
        justifyContent: "center",
      }}
      onClick={handleGotIt}
    >
      <div
        ref={dialogRef}
        style={{
          background: "#141414",
          borderRadius: "16px 16px 0 0",
          padding: "24px 20px 36px",
          maxWidth: 480,
          width: "100%",
          borderTop: "1px solid #2a2a2a",
        }}
        onClick={(e) => e.stopPropagation()}
      >
        <h2
          id="ios-install-hint-title"
          style={{
            margin: "0 0 12px",
            fontSize: 18,
            fontWeight: 700,
            color: "#e5e5e5",
          }}
        >
          {i18n.t("pwa.installIceq")}
        </h2>
        <p style={{ margin: "0 0 20px", fontSize: 14, color: "#999", lineHeight: 1.5 }}>
          {i18n.t("pwa.iosHelp")}
        </p>
        <button
          ref={dismissButtonRef}
          type="button"
          onClick={handleGotIt}
          style={{
            width: "100%",
            background: "#00b4d8",
            color: "#0a0a0a",
            border: "none",
            borderRadius: 10,
            padding: "12px",
            fontWeight: 700,
            fontSize: 15,
            cursor: "pointer",
          }}
        >
          {i18n.t("pwa.gotIt")}
        </button>
      </div>
    </div>
  );
}
