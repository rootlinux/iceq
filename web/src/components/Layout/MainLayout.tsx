// src/components/Layout/MainLayout.tsx
//
// Encrypted Aurora messenger shell — two spatial layers + drawer:
//
//   1. Identity rail (72 px) — compact vertical rail with Ice Bloom Q
//      logo toggle, connection-state indicator.
//   2. Navigation drawer — overlays the conversation; contains
//      Chats / Contacts / Groups tabs, settings, sign out.
//   3. Active transmission — full-width conversation area.
//
// On mobile (<768 px), the drawer is full-height.

import { createContext, useCallback, useContext, useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Sidebar } from "./Sidebar";
import { useMessageTransport } from "../../hooks/useMessageTransport";
import { useOnlineStatus } from "../../hooks/useOnlineStatus";
import { useAuthStore } from "../../store/authStore";
import { useSignalStore } from "../../store/signalStore";
import { ensureSignalProvisioning } from "../../lib/signalBootstrap";
import { useI18n } from "../../i18n";
import { InstallPrompt } from "../PWA/InstallPrompt";
import { IOSInstallHint } from "../PWA/IOSInstallHint";
import { IceQMark } from "../Brand/IceQMark";
import type { EnvelopeType } from "../../types/envelope";

interface MainLayoutProps {
  children: React.ReactNode;
}

export interface ChatShellContextValue {
  send: (frame: { type: EnvelopeType; id: string; ts: number; payload: unknown }) => boolean;
  connected: boolean;
}

const ChatShellContext = createContext<ChatShellContextValue | null>(null);

export function useChatShell(): ChatShellContextValue {
  const v = useContext(ChatShellContext);
  if (!v) throw new Error("useChatShell: not inside <MainLayout>");
  return v;
}

const RAIL_W = 72;

export function MainLayout({ children }: MainLayoutProps): JSX.Element {
  const navigate = useNavigate();
  const { connected, send } = useMessageTransport();
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [mobileViewport, setMobileViewport] = useState(
    () => window.matchMedia("(max-width: 767px)").matches,
  );
  const logoToggleRef = useRef<HTMLButtonElement>(null);
  const drawerRef = useRef<HTMLDivElement>(null);

  // Manage inert on drawer — React 18 doesn't support the inert attribute in JSX
  useEffect(() => {
    const el = drawerRef.current;
    if (!el) return;
    if (drawerOpen) {
      el.removeAttribute("inert");
    } else {
      el.setAttribute("inert", "");
    }
  }, [drawerOpen]);
  const { isOnline } = useOnlineStatus();
  const selfUin = useAuthStore((s) => s.uin);
  const setSignalReady = useSignalStore((s) => s.setReady);
  const setSignalError = useSignalStore((s) => s.setError);
  const refreshPrekeyCount = useSignalStore((s) => s.refreshPrekeyCount);
  const signalError = useSignalStore((s) => s.lastError);
  const isMissingIdentity = signalError !== null && signalError.includes("missing this device");
  const i18n = useI18n();

  const openDrawer = useCallback(() => setDrawerOpen(true), []);
  const closeDrawer = useCallback((): void => {
    setDrawerOpen(false);
    // Return focus to logo toggle
    requestAnimationFrame(() => logoToggleRef.current?.focus());
  }, []);

  // Close drawer on Escape
  useEffect(() => {
    if (!drawerOpen) return;
    const onKey = (e: KeyboardEvent): void => {
      if (e.key === "Escape") {
        // Only close if no modal is open above the drawer
        const modals = document.querySelectorAll("[role=dialog][aria-modal=true]");
        if (modals.length === 0) closeDrawer();
      }
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [drawerOpen, closeDrawer]);

  // Track mobile viewport
  useEffect(() => {
    const media = window.matchMedia("(max-width: 767px)");
    const onChange = (): void => setMobileViewport(media.matches);
    onChange();
    media.addEventListener("change", onChange);
    return () => media.removeEventListener("change", onChange);
  }, []);

  // Move focus into drawer when opened
  useEffect(() => {
    if (!drawerOpen || !drawerRef.current) return;
    const frame = requestAnimationFrame(() => {
      const first = drawerRef.current?.querySelector<HTMLElement>(
        "button, a, input, [tabindex]:not([tabindex='-1'])",
      );
      first?.focus();
    });
    return () => cancelAnimationFrame(frame);
  }, [drawerOpen]);

  // Signal provisioning
  useEffect(() => {
    if (selfUin === null) return;
    let cancelled = false;
    const controller = new AbortController();

    void ensureSignalProvisioning(selfUin, undefined, controller.signal)
      .then(() => refreshPrekeyCount(controller.signal))
      .then(() => {
        if (cancelled) return;
        setSignalReady(true);
        setSignalError(null);
      })
      .catch((error: Error) => {
        if (cancelled) return;
        if ((error as { name?: string }).name === "AbortError") return;
        setSignalReady(false);
        setSignalError(error.message);
      });

    return () => {
      cancelled = true;
      controller.abort();
    };
  }, [refreshPrekeyCount, selfUin, setSignalError, setSignalReady]);

  return (
    <div className="flex h-full w-full flex-col bg-abyss">
      {/* ── Offline banner ─────────────────────────────────────────── */}
      {!isOnline && (
        <div role="status" aria-live="polite" className="iceq-banner iceq-banner--offline">
          {i18n.t("connection.offline")}
        </div>
      )}

      {/* ── Signal error banner ────────────────────────────────────── */}
      {signalError && (
        <div
          role="alert"
          aria-live="assertive"
          className="iceq-banner iceq-banner--error"
          style={{ flexWrap: "wrap", gap: 8, padding: "8px 16px", textAlign: "center" }}
        >
          <span>{signalError}</span>
          {isMissingIdentity && (
            <button
              type="button"
              className="iceq-btn-secondary text-xs"
              onClick={() => navigate("/recovery")}
            >
              {i18n.t("auth.recoveryLink")}
            </button>
          )}
        </div>
      )}

      {/* ── Shell ──────────────────────────────────────────────────── */}
      <div className="flex flex-1 overflow-hidden">

        {/* ═══════════════════════════════════════════════════════════
            LAYER 1: Identity Rail — compact, always visible
            ═══════════════════════════════════════════════════════════ */}
        <nav
          className="secure-channel-vertical flex shrink-0 flex-col items-center border-r border-ice-border bg-abyss py-4"
          style={{ width: RAIL_W }}
          aria-label={i18n.t("nav.toggleMenu")}
        >
          {/* Ice Bloom Q logo — primary menu toggle */}
          <button
            type="button"
            ref={logoToggleRef}
            className="iceq-btn-icon mb-3"
            onClick={() => drawerOpen ? closeDrawer() : openDrawer()}
            aria-label={i18n.t("nav.toggleMenu")}
            aria-expanded={drawerOpen}
            aria-controls="navigation-drawer"
          >
            <IceQMark size={28} compact monochrome />
          </button>

          {/* Spacer — pushes connection state to bottom */}
          <div className="flex-1" />

          {/* Connection state indicator */}
          <div className="mb-3 flex flex-col items-center gap-1">
            <span
              aria-hidden="true"
              className={`inline-block h-2 w-2 rounded-full ${
                connected ? "bg-secure-mint" : "bg-offline"
              }`}
              style={
                connected
                  ? { boxShadow: "0 0 6px rgba(76,225,161,0.4)" }
                  : undefined
              }
              title={connected ? i18n.t("connection.connected") : i18n.t("connection.reconnecting")}
            />
            <span className="text-[9px] font-semibold uppercase tracking-wider text-mist-dim">
              {connected ? i18n.t("connection.secureLabel") : i18n.t("connection.offLabel")}
            </span>
          </div>
        </nav>

        {/* ═══════════════════════════════════════════════════════════
            LAYER 2: Navigation Drawer — overlay
            ═══════════════════════════════════════════════════════════ */}
        {/* Backdrop */}
        {drawerOpen && (
          <div
            className="fixed inset-0 z-30 md:absolute"
            style={{
              background: mobileViewport
                ? "rgba(5,7,19,0.7)"
                : "rgba(5,7,19,0.35)",
              backdropFilter: "blur(2px)",
              WebkitBackdropFilter: "blur(2px)",
              left: RAIL_W,
            }}
            aria-hidden="true"
            onClick={closeDrawer}
          />
        )}

        {/* Drawer panel */}
        <div
          id="navigation-drawer"
          ref={drawerRef}
          className={
            "fixed inset-y-0 z-40 transition-transform duration-200 ease-out " +
            (mobileViewport ? "left-0 right-0" : "border-r border-ice-border")
          }
          style={{
            width: mobileViewport ? "100%" : 340,
            left: mobileViewport ? 0 : RAIL_W,
            transform: drawerOpen ? "translateX(0)" : `translateX(-100%)`,
            background:
              "linear-gradient(180deg, rgba(16,27,61,0.95) 0%, rgba(10,16,36,0.98) 100%)",
            backdropFilter: "blur(12px)",
            WebkitBackdropFilter: "blur(12px)",
            boxShadow: drawerOpen
              ? "4px 0 32px rgba(0,0,0,0.4)"
              : "none",
          }}
          aria-hidden={!drawerOpen}
          onKeyDown={(e) => {
            if (e.key === "Escape") { closeDrawer(); e.stopPropagation(); }
          }}
        >
          <Sidebar open={drawerOpen} onClose={closeDrawer} />
        </div>

        {/* ═══════════════════════════════════════════════════════════
            LAYER 3: Active Transmission — full width
            ═══════════════════════════════════════════════════════════ */}
        <main
          className="relative flex flex-1 flex-col bg-deep-ice"
          style={{
            background:
              "radial-gradient(ellipse 80% 50% at 50% 100%, rgba(16,27,61,0.3) 0%, transparent 60%), " +
              "#0A1024",
          }}
        >
          {/* ── Top bar ────────────────────────────────────────────── */}
          <header
            className="secure-channel flex h-12 shrink-0 items-center px-4"
            data-connected={connected ? "true" : "false"}
          >
            {/* Desktop: connection text */}
            <div className="ml-auto hidden items-center gap-2 text-xs md:flex">
              <span
                aria-hidden="true"
                className={`inline-block h-2 w-2 rounded-full ${
                  connected ? "bg-secure-mint" : "bg-offline"
                }`}
              />
              <span className={connected ? "text-secure-mint" : "text-mist-dim"}>
                {connected ? i18n.t("connection.connected") : i18n.t("connection.reconnecting")}
              </span>
            </div>
          </header>

          {/* ── Chat area ──────────────────────────────────────────── */}
          <div className="flex-1 overflow-hidden">
            <ChatShellContext.Provider value={{ send, connected }}>
              {children}
            </ChatShellContext.Provider>
          </div>
        </main>
      </div>

      <InstallPrompt />
      <IOSInstallHint visible={selfUin !== null} />
    </div>
  );
}

export default MainLayout;
