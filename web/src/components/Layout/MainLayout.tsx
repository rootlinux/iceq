// src/components/Layout/MainLayout.tsx
//
// The authenticated shell. The Sidebar lives on the left;
// the children (the chat window) fill the remaining area.
// On mobile, the sidebar slides over the chat when open.

import { useEffect, useState } from "react";
import { Sidebar } from "./Sidebar";
import { useMessageTransport } from "../../hooks/useMessageTransport";
import { useOnlineStatus } from "../../hooks/useOnlineStatus";
import { useAuthStore } from "../../store/authStore";
import { useSignalStore } from "../../store/signalStore";
import { ensureSignalProvisioning } from "../../lib/signalBootstrap";
import { useI18n } from "../../i18n";

interface MainLayoutProps {
  children: React.ReactNode;
}

export function MainLayout({ children }: MainLayoutProps): JSX.Element {
  // Mount the WebSocket here, at the top of the authenticated
  // tree. The hook's send() is what components use to publish
  // frames; we don't propagate it via context — components
  // call the hook directly.
  const { connected, send } = useMessageTransport();
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const { isOnline } = useOnlineStatus();
  const selfUin = useAuthStore((s) => s.uin);
  const setSignalReady = useSignalStore((s) => s.setReady);
  const setSignalError = useSignalStore((s) => s.setError);
  const refreshPrekeyCount = useSignalStore((s) => s.refreshPrekeyCount);
  const signalError = useSignalStore((s) => s.lastError);
  const i18n = useI18n();

  // Close the sidebar on viewport widening so it doesn't
  // stay slid in when the user rotates their phone.
  useEffect(() => {
    const onResize = (): void => {
      if (window.innerWidth >= 768) setSidebarOpen(false);
    };
    window.addEventListener("resize", onResize);
    return () => window.removeEventListener("resize", onResize);
  }, []);

  useEffect(() => {
    if (selfUin === null) return;
    let cancelled = false;

    void ensureSignalProvisioning(selfUin)
      .then(() => refreshPrekeyCount())
      .then(() => {
        if (cancelled) return;
        setSignalReady(true);
        setSignalError(null);
      })
      .catch((error: Error) => {
        if (cancelled) return;
        setSignalReady(false);
        setSignalError(error.message);
      });

    return () => {
      cancelled = true;
    };
  }, [refreshPrekeyCount, selfUin, setSignalError, setSignalReady]);

  return (
    <div className="flex h-full w-full flex-col bg-bg">
      {!isOnline && (
        <div
          role="status"
          aria-live="polite"
          style={{
            background: "#eab308",
            color: "#0a0a0a",
            height: 32,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            fontSize: 13,
            fontWeight: 500,
            width: "100%",
            flexShrink: 0,
          }}
        >
          {i18n.t("connection.offline")}
        </div>
      )}
      {signalError && (
        <div
          role="alert"
          aria-live="assertive"
          style={{
            background: "#7f1d1d",
            color: "#fef2f2",
            minHeight: 40,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            fontSize: 13,
            padding: "8px 12px",
            textAlign: "center",
            width: "100%",
            flexShrink: 0,
          }}
        >
          {signalError}
        </div>
      )}
      <div className="flex flex-1 overflow-hidden">
        <Sidebar open={sidebarOpen} onClose={() => setSidebarOpen(false)} />
        <main className="relative flex flex-1 flex-col bg-surface">
          <header className="flex h-12 items-center justify-between border-b border-border px-4">
            <button
              type="button"
              className="iceq-btn-secondary md:hidden"
              onClick={() => setSidebarOpen((s) => !s)}
              aria-label={i18n.t("nav.toggleMenu")}
            >
              ☰
            </button>
            <div className="ml-auto flex items-center gap-2 text-xs text-text-2">
              <span
                aria-hidden="true"
                data-connected={connected ? "true" : "false"}
                className={
                  "inline-block h-2 w-2 rounded-full " +
                  (connected ? "bg-presence-online" : "bg-presence-offline")
                }
              />
              <span>{connected ? i18n.t("connection.connected") : i18n.t("connection.reconnecting")}</span>
            </div>
          </header>
          <div className="flex-1 overflow-hidden">
            {/* Children are responsible for their own scroll
                containers; we just give them the height. */}
            <ChatShellContext.Provider value={{ send, connected }}>
              {children}
            </ChatShellContext.Provider>
          </div>
        </main>
      </div>
    </div>
  );
}

// ----------------------------------------------------------------------------
// Context plumbing. Some children (e.g. MessageInput) want
// the WS `send` reference without re-invoking the hook.
// ----------------------------------------------------------------------------
import { createContext, useContext } from "react";
import type { EnvelopeType } from "../../types/envelope";

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

export default MainLayout;
