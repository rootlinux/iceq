// src/App.tsx
//
// Top-level router. Two top-level paths:
//
//   /login, /register   — public, no WebSocket.
//   /setup               — mandatory first-login security setup.
//   /app/*               — authenticated. Mounted only after
//                          isAuthenticated flips to true AND
//                          security setup is complete. The
//                          WebSocket hook lives here so the
//                          socket is bound to the lifetime of
//                          the chat shell.
//
// We also listen for the "iceq:wiped" event fired by
// useWebSocket on a 4403 close; the auth store clears state
// and we redirect to /login.

import { useEffect, useState } from "react";
import { Navigate, Route, Routes, useNavigate } from "react-router-dom";
import { useAuthStore } from "./store/authStore";
import { LoginForm } from "./components/Auth/LoginForm";
import { RegisterForm } from "./components/Auth/RegisterForm";
import { SecuritySetupGate } from "./components/Auth/SecuritySetupGate";
import { RecoveryImportScreen } from "./components/Auth/RecoveryImportScreen";
import { MainLayout } from "./components/Layout/MainLayout";
import { ChatShell } from "./components/Chat/ChatShell";
import { useI18n } from "./i18n";
import { ICEQ_CLEANUP_REQUIRED_MARKER_KEY } from "./lib/localDataCleanup";
import { hasSecuritySetupCompleted, loadOrCreateDeviceId, setActiveCryptoNamespace } from "./lib/indexeddb";

export default function App(): JSX.Element {
  const isAuthed = useAuthStore((s) => s.isAuthenticated);
  const uin = useAuthStore((s) => s.uin);
  const hydrated = useAuthStore((s) => s.hydrated);
  const navigate = useNavigate();
  const i18n = useI18n();
  const [cleanupFailed, setCleanupFailed] = useState(() => localStorage.getItem(ICEQ_CLEANUP_REQUIRED_MARKER_KEY) === "1");
  const [setupStatus, setSetupStatus] = useState<{ uin: number; complete: boolean } | null>(null);

  // Check security setup completion when authenticated
  useEffect(() => {
    if (!isAuthed) {
      setSetupStatus(null);
      return;
    }
    if (uin === null) {
      setSetupStatus(null);
      return;
    }

    let cancelled = false;
    void (async () => {
      try {
        const ns = { uin, deviceId: await loadOrCreateDeviceId() };
        setActiveCryptoNamespace(ns);
        const done = await hasSecuritySetupCompleted(ns);
        if (!cancelled) setSetupStatus({ uin, complete: done });
      } catch {
        if (!cancelled) setSetupStatus({ uin, complete: false });
      }
    })();

    return () => { cancelled = true; };
  }, [isAuthed, uin]);

  // The auth-expired event is fired by the api/client when a
  // refresh fails. We bounce to /login and clear state.
  useEffect(() => {
    function onExpired(): void {
      void useAuthStore.getState().expireSession().catch((error) => {
        console.error("[IceQ cleanup] auth-expired local cleanup failed", error);
      });
      navigate("/login", { replace: true });
    }
    function onWiped(): void {
      // 4403 — the WS hook already cleared all local state;
      // we just navigate.
      navigate("/login", { replace: true });
    }
    function onCleanupFailed(): void { setCleanupFailed(true); }
    window.addEventListener("iceq:auth-expired", onExpired);
    window.addEventListener("iceq:wiped", onWiped);
    window.addEventListener("iceq:local-cleanup-failed", onCleanupFailed);
    return () => {
      window.removeEventListener("iceq:auth-expired", onExpired);
      window.removeEventListener("iceq:wiped", onWiped);
      window.removeEventListener("iceq:local-cleanup-failed", onCleanupFailed);
    };
  }, [navigate]);

  // Don't render anything until the auth store has read
  // tokens from localStorage. Otherwise we'd flash the
  // login form for one render before re-routing to /app.
  if (!hydrated) {
    return (
      <div className="flex h-full items-center justify-center bg-bg text-text-2">
        {i18n.t("app.loading")}
      </div>
    );
  }

  // Show setup if authenticated but setup not yet complete
  const setupChecked = isAuthed && uin !== null && setupStatus?.uin === uin;
  const setupComplete = setupChecked && setupStatus.complete;
  const showSetup = setupChecked && !setupComplete;
  // Still checking — show spinner
  const checkingSetup = isAuthed && !setupChecked;

  return (
    <>
    {cleanupFailed && <div role="alert" className="fixed inset-x-0 top-0 z-50 bg-danger p-3 text-white">
      <span>{i18n.t("cleanup.failed")}</span>{" "}
      <button type="button" onClick={() => void useAuthStore.getState().retryLocalCleanup().then(() => setCleanupFailed(false)).catch(() => setCleanupFailed(true))}>{i18n.t("cleanup.retry")}</button>
    </div>}
    {checkingSetup ? (
      <div className="flex h-full items-center justify-center bg-bg text-text-2">
        {i18n.t("app.loading")}
      </div>
    ) : (
    <Routes>
      <Route path="/login" element={isAuthed ? <Navigate to="/app" replace /> : <LoginForm />} />
      <Route path="/register" element={isAuthed ? <Navigate to="/app" replace /> : <RegisterForm />} />
      <Route path="/setup" element={showSetup ? <SecuritySetupGate onSetupComplete={() => uin !== null && setSetupStatus({ uin, complete: true })} /> : <Navigate to="/app" replace />} />
      <Route path="/recovery" element={isAuthed ? <RecoveryImportScreen /> : <Navigate to="/login" replace />} />
      <Route
        path="/app/*"
        element={showSetup ? <Navigate to="/setup" replace /> : (isAuthed ? <MainLayout><ChatShell /></MainLayout> : <Navigate to="/login" replace />)}
      />
      <Route path="*" element={<Navigate to={isAuthed ? (showSetup ? "/setup" : "/app") : "/login"} replace />} />
    </Routes>)}
    </>
  );
}
