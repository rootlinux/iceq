// src/components/Auth/LoginForm.tsx
//
// Username + password form. The signal key generation is
// register-only; on login the client just uses whatever is
// already in IndexedDB (the local device identity).
//
// On submit, the auth store's login() posts to /api/auth/login.
// On 2xx, isAuthenticated flips to true and the App router
// redirects to /app. On 4xx, we render an inline error.
//
// Privacy: the password is held in component state only
// for the duration of the submit. The input element uses
// type="password" so the browser doesn't render the value
// in the saved-credentials UI. We never log it.

import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useAuthStore } from "../../store/authStore";
import { useI18n } from "../../i18n";

export function LoginForm(): JSX.Element {
  const i18n = useI18n();
  const navigate = useNavigate();
  const login = useAuthStore((s) => s.login);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const onSubmit = async (e: React.FormEvent): Promise<void> => {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      await login(username, password);
      navigate("/app", { replace: true });
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="flex h-full items-center justify-center bg-bg p-4">
      <form
        onSubmit={onSubmit}
        className="w-full max-w-sm space-y-4 rounded-lg border border-border bg-surface-2 p-6"
      >
        <h1 className="text-2xl font-semibold text-text">{i18n.t("auth.signInTitle")}</h1>

        <div className="space-y-1">
          <label htmlFor="login-username" className="text-sm text-text-2">
            Username
          </label>
          <input
            id="login-username"
            type="text"
            autoComplete="username"
            className="iceq-input"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            required
            minLength={3}
            maxLength={32}
            disabled={submitting}
          />
        </div>

        <div className="space-y-1">
          <label htmlFor="login-password" className="text-sm text-text-2">
            Password
          </label>
          <input
            id="login-password"
            type="password"
            autoComplete="current-password"
            className="iceq-input"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
            minLength={8}
            maxLength={128}
            disabled={submitting}
          />
        </div>

        {error && (
          <div role="alert" className="rounded-md border border-presence-dnd bg-surface p-3 text-sm">
            {error}
          </div>
        )}

        <button type="submit" className="iceq-btn-primary w-full" disabled={submitting}>
          {submitting ? "Signing in…" : "Sign in"}
        </button>

        <p className="text-sm text-text-2">
          Don't have an account?{" "}
          <Link to="/register" className="text-accent hover:underline">
            Register
          </Link>
        </p>
      </form>
    </div>
  );
}

export default LoginForm;
