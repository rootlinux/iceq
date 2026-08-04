// src/components/Auth/LoginForm.tsx
//
// Encrypted Aurora login experience.
// Asymmetric split: Ice Bloom Q mark on the left, sign-in form on the right.
// Controlled aurora illumination behind the focal area.
//
// Privacy: the password is held in component state only for the
// duration of the submit. The input uses type="password" so the
// browser doesn't render the value in the saved-credentials UI.

import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useAuthStore } from "../../store/authStore";
import { useI18n } from "../../i18n";
import type { MessageKey } from "../../i18n/en";
import { ApiError, ApiNetworkError } from "../../api/client";
import { IceQWordmark } from "../Brand/IceQWordmark";

export function getLoginErrorMessage(
  error: unknown,
  translate: (key: MessageKey) => string,
): string {
  if (error instanceof ApiNetworkError) return translate("auth.networkError");
  if (error instanceof ApiError) {
    if (error.code === "INVALID_CREDENTIALS") return translate("auth.invalidCredentials");
    if (error.code === "RATE_LIMITED") return translate("auth.rateLimited");
  }
  return translate("auth.signInFailed");
}

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
      setError(getLoginErrorMessage(err, i18n.t));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="abyss-depth grain-overlay flex min-h-full items-center justify-center p-4 sm:p-8">
      {/* ── Aurora illumination behind focal area ──────────────────── */}
      <div className="aurora-glow flex w-full max-w-5xl flex-col overflow-hidden rounded-3xl md:flex-row">

        {/* ── LEFT: Ice Bloom Q hero lockup ──────────────────────────── */}
        <div className="relative flex flex-col items-center justify-center px-8 py-10 md:w-1/2 md:py-14">
          {/* Background depth gradient */}
          <div
            className="pointer-events-none absolute inset-0"
            style={{
              background:
                "radial-gradient(ellipse 70% 50% at 40% 50%, rgba(139,108,255,0.07) 0%, transparent 70%), " +
                "radial-gradient(ellipse 50% 40% at 55% 45%, rgba(89,216,255,0.04) 0%, transparent 60%)",
            }}
          />

          {/* One brand lockup: mark (~150 px) + wordmark text below */}
          <div className="relative">
            <IceQWordmark variant="stacked" size="hero" />
          </div>

          {/* Privacy context — below the lockup */}
          <p className="relative mt-6 max-w-xs text-center text-sm leading-relaxed text-mist">
            {i18n.t("auth.registerHelp")}
          </p>

          {/* Secure channel motif */}
          <div className="relative mt-4 w-32 secure-channel" data-secure="true" />
        </div>

        {/* ── RIGHT: Form panel ────────────────────────────────────── */}
        <div className="flex flex-col justify-center px-6 py-10 md:w-1/2 md:px-10 md:py-14">
          <div className="iceq-panel w-full max-w-auth-form mx-auto">
            {/* Panel header */}
            <div className="mb-6 secure-channel pb-4" data-connected="true">
              <h1 className="text-display text-frozen font-display">
                {i18n.t("auth.signInTitle")}
              </h1>
              <p className="mt-1.5 text-sm text-mist">
                {i18n.t("auth.signIn")}
              </p>
            </div>

            <form onSubmit={onSubmit} className="space-y-4" noValidate>
              {/* Username */}
              <div className="space-y-1.5">
                <label htmlFor="login-username" className="text-label text-mist">
                  {i18n.t("auth.username")}
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

              {/* Password */}
              <div className="space-y-1.5">
                <label htmlFor="login-password" className="text-label text-mist">
                  {i18n.t("auth.password")}
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

              {/* Error */}
              {error && (
                <div role="alert" className="iceq-alert-error">
                  {error}
                </div>
              )}

              {/* Submit */}
              <button
                type="submit"
                className="iceq-btn-primary w-full"
                disabled={submitting}
              >
                {submitting ? (
                  <span className="flex items-center justify-center gap-2">
                    <span className="iceq-spinner" style={{ width: 16, height: 16, borderTopColor: "#050713" }} />
                    {i18n.t("auth.signingIn")}
                  </span>
                ) : (
                  i18n.t("auth.signIn")
                )}
              </button>

              {/* Footer links */}
              <div className="flex flex-col gap-2 pt-2 text-center text-sm">
                <p className="text-mist">
                  {i18n.t("auth.noAccount")}{" "}
                  <Link
                    to="/register"
                    className="font-semibold text-electric hover:underline focus-visible:rounded-sm"
                  >
                    {i18n.t("auth.register")}
                  </Link>
                </p>
                <Link
                  to="/recovery"
                  className="text-xs text-mist-dim hover:text-mist focus-visible:rounded-sm"
                >
                  {i18n.t("auth.recoveryLink")}
                </Link>
              </div>
            </form>
          </div>
        </div>
      </div>
    </div>
  );
}

export default LoginForm;
