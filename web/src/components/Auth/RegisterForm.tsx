// src/components/Auth/RegisterForm.tsx
//
// Encrypted Aurora registration experience.
// Same asymmetric split as login but with aurora-violet tint for the
// key-generation states. Ice Bloom Q mark transitions subtly during crypto
// generation.
//
// Registration flow:
//   1. User picks a username and password (no email).
//   2. Client generates an IdentityKeyPair in-browser via Signal bindings.
//   3. Private key written to IndexedDB; public key sent to /api/auth/register.
//   4. Auth-service creates user row, returns tokens. Client auto-logs in.
//   5. Client generates prekey bundle and uploads to /api/keys/bundle.
//   6. Client navigates to /app.

import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useAuthStore } from "../../store/authStore";
import { fetchBundle, uploadBundle, type OneTimePreKeyUpload, type SignedPreKeyUpload } from "../../api/keys";
import { me } from "../../api/auth";
import { ApiError } from "../../api/client";
import { useI18n } from "../../i18n";
import type { MessageKey } from "../../i18n/en";
import { runRegistration, type PendingRegistration } from "../../lib/registrationRecovery";
import { IceQWordmark } from "../Brand/IceQWordmark";

const ONETIMEPREKEY_COUNT = 20;

type RegStage = "idle" | "generating" | "uploading" | "registering";

const stageLabel: Record<RegStage, MessageKey> = {
  idle: "auth.createAccount",
  generating: "auth.generatingKeys",
  registering: "auth.creatingAccount",
  uploading: "auth.uploadingPrekeys",
};

export function RegisterForm(): JSX.Element {
  const i18n = useI18n();
  const navigate = useNavigate();
  const register = useAuthStore((s) => s.register);
  const setSignalReady = useSignalStoreReady();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [stage, setStage] = useState<RegStage>("idle");
  const [error, setError] = useState<string | null>(null);

  const warmSignal = (): void => {
    void import("../../lib/signal")
      .then(({ preloadSignal }) => preloadSignal())
      .catch(() => {
        // Best-effort warmup; failure surfaces on submit.
      });
  };

  const onSubmit = async (e: React.FormEvent): Promise<void> => {
    e.preventDefault();
    setError(null);
    try {
      const {
        assertValidIdentityKey,
        generateIdentityKeyPair,
        generatePreKeyBundle,
        generateRegistrationId,
        saveOwnIdentity,
      } = await import("../../lib/signal");
      const {createRegistrationCryptoNamespace,commitCryptoNamespace,loadOrCreateDeviceId,setActiveCryptoNamespace,loadPendingRegistration,savePendingRegistration,clearPendingRegistration}=await import("../../lib/indexeddb");
      const activeNamespace=await runRegistration({username,password},{
        store:{load:()=>loadPendingRegistration<PendingRegistration>(),save:savePendingRegistration,clear:clearPendingRegistration},
        prepare:async()=>{
          const stagingNamespace=createRegistrationCryptoNamespace();
          const identity=await generateIdentityKeyPair();const registrationId=generateRegistrationId();await saveOwnIdentity(identity,registrationId,stagingNamespace);
          const bundle=await generatePreKeyBundle(identity,1,ONETIMEPREKEY_COUNT,registrationId,stagingNamespace);
          const signedPreKey:SignedPreKeyUpload={id:bundle.signed_pre_key.id,public_key:bundle.signed_pre_key.public_key,signature:bundle.signed_pre_key.signature};
          const oneTimePreKeys:OneTimePreKeyUpload[]=bundle.one_time_pre_keys.map(p=>({id:p.id,public_key:p.public_key}));assertValidIdentityKey(bundle.identity_key);
          return{stagingNamespace,identityKey:bundle.identity_key,bundle:{identity_key:bundle.identity_key,signed_pre_key:signedPreKey,one_time_pre_keys:oneTimePreKeys,registration_id:registrationId}};
        },
        register:async input=>{await register(input);const uin=useAuthStore.getState().uin;if(uin===null)throw new Error("registration session missing account");return{uin};},
        authenticatedAccount:async()=>{try{const account=await me();return{uin:account.uin,username:account.username};}catch{return null;}},
        fetchDirectory:async uin=>{try{return await fetchBundle(uin);}catch(error){if(error instanceof ApiError&&error.status===404)return null;throw error;}},
        deviceId:loadOrCreateDeviceId,upload:uploadBundle,commit:commitCryptoNamespace,
      },setStage);
      setActiveCryptoNamespace(activeNamespace);

      setSignalReady(true);
      navigate("/app", { replace: true });
    } catch (err) {
      setError((err as Error).message);
      setStage("idle");
    }
  };

  const isBusy = stage !== "idle";

  return (
    <div className="abyss-depth grain-overlay flex min-h-full items-center justify-center p-4 sm:p-8">
      {/* ── Aurora illumination — violet tint for registration ─────── */}
      <div className="aurora-glow flex w-full max-w-5xl flex-col overflow-hidden rounded-3xl md:flex-row">

        {/* ── LEFT: Ice Bloom Q hero lockup ──────────────────────────── */}
        <div className="relative flex flex-col items-center justify-center px-8 py-10 md:w-1/2 md:py-14">
          {/* Registration depth gradient — violet-dominant */}
          <div
            className="pointer-events-none absolute inset-0"
            style={{
              background:
                "radial-gradient(ellipse 70% 50% at 40% 50%, rgba(139,108,255,0.10) 0%, transparent 70%), " +
                "radial-gradient(ellipse 50% 40% at 55% 45%, rgba(233,92,255,0.04) 0%, transparent 60%)",
            }}
          />

          {/* One brand lockup: mark (~150 px) + wordmark text below */}
          <div className="relative">
            <IceQWordmark variant="stacked" size="hero" />
          </div>

          {/* Stage indicator — what's happening */}
          {isBusy && (
            <div className="relative mt-4 flex items-center gap-2 text-sm text-aurora-violet">
              <span className="iceq-spinner" style={{ width: 14, height: 14, borderTopColor: "#8B6CFF" }} />
              <span className="animate-reveal">{i18n.t(stageLabel[stage])}</span>
            </div>
          )}

          {/* Privacy context */}
          {!isBusy && (
            <p className="relative mt-5 max-w-xs text-center text-sm leading-relaxed text-mist">
              {i18n.t("auth.registerHelp")}
            </p>
          )}

          {/* Signal metadata visualization */}
          <div className="relative mt-4 w-32 secure-channel" data-secure="true" />
        </div>

        {/* ── RIGHT: Form panel ────────────────────────────────────── */}
        <div className="flex flex-col justify-center px-6 py-10 md:w-1/2 md:px-10 md:py-14">
          <div className="iceq-panel w-full max-w-auth-form mx-auto">
            {/* Panel header — violet tint */}
            <div className="mb-6 secure-channel pb-4" data-secure="true">
              <h1 className="text-display text-frozen font-display">
                {i18n.t("auth.createTitle")}
              </h1>
              <p className="mt-1.5 text-sm text-mist">
                {i18n.t("auth.createAccount")}
              </p>
            </div>

            <form onSubmit={onSubmit} className="space-y-4" noValidate>
              {/* Privacy context (compact, inside form for mobile) */}
              <div className="iceq-alert-info text-xs">{i18n.t("auth.registerHelp")}</div>

              {/* Username */}
              <div className="space-y-1.5">
                <label htmlFor="register-username" className="text-label text-mist">
                  {i18n.t("auth.username")}
                </label>
                <input
                  id="register-username"
                  type="text"
                  autoComplete="username"
                  className="iceq-input"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  onFocus={warmSignal}
                  required
                  minLength={3}
                  maxLength={32}
                  disabled={isBusy}
                />
              </div>

              {/* Password */}
              <div className="space-y-1.5">
                <label htmlFor="register-password" className="text-label text-mist">
                  {i18n.t("auth.password")}
                </label>
                <input
                  id="register-password"
                  type="password"
                  autoComplete="new-password"
                  className="iceq-input"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  onFocus={warmSignal}
                  required
                  minLength={8}
                  maxLength={128}
                  disabled={isBusy}
                />
              </div>

              {/* Error */}
              {error && (
                <div role="alert" className="iceq-alert-error">{error}</div>
              )}

              {/* Submit */}
              <button
                type="submit"
                className="iceq-btn-primary w-full"
                disabled={isBusy}
                style={isBusy ? { background: "#8B6CFF" } : undefined}
              >
                {isBusy ? (
                  <span className="flex items-center justify-center gap-2">
                    <span className="iceq-spinner" style={{ width: 16, height: 16, borderTopColor: "#050713" }} />
                    {i18n.t(stageLabel[stage])}
                  </span>
                ) : (
                  i18n.t("auth.createAccount")
                )}
              </button>

              {/* Footer links */}
              <p className="pt-2 text-center text-sm text-mist">
                {i18n.t("auth.haveAccount")}{" "}
                <Link
                  to="/login"
                  className="font-semibold text-electric hover:underline focus-visible:rounded-sm"
                >
                  {i18n.t("auth.signIn")}
                </Link>
              </p>
            </form>
          </div>
        </div>
      </div>
    </div>
  );
}

export default RegisterForm;

// ---------------------------------------------------------------------------
// Local hook
// ---------------------------------------------------------------------------
import { useSignalStore } from "../../store/signalStore";
function useSignalStoreReady(): (ready: boolean) => void {
  const setReady = useSignalStore((s) => s.setReady);
  return setReady;
}
