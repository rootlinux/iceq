// src/components/Auth/RegisterForm.tsx
//
// Registration flow. The spec is:
//
//   1. User picks a username and password (no email).
//   2. Client generates an IdentityKeyPair in-browser via
//      the Signal bindings.
//   3. The PRIVATE half of the key pair is written to
//      IndexedDB. The public half goes on the wire to
//      /api/auth/register.
//   4. The auth-service creates the user row and returns
//      tokens. The client auto-logs in.
//   5. The client generates a prekey bundle (one signed
//      prekey + 20 one-time prekeys) and uploads it to
//      /api/keys/bundle.
//   6. The client navigates to /app.
//
// Step 2 is heavy: Curve25519 key generation is single-threaded
// JS and takes ~50–200ms. We surface this with a "Generating
// keys…" button label so the user doesn't think the form
// is stuck.

import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useAuthStore } from "../../store/authStore";
import { fetchBundle, uploadBundle, type OneTimePreKeyUpload, type SignedPreKeyUpload } from "../../api/keys";
import { me } from "../../api/auth";
import { ApiError } from "../../api/client";
import { useI18n } from "../../i18n";
import { runRegistration, type PendingRegistration } from "../../lib/registrationRecovery";

const ONETIMEPREKEY_COUNT = 20;

export function RegisterForm(): JSX.Element {
  const i18n = useI18n();
  const navigate = useNavigate();
  const register = useAuthStore((s) => s.register);
  const setSignalReady = useSignalStoreReady();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [stage, setStage] = useState<"idle" | "generating" | "uploading" | "registering">("idle");
  const [error, setError] = useState<string | null>(null);

  const warmSignal = (): void => {
    void import("../../lib/signal")
      .then(({ preloadSignal }) => preloadSignal())
      .catch(() => {
        // Keep the actual failure surfaced on submit; warmup is best-effort only.
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
    <div className="flex h-full items-center justify-center bg-bg p-4">
      <form
        onSubmit={onSubmit}
        className="w-full max-w-sm space-y-4 rounded-lg border border-border bg-surface-2 p-6"
      >
        <h1 className="text-2xl font-semibold text-text">{i18n.t("auth.createTitle")}</h1>
        <p className="text-sm text-text-2">{i18n.t("auth.registerHelp")}</p>

        <div className="space-y-1">
          <label htmlFor="register-username" className="text-sm text-text-2">
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

        <div className="space-y-1">
          <label htmlFor="register-password" className="text-sm text-text-2">
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

        {error && (
          <div role="alert" className="rounded-md border border-presence-dnd bg-surface p-3 text-sm">
            {error}
          </div>
        )}

        <button type="submit" className="iceq-btn-primary w-full" disabled={isBusy}>
          {stage === "generating"
            ? i18n.t("auth.generatingKeys")
            : stage === "registering"
              ? i18n.t("auth.creatingAccount")
              : stage === "uploading"
                ? i18n.t("auth.uploadingPrekeys")
                : i18n.t("auth.createAccount")}
        </button>

        <p className="text-sm text-text-2">
          {i18n.t("auth.haveAccount")} {" "}
          <Link to="/login" className="text-accent hover:underline">
            {i18n.t("auth.signIn")}
          </Link>
        </p>
      </form>
    </div>
  );
}

export default RegisterForm;

// ----------------------------------------------------------------------------
// Local hook — we don't have a direct import path from the
// signalStore because the bundle is in the same package; using
// a tiny hook keeps the JSX readable.
// ----------------------------------------------------------------------------
import { useSignalStore } from "../../store/signalStore";
function useSignalStoreReady(): (ready: boolean) => void {
  const setReady = useSignalStore((s) => s.setReady);
  return setReady;
}
