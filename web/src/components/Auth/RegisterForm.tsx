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
import { uploadBundle, type OneTimePreKeyUpload, type SignedPreKeyUpload } from "../../api/keys";

const ONETIMEPREKEY_COUNT = 20;

export function RegisterForm(): JSX.Element {
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
    setStage("generating");
    try {
      const {
        assertValidIdentityKey,
        generateIdentityKeyPair,
        generatePreKeyBundle,
        generateRegistrationId,
        saveOwnIdentity,
      } = await import("../../lib/signal");
      // ---- 1. Generate identity + bundle ----
      const identity = await generateIdentityKeyPair();
      const registrationId = generateRegistrationId();
      await saveOwnIdentity(identity, registrationId);

      // The bundle includes the public key + a signature
      // that the server can verify against the identity.
      // The Signal bindings expose a helper to build the
      // signed prekey with a valid signature; we re-use
      // the same primitive for both upload and persist.
      const bundle = await generatePreKeyBundle(
        identity,
        1,
        ONETIMEPREKEY_COUNT,
        registrationId,
      );
      const signedPreKey: SignedPreKeyUpload = {
        id: bundle.signed_pre_key.id,
        public_key: bundle.signed_pre_key.public_key,
        // The signature is computed by KeyHelper.generateSignedPreKey
        // (an Ed25519 signature by the identity private key over
        // the signed prekey public bytes) and passed through here.
        // The server verifies it on upload.
        signature: bundle.signed_pre_key.signature,
      };
      const oneTimePreKeys: OneTimePreKeyUpload[] = bundle.one_time_pre_keys.map((p) => ({
        id: p.id,
        public_key: p.public_key,
      }));
      assertValidIdentityKey(bundle.identity_key);

      // ---- 2. Register the user (also mints tokens) ----
      setStage("registering");
      await register({
        username,
        password,
        identityKey: bundle.identity_key,
      });

      // ---- 3. Upload prekey bundle. Must happen after
      //         /register because /keys/bundle is authed. ----
      setStage("uploading");
      await uploadBundle({
        identity_key: bundle.identity_key,
        signed_pre_key: signedPreKey,
        one_time_pre_keys: oneTimePreKeys,
        registration_id: registrationId,
      });

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
        <h1 className="text-2xl font-semibold text-text">Create your IceQ account</h1>
        <p className="text-sm text-text-2">
          We will generate an encryption key on this device. Your messages are
          end-to-end encrypted; we can't read them and we can't recover them if
          you lose this device.
        </p>

        <div className="space-y-1">
          <label htmlFor="register-username" className="text-sm text-text-2">
            Username
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
            Password
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
            ? "Generating keys…"
            : stage === "registering"
              ? "Creating account…"
              : stage === "uploading"
                ? "Uploading prekeys…"
                : "Create account"}
        </button>

        <p className="text-sm text-text-2">
          Already have an account?{" "}
          <Link to="/login" className="text-accent hover:underline">
            Sign in
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
