import assert from "node:assert/strict";
import test from "node:test";

import { ApiError, ApiNetworkError } from "../src/api/client.ts";
import { getLoginErrorMessage } from "../src/components/Auth/LoginForm.tsx";
import { en } from "../src/i18n/en.ts";

const t = (key: keyof typeof en): string => en[key];

test("login translates invalid credentials instead of exposing a raw 401", () => {
  const error = new ApiError("401", 401, "INVALID_CREDENTIALS");
  const message = getLoginErrorMessage(error, t);

  assert.equal(message, en["auth.invalidCredentials"]);
  assert.doesNotMatch(message, /401/);
});

test("login gives rate-limit, network, and generic failures safe localized copy", () => {
  assert.equal(
    getLoginErrorMessage(new ApiError("429", 429, "RATE_LIMITED"), t),
    en["auth.rateLimited"],
  );
  assert.equal(
    getLoginErrorMessage(new ApiNetworkError("offline"), t),
    en["auth.networkError"],
  );
  assert.equal(
    getLoginErrorMessage(new Error("internal detail"), t),
    en["auth.signInFailed"],
  );
});
