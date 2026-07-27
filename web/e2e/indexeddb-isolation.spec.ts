import { expect, test } from "@playwright/test";
import { assertNoSensitiveBody, assertSignalHealthy, installSyntheticAPI, publishSyntheticDirectory } from "./helpers";

test.use({ serviceWorkers: "block" });

const ACCOUNT_A = {
  uin: 700000011,
  username: "synthetic_account_a",
  accessToken: "synthetic.account.a",
  refreshToken: "synthetic-refresh-a",
};
const ACCOUNT_B = {
  uin: 700000022,
  username: "synthetic_account_b",
  accessToken: "synthetic.account.b",
  refreshToken: "synthetic-refresh-b",
};

test("auth account change deletes prior IndexedDB identity before the next session survives reload", async ({ page }) => {
  const network = await installSyntheticAPI(page, [ACCOUNT_A, ACCOUNT_B]);
  await page.goto("/login");

  const switched = await page.evaluate(async ({ accountA, accountB }) => {
    const { useAuthStore } = await import("/src/store/authStore.ts");
    const idb = await import("/src/lib/indexeddb.ts");
    const signal = await import("/src/lib/signal.ts");
    await idb.clearAll();

    await useAuthStore.getState().setSession(
      { uin: accountA.uin, username: accountA.username },
      accountA.accessToken,
      accountA.refreshToken,
    );
    const deviceId = await idb.loadOrCreateDeviceId();
    const namespaceA = { uin: accountA.uin, deviceId };
    const identityA = await signal.generateIdentityKeyPair();
    await signal.saveOwnIdentity(identityA, 101, namespaceA);

    await useAuthStore.getState().setSession(
      { uin: accountB.uin, username: accountB.username },
      accountB.accessToken,
      accountB.refreshToken,
    );
    const namespaceB = { uin: accountB.uin, deviceId: await idb.loadOrCreateDeviceId() };
    const identityB = await signal.generateIdentityKeyPair();
    await signal.saveOwnIdentity(identityB, 202, namespaceB);
    const bundleB = await signal.generatePreKeyBundle(identityB, 1, 1, 202, namespaceB);
    await idb.setSecuritySetupCompleted(namespaceB);
    idb.setActiveCryptoNamespace(namespaceB);

    const priorIdentity = await idb.loadIdentity(namespaceA);
    const currentIdentity = await idb.loadIdentity(namespaceB);
    const mixedIdentity = await idb.loadIdentity({ uin: accountA.uin, deviceId: `${namespaceB.deviceId}_mixed` });

    return {
      namespaceA,
      namespaceB,
      priorIdentityPresent: priorIdentity !== null,
      currentPublicKey: currentIdentity?.publicKey ?? "",
      currentHasPrivateKey: Boolean(currentIdentity?.privateKey),
      mixedIdentityPresent: mixedIdentity !== null,
      directoryBundle: {
        identity_key: bundleB.identity_key,
        signed_pre_key: bundleB.signed_pre_key,
        pre_key: bundleB.one_time_pre_keys[0],
        registration_id: bundleB.registration_id,
      },
    };
  }, { accountA: ACCOUNT_A, accountB: ACCOUNT_B });

  expect(switched.priorIdentityPresent).toBe(false);
  expect(switched.currentPublicKey).not.toBe("");
  expect(switched.currentHasPrivateKey).toBe(true);
  expect(switched.mixedIdentityPresent).toBe(false);
  expect(switched.directoryBundle.identity_key).toBe(switched.currentPublicKey);
  await publishSyntheticDirectory(page, ACCOUNT_B.uin, switched.directoryBundle);

  await page.reload();
  await expect(page.getByText(ACCOUNT_B.username, { exact: false })).toBeVisible();
  await assertSignalHealthy(page);
  const reloaded = await page.evaluate(async ({ namespaceA, namespaceB }) => {
    const idb = await import("/src/lib/indexeddb.ts");
    idb.setActiveCryptoNamespace(namespaceB);
    const currentIdentity = await idb.loadIdentity(namespaceB);
    return {
      active: idb.getActiveCryptoNamespace(),
      currentPublicKey: currentIdentity?.publicKey ?? "",
      currentHasPrivateKey: Boolean(currentIdentity?.privateKey),
      priorIdentityPresent: await idb.loadIdentity(namespaceA) !== null,
      localStorageValues: Object.values(localStorage),
    };
  }, { namespaceA: switched.namespaceA, namespaceB: switched.namespaceB });

  expect(reloaded.active).toEqual(switched.namespaceB);
  expect(reloaded.currentPublicKey).toBe(switched.currentPublicKey);
  expect(reloaded.currentHasPrivateKey).toBe(true);
  expect(reloaded.priorIdentityPresent).toBe(false);
  expect(reloaded.localStorageValues.join(" ")).not.toContain("privateKey");
  await assertNoSensitiveBody(page, network);
});
