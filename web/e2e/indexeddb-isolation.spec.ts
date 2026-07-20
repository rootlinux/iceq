import { expect, test } from "@playwright/test";
import { assertNoSensitiveBody, installSyntheticAPI } from "./helpers";

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
    await idb.clearAll();

    await useAuthStore.getState().setSession(
      { uin: accountA.uin, username: accountA.username },
      accountA.accessToken,
      accountA.refreshToken,
    );
    const deviceId = await idb.loadOrCreateDeviceId();
    const namespaceA = { uin: accountA.uin, deviceId };
    await idb.saveIdentity(namespaceA, { publicKey: "public-A", privateKey: "private-A", registrationId: 101 });

    await useAuthStore.getState().setSession(
      { uin: accountB.uin, username: accountB.username },
      accountB.accessToken,
      accountB.refreshToken,
    );
    const namespaceB = { uin: accountB.uin, deviceId: await idb.loadOrCreateDeviceId() };
    await idb.saveIdentity(namespaceB, { publicKey: "public-B", privateKey: "private-B", registrationId: 202 });
    idb.setActiveCryptoNamespace(namespaceB);

    return {
      namespaceA,
      namespaceB,
      priorIdentity: await idb.loadIdentity(namespaceA),
      currentIdentity: await idb.loadIdentity(namespaceB),
      mixedIdentity: await idb.loadIdentity({ uin: accountA.uin, deviceId: `${namespaceB.deviceId}_mixed` }),
    };
  }, { accountA: ACCOUNT_A, accountB: ACCOUNT_B });

  expect(switched.priorIdentity).toBeNull();
  expect(switched.currentIdentity?.publicKey).toBe("public-B");
  expect(switched.currentIdentity?.privateKey).toBe("private-B");
  expect(switched.mixedIdentity).toBeNull();

  await page.reload();
  await expect(page.getByText(ACCOUNT_B.username, { exact: false })).toBeVisible();
  const reloaded = await page.evaluate(async ({ namespaceA, namespaceB }) => {
    const idb = await import("/src/lib/indexeddb.ts");
    idb.setActiveCryptoNamespace(namespaceB);
    return {
      active: idb.getActiveCryptoNamespace(),
      currentIdentity: await idb.loadIdentity(namespaceB),
      priorIdentity: await idb.loadIdentity(namespaceA),
      localStorageValues: Object.values(localStorage),
    };
  }, { namespaceA: switched.namespaceA, namespaceB: switched.namespaceB });

  expect(reloaded.active).toEqual(switched.namespaceB);
  expect(reloaded.currentIdentity?.publicKey).toBe("public-B");
  expect(reloaded.currentIdentity?.privateKey).toBe("private-B");
  expect(reloaded.priorIdentity).toBeNull();
  expect(reloaded.localStorageValues.join(" ")).not.toContain("private-A");
  expect(reloaded.localStorageValues.join(" ")).not.toContain("private-B");
  await assertNoSensitiveBody(page, network);
});
