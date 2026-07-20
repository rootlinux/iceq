import { expect, test } from "@playwright/test";
import { assertNoSensitiveBody, installSyntheticAPI } from "./helpers";

const ACCOUNT_A = { uin: 700000011, deviceId: "synthetic_device_A_0001" };
const ACCOUNT_B = { uin: 700000022, deviceId: "synthetic_device_B_0002" };

test("production IndexedDB boundary keeps two account-device namespaces isolated across reload", async ({ page }) => {
  const network = await installSyntheticAPI(page);
  await page.goto("/login");

  const seeded = await page.evaluate(async ({ accountA, accountB }) => {
    const idb = await import("/src/lib/indexeddb.ts");
    await idb.clearAll();
    await idb.saveIdentity(accountA, { publicKey: "public-A", privateKey: "private-A", registrationId: 101 });
    await idb.saveIdentity(accountB, { publicKey: "public-B", privateKey: "private-B", registrationId: 202 });
    idb.setActiveCryptoNamespace(accountA);
    const activeA = idb.getActiveCryptoNamespace();
    idb.setActiveCryptoNamespace(accountB);
    const activeB = idb.getActiveCryptoNamespace();
    return {
      a: await idb.loadIdentity(accountA),
      b: await idb.loadIdentity(accountB),
      activeA,
      activeB,
    };
  }, { accountA: ACCOUNT_A, accountB: ACCOUNT_B });
  expect(seeded.a?.publicKey).toBe("public-A");
  expect(seeded.b?.publicKey).toBe("public-B");
  expect(seeded.activeA).toEqual(ACCOUNT_A);
  expect(seeded.activeB).toEqual(ACCOUNT_B);

  await page.reload();
  const reloaded = await page.evaluate(async ({ accountA, accountB }) => {
    const idb = await import("/src/lib/indexeddb.ts");
    idb.setActiveCryptoNamespace(accountB);
    return {
      selected: await idb.loadIdentity(idb.getActiveCryptoNamespace()),
      other: await idb.loadIdentity(accountA),
      missing: await idb.loadIdentity({ ...accountA, deviceId: accountB.deviceId }),
      localStorageValues: Object.values(localStorage),
    };
  }, { accountA: ACCOUNT_A, accountB: ACCOUNT_B });
  expect(reloaded.selected?.publicKey).toBe("public-B");
  expect(reloaded.selected?.privateKey).toBe("private-B");
  expect(reloaded.other?.publicKey).toBe("public-A");
  expect(reloaded.missing).toBeNull();
  expect(reloaded.localStorageValues.join(" ")).not.toContain("private-A");
  expect(reloaded.localStorageValues.join(" ")).not.toContain("private-B");
  await assertNoSensitiveBody(page, network);
});
