import assert from "node:assert/strict";
import test from "node:test";
import { en } from "../src/i18n/en.ts";
import { tr } from "../src/i18n/tr.ts";
import { createI18n, localeStorageKey, resolveLocale } from "../src/i18n/index.ts";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

test("Turkish catalog covers exactly every English message key", () => {
  assert.deepEqual(Object.keys(tr).sort(), Object.keys(en).sort());
});

test("locale resolution uses explicit choice, browser preference, then English fallback", () => {
  assert.equal(resolveLocale("tr", ["en-US"]), "tr");
  assert.equal(resolveLocale(null, ["tr-TR", "en-US"]), "tr");
  assert.equal(resolveLocale("unsupported", ["de-DE"]), "en");
});

test("runtime translation falls back to English and only persists the locale code", () => {
  const writes: Array<[string, string]> = [];
  const i18n = createI18n({
    browserLanguages: ["tr-TR"],
    storage: { getItem: () => null, setItem: (key, value) => writes.push([key, value]) },
  });
  assert.equal(i18n.t("auth.signInTitle"), tr["auth.signInTitle"]);
  i18n.setLocale("en");
  assert.deepEqual(writes, [[localeStorageKey, "en"]]);
  assert.doesNotMatch(JSON.stringify(writes), /message|conversation|uin|username|identifier/i);
});

test("migrated components do not regress to raw catalog copy", () => {
  const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
  const migrated = ["src/App.tsx", "src/components/Auth/LoginForm.tsx", "src/components/Auth/RegisterForm.tsx", "src/components/Chat/ChatShell.tsx", "src/components/Layout/MainLayout.tsx", "src/components/Layout/Sidebar.tsx"];
  const source = migrated.map((path) => readFileSync(resolve(root, path), "utf8")).join("\n");
  for (const raw of [en["app.loading"], en["auth.signInTitle"], en["auth.createTitle"], en["nav.settings"], en["nav.signOut"], en["connection.offline"], en["chat.selectContact"]]) {
    assert.ok(!source.includes(`>${raw}<`) && !source.includes(`\n          ${raw}\n`), `raw UI copy returned: ${raw}`);
  }
});
