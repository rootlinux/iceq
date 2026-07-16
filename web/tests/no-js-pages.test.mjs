import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
test("noscript links point at self-contained static bilingual pages", () => {
  const index = readFileSync(resolve(root, "index.html"), "utf8");
  for (const page of ["security", "install", "tor"]) {
    assert.match(index, new RegExp(`/${page}\\.html`));
    const html = readFileSync(resolve(root, `public/${page}.html`), "utf8");
    assert.match(html, /lang="en"/);
    assert.match(html, /lang="tr"/);
    assert.match(html, /JavaScript/i);
    assert.match(html, /end-to-end encryption|uçtan uca şifreleme/i);
    assert.doesNotMatch(html, /https?:\/\/[^"']+\.(css|js|png|woff)/i);
  }
});
