import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";

const distDir = path.resolve(process.cwd(), "dist");
const assetsDir = path.join(distDir, "assets");

function listFiles(extension) {
  return readdirSync(assetsDir).filter((file) => file.endsWith(extension)).sort();
}

test("production build does not emit the broken curveasm wasm placeholder", () => {
  const wasmFiles = listFiles(".wasm");
  assert.equal(
    wasmFiles.includes("curveasm.wasm"),
    false,
    `expected no curveasm.wasm placeholder in ${assetsDir}, found: ${wasmFiles.join(", ") || "(none)"}`,
  );
});

test("production build javascript does not reference curveasm.wasm", () => {
  const jsBundle = listFiles(".js")
    .map((file) => readFileSync(path.join(assetsDir, file), "utf8"))
    .join("\n");

  assert.equal(
    jsBundle.includes("curveasm.wasm"),
    false,
    "expected built javascript not to reference curveasm.wasm",
  );
});
