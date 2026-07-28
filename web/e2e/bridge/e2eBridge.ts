// Test-only bridge, built as its own Vite entry (see vite.config.ts, gated
// behind ICEQ_E2E=1) so E2E tests can reach these exact modules with a
// stable, non-hashed output filename regardless of which server they run
// against.
//
// Why this exists: most of the E2E suite runs against `vite dev`
// (playwright.config.ts), where test helpers reach internal app modules
// via dynamic import of their raw dev-server source path, e.g.
// import("/src/lib/indexeddb.ts") -- Vite's dev server transpiles that on
// the fly. The service-worker test (e2e/production/service-worker.spec.ts)
// has to run against a real production build instead (see that file for
// why), and a production build has no /src/*.ts paths to import at all --
// everything is bundled into hashed chunks under /assets/, and individual
// internal modules aren't separately addressable once bundled. This file
// is a second, deliberately separate build entry that re-exposes exactly
// the modules e2e/helpers.ts's dynamic imports need, under a fixed
// filename (e2e-bridge.js) helpers.ts falls back to when the dev-style
// path 404s.
//
// Exposed as a plain `window` assignment rather than ES module exports:
// this file is a build *entry*, and nothing in the real app graph imports
// FROM it (only a runtime string-based dynamic import from test code
// does, which the bundler's static analysis can't see) -- Rollup/Rolldown
// tree-shook a first attempt using `export * as` down to an empty module
// because it could prove none of its own exports were statically consumed
// anywhere. Assigning to `window` is an observable side effect the
// bundler cannot remove.
//
// This does not change what tests can already do -- Playwright's
// page.evaluate already has unrestricted access to every export of every
// module in dev mode. It only makes that same, pre-existing test
// capability keep working when the page under test is a production build
// instead of the dev server. It is never referenced by index.html or any
// application code, so it ships in no real user-facing artifact, and it
// is entirely absent unless ICEQ_E2E=1 is set at build time.
import * as indexeddb from "../../src/lib/indexeddb";
import * as signal from "../../src/lib/signal";
import * as authStore from "../../src/store/authStore";
import * as signalStore from "../../src/store/signalStore";

declare global {
  interface Window {
    __iceqE2EBridge?: {
      indexeddb: typeof indexeddb;
      signal: typeof signal;
      authStore: typeof authStore;
      signalStore: typeof signalStore;
    };
  }
}

window.__iceqE2EBridge = { indexeddb, signal, authStore, signalStore };
