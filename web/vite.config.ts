// Vite config for the IceQ web client.
//
// Notes:
//   - Dev server proxies /api -> the Caddy front door at :80 (or
//     :443 in TLS). The browser keeps the same origin so the
//     access_token cookie / Authorization header doesn't leak to
//     a different site.
//   - Production builds go to /dist. Docker copies this into
//     caddy:2-alpine at /srv. Caddy's try_files rewrite makes
//     /app/* -> /index.html so the SPA router takes over.
//   - Production strips source maps; in dev we keep them for
//     debugging.
import { defineConfig, type Plugin } from "vite";
import react from "@vitejs/plugin-react";
import path from "node:path";

const E2E_PROBE_PATHS = new Set(["/api/e2e-cache-probe", "/ws/e2e-cache-probe"]);

function e2eProbeSink(): Plugin {
  // configureServer wires this into `vite` (the dev server); preview mode
  // uses a separate Connect app entirely, so the production-build service
  // worker E2E test (which serves via `vite preview`, not `vite dev`)
  // needs the same middleware registered through configurePreviewServer
  // too, or its cache probes 404 instead of returning 204.
  const respondToProbe = (request: import("node:http").IncomingMessage, response: import("node:http").ServerResponse, next: () => void): void => {
    const pathname = new URL(request.url ?? "/", "http://127.0.0.1").pathname;
    if (request.headers["x-iceq-e2e-cache-probe"] !== "1" || !E2E_PROBE_PATHS.has(pathname)) {
      next();
      return;
    }
    response.statusCode = 204;
    response.end();
  };
  return {
    name: "iceq-e2e-probe-sink",
    configureServer(server) {
      server.middlewares.use(respondToProbe);
    },
    configurePreviewServer(server) {
      server.middlewares.use(respondToProbe);
    },
  };
}

export default defineConfig(({ mode }) => ({
  plugins: [react(), ...(process.env.ICEQ_E2E === "1" ? [e2eProbeSink()] : [])],
  resolve: {
    alias: {
      "@privacyresearch/curve25519-typescript": path.resolve(
        __dirname,
        "src/lib/vendor/curve25519.ts",
      ),
    },
  },
  build: {
    outDir: "dist",
    sourcemap: mode === "development",
    // The default chunking is fine; we don't have a giant vendor
    // pool, and aggressive code splitting just makes dev harder.
    //
    // ICEQ_E2E=1 adds a second, independent entry point (see
    // e2e/bridge/e2eBridge.ts) that re-exports the app modules the E2E
    // helpers need to reach directly when running against this real build
    // via `vite preview` instead of `vite dev`. It's never linked from
    // index.html or any app code, so it changes nothing about what a real
    // deploy (built without ICEQ_E2E set) ships.
    rollupOptions: process.env.ICEQ_E2E === "1" ? {
      input: {
        main: path.resolve(__dirname, "index.html"),
        e2eBridge: path.resolve(__dirname, "e2e/bridge/e2eBridge.ts"),
      },
      output: {
        entryFileNames: (chunkInfo) => (
          chunkInfo.name === "e2eBridge" ? "e2e-bridge.js" : "assets/[name]-[hash].js"
        ),
      },
    } : undefined,
  },
  server: {
    port: 5173,
    proxy: {
      // In dev, the Caddy front door isn't running. Vite forwards
      // /api/* to whatever's serving IceQ on the host (typically
      // the docker-compose stack via 127.0.0.1:80 or 127.0.0.1:443).
      "/api": {
        target: "http://localhost",
        changeOrigin: false,
        secure: false,
      },
      // /ws is the WebSocket endpoint. The browser will hit it on
      // the same host (no DNS) and the Vite proxy upgrades to ws.
      "/ws": {
        target: "ws://localhost",
        ws: true,
        changeOrigin: false,
        secure: false,
      },
    },
  },
  define: {
    // __DEV__ is true in `vite` (dev server) and `vite build` is
    // production. A vite-plugin can flip the polarity; we use
    // import.meta.env.DEV because that's the canonical Vite
    // signal. We re-export a constant so the rest of the code
    // can read it without a vite-only import.
    __DEV__: JSON.stringify(mode !== "production"),
  },
}));
