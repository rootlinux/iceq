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
  return {
    name: "iceq-e2e-probe-sink",
    configureServer(server) {
      server.middlewares.use((request, response, next) => {
        const pathname = new URL(request.url ?? "/", "http://127.0.0.1").pathname;
        if (request.headers["x-iceq-e2e-cache-probe"] !== "1" || !E2E_PROBE_PATHS.has(pathname)) {
          next();
          return;
        }
        response.statusCode = 204;
        response.end();
      });
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
