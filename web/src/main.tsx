// src/main.tsx
//
// Entry point. The Vite dev server compiles this; production
// builds inline it into /dist/assets/*.
//
// Mounts the App under <BrowserRouter> and pulls the auth
// store's hydration on first paint so the first frame is
// either the login screen or the chat shell — never a
// flash of "loading…" that flickers into either of them.

import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import App from "./App";
import "./index.css";
import { useAuthStore } from "./store/authStore";

// Hydrate the auth store from localStorage before the first
// render. We do this synchronously here (rather than in a
// useEffect inside App) so the very first render of <App>
// can branch on `isAuthenticated` and route to /login or
// /app without an intermediate render.
useAuthStore.getState().hydrate();

const root = document.getElementById("root");
if (!root) {
  throw new Error("root element missing from index.html");
}

ReactDOM.createRoot(root).render(
  <React.StrictMode>
    <BrowserRouter>
      <App />
    </BrowserRouter>
  </React.StrictMode>,
);

if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker
      .register('/sw.js', { scope: '/' })
      .then(reg => {
        console.log('[IceQ SW] registered', reg.scope);
      })
      .catch(err => {
        console.error('[IceQ SW] registration failed', err);
      });
  });
}
