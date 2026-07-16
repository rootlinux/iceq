// Static-only service worker. Authenticated traffic and navigations always use the network.
const CACHE_NAME = "iceq-static-v2";
const STATIC_ASSETS = new Set([
  "/manifest.json",
  "/icons/icon-192.png",
  "/icons/icon-512.png",
  "/icons/apple-touch-icon.png",
]);
const SENSITIVE_PREFIXES = ["/api", "/ws", "/auth", "/upload", "/download"];

self.addEventListener("install", (event) => {
  event.waitUntil(caches.open(CACHE_NAME).then((cache) => cache.addAll([...STATIC_ASSETS])));
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(caches.keys().then((keys) => Promise.all(keys.filter((key) => key !== CACHE_NAME).map((key) => caches.delete(key)))));
  self.clients.claim();
});

self.addEventListener("fetch", (event) => {
  const { request } = event;
  const url = new URL(request.url);
  if (
    request.method !== "GET" ||
    url.origin !== self.location.origin ||
    request.destination === "document" ||
    request.mode === "navigate" ||
    request.credentials === "include" ||
    request.headers.has("authorization") ||
    SENSITIVE_PREFIXES.some((prefix) => url.pathname === prefix || url.pathname.startsWith(`${prefix}/`)) ||
    !STATIC_ASSETS.has(url.pathname)
  ) return;
  event.respondWith(caches.open(CACHE_NAME).then(async (cache) => (await cache.match(request)) ?? fetch(request)));
});

self.addEventListener("push", (event) => {
  event.waitUntil(self.registration.showNotification("IceQ", {
    body: "Open IceQ to view the notification.",
    icon: "/icons/icon-192.png",
    badge: "/icons/icon-192.png",
    tag: "iceq-notification",
    data: { url: "/" },
  }));
});

self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  event.waitUntil(clients.matchAll({ type: "window", includeUncontrolled: true }).then((windows) => windows[0]?.focus() ?? clients.openWindow("/")));
});
