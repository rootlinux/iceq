// Static-only service worker. Authenticated traffic and navigations always use the network.
const CACHE_NAME = "iceq-static-v3";
const HASHED_ASSET = /^\/assets\/[a-zA-Z0-9_-]+-[a-zA-Z0-9_-]{8,}\.(js|css)$/;
const SENSITIVE_PREFIXES = ["/api", "/ws", "/auth", "/upload", "/download"];

self.addEventListener("install", (event) => {
  event.waitUntil(caches.open(CACHE_NAME));
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
    request.credentials !== "omit" ||
    request.headers.has("authorization") ||
    SENSITIVE_PREFIXES.some((prefix) => url.pathname === prefix || url.pathname.startsWith(`${prefix}/`)) ||
    url.search !== "" ||
    !HASHED_ASSET.test(url.pathname)
  ) return;
  event.respondWith(caches.open(CACHE_NAME).then(async (cache) => {
    const cached = await cache.match(request);
    if (cached) return cached;
    const response = await fetch(request);
    const contentType = response.headers.get("content-type")?.split(";", 1)[0]?.trim().toLowerCase() ?? "";
    const expectedType = url.pathname.endsWith(".css") ? "text/css" : "javascript";
    const typeMatches = expectedType === "text/css"
      ? contentType === "text/css"
      : contentType === "text/javascript" || contentType === "application/javascript";
    if (response.ok && !response.redirected && (response.type === "basic" || response.type === "cors") && typeMatches) {
      await cache.put(request, response.clone());
    }
    return response;
  }));
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
