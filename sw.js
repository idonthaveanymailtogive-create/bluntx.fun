// BluntX service worker: caches the site's own files for offline/app use.
// It never touches third-party API requests, so token checks always go live to the data sources and nothing is stored.
const CACHE = "bluntx-v5";
const ASSETS = ["/", "/index.html", "/how.html", "/extension.html", "/faq.html", "/whitepaper.html",
  "/style.css", "/whitepaper.css", "/app.js", "/logo.svg", "/favicon.svg", "/favicon.png",
  "/apple-touch-icon.png", "/manifest.webmanifest", "/framebuster.js", "/icon-192.png", "/icon-512.png", "/icon-512-maskable.png"];

self.addEventListener("install", (event) => {
  event.waitUntil(caches.open(CACHE).then((c) => c.addAll(ASSETS)).then(() => self.skipWaiting()));
});

self.addEventListener("activate", (event) => {
  event.waitUntil(caches.keys()
    .then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
    .then(() => self.clients.claim()));
});

self.addEventListener("fetch", (event) => {
  const req = event.request;
  if (req.method !== "GET") return;
  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return; // API calls go straight to the network
  if (/\.(zip|pdf)$/.test(url.pathname)) return;   // downloads are never cached
  // Network first, so updates show up immediately; cached copy when offline.
  event.respondWith(
    fetch(req).then((res) => {
      if (res && res.ok && res.type === "basic") { const copy = res.clone(); caches.open(CACHE).then((c) => c.put(req, copy)); }
      return res;
    }).catch(() => caches.match(req).then((r) => r || caches.match("/index.html")))
  );
});
