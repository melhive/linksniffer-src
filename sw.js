const CACHE_NAME = "linksniffer-v1.0.0";
const APP_SHELL = [
  "./",
  "./index.html",
  "./style.css",
  "./heuristics.js",
  "./app.js",
  "./manifest.json",
  "./icon.svg",
];

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(APP_SHELL))
  );
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k)))
    )
  );
  self.clients.claim();
});

// App shell: cache-first. Anything else (e.g. calls to the worker API): network-first,
// so scan requests always try to hit live threat intel and are never served stale.
self.addEventListener("fetch", (event) => {
  const url = new URL(event.request.url);
  const isAppShell = APP_SHELL.some((p) => url.pathname.endsWith(p.replace("./", "/")) || url.pathname === "/");

  if (event.request.method !== "GET") return; // let API POSTs pass straight through

  if (isAppShell) {
    event.respondWith(
      caches.match(event.request).then((cached) => cached || fetch(event.request))
    );
  } else {
    event.respondWith(
      fetch(event.request).catch(() => caches.match(event.request))
    );
  }
});
