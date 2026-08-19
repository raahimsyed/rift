importScripts("/controller/controller.sw.js");

self.addEventListener("install", () => {
    self.skipWaiting();
});

self.addEventListener("activate", (event) => {
    event.waitUntil(self.clients.claim());
});

self.addEventListener("fetch", (event) => {
    if (typeof $scramjetController !== "undefined" && $scramjetController.shouldRoute(event)) {
        event.respondWith($scramjetController.route(event));
    }
});
