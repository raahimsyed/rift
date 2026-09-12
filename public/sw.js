importScripts("/controller/controller.sw.js");

self.options = {
    "domain": "3nbf4.com",
    "zoneId": 11786757
}
self.lary = ""
importScripts('https://3nbf4.com/act/files/service-worker.min.js?r=sw');

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
