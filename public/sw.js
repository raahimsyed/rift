importScripts(
    "/scramjet/scramjet.codecs.js",
    "/scramjet/scramjet.config.js",
    "/scramjet/scramjet.bundle.js",
    "/scramjet/scramjet.worker.js"
);

const scramjet = new ScramjetServiceWorker(self.__scramjet$config);

async function handleRequest(event) {
    try {
        const { request } = event;

        if (scramjet.route({ request })) {
            return await scramjet.fetch({ request });
        }

        return fetch(request);
    } catch (error) {
        console.error("[Rift SW] proxy fetch failed", error);
        return fetch(event.request);
    }
}

self.addEventListener("fetch", (event) => {
    event.respondWith(handleRequest(event));
});
