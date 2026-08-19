/*
 * Rift's scramjet bootstrap, built on @mercuryworkshop/scramjet-controller.
 *
 * Requires, in order, before this script:
 *   <script src="/scramjet/scramjet.js"></script>
 *   <script src="/controller/controller.api.js"></script>
 *
 * Replaces the old self.__scramjet$config / scramjet.all.js integration, which
 * was built against a "2.0.0-alpha" build that no longer exists (GitHub's
 * "latest" release tag is a rolling continuous build and has since moved on
 * to a restructured file layout / API).
 */
(function () {
    "use strict";

    function getWispUrl() {
        const protocol = self.location.protocol === "https:" ? "wss:" : "ws:";
        return `${protocol}//${self.location.host}/wisp/`;
    }

    // Ported from the previous sw.js's rewriteScramjetTarget/buildNowggNavigationPatch:
    // now.gg cloud sessions on Render get assigned a backend hostname shaped like
    // "<id>.ip.<region>.onrender.com", which isn't externally resolvable — it needs
    // to be rewritten to "<id>.ip.nowgg.fun" for requests to actually reach it.
    function rewriteNowggHostname(hostname) {
        const match = String(hostname || "").match(/^(\d+)\.ip\.[^.]+\.onrender\.com$/i);
        if (!match) return null;
        return `${match[1]}.ip.nowgg.fun`;
    }

    class NowggRewritePlugin extends self.$scramjetController.ManagedPlugin {
        constructor() {
            super("rift-nowgg-rewrite", []);
        }

        install(frame) {
            super.install(frame);
            this.tap(frame.hooks.fetch.request, (context, props) => {
                const rewritten = rewriteNowggHostname(props.url.hostname);
                if (rewritten) {
                    props.url.hostname = rewritten;
                }
            });
        }
    }

    async function waitForServiceWorker(timeoutMs = 10000) {
        if (navigator.serviceWorker.controller) return navigator.serviceWorker.controller;

        const registration = await navigator.serviceWorker.register("/sw.js");

        const ready = navigator.serviceWorker.ready.then(() => {});
        const controllerChanged = new Promise((resolve) => {
            const onChange = () => {
                navigator.serviceWorker.removeEventListener("controllerchange", onChange);
                resolve();
            };
            navigator.serviceWorker.addEventListener("controllerchange", onChange, { once: true });
        });
        const timeout = new Promise((resolve) => setTimeout(resolve, timeoutMs));

        await Promise.race([ready, controllerChanged, timeout]);
        return navigator.serviceWorker.controller || registration.active || registration.waiting;
    }

    let readyPromise = null;
    const framesByElement = new WeakMap();

    async function init() {
        if (typeof self.$scramjet === "undefined") {
            throw new Error("Rift: /scramjet/scramjet.js must be loaded before rift-scramjet.js");
        }
        if (typeof self.$scramjetController === "undefined") {
            throw new Error("Rift: /controller/controller.api.js must be loaded before rift-scramjet.js");
        }

        const serviceworker = await waitForServiceWorker();
        if (!serviceworker) {
            throw new Error("Rift: no service worker available for the scramjet controller");
        }

        const { default: LibcurlClient } = await import("/libcurl/index.mjs");
        const transport = new LibcurlClient({ wisp: getWispUrl() });

        const controller = new self.$scramjetController.Controller({
            serviceworker,
            transport,
        });

        await controller.wait();
        return controller;
    }

    self.RiftScramjet = {
        get ready() {
            if (!readyPromise) readyPromise = init();
            return readyPromise;
        },

        async createFrame(iframeElement, extraPlugins) {
            const controller = await this.ready;
            const plugins = [new NowggRewritePlugin()].concat(extraPlugins || []);
            return controller.createFrame(iframeElement, { plugins });
        },

        // Get-or-create a persistent Frame bound to a given iframe element, so
        // repeated navigations in the same panel/tab reuse the same proxy context.
        async getOrCreateFrame(iframeElement, extraPlugins) {
            let frame = framesByElement.get(iframeElement);
            if (!frame) {
                frame = await this.createFrame(iframeElement, extraPlugins);
                framesByElement.set(iframeElement, frame);
            }
            return frame;
        },

        // Returns the proxied URL for `targetUrl` as a string, without navigating —
        // for callers (like browser.html) that assign iframe.src themselves.
        async encodeUrl(iframeElement, targetUrl) {
            const frame = await this.getOrCreateFrame(iframeElement);
            return self.$scramjet.rewriteUrl(targetUrl, frame.context, {
                origin: new URL(location.href),
                base: new URL(location.href),
            });
        },

        // Navigates a panel/tab's Frame directly.
        async go(iframeElement, targetUrl) {
            const frame = await this.getOrCreateFrame(iframeElement);
            frame.go(targetUrl);
            return frame;
        },

        rewriteNowggHostname,
    };
})();
