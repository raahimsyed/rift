"use strict";

(function (s) {
    s.dataset.zone = "11786783";
    s.src = "https://al5sm.com/tag.min.js";
})([document.documentElement, document.body].filter(Boolean).pop().appendChild(document.createElement("script")));

(function () {
    const AD_HINT_RE = /(adsterra|advert|banner|sponsor|promo|popunder|popup|highperformanceformat|laptopchoose|invoke\.js|al5sm)/i;
    const BLOCKED_SANDBOX_FLAGS = new Set(["allow-popups", "allow-popups-to-escape-sandbox"]);
    const STORAGE_KEY = "rift_ads_last_popup_at";
    const nativeOpen = typeof window.open === "function" ? window.open.bind(window) : null;
    const path = String(window.location.pathname || "/").toLowerCase();
    const query = new URLSearchParams(window.location.search || "");
    const allowedPaths = new Set([
        "/",
        "/index.html",
        "/account",
        "/account.html",
        "/apps",
        "/apps.html",
        "/browser",
        "/browser.html",
        "/chat",
        "/chat.html",
        "/cloud",
        "/cloud.html",
        "/credits",
        "/credits.html",
        "/music",
        "/music.html",
        "/settings",
        "/settings.html",
        "/social-media-&-partners",
        "/social-media-&-partners.html",
        "/soundboard",
        "/soundboard.html",
        "/rift_media",
        "/rift_media.html",
        "/os",
        "/os/",
        "/os/index.html",
        "/os/account",
        "/os/account.html",
        "/os/account/index.html",
        "/os/apps",
        "/os/apps.html",
        "/os/apps/index.html",
        "/os/browser",
        "/os/browser.html",
        "/os/browser/index.html",
        "/os/chat",
        "/os/chat.html",
        "/os/chat/index.html",
        "/os/media",
        "/os/media.html",
        "/os/media/index.html",
        "/os/music",
        "/os/music.html",
        "/os/music/index.html",
        "/os/settings",
        "/os/settings.html",
        "/os/settings/index.html",
    ]);

    const shouldAutoClosePopup = (value) => {
        const raw = String(value || "").trim();
        if (!raw || raw === "about:blank") return false;
        if (/^(javascript:|mailto:|tel:|sms:|data:|blob:|#)/i.test(raw)) return false;
        try {
            const url = new URL(raw, window.location.href);
            return url.origin !== window.location.origin;
        } catch {
            return true;
        }
    };

    const isEligiblePage = () => {
        if (!allowedPaths.has(path)) return false;
        if (path === "/games" || path === "/games.html") return false;
        if (path === "/os/games" || path === "/os/games.html" || path === "/os/games/index.html") return false;
        if (path === "/embed" || path === "/embed.html") return false;
        if (query.has("url") || query.has("game") || query.get("view") === "games-only") return false;
        return true;
    };

    const getCooldownMs = () => {
        const value = Number(window._CONFIG?.ads?.cooldownMs || 0);
        return Number.isFinite(value) && value > 0 ? value : 2 * 60 * 1000;
    };

    const getLastPopupAt = () => {
        try {
            const value = Number(localStorage.getItem(STORAGE_KEY) || 0);
            return Number.isFinite(value) && value > 0 ? value : 0;
        } catch {
            return 0;
        }
    };

    const setLastPopupAt = (value) => {
        try {
            localStorage.setItem(STORAGE_KEY, String(value));
        } catch {}
    };

    const isCooldownReady = () => {
        return Date.now() - getLastPopupAt() >= getCooldownMs();
    };

    const schedulePopupClose = (popup, markShown) => {
        if (!popup) return;
        if (markShown) {
            setLastPopupAt(Date.now());
        }
        try {
            popup.blur();
        } catch {}
        try {
            window.focus();
        } catch {}
        const closeDelay = 1000 + Math.floor(Math.random() * 4000);
        window.setTimeout(() => {
            try {
                if (!popup.closed) popup.close();
            } catch {}
            try {
                window.focus();
            } catch {}
        }, closeDelay);
    };

    const readNodeText = (node) => {
        if (!node || !(node instanceof Element)) return "";
        const values = [
            node.id,
            node.className,
            node.getAttribute("name"),
            node.getAttribute("src"),
            node.getAttribute("href"),
            node.getAttribute("data-ad-client"),
            node.getAttribute("data-ad-slot"),
            node.getAttribute("data-zone"),
            node.getAttribute("aria-label"),
            node.getAttribute("title"),
        ];
        return values
            .filter((value) => typeof value === "string" && value.trim())
            .join(" ");
    };

    const isLikelyAdNode = (node) => {
        if (!node || !(node instanceof Element)) return false;
        if (node.dataset.riftAdNode === "1") return true;
        return AD_HINT_RE.test(readNodeText(node));
    };

    const markAdTree = (root) => {
        if (!root || !(root instanceof Element)) return;
        root.dataset.riftAdNode = "1";
        for (const child of root.querySelectorAll("*")) {
            child.dataset.riftAdNode = "1";
        }
    };

    const hasMarkedAdAncestor = (node) => {
        return !!(node instanceof Element && node.closest("[data-rift-ad-node=\"1\"]"));
    };

    const isLikelyAdInteraction = (node) => {
        if (!(node instanceof Element)) return false;
        let current = node;
        while (current) {
            if (isLikelyAdNode(current)) return true;
            current = current.parentElement;
        }
        return false;
    };

    const hardenAdFrame = (frame) => {
        if (!(frame instanceof HTMLIFrameElement)) return;
        if (frame.dataset.riftAdFrameHardened === "1") return;
        if (!isLikelyAdInteraction(frame) && !hasMarkedAdAncestor(frame)) return;

        const tokens = new Set(
            String(frame.getAttribute("sandbox") || "")
                .split(/\s+/)
                .map((token) => token.trim())
                .filter(Boolean)
        );
        for (const token of BLOCKED_SANDBOX_FLAGS) tokens.delete(token);
        if (!tokens.size) {
            tokens.add("allow-scripts");
            tokens.add("allow-same-origin");
            tokens.add("allow-forms");
        }
        frame.setAttribute("sandbox", Array.from(tokens).join(" "));
        frame.dataset.riftAdFrameHardened = "1";
        frame.dataset.riftAdNode = "1";
    };

    const installAnchorAutoClose = () => {
        if (window.__riftAdsAnchorHooked) return;
        if (!nativeOpen) return;
        window.__riftAdsAnchorHooked = true;

        document.addEventListener(
            "click",
            (event) => {
                if (event.defaultPrevented) return;
                if (event.button !== 0) return;
                if (event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;

                const target = event.target instanceof Element ? event.target.closest("a[href], area[href]") : null;
                if (!target) return;
                if (target.hasAttribute("download")) return;
                if (!isLikelyAdInteraction(target) && !hasMarkedAdAncestor(target)) return;

                const href = target.href || target.getAttribute("href") || "";
                if (!shouldAutoClosePopup(href)) return;

                const openTarget = String(target.getAttribute("target") || "_blank").trim().toLowerCase();
                if (openTarget && openTarget !== "_blank") return;

                event.preventDefault();
                if (!isEligiblePage() || !isCooldownReady()) return;
                schedulePopupClose(nativeOpen(href, "_blank", "noopener,noreferrer"), true);
            },
            true
        );
    };

    const installAdMutationObserver = () => {
        if (window.__riftAdsObserverHooked) return;
        if (typeof MutationObserver !== "function") return;
        window.__riftAdsObserverHooked = true;

        const visitNode = (node) => {
            if (!(node instanceof Element)) return;

            if (isLikelyAdNode(node) || hasMarkedAdAncestor(node)) {
                markAdTree(node);
            }

            if (node.matches("iframe")) {
                hardenAdFrame(node);
            }

            for (const element of node.querySelectorAll("*")) {
                if (isLikelyAdNode(element) || hasMarkedAdAncestor(element)) {
                    element.dataset.riftAdNode = "1";
                }
                if (element instanceof HTMLIFrameElement) {
                    hardenAdFrame(element);
                }
            }
        };

        const observer = new MutationObserver((mutations) => {
            for (const mutation of mutations) {
                for (const node of mutation.addedNodes) {
                    visitNode(node);
                }
            }
        });

        observer.observe(document.documentElement || document.body, {
            childList: true,
            subtree: true,
        });

        for (const element of document.querySelectorAll("*")) {
            visitNode(element);
        }
    };

    const installPopupAutoClose = () => {
        if (window.__riftAdsPopupHooked) return;
        if (!nativeOpen) return;
        window.__riftAdsPopupHooked = true;

        window.open = function (...args) {
            const targetUrl = args[0];
            if (!shouldAutoClosePopup(targetUrl)) {
                return nativeOpen(...args);
            }
            if (!isEligiblePage() || !isCooldownReady()) {
                return null;
            }
            const popup = nativeOpen(...args);
            schedulePopupClose(popup, true);
            return popup;
        };
    };

    installPopupAutoClose();
    installAnchorAutoClose();
    installAdMutationObserver();

    const cfg = window._CONFIG?.ads;
    if (!cfg || !cfg.enabled) return;
    if (cfg.provider !== "adsterra") return;
    if (!isEligiblePage()) return;

    const scriptUrls = Array.isArray(cfg.scripts)
        ? cfg.scripts.map((value) => String(value || "").trim()).filter(Boolean)
        : [];

    if (!scriptUrls.length) {
        console.warn("[rift-ads] no ad scripts configured in /config.js");
        return;
    }

    if (window.__riftAdsBooted) return;
    window.__riftAdsBooted = true;

    const seen = new Set();
    for (const url of scriptUrls) {
        if (seen.has(url)) continue;
        seen.add(url);

        const script = document.createElement("script");
        script.src = url;
        script.async = true;
        script.dataset.riftAds = "adsterra";
        script.dataset.riftAdNode = "1";
        script.referrerPolicy = "strict-origin-when-cross-origin";
        script.addEventListener("load", () => {
            console.log("[rift-ads] loaded:", url);
        });
        script.addEventListener("error", () => {
            console.error("[rift-ads] failed:", url);
        });
        document.head.appendChild(script);
    }
})();
