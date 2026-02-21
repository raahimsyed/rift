"use strict";

(function () {
    const cfg = window._CONFIG?.ads;
    if (!cfg || !cfg.enabled) return;
    if (cfg.provider !== "adsterra") return;

    const scriptUrls = Array.isArray(cfg.scripts)
        ? cfg.scripts.map((u) => String(u || "").trim()).filter(Boolean)
        : [];

    if (!scriptUrls.length) {
        console.warn("[rift-ads] No Adsterra scripts configured in /config.js");
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
        script.referrerPolicy = "strict-origin-when-cross-origin";
        script.addEventListener("load", () => {
            console.log("[rift-ads] Loaded:", url);
        });
        script.addEventListener("error", () => {
            console.error("[rift-ads] Failed:", url);
        });
        document.head.appendChild(script);
    }
})();

