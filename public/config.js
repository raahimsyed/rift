window._CONFIG = window._CONFIG || {};

(function () {
    const host = String(window.location.hostname || "").toLowerCase();

    const zoneByHost = {
        "iptest.rift.polden.com": "5603882",
        "rift-bftc.onrender.com": "5601969",
        "riftcname.chickenkiller.com": "5601977",
        "riftedproxies.vercel.app": "5600263",
        "rift.polden.com": "5602000",
        "rift.theprojectplateau.space": "5601948"
    };

    // Any subdomain under rift.polden.com falls back to the main zone.
    let zoneId = zoneByHost[host];
    if (!zoneId && host.endsWith(".rift.polden.com")) {
        zoneId = "5602000";
    }

    // Final fallback so ads still load on unknown hosts.
    if (!zoneId) zoneId = "5602000";

    window._CONFIG.ads = {
        enabled: true,
        provider: "adsterra",
        scripts: [
            `https://www.highperformanceformat.com/${zoneId}/invoke.js`
        ]
    };
})();
