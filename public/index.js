"use strict";

const form = document.getElementById("sj-form");
const address = document.getElementById("sj-address");
const searchEngine = document.getElementById("sj-search-engine");
const error = document.getElementById("sj-error");
const errorCode = document.getElementById("sj-error-code");
const frame = document.getElementById("sj-frame");

// BareMux wiring for network transport
const connection = new BareMux.BareMuxConnection("/baremux/worker.js");

async function ensureTransport() {
    const transport = await connection.getTransport();
    const wispUrl =
        (location.protocol === "https:" ? "wss" : "ws") +
        "://" +
        location.host +
        "/wisp/";

    if (transport !== "/libcurl/index.mjs") {
        await connection.setTransport("/libcurl/index.mjs", [
            { websocket: wispUrl },
        ]);
    }
}

function normalizeTarget(raw) {
    const target = search(raw, searchEngine.value);
    try {
        return new URL(target, window.location.origin).toString();
    } catch {
        return null;
    }
}

function encodeTarget(input) {
    const encoder = self.__scramjet$bundle?.rewriters?.url?.encodeUrl;
    if (!encoder) return input;

    const base = window.location.origin;

    try {
        return encoder(input, base);
    } catch (err) {
        const fallback = new URL(input, window.location.origin).toString();
        return encoder(fallback, base);
    }
}

function loadIntoFrame(raw) {
    const target = normalizeTarget(raw);
    if (!target) {
        throw new TypeError("Invalid URL");
    }

    const encoded = encodeTarget(target);
    frame.src = encoded;
    frame.dataset.url = target;
    frame.classList.add("is-visible");
}

function showError(message, details = "") {
    if (error) error.textContent = message;
    if (errorCode) errorCode.textContent = details;
}

form.addEventListener("submit", async (event) => {
    event.preventDefault();
    showError("", "");

    const raw = address.value.trim();
    if (!raw) return;

    try {
        await registerSW();
        await ensureTransport();
        loadIntoFrame(raw);
    } catch (err) {
        console.error("Rift proxy failed to start", err);
        showError("Rift could not start the proxy.", err?.toString());
    }
});

document.getElementById("back-btn")?.addEventListener("click", () => {
    try {
        frame.contentWindow?.history?.back();
    } catch {
        window.history.back();
    }
});

document.getElementById("forward-btn")?.addEventListener("click", () => {
    try {
        frame.contentWindow?.history?.forward();
    } catch {
        window.history.forward();
    }
});

document.getElementById("refresh-btn")?.addEventListener("click", () => {
    try {
        frame.contentWindow?.location?.reload();
    } catch {
        const current = frame.dataset.url;
        if (current) loadIntoFrame(current);
    }
});

document.getElementById("home-btn")?.addEventListener("click", () => {
    frame.removeAttribute("src");
    frame.classList.remove("is-visible");
    address.value = "";
});

// Support deep links (?url=...)
const urlParams = new URLSearchParams(window.location.search);
const initialUrl = urlParams.get("url");
if (initialUrl) {
    address.value = initialUrl;
    form.dispatchEvent(new Event("submit"));
}
