"use strict";
const VAULT_CONFIG = {
     keys: {
          disguiseTitle: "rift__disguise-title",
          disguiseFavicon: "rift__disguise-favicon",
          launchMode: "rift__launch-mode",
     },
     defaults: {
          mode: "window",
          title: "Google",
          favicon: "https://www.google.com/favicon.ico",
     },
     catalogs: {
          gnMath: {
               key: "gn-math",
               label: "GN-Math",
               bases: ["https://cdn.jsdelivr.net/gh/gn-math"],
          },
          sdxp: {
               key: "sdxp",
               label: "SDXP",
               bases: [],
               localCatalogUrl: "/sdxp-catalog",
          },
          truffled: {
               key: "truffled",
               label: "Truffled",
               bases: [],
               localCatalogUrl: "/truffled-catalog",
          },
          velara: {
               key: "velara",
               label: "Velara",
               bases: [],
               localCatalogUrl: "/velara-catalog",
          },
          petezah: {
               key: "petezah",
               label: "PeteZah Lite",
               bases: [],
               catalogUrl: "https://cdn.jsdelivr.net/gh/PeteZah-Games/PeteZahLite@main/search.json",
          },
     },
     blocked: ["chat", "bot", "ai"],
};

let catalog = [];
let launchMode = VAULT_CONFIG.defaults.mode;
let drag = { active: false, x: 0, y: 0, ox: 0, oy: 0 };

const el = (id) => document.getElementById(id);

const sanitize = (text) => {
     const node = document.createElement("span");
     node.textContent = text;
     return node.innerHTML;
};

const RiftVault = {
     async boot() {
          launchMode = localStorage.getItem(VAULT_CONFIG.keys.launchMode) || VAULT_CONFIG.defaults.mode;
          this.applyDisguise();
          this.bind();

          try {
               await this.fetchCatalog();
               this.display();
          } catch (err) {
               this.toast("failed to load games. please refresh.");
               console.error(err);
          }
     },

     async fetchCatalog() {
          const sources = Object.values(VAULT_CONFIG.catalogs);
          const loaded = await Promise.allSettled(
               sources.map((source) => this.fetchSourceCatalog(source))
          );

          const merged = loaded
               .filter((item) => item.status === "fulfilled")
               .flatMap((item) => item.value);

          catalog = merged;

          if (!catalog.length) {
               throw new Error("no game sources loaded");
          }
     },

     async fetchSourceCatalog(source) {
          if (source.catalogUrl) {
               const res = await fetch(`${source.catalogUrl}?t=${Date.now()}`);
               if (!res.ok) throw new Error(`catalog ${res.status}`);
               const data = await res.json();
               const rows = Array.isArray(data?.games) ? data.games : [];
               return rows.map((item, index) => ({
                    id: `${source.key}:${index}`,
                    name: item?.label || `game ${index + 1}`,
                    url: this.normalizeExternalUrl(item?.url),
                    cover: item?.imageUrl || "",
                    source: source.key,
                    sourceLabel: source.label,
                    sourceBase: window.location.origin,
               }));
          }

          if (source.localCatalogUrl) {
               const res = await fetch(`${source.localCatalogUrl}?t=${Date.now()}`);
               if (!res.ok) throw new Error(`catalog ${res.status}`);
               const data = await res.json();
               const rows = Array.isArray(data) ? data : [];
               return rows.map((item) => ({
                    ...item,
                    source: source.key,
                    sourceLabel: source.label,
                    sourceBase: window.location.origin,
               }));
          }

          const stamp = Date.now();
          let lastError = null;

          for (const base of source.bases) {
               const url = `${base}/assets@main/zones.json?t=${stamp}`;
               try {
                    const res = await fetch(url);
                    if (!res.ok) throw new Error(`catalog ${res.status}`);
                    const data = await res.json();
                    const rows = Array.isArray(data) ? data.slice(1) : [];
                    return rows.map((item) => ({
                         ...item,
                         source: source.key,
                         sourceLabel: source.label,
                         sourceBase: base,
                    }));
               } catch (err) {
                    lastError = err;
               }
          }

          throw lastError || new Error(`failed source ${source.key}`);
     },

     normalizeExternalUrl(url) {
          const value = String(url || "").trim();
          if (!value) return "";
          if (!/^https?:\/\//i.test(value)) return `https://${value.replace(/^\/+/, "")}`;
          if (/\.[a-z0-9]+(\?|#|$)/i.test(value) || value.endsWith("/")) return value;
          return `${value}/index.html`;
     },

     bind() {
          const searchBox = el("vault-search");
          const clearBtn = el("vault-clear");
          const sourceFilter = el("vault-source-filter");
          if (searchBox) {
               searchBox.addEventListener("input", (e) => {
                    this.display(e.target.value, sourceFilter?.value || "all");
                    if (clearBtn) clearBtn.style.display = e.target.value ? "flex" : "none";
               });
          }
          if (clearBtn) {
               clearBtn.addEventListener("click", () => {
                    if (searchBox) { searchBox.value = ""; searchBox.focus(); }
                    clearBtn.style.display = "none";
                    this.display("", sourceFilter?.value || "all");
               });
          }
          if (sourceFilter) {
               sourceFilter.addEventListener("change", () => {
                    const nextSource = sourceFilter.value || "all";
                    this.display(searchBox?.value || "", nextSource);
                    this.updateTruffledNote(nextSource);
               });
          }
          this.updateTruffledNote(sourceFilter?.value || "all");

          const bar = el("viewer-bar");
          if (bar) {
               bar.querySelector(".dot.close")?.addEventListener("click", () => this.closeViewer());
               bar.querySelector(".dot.min")?.addEventListener("click", () => this.shrinkViewer());
               bar.querySelector(".dot.max")?.addEventListener("click", () => this.expandViewer());
               bar.addEventListener("dblclick", (e) => {
                    if (e.target.id === "viewer-bar" || e.target.id === "viewer-label") this.expandViewer();
               });
          }

          el("viewer-restore")?.addEventListener("click", () => this.unshrinkViewer());
          this.enableDrag();
     },

     updateTruffledNote(source) {
          const note = el("truffled-launch-note");
          if (!note) return;
          note.style.display = (source === "truffled" || source === "all") ? "block" : "none";
     },

     enableDrag() {
          const viewer = el("game-viewer");
          const bar = el("viewer-bar");
          if (!viewer || !bar) return;

          const pos = (e) => ({
               x: e.touches?.[0].clientX ?? e.clientX,
               y: e.touches?.[0].clientY ?? e.clientY,
          });

          const start = (e) => {
               if (viewer.classList.contains("expanded") || e.target.closest(".viewer-controls")) return;
               if (!bar.contains(e.target)) return;
               drag.active = true;
               if (e.touches) e.preventDefault();
               const p = pos(e);
               drag.x = p.x - drag.ox;
               drag.y = p.y - drag.oy;
          };

          const move = (e) => {
               if (!drag.active) return;
               if (e.touches) e.preventDefault();
               const p = pos(e);
               drag.ox = p.x - drag.x;
               drag.oy = p.y - drag.y;
               viewer.style.transform = `translate(${drag.ox}px, ${drag.oy}px)`;
          };

          const end = () => (drag.active = false);

          bar.addEventListener("mousedown", start);
          document.addEventListener("mousemove", move);
          document.addEventListener("mouseup", end);
          bar.addEventListener("touchstart", start, { passive: false });
          document.addEventListener("touchmove", move, { passive: false });
          document.addEventListener("touchend", end);
     },

     normalizeGameName(name) {
          return String(name || "")
               .toLowerCase()
               .replace(/[^a-z0-9]+/g, " ")
               .trim();
     },

     sourceRank(source) {
          const rank = {
               truffled: 0,
               sdxp: 1,
               velara: 2,
               "gn-math": 3,
               petezah: 4,
          };
          return rank[source] ?? 9;
     },

     dedupeGames(items, source) {
          if (source !== "all") return items;
          const byName = new Map();
          for (const game of items) {
               const key = this.normalizeGameName(game.name);
               if (!key) continue;
               const existing = byName.get(key);
               if (!existing) {
                    byName.set(key, game);
                    continue;
               }

               const currentRank = this.sourceRank(existing.source);
               const nextRank = this.sourceRank(game.source);
               const preferNext =
                    nextRank < currentRank ||
                    (nextRank === currentRank && !existing.cover && !!game.cover);

               if (preferNext) byName.set(key, game);
          }
          return Array.from(byName.values());
     },

     display(query = "", source = "all") {
          const grid = el("vault-grid");
          if (!grid) return;

          const q = query.toLowerCase();
          const filtered = catalog.filter((g) => {
               const n = g.name.toLowerCase();
               const passesQuery = n.includes(q);
               const passesBlocked = !VAULT_CONFIG.blocked.some((b) => n.includes(b));
               const passesSource = source === "all" ? true : g.source === source;
               return passesQuery && passesBlocked && passesSource;
          });
          const results = this.dedupeGames(filtered, source).sort((a, b) => a.name.localeCompare(b.name));

          grid.innerHTML = "";
          results.forEach((g) => {
               const tile = document.createElement("div");
               tile.className = "vault-tile";

               if (g.cover) {
                    const coverUrl = this.resolveCoverUrl(g);
                    if (coverUrl) {
                         const img = document.createElement("img");
                         img.src = coverUrl;
                         img.alt = g.name;
                         img.loading = "lazy";
                         img.onerror = () => img.remove();
                         tile.appendChild(img);
                    }
               }

               const label = document.createElement("span");
               label.textContent = g.name.toUpperCase();
               tile.appendChild(label);

               tile.addEventListener("click", () => this.launch(g.id));
               grid.appendChild(tile);
          });
     },

     resolveCoverUrl(game) {
          const cover = String(game?.cover || "").trim();
          if (!cover) return "";
          if (cover.includes("{COVER_URL}")) {
               return cover.replace("{COVER_URL}", `${game.sourceBase}/covers@main`);
          }
          if (/^https?:\/\//i.test(cover) || cover.startsWith("data:")) {
               return cover;
          }
          try {
               return new URL(cover, `${game.sourceBase || window.location.origin}/`).href;
          } catch {
               return "";
          }
     },

     closeViewer() {
          const viewer = el("game-viewer");
          const backdrop = el("viewer-backdrop");
          const frame = el("viewer-frame");
          const restore = el("viewer-restore");

          if (!viewer || !backdrop || !frame) return;
          viewer.classList.remove("active", "shrunk");
          if (restore) restore.style.display = "none";

          setTimeout(() => {
               frame.srcdoc = "";
               frame.src = "";
               backdrop.style.display = "none";
               viewer.style.transform = "";
               drag.ox = drag.oy = 0;
          }, 400);
     },

     expandViewer() {
          const viewer = el("game-viewer");
          if (!viewer) return;
          viewer.classList.toggle("expanded");
          if (viewer.classList.contains("expanded")) viewer.style.transform = "";
          el("viewer-frame")?.focus();
     },

     shrinkViewer() {
          const viewer = el("game-viewer");
          if (viewer) {
               viewer.classList.add("shrunk");
               viewer.classList.remove("expanded");
          }
          const restore = el("viewer-restore");
          if (restore) restore.style.display = "block";
     },

     unshrinkViewer() {
          const viewer = el("game-viewer");
          if (viewer) viewer.classList.remove("shrunk");
          const restore = el("viewer-restore");
          if (restore) restore.style.display = "none";
          el("viewer-frame")?.focus();
     },

     applyDisguise() {
          const title = localStorage.getItem(VAULT_CONFIG.keys.disguiseTitle);
          const favicon = localStorage.getItem(VAULT_CONFIG.keys.disguiseFavicon);
          if (title || favicon) {
               this.setDisguise(
                    title || VAULT_CONFIG.defaults.title,
                    favicon || VAULT_CONFIG.defaults.favicon
               );
          }
     },

     setDisguise(title, favicon) {
          if (title) document.title = sanitize(title);
          if (favicon) {
               let link = document.querySelector("link[rel*='icon']");
               if (!link) {
                    link = document.createElement("link");
                    link.rel = "icon";
                    document.head.appendChild(link);
               }
               link.href = favicon;
          }
     },

     buildShell(body, title, favicon) {
          return `<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${sanitize(title)}</title><link rel="icon" href="${favicon}"><style>body,html{margin:0;padding:0;width:100%;height:100%;overflow:hidden;background:#000;display:flex;align-items:center;justify-content:center}iframe{width:100%;height:100%;border:none}</style></head><body>${body}</body></html>`;
     },

     inject(content, raw, win, title, favicon) {
          const fav = favicon || VAULT_CONFIG.defaults.favicon;
          let html = raw
               ? content
                    .replace(/<title>.*?<\/title>/i, `<title>${sanitize(title)}</title>`)
                    .replace(/<head>/i, `<head><link rel="icon" href="${fav}">`)
               : this.buildShell(content, title, fav);

          if (win) {
               win.document.open();
               win.document.write(html);
               win.document.close();
               win.document.title = sanitize(title);
          } else {
               const frame = el("viewer-frame");
               const backdrop = el("viewer-backdrop");
               if (frame) frame.srcdoc = html;
               if (backdrop) {
                    backdrop.style.display = "flex";
                    setTimeout(() => el("game-viewer")?.classList.add("active"), 10);
               }
          }
     },

     async launch(id) {
          const game = catalog.find((g) => g.id === id);
          if (!game) return this.toast("game not found");

          try {
               const title = localStorage.getItem(VAULT_CONFIG.keys.disguiseTitle) || VAULT_CONFIG.defaults.title;
               const favicon = localStorage.getItem(VAULT_CONFIG.keys.disguiseFavicon) || VAULT_CONFIG.defaults.favicon;
               const gameUrl = typeof game.url === "string" ? game.url : "";
               if (!gameUrl) return this.toast("game url unavailable");
               const external = gameUrl.includes("://") || gameUrl.startsWith("/");
               let url = external
                    ? gameUrl
                    : gameUrl
                         .replace("{COVER_URL}", `${game.sourceBase}/covers@main`)
                         .replace("{HTML_URL}", `${game.sourceBase}/html@main`);

               // Keep Velara Astra on original origin so its anti-bot token flow can run.

               if (url.includes("{prefix}")) {
                    const encodedPrefix = encodeURIComponent(window.location.origin);
                    url = url.split("{prefix}").join(encodedPrefix);
               }

               const isVelaraAstra = game.source === "velara" && /^https?:\/\/velara\.my\/astra(?:\/|$)/i.test(url);
               if (isVelaraAstra) {
                    const inRiftUrl = `${window.location.origin}/browser?url=${encodeURIComponent(url)}`;
                    window.location.href = inRiftUrl;
                    return;
               }

               if (game.source === "duckmath" && /^https?:\/\//i.test(url)) {
                    url = `/proxy?url=${encodeURIComponent(url)}`;
               }

               if (game.source === "truffled" || external) {
                    launchMode = "tab";
                    localStorage.setItem(VAULT_CONFIG.keys.launchMode, "tab");
               }

               const effectiveMode = (game.source === "truffled" || external) ? "tab" : launchMode;
               if (effectiveMode === "tab") {
                    await this.launchTab(url, external, title, favicon, game);
               } else {
                    await this.launchViewer(url, external, game.name, title, favicon, game);
               }
          } catch (err) {
               console.error(err);
               const rawFallbackUrl = typeof game?.url === "string" ? game.url : "";
               const isExternalFallback = rawFallbackUrl.includes("://") || rawFallbackUrl.startsWith("/");
               if (isExternalFallback) {
                    try {
                         const isVelaraAstraFallback = game.source === "velara" && /^https?:\/\/velara\.my\/astra(?:\/|$)/i.test(rawFallbackUrl);
                         const browserUrl = isVelaraAstraFallback
                              ? `${window.location.origin}/browser?url=${encodeURIComponent(rawFallbackUrl)}`
                              : `${window.location.origin}/browser?url=${encodeURIComponent(rawFallbackUrl)}&popout=1`;
                         if (isVelaraAstraFallback) {
                              window.location.href = browserUrl;
                              return;
                         }
                         const win = window.open("about:blank", "_blank");
                         if (win) {
                              win.location.replace(browserUrl);
                              return;
                         }
                    } catch (fallbackErr) {
                         console.error("fallback launch failed", fallbackErr);
                    }
               }
               this.toast("failed to load game");
          }
     },

     async launchTab(url, external, title, favicon, game) {
          const win = window.open("about:blank", "_blank");
          if (!win) return this.toast("popups blocked — allow popups and try again");

          if (external) {
               const browserUrl = `${window.location.origin}/browser?url=${encodeURIComponent(url)}&popout=1`;
               win.location.replace(browserUrl);
          } else {
               const html = await fetch(url).then((r) => r.text());
               this.inject(html, true, win, title, favicon);
          }
     },

     async launchViewer(url, external, name, title, favicon, game) {
          const label = el("viewer-label");
          if (label) label.textContent = name.toUpperCase();

          if (external) {
               const frame = el("viewer-frame");
               const backdrop = el("viewer-backdrop");
               if (frame) frame.src = url;
               if (backdrop) backdrop.style.display = "flex";
               setTimeout(() => el("game-viewer")?.classList.add("active"), 10);
          } else {
               const html = await fetch(url).then((r) => r.text());
               this.inject(html, true, null, title, favicon);
          }
     },

     toast(message) {
          const t = document.createElement("div");
          t.className = "rift-toast";
          t.textContent = message;
          document.body.appendChild(t);
          setTimeout(() => t.remove(), 5000);
     },
};

document.addEventListener("DOMContentLoaded", () => {
     if (!document.body || !document.body.classList.contains("games-page")) return;
     RiftVault.boot();
});
