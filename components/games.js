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
     catalog: {
          base: "https://cdn.jsdelivr.net/gh/gn-math",
          get url() {
               return `${this.base}/assets@main/zones.json?t=${Date.now()}`;
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
          const res = await fetch(VAULT_CONFIG.catalog.url);
          if (!res.ok) throw new Error(`catalog ${res.status}`);
          const data = await res.json();
          catalog = Array.isArray(data) ? data.slice(1) : [];
     },

     bind() {
          const searchBox = el("vault-search");
          const clearBtn = el("vault-clear");
          if (searchBox) {
               searchBox.addEventListener("input", (e) => {
                    this.display(e.target.value);
                    if (clearBtn) clearBtn.style.display = e.target.value ? "flex" : "none";
               });
          }
          if (clearBtn) {
               clearBtn.addEventListener("click", () => {
                    if (searchBox) { searchBox.value = ""; searchBox.focus(); }
                    clearBtn.style.display = "none";
                    this.display();
               });
          }

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

     display(query = "") {
          const grid = el("vault-grid");
          if (!grid) return;

          const q = query.toLowerCase();
          const results = catalog.filter((g) => {
               const n = g.name.toLowerCase();
               return n.includes(q) && !VAULT_CONFIG.blocked.some((b) => n.includes(b));
          }).sort((a, b) => a.name.localeCompare(b.name));

          grid.innerHTML = "";
          results.forEach((g) => {
               const tile = document.createElement("div");
               tile.className = "vault-tile";

               if (g.cover) {
                    const img = document.createElement("img");
                    img.src = g.cover.replace("{COVER_URL}", `${VAULT_CONFIG.catalog.base}/covers@main`);
                    img.alt = g.name;
                    img.loading = "lazy";
                    img.onerror = () => img.remove();
                    tile.appendChild(img);
               }

               const label = document.createElement("span");
               label.textContent = g.name.toUpperCase();
               tile.appendChild(label);

               tile.addEventListener("click", () => this.launch(g.id));
               grid.appendChild(tile);
          });
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
               const external = game.url.includes("://");
               const url = external
                    ? game.url
                    : game.url
                         .replace("{COVER_URL}", `${VAULT_CONFIG.catalog.base}/covers@main`)
                         .replace("{HTML_URL}", `${VAULT_CONFIG.catalog.base}/html@main`);

               if (launchMode === "tab") {
                    await this.launchTab(url, external, title, favicon);
               } else {
                    await this.launchViewer(url, external, game.name, title, favicon);
               }
          } catch (err) {
               this.toast("failed to load game");
               console.error(err);
          }
     },

     async launchTab(url, external, title, favicon) {
          const win = window.open("about:blank", "_blank");
          if (!win) return this.toast("popups blocked — allow popups and try again");

          if (external) {
               this.inject(`<iframe src="${sanitize(url)}"></iframe>`, false, win, title, favicon);
          } else {
               const html = await fetch(url).then((r) => r.text());
               this.inject(html, true, win, title, favicon);
          }
     },

     async launchViewer(url, external, name, title, favicon) {
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

document.addEventListener("DOMContentLoaded", () => RiftVault.boot());
