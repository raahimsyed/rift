"use strict";
const RiftShield = {
     keys: {
          title: "rift__disguise-title",
          favicon: "rift__disguise-favicon",
     },
     defaults: {
          title: "Google",
          favicon: "https://www.google.com/favicon.ico",
     },

     /** Apply saved disguise on page load */
     apply() {
          const title = localStorage.getItem(this.keys.title);
          const favicon = localStorage.getItem(this.keys.favicon);
          if (title) document.title = title;
          if (favicon) this._setFavicon(favicon);
     },

     /** Save new disguise values */
     save(title, favicon) {
          if (title) localStorage.setItem(this.keys.title, title);
          else localStorage.removeItem(this.keys.title);
          if (favicon) localStorage.setItem(this.keys.favicon, favicon);
          else localStorage.removeItem(this.keys.favicon);
          this.apply();
     },

     /** Read stored values */
     read() {
          return {
               title: localStorage.getItem(this.keys.title) || "",
               favicon: localStorage.getItem(this.keys.favicon) || "",
          };
     },

     /** Clear all disguise settings */
     clear() {
          localStorage.removeItem(this.keys.title);
          localStorage.removeItem(this.keys.favicon);
          document.title = "Rift";
          this._setFavicon("");
     },

     _setFavicon(href) {
          let link = document.querySelector("link[rel*='icon']");
          if (!link) {
               link = document.createElement("link");
               link.rel = "icon";
               document.head.appendChild(link);
          }
          link.href = href;
     },
};

// Auto-apply on every page load
RiftShield.apply();
