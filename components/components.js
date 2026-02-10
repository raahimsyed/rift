"use strict";
function riftInject(container, html) {
     if (!container) return;
     container.innerHTML = html;

     container.querySelectorAll("script").forEach((old) => {
          const fresh = document.createElement("script");
          if (old.src) {
               fresh.src = old.src;
               fresh.async = false;
          } else {
               fresh.textContent = old.textContent;
          }
          old.parentNode.replaceChild(fresh, old);
     });
}

let _navReady = false;

function riftNav(path, target = "nav-slot") {
     if (_navReady) return Promise.resolve();

     const slot = document.getElementById(target);
     if (!slot) return Promise.reject(new Error(`nav slot "${target}" not found`));

     _navReady = true;

     return fetch(path)
          .then((r) => {
               if (!r.ok) throw new Error(`${path}: ${r.status}`);
               return r.text();
          })
          .then((html) => riftInject(slot, html))
          .catch((err) => {
               console.error("rift nav load failed:", err);
               _navReady = false;
          });
}
