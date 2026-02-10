"use strict";
function riftMissing(config = {}) {
     const defaults = {
          code: "404",
          heading: "page not found",
          lines: [
               "the rift couldn't find what you're looking for.",
               "check the url and try again.",
          ],
          actionLabel: "go back",
          actionHref: "/",
          rootClass: "error-page",
     };

     const opts = { ...defaults, ...config };

     const root = document.querySelector(`.${opts.rootClass}`);
     if (!root) return;

     const content = root.querySelector(".error-content");
     if (!content) return;

     const code = content.querySelector(".error-title");
     if (code) code.textContent = opts.code;

     const heading = content.querySelector(".error-subtitle");
     if (heading) heading.textContent = opts.heading;

     const lines = content.querySelector(".error-messages");
     if (lines) {
          lines.innerHTML = opts.lines
               .map((l) => `<p class="error-message">${l}</p>`)
               .join("");
     }

     const action = content.querySelector(".error-button");
     if (action) {
          action.textContent = opts.actionLabel;
          action.href = opts.actionHref;
     }
}
