"use strict";
const RiftOverlay = {
     _sanitize(text) {
          const el = document.createElement("span");
          el.textContent = text;
          return el.innerHTML;
     },

     confirm(message, onYes, onNo) {
          const shade = document.createElement("div");
          shade.className = "overlay-shade";

          const box = document.createElement("div");
          box.className = "overlay-box";
          box.innerHTML = `
      <div class="overlay-body">
        <p>${this._sanitize(message)}</p>
        <div class="overlay-actions">
          <button class="overlay-btn overlay-cancel">cancel</button>
          <button class="overlay-btn overlay-accept">confirm</button>
        </div>
      </div>
    `;

          const close = () => shade.remove();

          box.querySelector(".overlay-cancel").addEventListener("click", () => {
               close();
               if (onNo) onNo();
          });

          box.querySelector(".overlay-accept").addEventListener("click", () => {
               close();
               if (onYes) onYes();
          });

          shade.addEventListener("click", (e) => {
               if (e.target === shade) { close(); if (onNo) onNo(); }
          });

          shade.appendChild(box);
          document.body.appendChild(shade);
          box.querySelector(".overlay-accept").focus();
     },

     prompt(message, initial = "", onSubmit, onCancel) {
          const shade = document.createElement("div");
          shade.className = "overlay-shade";

          const box = document.createElement("div");
          box.className = "overlay-box";
          box.innerHTML = `
      <div class="overlay-body">
        <p>${this._sanitize(message)}</p>
        <input type="text" class="overlay-input" value="${this._sanitize(initial)}">
        <div class="overlay-actions">
          <button class="overlay-btn overlay-cancel">cancel</button>
          <button class="overlay-btn overlay-accept">ok</button>
        </div>
      </div>
    `;

          const input = box.querySelector(".overlay-input");
          const close = () => shade.remove();

          const submit = () => {
               const val = input.value.trim();
               close();
               if (val && onSubmit) onSubmit(val);
               else if (!val && onCancel) onCancel();
          };

          box.querySelector(".overlay-cancel").addEventListener("click", () => {
               close();
               if (onCancel) onCancel();
          });

          box.querySelector(".overlay-accept").addEventListener("click", submit);

          input.addEventListener("keydown", (e) => {
               if (e.key === "Enter") submit();
               else if (e.key === "Escape") { close(); if (onCancel) onCancel(); }
          });

          shade.addEventListener("click", (e) => {
               if (e.target === shade) { close(); if (onCancel) onCancel(); }
          });

          shade.appendChild(box);
          document.body.appendChild(shade);
          input.select();
          input.focus();
     },

     toast(message, duration = 4000) {
          const t = document.createElement("div");
          t.className = "rift-toast";
          t.textContent = message;
          document.body.appendChild(t);
          setTimeout(() => t.remove(), duration);
     },
};
