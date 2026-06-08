/**
 * CyberNotify Modal Controller
 * Replaces native alert() and confirm() with themed, accessible modals.
 */

const CyberNotify = {
  _currentCallback: null,

  _resolveIcon(type) {
    const _v = (n, fb) => {
      try {
        return (
          getComputedStyle(document.documentElement)
            .getPropertyValue(n)
            .trim() || fb
        );
      } catch (_) {
        return fb;
      }
    };
    const ICON_MAP = {
      warning: { icon: "warning", color: _v("--cg-warning", "#FBBF24") },
      error: { icon: "error", color: _v("--cg-danger", "#F87171") },
      info: { icon: "info", color: _v("--cg-info", "#38BDF8") },
    };
    return ICON_MAP[type] || ICON_MAP["info"];
  },

  _hide() {
    const modal = document.getElementById("cyber-notify-modal");
    if (!modal) return;
    modal.classList.remove("cyber-notify-open");
    setTimeout(() => {
      modal.classList.add("hidden");
    }, 300);
    this._currentCallback = null;
  },

  _show(message, mode, callback, type, defaultValue = "", options = {}) {
    const modal = document.getElementById("cyber-notify-modal");
    const iconEl = document.getElementById("cyber-notify-icon");
    const msgEl = document.getElementById("cyber-notify-message");
    const confirmBtn = document.getElementById("cyber-notify-confirm-btn");
    const cancelBtn = document.getElementById("cyber-notify-cancel-btn");

    if (!modal || !iconEl || !msgEl || !confirmBtn || !cancelBtn) {
      console.error("CyberNotify: Required DOM elements not found");
      return;
    }

    // Dynamic creation of text input for prompt mode if not present
    let inputEl = document.getElementById("cyber-notify-input");
    if (!inputEl) {
      inputEl = document.createElement("input");
      inputEl.id = "cyber-notify-input";
      inputEl.type = "text";
      inputEl.className = "w-full bg-slate-950/80 border border-white/15 focus:border-blue-500/80 rounded-lg px-3.5 py-2 text-sm text-white focus:outline-none mt-1 mb-5 transition-colors font-sans text-center shadow-inner shadow-black/40";
      const actions = document.getElementById("cyber-notify-actions");
      if (actions) {
        actions.parentNode.insertBefore(inputEl, actions);
      }
    }

    if (mode === "prompt") {
      inputEl.value = defaultValue || "";
      inputEl.style.display = "block";
      setTimeout(() => {
        inputEl.focus();
        inputEl.select();
      }, 100);
    } else {
      inputEl.style.display = "none";
    }

    const { icon, color } = this._resolveIcon(type);
    iconEl.textContent = icon;
    iconEl.style.color = color;

    msgEl.textContent = String(message ?? "");

    if (mode === "alert" || options.singleButton) {
      confirmBtn.textContent = options.confirmText || "OK";
      confirmBtn.style.display = "";
      cancelBtn.style.display = "none";

      const okHandler = () => {
        confirmBtn.removeEventListener("click", okHandler);
        if (options.singleButton && mode === "prompt") {
          inputEl.removeEventListener("keydown", inputKeydownHandler);
        }
        this._hide();
        if (typeof callback === "function") {
          callback(mode === "prompt" ? inputEl.value : true);
        }
      };
      const inputKeydownHandler = (e) => {
        if (e.key === "Enter") {
          e.preventDefault();
          okHandler();
        }
      };

      confirmBtn.addEventListener("click", okHandler);
      if (options.singleButton && mode === "prompt") {
        inputEl.addEventListener("keydown", inputKeydownHandler);
      }
    } else {
      confirmBtn.textContent = "Confirm";
      cancelBtn.textContent = "Cancel";
      confirmBtn.style.display = "";
      cancelBtn.style.display = "";

      const confirmHandler = () => {
        confirmBtn.removeEventListener("click", confirmHandler);
        cancelBtn.removeEventListener("click", cancelHandler);
        if (mode === "prompt") {
          inputEl.removeEventListener("keydown", inputKeydownHandler);
        }
        this._hide();
        if (typeof callback === "function") {
          callback(mode === "prompt" ? inputEl.value : true);
        }
      };
      const cancelHandler = () => {
        confirmBtn.removeEventListener("click", confirmHandler);
        cancelBtn.removeEventListener("click", cancelHandler);
        if (mode === "prompt") {
          inputEl.removeEventListener("keydown", inputKeydownHandler);
        }
        this._hide();
        if (typeof callback === "function") {
          callback(mode === "prompt" ? null : false);
        }
      };
      const inputKeydownHandler = (e) => {
        if (e.key === "Enter") {
          e.preventDefault();
          confirmHandler();
        } else if (e.key === "Escape") {
          e.preventDefault();
          cancelHandler();
        }
      };

      confirmBtn.addEventListener("click", confirmHandler);
      cancelBtn.addEventListener("click", cancelHandler);
      if (mode === "prompt") {
        inputEl.addEventListener("keydown", inputKeydownHandler);
      }
    }

    modal.classList.remove("hidden");
    requestAnimationFrame(() => {
      modal.classList.add("cyber-notify-open");
    });
  },

  alert(message, callback, options = {}) {
    if (typeof callback === "object" && callback !== null) {
      options = callback;
      callback = null;
    }
    this._show(message, "alert", callback, options.type, "", options);
  },

  confirm(message, callback, options = {}) {
    if (typeof callback !== "function") {
      console.warn("CyberNotify.confirm: callback is not a function");
      this._hide();
      return;
    }
    this._show(message, "confirm", callback, options.type, "", options);
  },

  prompt(message, defaultValue, callback, options = {}) {
    if (typeof callback !== "function") {
      console.warn("CyberNotify.prompt: callback is not a function");
      this._hide();
      return;
    }
    this._show(message, "prompt", callback, options.type, defaultValue, options);
  },
};

window.CyberNotify = CyberNotify;
