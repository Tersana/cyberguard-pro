(function initCyberNotify() {
  if (window.CyberNotify && typeof window.CyberNotify.alert === "function") {
    return;
  }

  const TYPE_STYLES = {
    success: "border-[var(--cg-success)] bg-[rgba(52,211,153,0.15)] text-[var(--cg-success)]",
    warning: "border-[var(--cg-warning)] bg-[rgba(251,191,36,0.15)] text-[var(--cg-warning)]",
    error: "border-[var(--cg-danger)] bg-[rgba(248,113,113,0.15)] text-[var(--cg-danger)]",
    info: "border-[var(--cg-info)] bg-[rgba(56,189,248,0.15)] text-[var(--cg-info)]"
  };

  function ensureContainer() {
    let container = document.getElementById("cyber-notify-toast-container");
    if (container) return container;

    container = document.createElement("div");
    container.id = "cyber-notify-toast-container";
    container.className = "fixed top-4 right-4 z-[100] flex flex-col gap-3 w-[min(92vw,380px)]";
    document.body.appendChild(container);
    return container;
  }

  function showToast(message, type = "info", className = "") {
    const container = ensureContainer();
    const toast = document.createElement("div");
    toast.className = className || `rounded-xl border px-4 py-3 shadow-2xl backdrop-blur-md ${TYPE_STYLES[type] || TYPE_STYLES.info}`;
    toast.textContent = String(message || "");
    container.appendChild(toast);

    setTimeout(() => {
      toast.remove();
    }, 4200);
  }

  window.CyberNotify = {
    alert(message, options = {}) {
      showToast(message, options.type || "info", options.className || "");
    }
  };
})();
