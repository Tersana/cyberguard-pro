(function initCyberNotify() {
  if (window.CyberNotify && typeof window.CyberNotify.alert === "function") {
    return;
  }

  const TYPE_STYLES = {
    success: "border-[#059669] bg-[#064e3b] text-[#ecfdf5]",
    warning: "border-[#d97706] bg-[#78350f] text-[#fffbeb]",
    error: "border-[#dc2626] bg-[#7f1d1d] text-[#fef2f2]",
    info: "border-[#2563eb] bg-[#1e3a5f] text-[#eff6ff]"
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
