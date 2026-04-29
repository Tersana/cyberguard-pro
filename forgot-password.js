const FORGOT_PASSWORD_ENDPOINTS = [
  "https://peptonelike-lelia-interdepartmentally.ngrok-free.dev/api/auth/forget-password",
  "https://peptonelike-lelia-interdepartmentally.ngrok-free.dev/api/auth/forgot-password"
];
const UNIFIED_SECURITY_MESSAGE = "If this email is registered, a password reset link has been sent.";
const UNIFIED_SECURITY_FEEDBACK_CLASSES = "rounded-xl border px-4 py-3 shadow-2xl backdrop-blur-md bg-[#064e3b] border-[#059669] text-[#ecfdf5]";

function notify(message, type, className) {
  const statusEl = document.getElementById("forgotPasswordStatus");
  if (statusEl) {
    statusEl.textContent = message;
    statusEl.classList.remove("hidden");
    statusEl.className = `${className || "text-sm rounded-lg px-3 py-2 border"}`;

    if (className) {
      // Explicit className should fully define appearance.
    } else if (type === "success") {
      statusEl.classList.add("text-green-300", "bg-green-900/30", "border-green-700");
    } else if (type === "warning") {
      statusEl.classList.add("text-yellow-300", "bg-yellow-900/30", "border-yellow-700");
    } else {
      statusEl.classList.add("text-red-300", "bg-red-900/30", "border-red-700");
    }
  }

  if (window.CyberNotify && typeof window.CyberNotify.alert === "function") {
    window.CyberNotify.alert(message, { type, className });
    return;
  }
}

function setSubmittingState(button, isSubmitting, defaultLabel) {
  if (!button) return;
  button.disabled = isSubmitting;
  button.textContent = isSubmitting ? "Sending..." : defaultLabel;
}

function notifyUnifiedSecurityFeedback() {
  notify(UNIFIED_SECURITY_MESSAGE, "success", UNIFIED_SECURITY_FEEDBACK_CLASSES);
}

function isValidEmail(email) {
  if (typeof email !== "string") return false;
  if (email.length > 254) return false;
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

async function handleForgotPasswordSubmit(event) {
  event.preventDefault();

  const form = event.currentTarget;
  const submitButton = form.querySelector("button[type='submit']");
  const emailInput = form.querySelector("input[name='email']");
  const email = emailInput ? emailInput.value.trim() : "";
  const alreadySubmitted = form.dataset.recoverySent === "true";

  if (alreadySubmitted) {
    notifyUnifiedSecurityFeedback();
    return;
  }

  if (!email) {
    notify("Please enter your email address.", "warning");
    return;
  }

  if (!isValidEmail(email)) {
    notify("Please enter a valid email address.", "warning");
    return;
  }

  setSubmittingState(submitButton, true, "Send Reset Link");

  try {
    let response = null;

    // Some backends use /forget-password while others use /forgot-password.
    // Retry on 404 to support both without requiring code changes.
    for (const endpoint of FORGOT_PASSWORD_ENDPOINTS) {
      response = await fetch(endpoint, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "ngrok-skip-browser-warning": "true"
        },
        body: JSON.stringify({ email })
      });

      if (response.ok) {
        break;
      }

      // Stop retrying when route exists but returns an app-level error.
      if (response.status !== 404) {
        break;
      }
    }
  } catch (_error) {
    // Intentionally do not reveal backend/network details to avoid account enumeration hints.
  } finally {
    notifyUnifiedSecurityFeedback();
    if (submitButton) {
      submitButton.disabled = true;
      submitButton.textContent = "Check Email";
    }
    form.dataset.recoverySent = "true";
    if (emailInput) {
      emailInput.readOnly = true;
    }
  }
}

function initForgotPasswordPage() {
  const form = document.getElementById("forgotPasswordForm");
  if (!form) return;
  form.addEventListener("submit", handleForgotPasswordSubmit);
}

if (typeof window !== "undefined") {
  window.handleForgotPasswordSubmit = handleForgotPasswordSubmit;
  window.initForgotPasswordPage = initForgotPasswordPage;
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", initForgotPasswordPage);
} else {
  initForgotPasswordPage();
}
