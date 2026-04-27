const FORGOT_PASSWORD_ENDPOINTS = [
  "https://peptonelike-lelia-interdepartmentally.ngrok-free.dev/api/auth/forget-password",
  "https://peptonelike-lelia-interdepartmentally.ngrok-free.dev/api/auth/forgot-password"
];

function notify(message, type) {
  const statusEl = document.getElementById("forgotPasswordStatus");
  if (statusEl) {
    statusEl.textContent = message;
    statusEl.classList.remove("hidden");
    statusEl.className = "text-sm rounded-lg px-3 py-2 border";

    if (type === "success") {
      statusEl.classList.add("text-green-300", "bg-green-900/30", "border-green-700");
    } else if (type === "warning") {
      statusEl.classList.add("text-yellow-300", "bg-yellow-900/30", "border-yellow-700");
    } else {
      statusEl.classList.add("text-red-300", "bg-red-900/30", "border-red-700");
    }
  }

  if (window.CyberNotify && typeof window.CyberNotify.alert === "function") {
    window.CyberNotify.alert(message, { type });
    return;
  }

  if (type === "error") {
    window.alert(message);
  } else {
    console.info(message);
  }
}

function setSubmittingState(button, isSubmitting, defaultLabel) {
  if (!button) return;
  button.disabled = isSubmitting;
  button.textContent = isSubmitting ? "Sending..." : defaultLabel;
}

function extractErrorMessage(errorPayload) {
  if (!errorPayload || typeof errorPayload !== "object") {
    return "";
  }

  if (typeof errorPayload.message === "string" && errorPayload.message.trim()) {
    return errorPayload.message;
  }

  if (errorPayload.errors && typeof errorPayload.errors === "object") {
    const firstField = Object.values(errorPayload.errors)[0];
    if (Array.isArray(firstField) && firstField[0]) {
      return String(firstField[0]);
    }
    if (typeof firstField === "string") {
      return firstField;
    }
  }

  return "";
}

async function handleForgotPasswordSubmit(event) {
  event.preventDefault();

  const form = event.currentTarget;
  const submitButton = form.querySelector("button[type='submit']");
  const emailInput = form.querySelector("input[name='email']");
  const email = emailInput ? emailInput.value.trim() : "";

  if (!email) {
    notify("Please enter your email address.", "warning");
    return;
  }

  setSubmittingState(submitButton, true, "Send Reset Link");

  try {
    let response = null;
    let payload = {};

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

      payload = await response.json().catch(() => ({}));

      // Stop retrying when route exists but returns an app-level error.
      if (response.status !== 404) {
        break;
      }
    }

    if (response.ok) {
      notify(
        "Password reset link sent! Please check your email inbox and spam folder.",
        "success"
      );
      form.reset();
      return;
    }

    const message = extractErrorMessage(payload) || "Unable to send reset link right now. Please try again.";
    notify(message, "error");
  } catch (error) {
    notify("Network error while sending reset link. Please try again.", "error");
  } finally {
    setSubmittingState(submitButton, false, "Send Reset Link");
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
