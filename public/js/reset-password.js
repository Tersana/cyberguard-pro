const RESET_PASSWORD_URL = "https://peptonelike-lelia-interdepartmentally.ngrok-free.dev/api/auth/reset-password";
const INVALID_LINK_MESSAGE = "This reset link is no longer valid. Please request a new one.";

function notify(message, type) {
  const statusEl = document.getElementById("resetPasswordStatus");
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
  console[type === "error" ? "error" : "info"](message);
}

function setSubmittingState(button, isSubmitting, defaultLabel) {
  if (!button) return;
  button.disabled = isSubmitting;
  button.textContent = isSubmitting ? "Updating..." : defaultLabel;
}

function parseResetParams(search) {
  const params = new URLSearchParams(search || window.location.search);
  return {
    token: (params.get("token") || "").trim(),
    email: (params.get("email") || "").trim()
  };
}

function scrubSensitiveResetQueryParams() {
  if (!window.history || typeof window.history.replaceState !== "function") return;
  const params = new URLSearchParams(window.location.search || "");
  params.delete("token");
  params.delete("email");
  const query = params.toString();
  const cleanPath = window.location.pathname || "/reset-password";
  const nextUrl = query ? `${cleanPath}?${query}` : cleanPath;
  window.history.replaceState({}, document.title, nextUrl);
}

function extractBackendMessage(payload) {
  if (!payload || typeof payload !== "object") {
    return "";
  }

  if (typeof payload.message === "string" && payload.message.trim()) {
    return payload.message;
  }

  if (payload.errors && typeof payload.errors === "object") {
    const first = Object.values(payload.errors)[0];
    if (Array.isArray(first) && first[0]) {
      return String(first[0]);
    }
    if (typeof first === "string" && first.trim()) {
      return first;
    }
  }

  return "";
}

function applyResetParamsToForm(form, params) {
  const emailInput = form.querySelector("input[name='email']");
  const tokenInput = form.querySelector("input[name='token']");

  if (emailInput) {
    emailInput.value = params.email;
    emailInput.readOnly = true;
  }

  if (tokenInput) {
    tokenInput.value = params.token;
  }
}

function validateResetPayload(payload) {
  if (!payload.token || !payload.email) {
    return INVALID_LINK_MESSAGE;
  }

  if (!payload.password || !payload.password_confirmation) {
    return "Please enter and confirm your new password.";
  }

  if (payload.password !== payload.password_confirmation) {
    return "Passwords do not match. Please re-enter both fields.";
  }

  return "";
}

async function handleResetPasswordSubmit(event) {
  event.preventDefault();

  const form = event.currentTarget;
  const submitButton = form.querySelector("button[type='submit']");
  const token = (form.querySelector("input[name='token']")?.value || "").trim();
  const email = (form.querySelector("input[name='email']")?.value || "").trim();
  const password = form.querySelector("input[name='new_password']")?.value || "";
  const passwordConfirmation = form.querySelector("input[name='password_confirmation']")?.value || "";

  const payload = {
    token,
    email,
    password,
    password_confirmation: passwordConfirmation
  };

  const validationMessage = validateResetPayload(payload);
  if (validationMessage) {
    notify(validationMessage, "warning");
    return;
  }

  setSubmittingState(submitButton, true, "Update Password");

  try {
    const response = await fetch(RESET_PASSWORD_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "ngrok-skip-browser-warning": "true"
      },
      body: JSON.stringify(payload)
    });

    if (response.ok) {
      notify("Password updated successfully. Redirecting to login...", "success");
      form.reset();
      setTimeout(() => {
        window.location.href = "/login";
      }, 3000);
      return;
    }

    const errorPayload = await response.json().catch(() => ({}));
    const backendMessage = extractBackendMessage(errorPayload);

    if ([400, 401, 403, 404, 410].includes(response.status)) {
      notify(INVALID_LINK_MESSAGE, "error");
      return;
    }

    if (response.status === 422) {
      notify(backendMessage || "Please check your input and try again.", "error");
      return;
    }

    notify(backendMessage || "Unable to reset password right now. Please try again.", "error");
  } catch (error) {
    notify("Network error while resetting password. Please try again.", "error");
  } finally {
    setSubmittingState(submitButton, false, "Update Password");
  }
}

function initResetPasswordPage() {
  const form = document.getElementById("resetPasswordForm");
  if (!form) return;

  const params = parseResetParams(window.location.search);
  scrubSensitiveResetQueryParams();
  applyResetParamsToForm(form, params);

  if (!params.token || !params.email) {
    notify(INVALID_LINK_MESSAGE, "error");
    const submitButton = form.querySelector("button[type='submit']");
    if (submitButton) {
      submitButton.disabled = true;
    }
  }

  form.addEventListener("submit", handleResetPasswordSubmit);

  const togglePasswordVisibility = (inputId, buttonId) => {
    const input = document.getElementById(inputId);
    const button = document.getElementById(buttonId);
    if (!input || !button) return;
    button.addEventListener("click", () => {
      input.type = input.type === "password" ? "text" : "password";
    });
  };

  togglePasswordVisibility("new_password", "toggleNewPassword");
  togglePasswordVisibility("password_confirmation", "toggleConfirmPassword");
}

if (typeof window !== "undefined") {
  window.parseResetParams = parseResetParams;
  window.validateResetPayload = validateResetPayload;
  window.handleResetPasswordSubmit = handleResetPasswordSubmit;
  window.initResetPasswordPage = initResetPasswordPage;
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", initResetPasswordPage);
} else {
  initResetPasswordPage();
}
