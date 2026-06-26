const RESET_PASSWORD_URL = "https://peptonelike-lelia-interdepartmentally.ngrok-free.dev/api/auth/reset-password";
const INVALID_LINK_MESSAGE = "This reset link is no longer valid. Please request a new one.";

let countdownInterval = null;

function notify(message, type) {
  if (window.CyberNotify && typeof window.CyberNotify.alert === "function") {
    window.CyberNotify.alert(message, { type });
    return;
  }

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

  console[type === "error" ? "error" : "info"](message);
}

function setSubmittingState(button, isSubmitting, defaultLabel) {
  if (!button) return;
  button.disabled = isSubmitting;
  if (isSubmitting) {
    button.innerHTML = `
      <svg class="animate-spin h-5 w-5 text-black" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
        <path d="M21 12a9 9 0 1 1-6.219-8.56"/>
      </svg>
      <span>Updating...</span>
    `;
  } else {
    button.innerHTML = defaultLabel;
  }
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

function updateStrengthUI(score, isEmpty) {
  const bars = document.querySelectorAll("#strengthBar > div");
  const strengthText = document.getElementById("strengthText");
  if (!strengthText || bars.length !== 4) return;

  // Reset all bars to default
  bars.forEach(bar => {
    bar.className = "h-1 rounded bg-slate-800 transition-colors duration-300";
  });

  if (isEmpty || score === 0) {
    strengthText.textContent = "";
    strengthText.className = "font-semibold transition-colors duration-300";
    return;
  }

  const levels = [
    { label: "Weak", colorClass: "text-red-500", bgClass: "bg-red-500" },
    { label: "Fair", colorClass: "text-orange-500", bgClass: "bg-orange-500" },
    { label: "Good", colorClass: "text-yellow-500", bgClass: "bg-yellow-500" },
    { label: "Strong", colorClass: "text-green-500", bgClass: "bg-green-500" }
  ];

  const level = levels[score - 1];
  strengthText.textContent = level.label;
  strengthText.className = `font-semibold transition-colors duration-300 ${level.colorClass}`;

  for (let i = 0; i < score; i++) {
    bars[i].className = `h-1 rounded ${level.bgClass} transition-colors duration-300`;
  }
}

function updateChecklistItem(elementId, isMet) {
  const el = document.getElementById(elementId);
  if (!el) return;

  const iconHolder = el.querySelector(".status-icon");
  if (!iconHolder) return;

  if (isMet) {
    el.className = "flex items-center gap-2 text-green-400 transition-colors duration-300";
    iconHolder.innerHTML = `
      <svg class="w-4 h-4 text-green-400 transition-colors duration-300" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
        <circle cx="12" cy="12" r="10"/>
        <path d="m9 12 2 2 4-4"/>
      </svg>
    `;
  } else {
    el.className = "flex items-center gap-2 text-slate-500 transition-colors duration-300";
    iconHolder.innerHTML = `
      <svg class="w-4 h-4 text-slate-500 transition-colors duration-300" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
        <circle cx="12" cy="12" r="10"/>
      </svg>
    `;
  }
}

function validateConfirmPassword(isBlur = false) {
  const newPass = document.getElementById("new_password")?.value || "";
  const confPass = document.getElementById("password_confirmation")?.value || "";
  const statusIcon = document.getElementById("confirmStatusIcon");
  const errorEl = document.getElementById("confirmError");

  if (!statusIcon) return;

  // Clear states initially if empty
  if (!confPass) {
    statusIcon.innerHTML = "";
    if (errorEl) errorEl.classList.add("hidden");
    return;
  }

  if (newPass === confPass) {
    if (errorEl) errorEl.classList.add("hidden");
    statusIcon.innerHTML = `
      <svg class="w-5 h-5 text-green-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
        <path d="M20 6 9 17l-5-5"/>
      </svg>
    `;
  } else {
    if (isBlur) {
      statusIcon.innerHTML = `
        <svg class="w-5 h-5 text-red-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
          <path d="M18 6 6 18M6 6l12 12"/>
        </svg>
      `;
      if (errorEl) errorEl.classList.remove("hidden");
    } else {
      statusIcon.innerHTML = "";
      if (errorEl) errorEl.classList.add("hidden");
    }
  }
}

function showSuccessState() {
  const formContainer = document.getElementById("resetPasswordContainer");
  const successContainer = document.getElementById("successStateContainer");
  const countdownText = document.getElementById("countdownText");

  if (formContainer && successContainer) {
    formContainer.classList.add("hidden");
    successContainer.classList.remove("hidden");
    successContainer.classList.add("animate-fade-in");

    let seconds = 5;
    if (countdownText) {
      countdownText.textContent = `Redirecting to login in ${seconds} seconds...`;
      countdownText.classList.remove("hidden");
    }

    countdownInterval = setInterval(() => {
      seconds--;
      if (countdownText) {
        countdownText.textContent = `Redirecting to login in ${seconds} seconds...`;
      }

      if (seconds <= 0) {
        clearInterval(countdownInterval);
        window.location.href = "/login";
      }
    }, 1000);
  }
}

async function handleResetPasswordSubmit(event) {
  if (event) event.preventDefault();

  const form = document.getElementById("resetPasswordForm");
  if (!form) return;
  const submitButton = document.getElementById("resetPasswordSubmit");
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
      form.reset();
      showSuccessState();
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

  const submitButton = document.getElementById("resetPasswordSubmit");

  if (!params.token || !params.email) {
    notify(INVALID_LINK_MESSAGE, "error");
    if (submitButton) {
      submitButton.disabled = true;
    }
  }

  form.addEventListener("submit", handleResetPasswordSubmit);
  if (submitButton) {
    submitButton.addEventListener("click", handleResetPasswordSubmit);
  }

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

  // Real-time password validation and checklist listeners
  const newPassInput = document.getElementById("new_password");
  const confirmPassInput = document.getElementById("password_confirmation");

  const runAllValidations = () => {
    const password = newPassInput?.value || "";
    const confirmVal = confirmPassInput?.value || "";

    // 1. Calculate and update strength
    const lengthMet = password.length >= 8;
    const uppercaseMet = /[A-Z]/.test(password);
    const lowercaseMet = /[a-z]/.test(password);
    const numberMet = /[0-9]/.test(password);
    const specialMet = /[!@#$%^&*]/.test(password);

    let score = 0;
    if (lengthMet) score++;
    if (uppercaseMet && lowercaseMet) score++;
    if (numberMet) score++;
    if (specialMet) score++;

    updateStrengthUI(score, password.length === 0);

    // 2. Update requirements checklist SVGs and classes
    updateChecklistItem("req-length", lengthMet);
    updateChecklistItem("req-uppercase", uppercaseMet);
    updateChecklistItem("req-lowercase", lowercaseMet);
    updateChecklistItem("req-number", numberMet);
    updateChecklistItem("req-special", specialMet);

    // 3. Confirm Password Match
    const passwordsMatch = (password === confirmVal) && password.length > 0;
    const allRequirementsMet = lengthMet && uppercaseMet && lowercaseMet && numberMet && specialMet;

    // Validate confirmation dynamically but without throwing error on active typing unless it matches
    validateConfirmPassword(false);

    // 4. Update submit button state
    const submitButton = document.getElementById("resetPasswordSubmit");
    if (submitButton) {
      if (allRequirementsMet && passwordsMatch) {
        submitButton.disabled = false;
        submitButton.className = "btn-neon w-full rounded-xl py-3.5 font-semibold text-black cursor-pointer transition-all duration-300";
      } else {
        submitButton.disabled = true;
        submitButton.className = "w-full rounded-xl py-3.5 font-semibold text-white bg-slate-800 border border-slate-700/50 opacity-50 cursor-not-allowed flex items-center justify-center gap-2 transition-all duration-300";
      }
    }
  };

  if (newPassInput) {
    newPassInput.addEventListener("input", runAllValidations);
  }
  if (confirmPassInput) {
    confirmPassInput.addEventListener("input", runAllValidations);
    confirmPassInput.addEventListener("blur", () => {
      validateConfirmPassword(true);
    });
  }

  // Bind Success State buttons
  document.getElementById("redirectNowButton")?.addEventListener("click", () => {
    if (countdownInterval) clearInterval(countdownInterval);
    window.location.href = "/login";
  });

  document.getElementById("stayOnPageButton")?.addEventListener("click", () => {
    if (countdownInterval) {
      clearInterval(countdownInterval);
      countdownInterval = null;
    }
    const countdownText = document.getElementById("countdownText");
    if (countdownText) {
      countdownText.classList.add("hidden");
    }
  });
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
