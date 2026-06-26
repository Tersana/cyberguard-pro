const FORGOT_PASSWORD_ENDPOINTS = [
  "https://peptonelike-lelia-interdepartmentally.ngrok-free.dev/api/auth/forget-password",
  "https://peptonelike-lelia-interdepartmentally.ngrok-free.dev/api/auth/forgot-password"
];
const UNIFIED_SECURITY_MESSAGE = "If this email is registered, a password reset link has been sent.";
const UNIFIED_SECURITY_FEEDBACK_CLASSES = "rounded-xl border px-4 py-3 shadow-2xl backdrop-blur-md bg-[#064e3b] border-[#059669] text-[#ecfdf5]";

let submittedEmail = "";
let countdownTimer = null;
let countdownSecondsLeft = 0;

function notify(message, type, className) {
  if (window.CyberNotify && typeof window.CyberNotify.alert === "function") {
    window.CyberNotify.alert(message, { type, className });
    return;
  }

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
}

function setSubmittingState(isSubmitting) {
  const submitButton = document.getElementById("forgotPasswordSubmit");
  const spinner = document.getElementById("submitSpinner");
  const arrow = document.getElementById("submitArrow");
  const btnText = document.getElementById("submitBtnText");

  if (!submitButton) return;

  submitButton.disabled = isSubmitting;
  if (isSubmitting) {
    if (spinner) spinner.classList.remove("hidden");
    if (arrow) arrow.classList.add("hidden");
    if (btnText) btnText.textContent = "Sending...";
  } else {
    if (spinner) spinner.classList.add("hidden");
    if (arrow) arrow.classList.remove("hidden");
    if (btnText) btnText.textContent = "Send Reset Link";
  }
}

function notifyUnifiedSecurityFeedback() {
  notify(UNIFIED_SECURITY_MESSAGE, "success", UNIFIED_SECURITY_FEEDBACK_CLASSES);
}

function isValidEmail(email) {
  if (typeof email !== "string") return false;
  if (email.length > 254) return false;
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

// Perform the fetch requests safely without breaking execution flow
async function sendResetRequest(email) {
  try {
    let response = null;
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
      if (response.status !== 404) {
        break;
      }
    }
  } catch (_error) {
    // Intentionally ignore details for security
  }
}

// Handles smooth transitioning to the success state container
function showSuccessState() {
  const formContainer = document.getElementById("forgotPasswordContainer");
  const successContainer = document.getElementById("successStateContainer");

  if (formContainer && successContainer) {
    // Smooth transition
    formContainer.classList.add("hidden");
    successContainer.classList.remove("hidden");
    successContainer.classList.add("animate-fade-in");

    // Initiate countdown
    startCountdown(60);
  }
}

// Initiates resend countdown timer
function startCountdown(seconds) {
  const resendButton = document.getElementById("resendButton");
  const countdownText = document.getElementById("resendCountdownText");
  if (!resendButton || !countdownText) return;

  if (countdownTimer) {
    clearInterval(countdownTimer);
  }

  countdownSecondsLeft = seconds;
  resendButton.disabled = true;
  resendButton.className = "w-full py-3 rounded-xl text-xs font-semibold flex items-center justify-center gap-2 border border-slate-700 bg-slate-800/40 text-slate-400 cursor-not-allowed transition-all duration-300";

  updateCountdownText();

  countdownTimer = setInterval(() => {
    countdownSecondsLeft--;
    updateCountdownText();

    if (countdownSecondsLeft <= 0) {
      clearInterval(countdownTimer);
      countdownTimer = null;
      
      // Enable resend button with secondary purple hover state style
      resendButton.disabled = false;
      resendButton.textContent = "";
      
      // Re-add resend icon + active text
      resendButton.innerHTML = `
        <svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
          <path stroke-linecap="round" stroke-linejoin="round" d="M16.023 9.348h4.992v-.001M2.985 19.644v-4.992m0 0h4.992m-4.993 0l3.181 3.183a8.25 8.25 0 0013.803-3.7M4.031 9.865a8.25 8.25 0 0113.803-3.7l3.181 3.182m0-4.991v4.99" />
        </svg>
        <span>Resend Email</span>
      `;
      resendButton.className = "w-full py-3 rounded-xl text-xs font-semibold flex items-center justify-center gap-2 border border-blue-500/40 hover:border-blue-400 bg-blue-500/10 hover:bg-blue-500/20 text-blue-300 hover:text-white cursor-pointer shadow-md shadow-purple-500/5 transition-all duration-300";
    }
  }, 1000);
}

function updateCountdownText() {
  const countdownText = document.getElementById("resendCountdownText");
  if (!countdownText) return;
  const minutes = Math.floor(countdownSecondsLeft / 60);
  const seconds = countdownSecondsLeft % 60;
  const displaySeconds = seconds < 10 ? `0${seconds}` : seconds;
  countdownText.textContent = `Resend available in ${minutes}:${displaySeconds}`;
}

async function handleForgotPasswordSubmit(event) {
  if (event) event.preventDefault();

  const form = document.getElementById("forgotPasswordForm");
  if (!form) return;
  const emailInput = form.querySelector("input[name='email']");
  const email = emailInput ? emailInput.value.trim() : "";

  if (!email) {
    notify("Please enter your email address.", "warning");
    return;
  }

  if (!isValidEmail(email)) {
    notify("Please enter a valid email address.", "warning");
    return;
  }

  submittedEmail = email;
  setSubmittingState(true);

  // Send request in background
  await sendResetRequest(email);

  // Transition UI to success state
  setSubmittingState(false);
  notifyUnifiedSecurityFeedback();
  showSuccessState();
}

function initForgotPasswordPage() {
  const form = document.getElementById("forgotPasswordForm");
  if (!form) return;
  form.addEventListener("submit", handleForgotPasswordSubmit);

  const submitBtn = document.getElementById("forgotPasswordSubmit");
  if (submitBtn) {
    submitBtn.addEventListener("click", handleForgotPasswordSubmit);
  }

  const emailInput = document.getElementById("email");
  const statusIcon = document.getElementById("emailStatusIcon");
  const emailError = document.getElementById("emailError");

  if (emailInput && statusIcon) {
    function validateEmailInput(showErrorsOnInvalid) {
      const email = emailInput.value.trim();
      if (!email) {
        statusIcon.classList.add("hidden");
        if (emailError) emailError.classList.add("hidden");
        emailInput.classList.remove("border-red-500", "border-green-500");
        return false;
      }

      if (isValidEmail(email)) {
        statusIcon.innerHTML = `
          <svg class="w-5 h-5 text-green-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5">
            <path stroke-linecap="round" stroke-linejoin="round" d="M4.5 12.75l6 6 9-13.5" />
          </svg>
        `;
        statusIcon.classList.remove("hidden");
        if (emailError) emailError.classList.add("hidden");
        emailInput.classList.remove("border-red-500");
        emailInput.classList.add("border-green-500");
        return true;
      } else {
        if (showErrorsOnInvalid) {
          statusIcon.innerHTML = `
            <svg class="w-5 h-5 text-red-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5">
              <path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12" />
            </svg>
          `;
          statusIcon.classList.remove("hidden");
          if (emailError) emailError.classList.remove("hidden");
          emailInput.classList.remove("border-green-500");
          emailInput.classList.add("border-red-500");
        } else {
          statusIcon.classList.add("hidden");
          if (emailError) emailError.classList.add("hidden");
          emailInput.classList.remove("border-green-500", "border-red-500");
        }
        return false;
      }
    }

    emailInput.addEventListener("input", function () {
      validateEmailInput(false);
    });

    emailInput.addEventListener("blur", function () {
      validateEmailInput(true);
    });
  }

  // Setup resend handler
  const resendButton = document.getElementById("resendButton");
  if (resendButton) {
    resendButton.addEventListener("click", async () => {
      if (resendButton.disabled || !submittedEmail) return;
      
      // Disable button instantly and restart timer
      startCountdown(60);

      // Call API again in background
      await sendResetRequest(submittedEmail);
      notifyUnifiedSecurityFeedback();
    });
  }
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
