// Authentication API Configuration
const AUTH_API_BASE = "http://localhost:3002/api";

// Utility Functions
class AuthUtils {
  static showError(elementId, message) {
    const errorElement = document.getElementById(elementId);
    if (errorElement) {
      errorElement.textContent = message;
      errorElement.classList.remove("hidden");
    }
  }

  static hideError(elementId) {
    const errorElement = document.getElementById(elementId);
    if (errorElement) {
      errorElement.classList.add("hidden");
    }
  }

  static showLoading(
    buttonId,
    spinnerId,
    buttonTextId,
    loadingText = "Loading..."
  ) {
    const button = document.getElementById(buttonId);
    const spinner = document.getElementById(spinnerId);
    const buttonText = document.getElementById(buttonTextId);

    if (button) button.disabled = true;
    if (spinner) spinner.classList.remove("hidden");
    if (buttonText) buttonText.textContent = loadingText;
  }

  static hideLoading(buttonId, spinnerId, buttonTextId, originalText) {
    const button = document.getElementById(buttonId);
    const spinner = document.getElementById(spinnerId);
    const buttonText = document.getElementById(buttonTextId);

    if (button) button.disabled = false;
    if (spinner) spinner.classList.add("hidden");
    if (buttonText) buttonText.textContent = originalText;
  }

  static showToast(message, type = "info", duration = 5000) {
    const toastContainer = document.getElementById("toastContainer");
    if (!toastContainer) return;

    const toast = document.createElement("div");
    toast.className = `bg-white/10 backdrop-blur-lg border border-white/20 rounded-lg p-4 text-white shadow-lg transform transition-all duration-300 translate-x-full`;

    const iconMap = {
      success: "✅",
      error: "❌",
      warning: "⚠️",
      info: "ℹ️",
    };

    toast.innerHTML = `
            <div class="flex items-center space-x-3">
                <span class="text-lg">${iconMap[type] || iconMap.info}</span>
                <span class="flex-1">${message}</span>
                <button onclick="this.parentElement.parentElement.remove()" class="text-slate-300 hover:text-white transition-colors">
                    <svg class="w-4 h-4" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor">
                        <path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12" />
                    </svg>
                </button>
            </div>
        `;

    toastContainer.appendChild(toast);

    // Animate in
    setTimeout(() => {
      toast.classList.remove("translate-x-full");
    }, 100);

    // Auto remove
    setTimeout(() => {
      toast.classList.add("translate-x-full");
      setTimeout(() => {
        if (toast.parentElement) {
          toast.remove();
        }
      }, 300);
    }, duration);
  }

  static validateEmail(email) {
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return re.test(email);
  }

  static validatePassword(password) {
    const minLength = 8;
    const hasUpperCase = /[A-Z]/.test(password);
    const hasLowerCase = /[a-z]/.test(password);
    const hasNumbers = /\d/.test(password);
    const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);

    return {
      isValid:
        password.length >= minLength &&
        hasUpperCase &&
        hasLowerCase &&
        hasNumbers &&
        hasSpecialChar,
      minLength,
      hasUpperCase,
      hasLowerCase,
      hasNumbers,
      hasSpecialChar,
    };
  }

  static getPasswordStrength(password) {
    const validation = this.validatePassword(password);
    let score = 0;
    let strength = "";

    if (password.length >= 8) score += 1;
    if (password.length >= 12) score += 1;
    if (validation.hasUpperCase) score += 1;
    if (validation.hasLowerCase) score += 1;
    if (validation.hasNumbers) score += 1;
    if (validation.hasSpecialChar) score += 1;

    if (score <= 2) {
      strength = "Weak";
    } else if (score <= 4) {
      strength = "Medium";
    } else if (score <= 5) {
      strength = "Strong";
    } else {
      strength = "Very Strong";
    }

    return { score, strength, percentage: (score / 6) * 100 };
  }

  static updatePasswordStrength(password) {
    const strengthContainer = document.getElementById("passwordStrength");
    const strengthBar = document.getElementById("strengthBar");
    const strengthText = document.getElementById("strengthText");

    if (!strengthContainer || !strengthBar || !strengthText) return;

    if (password.length === 0) {
      strengthContainer.classList.add("hidden");
      return;
    }

    strengthContainer.classList.remove("hidden");
    const { strength, percentage } = this.getPasswordStrength(password);

    strengthBar.style.width = `${percentage}%`;
    strengthText.textContent = strength;

    // Update colors based on strength
    strengthBar.className = "h-2 rounded-full transition-all duration-300";
    if (percentage <= 33) {
      strengthBar.classList.add("bg-red-500");
    } else if (percentage <= 66) {
      strengthBar.classList.add("bg-yellow-500");
    } else {
      strengthBar.classList.add("bg-green-500");
    }
  }
}

// API Client
class AuthAPI {
  static async request(endpoint, options = {}) {
    const url = `${AUTH_API_BASE}${endpoint}`;
    const config = {
      headers: {
        "Content-Type": "application/json",
        ...options.headers,
      },
      credentials: "include",
      ...options,
    };

    try {
      const response = await fetch(url, config);
      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.message || "Request failed");
      }

      return data;
    } catch (error) {
      console.error("API Error:", error);
      throw error;
    }
  }

  static async register(userData) {
    return this.request("/auth/register", {
      method: "POST",
      body: JSON.stringify(userData),
    });
  }

  static async login(credentials) {
    return this.request("/auth/login", {
      method: "POST",
      body: JSON.stringify(credentials),
    });
  }

  static async verifyTwoFactor(token, tempToken) {
    return this.request("/2fa/verify", {
      method: "POST",
      body: JSON.stringify({ token, tempToken }),
    });
  }

  static async verifyBackupCode(backupCode, tempToken) {
    return this.request("/2fa/verify-backup", {
      method: "POST",
      body: JSON.stringify({ backupCode, tempToken }),
    });
  }

  static async forgotPassword(email) {
    return this.request("/auth/forgot-password", {
      method: "POST",
      body: JSON.stringify({ email }),
    });
  }

  static async resetPassword(token, password) {
    return this.request("/auth/reset-password", {
      method: "POST",
      body: JSON.stringify({ token, password }),
    });
  }

  static async verifyEmail(token) {
    return this.request(`/auth/verify?token=${token}`, {
      method: "GET",
    });
  }
}

// Form Handlers
class AuthForms {
  static init() {
    this.initPasswordToggles();
    this.initPasswordStrength();
    this.initFormValidation();
    this.initFormSubmission();
  }

  static initPasswordToggles() {
    const toggleButtons = document.querySelectorAll(
      '[id^="togglePassword"], [id^="toggleConfirmPassword"]'
    );
    toggleButtons.forEach((button) => {
      button.addEventListener("click", () => {
        const input = button.parentElement.querySelector("input");
        if (input) {
          input.type = input.type === "password" ? "text" : "password";
        }
      });
    });
  }

  static initPasswordStrength() {
    const passwordInput = document.getElementById("password");
    if (passwordInput) {
      passwordInput.addEventListener("input", (e) => {
        AuthUtils.updatePasswordStrength(e.target.value);
      });
    }
  }

  static initFormValidation() {
    const forms = document.querySelectorAll("form");
    forms.forEach((form) => {
      const inputs = form.querySelectorAll("input[required]");
      inputs.forEach((input) => {
        input.addEventListener("blur", () => {
          this.validateField(input);
        });
      });
    });
  }

  static validateField(input) {
    const value = input.value.trim();
    const fieldName = input.name;
    const errorElement = document.getElementById(`${fieldName}Error`);

    // Clear previous errors
    if (errorElement) {
      errorElement.classList.add("hidden");
    }

    // Required field validation
    if (input.hasAttribute("required") && !value) {
      this.showFieldError(fieldName, "This field is required");
      return false;
    }

    // Email validation
    if (fieldName === "email" && value && !AuthUtils.validateEmail(value)) {
      this.showFieldError(fieldName, "Please enter a valid email address");
      return false;
    }

    // Password validation
    if (fieldName === "password" && value) {
      const validation = AuthUtils.validatePassword(value);
      if (!validation.isValid) {
        this.showFieldError(
          fieldName,
          "Password must be at least 8 characters with uppercase, lowercase, number, and special character"
        );
        return false;
      }
    }

    // Confirm password validation
    if (fieldName === "confirmPassword" && value) {
      const password = document.getElementById("password")?.value;
      if (password && value !== password) {
        this.showFieldError(fieldName, "Passwords do not match");
        return false;
      }
    }

    return true;
  }

  static showFieldError(fieldName, message) {
    const errorElement = document.getElementById(`${fieldName}Error`);
    if (errorElement) {
      errorElement.textContent = message;
      errorElement.classList.remove("hidden");
    }
  }

  static initFormSubmission() {
    // Registration form
    const registerForm = document.getElementById("registerForm");
    if (registerForm) {
      registerForm.addEventListener("submit", this.handleRegister.bind(this));
    }

    // Login form
    const loginForm = document.getElementById("loginForm");
    if (loginForm) {
      loginForm.addEventListener("submit", this.handleLogin.bind(this));
    }

    // Forgot password form
    const forgotPasswordForm = document.getElementById("forgotPasswordForm");
    if (forgotPasswordForm) {
      forgotPasswordForm.addEventListener(
        "submit",
        this.handleForgotPassword.bind(this)
      );
    }

    // Reset password form
    const resetPasswordForm = document.getElementById("resetPasswordForm");
    if (resetPasswordForm) {
      resetPasswordForm.addEventListener(
        "submit",
        this.handleResetPassword.bind(this)
      );
    }

    // Two-factor authentication
    const verifyTwoFactorBtn = document.getElementById("verifyTwoFactorBtn");
    if (verifyTwoFactorBtn) {
      verifyTwoFactorBtn.addEventListener(
        "click",
        this.handleTwoFactorVerification.bind(this)
      );
    }

    const verifyBackupCodeBtn = document.getElementById("verifyBackupCodeBtn");
    if (verifyBackupCodeBtn) {
      verifyBackupCodeBtn.addEventListener(
        "click",
        this.handleBackupCodeVerification.bind(this)
      );
    }

    // Navigation between 2FA and backup code
    const useBackupCodeBtn = document.getElementById("useBackupCodeBtn");
    if (useBackupCodeBtn) {
      useBackupCodeBtn.addEventListener(
        "click",
        this.showBackupCodeSection.bind(this)
      );
    }

    const backToTwoFactorBtn = document.getElementById("backToTwoFactorBtn");
    if (backToTwoFactorBtn) {
      backToTwoFactorBtn.addEventListener(
        "click",
        this.showTwoFactorSection.bind(this)
      );
    }
  }

  static async handleRegister(e) {
    e.preventDefault();

    const formData = new FormData(e.target);
    const userData = {
      firstName: formData.get("firstName"),
      lastName: formData.get("lastName"),
      email: formData.get("email"),
      password: formData.get("password"),
      confirmPassword: formData.get("confirmPassword"),
      acceptTerms: formData.get("acceptTerms") === "on",
    };

    // Validate all fields
    let isValid = true;
    Object.keys(userData).forEach((key) => {
      if (
        key !== "acceptTerms" &&
        !this.validateField(document.getElementById(key))
      ) {
        isValid = false;
      }
    });

    if (!userData.acceptTerms) {
      this.showFieldError("terms", "You must accept the terms and conditions");
      isValid = false;
    }

    if (!isValid) return;

    AuthUtils.showLoading(
      "registerBtn",
      "registerSpinner",
      "registerBtnText",
      "Creating Account..."
    );

    try {
      await AuthAPI.register(userData);
      AuthUtils.showToast(
        "Account created successfully! Please check your email to verify your account.",
        "success",
        8000
      );

      // Redirect to login after a delay
      setTimeout(() => {
        window.location.href = "login.html";
      }, 3000);
    } catch (error) {
      AuthUtils.showToast(error.message || "Registration failed", "error");
    } finally {
      AuthUtils.hideLoading(
        "registerBtn",
        "registerSpinner",
        "registerBtnText",
        "Create Account"
      );
    }
  }

  static async handleLogin(e) {
    e.preventDefault();

    const formData = new FormData(e.target);
    const credentials = {
      email: formData.get("email"),
      password: formData.get("password"),
      rememberMe: formData.get("rememberMe") === "on",
    };

    AuthUtils.showLoading(
      "loginBtn",
      "loginSpinner",
      "loginBtnText",
      "Signing In..."
    );

    try {
      const response = await AuthAPI.login(credentials);

      if (response.requiresTwoFactor) {
        // Show two-factor authentication section
        this.showTwoFactorSection();
        this.tempToken = response.tempToken;
        AuthUtils.hideLoading(
          "loginBtn",
          "loginSpinner",
          "loginBtnText",
          "Sign In"
        );
      } else {
        // Login successful
        AuthUtils.showToast("Login successful!", "success");
        localStorage.setItem("accessToken", response.accessToken);
        localStorage.setItem("user", JSON.stringify(response.user));

        // Redirect to main application
        setTimeout(() => {
          window.location.href = "../index.html";
        }, 1000);
      }
    } catch (error) {
      AuthUtils.showToast(error.message || "Login failed", "error");
      AuthUtils.hideLoading(
        "loginBtn",
        "loginSpinner",
        "loginBtnText",
        "Sign In"
      );
    }
  }

  static async handleTwoFactorVerification() {
    const code = document.getElementById("twoFactorCode").value;

    if (!code || code.length !== 6) {
      AuthUtils.showError("twoFactorError", "Please enter a 6-digit code");
      return;
    }

    AuthUtils.showLoading(
      "verifyTwoFactorBtn",
      "verifyTwoFactorSpinner",
      "verifyTwoFactorBtnText",
      "Verifying..."
    );

    try {
      const response = await AuthAPI.verifyTwoFactor(code, this.tempToken);
      AuthUtils.showToast("Login successful!", "success");
      localStorage.setItem("accessToken", response.accessToken);
      localStorage.setItem("user", JSON.stringify(response.user));

      setTimeout(() => {
        window.location.href = "../index.html";
      }, 1000);
    } catch (error) {
      AuthUtils.showError(
        "twoFactorError",
        error.message || "Invalid verification code"
      );
    } finally {
      AuthUtils.hideLoading(
        "verifyTwoFactorBtn",
        "verifyTwoFactorSpinner",
        "verifyTwoFactorBtnText",
        "Verify Code"
      );
    }
  }

  static async handleBackupCodeVerification() {
    const backupCode = document.getElementById("backupCode").value;

    if (!backupCode) {
      AuthUtils.showError("backupCodeError", "Please enter a backup code");
      return;
    }

    AuthUtils.showLoading(
      "verifyBackupCodeBtn",
      "verifyBackupCodeSpinner",
      "verifyBackupCodeBtnText",
      "Verifying..."
    );

    try {
      const response = await AuthAPI.verifyBackupCode(
        backupCode,
        this.tempToken
      );
      AuthUtils.showToast("Login successful!", "success");
      localStorage.setItem("accessToken", response.accessToken);
      localStorage.setItem("user", JSON.stringify(response.user));

      setTimeout(() => {
        window.location.href = "../index.html";
      }, 1000);
    } catch (error) {
      AuthUtils.showError(
        "backupCodeError",
        error.message || "Invalid backup code"
      );
    } finally {
      AuthUtils.hideLoading(
        "verifyBackupCodeBtn",
        "verifyBackupCodeSpinner",
        "verifyBackupCodeBtnText",
        "Verify Backup Code"
      );
    }
  }

  static showTwoFactorSection() {
    document.getElementById("twoFactorSection").classList.remove("hidden");
    document.getElementById("backupCodeSection").classList.add("hidden");
    document.getElementById("twoFactorCode").focus();
  }

  static showBackupCodeSection() {
    document.getElementById("backupCodeSection").classList.remove("hidden");
    document.getElementById("twoFactorSection").classList.add("hidden");
    document.getElementById("backupCode").focus();
  }

  static async handleForgotPassword(e) {
    e.preventDefault();

    const email = document.getElementById("email").value;

    if (!AuthUtils.validateEmail(email)) {
      AuthUtils.showError("emailError", "Please enter a valid email address");
      return;
    }

    AuthUtils.showLoading(
      "resetBtn",
      "resetSpinner",
      "resetBtnText",
      "Sending..."
    );

    try {
      await AuthAPI.forgotPassword(email);
      AuthUtils.showToast(
        "If an account with that email exists, a password reset link has been sent.",
        "success",
        8000
      );
    } catch (error) {
      AuthUtils.showToast(
        error.message || "Failed to send reset link",
        "error"
      );
    } finally {
      AuthUtils.hideLoading(
        "resetBtn",
        "resetSpinner",
        "resetBtnText",
        "Send Reset Link"
      );
    }
  }

  static async handleResetPassword(e) {
    e.preventDefault();

    const password = document.getElementById("password").value;
    const confirmPassword = document.getElementById("confirmPassword").value;

    // Validate password
    const passwordValidation = AuthUtils.validatePassword(password);
    if (!passwordValidation.isValid) {
      AuthUtils.showError(
        "passwordError",
        "Password must be at least 8 characters with uppercase, lowercase, number, and special character"
      );
      return;
    }

    if (password !== confirmPassword) {
      AuthUtils.showError("confirmPasswordError", "Passwords do not match");
      return;
    }

    // Get token from URL
    const urlParams = new URLSearchParams(window.location.search);
    const token = urlParams.get("token");

    if (!token) {
      AuthUtils.showToast("Invalid reset link", "error");
      return;
    }

    AuthUtils.showLoading(
      "resetBtn",
      "resetSpinner",
      "resetBtnText",
      "Resetting..."
    );

    try {
      await AuthAPI.resetPassword(token, password);
      AuthUtils.showToast("Password reset successfully!", "success");

      setTimeout(() => {
        window.location.href = "login.html";
      }, 2000);
    } catch (error) {
      AuthUtils.showToast(error.message || "Password reset failed", "error");
    } finally {
      AuthUtils.hideLoading(
        "resetBtn",
        "resetSpinner",
        "resetBtnText",
        "Reset Password"
      );
    }
  }
}

// Initialize when DOM is loaded
document.addEventListener("DOMContentLoaded", () => {
  AuthForms.init();

  // Handle email verification if on verify page
  const urlParams = new URLSearchParams(window.location.search);
  const token = urlParams.get("token");
  if (token && window.location.pathname.includes("verify-email")) {
    AuthAPI.verifyEmail(token)
      .then(() => {
        AuthUtils.showToast("Email verified successfully!", "success");
        setTimeout(() => {
          window.location.href = "login.html";
        }, 2000);
      })
      .catch((error) => {
        AuthUtils.showToast(
          error.message || "Email verification failed",
          "error"
        );
      });
  }
});


