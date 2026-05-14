/**
 * CyberGuard Pro Authentication System
 * Handles user authentication, session management, and security features
 */

// Note: normalizeUserData and prepareUserDataForAPI are expected to be available globally
// from data-normalizer.js which should be loaded before this script in the HTML

class AuthManager {
  constructor() {
    this.currentUser = null;
    this.sessionTimeout = 30 * 60 * 1000; // 30 minutes
    // Initialize API client for backend communication
    this.apiClient = new APIClient();
    this.init();
  }

  init() {
    // Initialize admin account on startup
    this.initializeAdminAccount();

    this.loadUserSession();
    this.setupSessionTimeout();
    this.setupEventListeners();
    this.setupPageVisibilityHandler();
  }

  // Load user session from localStorage
  async loadUserSession() {
    try {
      // Check if JWT token exists in localStorage
      const token = this.apiClient.getToken();

      if (token) {
        // Token exists, attempt to restore session from backend
        const result = await this.restoreSession();

        if (result.success) {
          return true;
        } else {
          // Fall through to show guest UI (already handled in restoreSession)
          return false;
        }
      }

      // No token, check for legacy localStorage session
      const userData = localStorage.getItem("cyberguard_user");
      const sessionData = localStorage.getItem("cyberguard_session");

      if (userData && sessionData) {
        const user = JSON.parse(userData);
        const session = JSON.parse(sessionData);

        // Check if session is still valid
        if (Date.now() - session.timestamp < this.sessionTimeout) {
          this.currentUser = user;
          this.updateUI();
          return true;
        } else {
          this.logout();
        }
      }

      // No session found, show guest UI
      this.currentUser = null;
      this.updateUI();
    } catch (error) {
      console.error("Error loading user session:", error);
      // Clear session on error
      this.apiClient.clearToken();
      localStorage.removeItem("cyberguard_user");
      localStorage.removeItem("cyberguard_session");
      this.currentUser = null;
      this.updateUI();
    }
    return false;
  }

  // Save user session to localStorage
  saveUserSession(user) {
    try {
      const sessionData = {
        timestamp: Date.now(),
        userAgent: navigator.userAgent,
        ip: "127.0.0.1", // In a real app, this would be the actual IP
      };

      localStorage.setItem("cyberguard_user", JSON.stringify(user));
      localStorage.setItem("cyberguard_session", JSON.stringify(sessionData));
      this.currentUser = user;
      this.updateUI();
      return true;
    } catch (error) {
      console.error("Error saving user session:", error);
      return false;
    }
  }

  // Login function
  async login(email, password) {
    try {
      // Simulate API call
      const response = await this.authenticateUser(email, password);

      if (response.success) {
        const user = {
          id: response.user.id,
          email: response.user.email,
          name: response.user.name,
          company: response.user.company,
          role: response.user.role,
          lastLogin: new Date().toISOString(),
          preferences: response.user.preferences || {},
        };

        this.saveUserSession(user);
        this.trackLoginAttempt(email, true);
        return { success: true, user: user };
      } else {
        this.trackLoginAttempt(email, false);
        return { success: false, message: response.message };
      }
    } catch (error) {
      console.error("Login error:", error);
      return { success: false, message: "An error occurred during login" };
    }
  }

  // Register function
  async register(userData) {
    try {
      // Simulate API call
      const response = await this.createUser(userData);

      if (response.success) {
        const user = {
          id: response.user.id,
          email: response.user.email,
          name: response.user.name,
          company: response.user.company,
          role: "user",
          createdAt: new Date().toISOString(),
          preferences: response.user.preferences || {},
        };

        this.saveUserSession(user);
        this.trackRegistration(user.email);
        return { success: true, user: user };
      } else {
        return { success: false, message: response.message };
      }
    } catch (error) {
      console.error("Registration error:", error);
      return {
        success: false,
        message: "An error occurred during registration",
      };
    }
  }

  // Register with API - Backend integration
  async registerWithAPI(userData) {
    try {
      showLoading("Creating your account...");

      // Sanitize and normalize all fields
      const sanitizedData = {
        fullName: this.sanitizeInput(userData.fullName?.trim() || ""),
        email: this.sanitizeInput(userData.email?.trim().toLowerCase() || ""),
        jobTitle: this.sanitizeInput(userData.jobTitle?.trim() || ""),
        password: userData.password || "",
        passwordConfirmation: userData.passwordConfirmation || "",
      };

      // Frontend password match check — before any network call
      if (sanitizedData.password !== sanitizedData.passwordConfirmation) {
        throw new ValidationError([
          { field: "passwordConfirmation", message: "Passwords do not match" },
        ]);
      }

      // Frontend field validation
      const validationErrors = this.validateRegistrationData(sanitizedData);
      if (validationErrors.length > 0) {
        throw new ValidationError(validationErrors);
      }

      // Build strict snake_case payload matching backend schema exactly
      const apiData = {
        full_name: sanitizedData.fullName,
        email: sanitizedData.email,
        job_tittle: sanitizedData.jobTitle, // backend requires double-t
        password: sanitizedData.password,
        password_confirmation: sanitizedData.passwordConfirmation,
      };

      // Send registration request
      const response = await this.apiClient.post("auth/register", apiData);

      // Register returns 201 with NO token — user must login separately
      // Response shape: { status, message, data: { email, full_name, job_title } }
      const userData201 = response.data || response;

      // Build a minimal user object from the registration response
      const normalizedUser = this.normalizeUserData({
        email: userData201.email || sanitizedData.email,
        full_name: userData201.full_name || sanitizedData.fullName,
        job_tittle:
          userData201.job_title ||
          userData201.job_tittle ||
          sanitizedData.jobTitle,
      });

      this.trackRegistration(sanitizedData.email);

      return { success: true, user: normalizedUser };
    } catch (error) {
      if (error.name === "ValidationError" || error.name === "APIError") {
        throw error;
      }
      throw new Error("An error occurred during registration");
    } finally {
      hideLoading();
    }
  }

  // Login with API - Backend integration
  async loginWithAPI(email, password) {
    try {
      showLoading("Signing you in...");

      const sanitizedEmail = this.sanitizeInput(
        email?.trim().toLowerCase() || "",
      );

      const validationErrors = this.validateLoginData(sanitizedEmail, password);
      if (validationErrors.length > 0) {
        throw new ValidationError(validationErrors);
      }

      // Send login request
      // Response shape: { status, message, data: { user: {...}, token: "..." } }
      const response = await this.apiClient.post("auth/login", {
        email: sanitizedEmail,
        password: password,
      });

      // --- Phase 2 Fix: Check for 2FA requirement EARLY ---
      // The backend may signal 2FA is required via requires_2fa flag before
      // we can fully extract/normalize user data. Check this first to avoid
      // falling into the generic error handler.
      const requires2FA =
        response.data?.requires_2fa ||
        response.requires_2fa ||
        response.data?.requires2FA ||
        response.requires2FA;

      // Extract token and user from response.data
      const token = response.data?.token || response.token;
      const rawUser =
        response.data?.user || response.user || response.data || response;

      // Store token if present (even for 2FA flow — needed for verify endpoint)
      if (token) {
        this.apiClient.setToken(token);
      }

      // Attempt to normalize user data (may be partial during 2FA flow)
      let normalizedUser = null;
      try {
        normalizedUser = this.normalizeUserData(rawUser);
      } catch (normalizeError) {
        console.warn(
          "[2FA Debug] User data normalization failed:",
          normalizeError.message,
        );
        // If 2FA is required, normalization failure is acceptable — the backend
        // may not return full user data until after 2FA verification
      }

      // Determine if 2FA challenge is needed:
      // 1. Backend explicitly says requires_2fa = true, OR
      // 2. Normalized user has twoFactorEnabled = true
      const needs2FA =
        requires2FA === true ||
        (normalizedUser && normalizedUser.twoFactorEnabled === true);

      if (needs2FA) {
        // POST /api/auth/2fa/verify requires NO Bearer token (per API spec)
        // Clear any partial token that may have been set from the login response
        this.apiClient.clearToken();
        // Extract the email for the verify call
        const twoFAEmail =
          response.data?.email || response.email || sanitizedEmail;
        console.info(
          "[2FA] 2FA verification required — showing challenge modal",
        );
        return {
          success: true,
          requires2FA: true,
          email: twoFAEmail,
          message: "2FA verification required",
        };
      }

      // No 2FA needed — validate we have what we need for a full session
      if (!token) {
        throw new APIError("No authentication token received from server", 500);
      }

      if (!normalizedUser) {
        throw new APIError("Invalid user data received from server", 500);
      }

      // User has 2FA disabled, proceed to save session and redirect to dashboard
      this.saveUserSession(normalizedUser);
      this.trackLoginAttempt(email, true);

      return { success: true, user: normalizedUser, requires2FA: false };
    } catch (error) {
      this.trackLoginAttempt(email, false);
      if (error.name === "ValidationError" || error.name === "APIError") {
        throw error;
      }
      // Preserve the original error message for debugging instead of swallowing it
      console.error("[Login] Unexpected error:", error.message || error);
      throw new APIError(
        error.message || "An error occurred during login",
        error.status || 500,
      );
    } finally {
      hideLoading();
    }
  }

  // Verify 2FA code during login
  // API docs: POST /api/auth/2fa/verify  body: { email, code }
  // Response: { status, message, data: { user: {...}, token: "..." } }
  async verify2FA(code, email) {
    try {
      // Show loading indicator
      showLoading("Verifying code...");

      // Send 2FA verification request — backend requires both email and code
      const response = await this.apiClient.post("auth/2fa/verify", {
        email: email,
        code: code,
      });

      // Backend nests payload under response.data
      const payload = response.data || response;

      // Store JWT token
      const token = payload.token || response.token;
      if (token) {
        this.apiClient.setToken(token);
      }

      // Normalize user data
      const rawUser = payload.user || response.user;
      const normalizedUser = this.normalizeUserData(rawUser);

      // The verify endpoint response may not include two_factor_enabled,
      // but the user just passed 2FA — so it's definitively enabled
      normalizedUser.twoFactorEnabled = true;

      // Save user session
      this.saveUserSession(normalizedUser);

      return { success: true, user: normalizedUser };
    } catch (error) {
      console.error("2FA verification error:", error);

      if (error.name === "APIError" || error.name === "ValidationError") {
        throw error; // Re-throw for form handling
      }

      throw new Error("An error occurred during 2FA verification");
    } finally {
      // Hide loading indicator
      hideLoading();
    }
  }

  // Setup 2FA - Get QR code and secret
  async setup2FA() {
    try {
      // Show loading indicator
      showLoading("Setting up 2FA...");

      // Send 2FA setup request
      const response = await this.apiClient.post("auth/2fa/setup");

      // Backend may nest payload under response.data or return it flat
      const payload = response.data || response;

      // Extract QR code — handle multiple possible field names
      const qrCode =
        payload.qr_code ||
        payload.qr_code_url ||
        payload.qrCode ||
        payload.qr ||
        payload.svg ||
        payload.otpauth_url ||
        response.qr_code ||
        response.qrCode ||
        null;

      // Extract secret key
      const secret =
        payload.secret ||
        payload.secret_key ||
        payload.secretKey ||
        payload.manual_key ||
        response.secret ||
        null;

      if (!qrCode && !secret) {
        console.error(
          "[2FA Setup] No QR code or secret in response:",
          response,
        );
      }

      return {
        success: true,
        qrCode: qrCode,
        secret: secret,
      };
    } catch (error) {
      console.error("2FA setup error:", error);

      if (error.name === "APIError") {
        throw error; // Re-throw API errors for form handling
      }

      throw new Error("An error occurred during 2FA setup");
    } finally {
      // Hide loading indicator
      hideLoading();
    }
  }

  // Enable 2FA with verification code
  async enable2FA(code) {
    try {
      // Send 2FA enable request with verification code
      const response = await this.apiClient.post("auth/2fa/enable", {
        code: code,
      });

      // Update current user's 2FA status
      if (this.currentUser) {
        this.currentUser.twoFactorEnabled = true;
        localStorage.setItem(
          "cyberguard_user",
          JSON.stringify(this.currentUser),
        );
      }

      return {
        success: true,
        message: response.message || "2FA enabled successfully",
      };
    } catch (error) {
      console.error("2FA enable error:", error);

      if (error.name === "APIError") {
        throw error; // Re-throw API errors for form handling
      }

      throw new Error("An error occurred while enabling 2FA");
    }
  }

  // Disable 2FA
  // API docs: POST /api/auth/2fa/disable  body: { code }  auth: Bearer
  // 200 → disabled  |  400 → not enabled  |  401 → invalid code  |  422 → validation
  async disable2FA(code) {
    try {
      if (!code) {
        throw new APIError(
          "Please enter your authenticator code to confirm.",
          400,
        );
      }

      // Send 2FA disable request — body MUST include { "code": "<string>" }
      const response = await this.apiClient.post("auth/2fa/disable", {
        code: String(code), // must be a string per API spec
      });

      // Update current user's 2FA status in memory
      if (this.currentUser) {
        this.currentUser.twoFactorEnabled = false;
        this.currentUser.requires2FA = false;
        localStorage.setItem(
          "cyberguard_user",
          JSON.stringify(this.currentUser),
        );
      }

      // CRITICAL: Clear ALL 2FA-related state to prevent ghost 2FA prompts
      // on the next login after deactivation
      localStorage.removeItem("requires_2fa");
      localStorage.removeItem("cyberguard_2fa_pending");
      localStorage.removeItem("cyberguard_2fa_secret");

      sessionStorage.removeItem("requires_2fa");
      sessionStorage.removeItem("pending_2fa_verification");
      sessionStorage.removeItem("2fa_session_token");
      sessionStorage.removeItem("cyberguard_2fa_pending");

      // Double-check: ensure the persisted user object has twoFactorEnabled: false
      const storedUser = localStorage.getItem("cyberguard_user");
      if (storedUser) {
        try {
          const userObj = JSON.parse(storedUser);
          userObj.twoFactorEnabled = false;
          userObj.requires2FA = false;
          delete userObj.two_factor_enabled;
          localStorage.setItem("cyberguard_user", JSON.stringify(userObj));
        } catch (e) {
          console.warn("Failed to update stored user object:", e);
        }
      }

      return {
        success: true,
        message: response.message || "2FA disabled successfully",
      };
    } catch (error) {
      // Always log full error details — never swallow silently
      console.error(
        "[2FA] disable2FA error — status:",
        error.status,
        "| name:",
        error.name,
        "| data:",
        error.data,
      );

      if (error.status === 422 || error.name === "ValidationError") {
        // 422: log full body for debugging
        console.error(
          "[2FA] 422 Validation details:",
          JSON.stringify(error.errors || error.data, null, 2),
        );
        throw error;
      }

      if (error.name === "APIError") {
        throw error; // pass through so UI can show status-specific messages
      }

      throw new Error(error.message || "An error occurred while disabling 2FA");
    }
  }

  // Fetch user profile from backend
  async fetchUserProfile() {
    try {
      // Send GET request to fetch user profile
      const response = await this.apiClient.get("auth/me");

      // Normalize user data
      const normalizedUser = this.normalizeUserData(response.user || response);

      return {
        success: true,
        user: normalizedUser,
      };
    } catch (error) {
      console.error("Fetch user profile error:", error);

      if (error.name === "APIError") {
        throw error; // Re-throw API errors for handling
      }

      throw new Error("An error occurred while fetching user profile");
    }
  }

  // Fetch session status from backend
  async fetchSessionStatus() {
    try {
      // Send GET request to fetch session status
      const response = await this.apiClient.get("auth/status");

      return {
        success: true,
        emailVerified: response.email_verified || false,
        twoFactorEnabled: response.two_factor_enabled || false,
      };
    } catch (error) {
      console.error("Fetch session status error:", error);

      if (error.name === "APIError") {
        throw error; // Re-throw API errors for handling
      }

      throw new Error("An error occurred while fetching session status");
    }
  }

  // Fetch live 2FA on/off status from the backend
  // API docs: GET /api/auth/2fa/status  (Bearer required)
  // Response: { status, data: { two_factor_enabled: boolean } }
  async fetch2FAStatus() {
    try {
      const response = await this.apiClient.get("auth/2fa/status");
      const payload = response.data || response;
      const enabled =
        payload.two_factor_enabled === true ||
        payload.twoFactorEnabled === true;
      return { success: true, twoFactorEnabled: enabled };
    } catch (error) {
      console.error("[2FA] fetch2FAStatus error:", error);
      if (error.name === "APIError") throw error;
      throw new Error("Failed to fetch 2FA status");
    }
  }

  // Restore session on page load
  async restoreSession() {
    try {
      // Check if JWT token exists
      const token = this.apiClient.getToken();

      if (!token) {
        // No token, show guest UI
        this.currentUser = null;
        this.updateUI();
        return { success: false, message: "No token found" };
      }

      // Fetch user profile (which includes two_factor_enabled)
      const profileResult = await this.fetchUserProfile().catch((err) => ({
        success: false,
        error: err,
      }));

      // Check if request succeeded
      if (!profileResult.success) {
        // Request failed, clear session
        this.apiClient.clearToken();
        localStorage.removeItem("cyberguard_user");
        localStorage.removeItem("cyberguard_session");
        this.currentUser = null;
        this.updateUI();
        return { success: false, message: "Session validation failed" };
      }

      // Use the user data from profile (already includes two_factor_enabled)
      const user = profileResult.user;

      // Save user session
      this.saveUserSession(user);

      // Dispatch custom event to notify dashboard that session restoration is complete
      const sessionRestoredEvent = new CustomEvent(
        "cyberguard:sessionRestored",
        {
          detail: { user: user },
        },
      );
      document.dispatchEvent(sessionRestoredEvent);

      return { success: true, user: user };
    } catch (error) {
      console.error("Restore session error:", error);

      // Clear session on any error
      this.apiClient.clearToken();
      localStorage.removeItem("cyberguard_user");
      localStorage.removeItem("cyberguard_session");
      this.currentUser = null;
      this.updateUI();

      return { success: false, message: "Session restoration failed" };
    }
  }

  // Resend verification email
  // API docs: POST /api/email/verification-notification/resend  body: { email }
  // No auth required | Throttle: 6/min
  // 200 → sent | 400 → already verified | 403 → not registered
  async resendVerificationEmail(email = null) {
    try {
      // Show loading indicator
      showLoading("Sending verification email...");

      // Use provided email, fall back to current user's email
      const targetEmail = email || (this.currentUser && this.currentUser.email);
      if (!targetEmail) {
        throw new APIError("Email address is required to resend verification.", 400);
      }

      // Send POST request to resend verification email — no auth required
      const response = await this.apiClient.post(
        "email/verification-notification/resend",
        { email: targetEmail },
        { skipAuth: true }
      );

      return {
        success: true,
        message: response.message || "Verification email sent successfully",
      };
    } catch (error) {
      console.error("Resend verification email error:", error);

      if (error.name === "APIError") {
        throw error; // Re-throw API errors for form handling
      }

      throw new Error("An error occurred while resending verification email");
    } finally {
      // Hide loading indicator
      hideLoading();
    }
  }

  // Logout with API - Backend integration
  async logoutWithAPI() {
    // Capture email before clearing state
    const userEmail = this.currentUser?.email || "unknown";

    try {
      // Send logout request to backend
      await this.apiClient.post("auth/logout");
    } catch (error) {
      console.error("Logout API error:", error);
      // Continue with local cleanup even if API call fails
    } finally {
      // Clear JWT token
      this.apiClient.clearToken();

      // Clear core session data
      localStorage.removeItem("cyberguard_user");
      localStorage.removeItem("cyberguard_session");

      // Clear all 2FA-related state to prevent ghost prompts on next login
      localStorage.removeItem("requires_2fa");
      localStorage.removeItem("cyberguard_2fa_pending");
      localStorage.removeItem("cyberguard_2fa_secret");
      sessionStorage.removeItem("requires_2fa");
      sessionStorage.removeItem("pending_2fa_verification");
      sessionStorage.removeItem("2fa_session_token");
      sessionStorage.removeItem("cyberguard_2fa_pending");

      this.currentUser = null;

      // Track logout (using captured email)
      this.trackLogout(userEmail);

      // Redirect to login page
      window.location.href = "login.html";
    }
  }

  // Validate registration data
  validateRegistrationData(userData) {
    const errors = [];

    // Email validation
    if (!userData.email || !this.validateEmail(userData.email)) {
      errors.push({ field: "email", message: "Valid email is required" });
    }

    // Password validation
    const passwordValidation = this.validatePassword(userData.password);
    if (!passwordValidation.valid) {
      errors.push({
        field: "password",
        message:
          "Password must be at least 8 characters and include uppercase, lowercase, numbers, and symbols",
      });
    }

    // Full name validation (values are already trimmed in registerWithAPI)
    if (!userData.fullName || userData.fullName.length === 0) {
      errors.push({ field: "fullName", message: "Full name is required" });
    }

    // Job title validation (values are already trimmed in registerWithAPI)
    if (!userData.jobTitle || userData.jobTitle.length === 0) {
      errors.push({ field: "jobTitle", message: "Job title is required" });
    }

    // Password confirmation validation
    if (
      !userData.passwordConfirmation ||
      userData.passwordConfirmation.length === 0
    ) {
      errors.push({
        field: "passwordConfirmation",
        message: "Password confirmation is required",
      });
    }

    return errors;
  }

  // Validate login data
  validateLoginData(email, password) {
    const errors = [];

    // Email validation
    if (!email || !this.validateEmail(email)) {
      errors.push({ field: "email", message: "Valid email is required" });
    }

    // Password validation - just check if it exists for login
    if (!password || password.trim().length === 0) {
      errors.push({ field: "password", message: "Password is required" });
    }

    return errors;
  }

  // Sanitize user input to prevent XSS attacks
  // Uses character stripping instead of HTML encoding to preserve valid chars like @, +, etc.
  sanitizeInput(input) {
    if (typeof input !== "string") {
      return input;
    }
    // Remove actual dangerous HTML/script characters only — do NOT encode @ . + - _ etc.
    return input
      .replace(/</g, "")
      .replace(/>/g, "")
      .replace(/&/g, "")
      .replace(/"/g, "")
      .replace(/'/g, "")
      .replace(/`/g, "");
  }

  // Sanitize an object's string properties
  sanitizeObject(obj) {
    const sanitized = {};
    for (const key in obj) {
      if (obj.hasOwnProperty(key)) {
        if (typeof obj[key] === "string") {
          sanitized[key] = this.sanitizeInput(obj[key]);
        } else {
          sanitized[key] = obj[key];
        }
      }
    }
    return sanitized;
  }

  // Normalize user data to handle backend inconsistencies
  // Uses the external normalizeUserData utility from data-normalizer.js
  normalizeUserData(userData) {
    // Call the external utility function
    return normalizeUserData(userData);
  }

  // Logout function
  logout() {
    try {
      // Track logout
      if (this.currentUser) {
        this.trackLogout(this.currentUser.email);
      }

      // Clear all sensitive data including JWT token
      this.apiClient.clearToken();
      localStorage.removeItem("cyberguard_user");
      localStorage.removeItem("cyberguard_session");

      // Clear all 2FA-related state to prevent ghost prompts on next login
      localStorage.removeItem("requires_2fa");
      localStorage.removeItem("cyberguard_2fa_pending");
      localStorage.removeItem("cyberguard_2fa_secret");
      sessionStorage.removeItem("requires_2fa");
      sessionStorage.removeItem("pending_2fa_verification");
      sessionStorage.removeItem("2fa_session_token");
      sessionStorage.removeItem("cyberguard_2fa_pending");

      this.currentUser = null;

      // Redirect to login page
      window.location.href = "login.html";
    } catch (error) {
      console.error("Logout error:", error);
    }
  }

  // Check if user is authenticated
  isAuthenticated() {
    return this.currentUser !== null;
  }

  // Get current user
  getCurrentUser() {
    return this.currentUser;
  }

  // Update UI based on authentication status
  updateUI() {
    const authElements = document.querySelectorAll("[data-auth]");
    const guestElements = document.querySelectorAll("[data-guest]");
    const authRequiredElements = document.querySelectorAll(
      "[data-auth-required]",
    );

    if (this.isAuthenticated()) {
      // Mark document state for CSS overrides
      document.body.classList.add("authenticated");
      document.body.classList.remove("guest");
      // Show authenticated elements
      authElements.forEach((el) => {
        el.classList.remove("hidden");
        el.style.removeProperty("display");
      });
      guestElements.forEach((el) => {
        el.classList.add("hidden");
        el.style.removeProperty("display");
      });
      // Explicitly hide guest notice if present
      const guestNotice = document.getElementById("guest-notice");
      if (guestNotice) {
        guestNotice.classList.add("hidden");
        guestNotice.style.display = "none";
      }

      // Enable all auth-required elements
      authRequiredElements.forEach((el) => {
        el.disabled = false;
        el.classList.remove("disabled");
      });

      // Update header user info section
      const userNameEl = document.getElementById("userName");
      const userEmailEl = document.getElementById("userEmail");
      const userInfoEl = document.getElementById("user-info");

      if (userNameEl)
        userNameEl.textContent =
          this.currentUser.fullName || this.currentUser.name;
      if (userEmailEl) userEmailEl.textContent = this.currentUser.email;

      // Show user info section
      if (userInfoEl) {
        userInfoEl.classList.remove("hidden");
      }

      // Update landing page user initials and mobile user name
      const userInitialsEl = document.getElementById("userInitials");
      const mobileUserInitialsEl = document.getElementById("mobileUserInitials");
      const mobileUserNameEl = document.getElementById("mobileUserName");
      
      const fullName = this.currentUser.fullName || this.currentUser.name || "";
      const parts = fullName.trim().split(/\s+/);
      let initials = "";
      
      if (parts.length >= 2) {
        initials = (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
      } else if (parts.length === 1 && parts[0].length >= 2) {
        initials = parts[0].substring(0, 2).toUpperCase();
      } else {
        initials = fullName.substring(0, 2).toUpperCase() || "U";
      }
      
      if (userInitialsEl) {
        userInitialsEl.textContent = initials;
      }
      if (mobileUserInitialsEl) {
        mobileUserInitialsEl.textContent = initials;
      }
      if (mobileUserNameEl) {
        mobileUserNameEl.textContent = fullName;
      }

      // Update sidebar profile card with full_name and job_title
      const sidebarName = document.getElementById("sidebarUserName");
      const sidebarRole = document.getElementById("sidebarUserRole");
      const sidebarInitials = document.getElementById("sidebarUserInitials");

      if (sidebarName) {
        sidebarName.textContent =
          this.currentUser.fullName || this.currentUser.name;
      }

      if (sidebarRole) {
        // Use job_title from session data, fallback to role or default
        sidebarRole.textContent =
          this.currentUser.jobTitle ||
          this.currentUser.role ||
          "Security Analyst";
      }

      // Calculate and display user initials from full_name
      if (sidebarInitials) {
        sidebarInitials.textContent = initials;
      }
    } else {
      // Mark document state for CSS overrides
      document.body.classList.remove("authenticated");
      document.body.classList.add("guest");
      // Show guest elements
      authElements.forEach((el) => {
        el.classList.add("hidden");
        el.style.removeProperty("display");
      });
      guestElements.forEach((el) => {
        el.classList.remove("hidden");
        el.style.removeProperty("display");
      });
      // Explicitly show guest notice if present
      const guestNotice = document.getElementById("guest-notice");
      if (guestNotice) {
        guestNotice.classList.remove("hidden");
        guestNotice.style.display = "";
      }

      // Auth-required elements are now handled by CSS pseudo-elements
      // The lock icon will appear via CSS when body has 'guest' class
      authRequiredElements.forEach((el) => {
        el.classList.add("auth-required");
      });
    }
  }

  // Setup session timeout
  setupSessionTimeout() {
    setInterval(() => {
      if (this.isAuthenticated()) {
        const sessionData = localStorage.getItem("cyberguard_session");
        if (sessionData) {
          const session = JSON.parse(sessionData);
          if (Date.now() - session.timestamp > this.sessionTimeout) {
            this.handleSessionExpiration();
          }
        }
      }
    }, 60000); // Check every minute
  }

  // Setup page visibility handler to check session on every page load/focus
  setupPageVisibilityHandler() {
    // Check session validity when page becomes visible
    document.addEventListener("visibilitychange", async () => {
      if (!document.hidden && this.isAuthenticated()) {
        await this.validateSessionOnPageLoad();
      }
    });

    // Check session validity when window gains focus
    window.addEventListener("focus", async () => {
      if (this.isAuthenticated()) {
        await this.validateSessionOnPageLoad();
      }
    });

    // Check session validity on page load (beforeunload event for next page)
    window.addEventListener("beforeunload", () => {
      // Store timestamp of last activity for next page load check
      if (this.isAuthenticated()) {
        const sessionData = localStorage.getItem("cyberguard_session");
        if (sessionData) {
          const session = JSON.parse(sessionData);
          session.lastChecked = Date.now();
          localStorage.setItem("cyberguard_session", JSON.stringify(session));
        }
      }
    });
  }

  // Validate session on every page load
  async validateSessionOnPageLoad() {
    try {
      const token = this.apiClient.getToken();

      if (!token) {
        // No token, clear session
        this.currentUser = null;
        this.updateUI();
        return;
      }

      // Check if session has expired locally
      const sessionData = localStorage.getItem("cyberguard_session");
      if (sessionData) {
        const session = JSON.parse(sessionData);
        if (Date.now() - session.timestamp > this.sessionTimeout) {
          this.handleSessionExpiration();
          return;
        }
      }

      // Validate session with backend (lightweight check)
      const statusResult = await this.fetchSessionStatus().catch((err) => {
        console.error("Session validation failed:", err);
        return { success: false };
      });

      if (!statusResult.success) {
        // Session invalid, clear and show guest UI
        this.handleSessionExpiration();
      }
    } catch (error) {
      console.error("Error validating session on page load:", error);
      // Don't clear session on network errors, only on auth errors
    }
  }

  // Handle session expiration gracefully
  handleSessionExpiration() {
    // Clear session data
    this.apiClient.clearToken();
    localStorage.removeItem("cyberguard_user");
    localStorage.removeItem("cyberguard_session");

    // Clear 2FA state to prevent ghost prompts
    localStorage.removeItem("requires_2fa");
    localStorage.removeItem("cyberguard_2fa_pending");
    localStorage.removeItem("cyberguard_2fa_secret");
    sessionStorage.removeItem("requires_2fa");
    sessionStorage.removeItem("pending_2fa_verification");
    sessionStorage.removeItem("2fa_session_token");
    sessionStorage.removeItem("cyberguard_2fa_pending");

    this.currentUser = null;

    // Show user-friendly notification
    if (typeof CyberNotify !== "undefined") {
      CyberNotify.alert(
        "Your session has expired. Please log in again to continue.",
        {
          type: "warning",
          duration: 5000,
        },
      );
    }

    // Update UI to guest state
    this.updateUI();

    // Redirect to login page if not already there
    if (
      window.location.pathname !== "/login.html" &&
      window.location.pathname !== "/index.html"
    ) {
      setTimeout(() => {
        window.location.href = "login.html?session_expired=true";
      }, 2000); // Give user time to see the notification
    }
  }

  // Setup event listeners
  setupEventListeners() {
    // Ensure UI updates once DOM is fully ready
    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", () => this.updateUI());
    } else {
      // DOM already parsed
      this.updateUI();
    }

    // Logout buttons (multiple IDs for different pages)
    const logoutBtn = document.getElementById("logoutBtn");
    const logoutBtnHyphen = document.getElementById("logout-btn");
    const mobileLogoutBtn = document.getElementById("mobile-logout-btn");
    
    if (logoutBtn) {
      logoutBtn.addEventListener("click", () => this.logoutWithAPI());
    }
    if (logoutBtnHyphen) {
      logoutBtnHyphen.addEventListener("click", () => this.logoutWithAPI());
    }
    if (mobileLogoutBtn) {
      mobileLogoutBtn.addEventListener("click", () => this.logoutWithAPI());
    }

    // Add click listeners to auth-required elements (excluding API Keys which is handled in main.js)
    document.addEventListener("click", (e) => {
      const authRequiredElement = e.target.closest("[data-auth-required]");
      if (authRequiredElement && !this.isAuthenticated()) {
        // Skip API Keys toggle as it's handled in main.js
        if (authRequiredElement.id === "api-keys-toggle") {
          return;
        }
        // For other elements, just show an informative message
        this.showFeatureLimitation();
      }
    });

    // Session activity tracking
    ["mousedown", "mousemove", "keypress", "scroll", "touchstart"].forEach(
      (event) => {
        document.addEventListener(event, () => this.updateSessionActivity());
      },
    );
  }

  // Show authentication prompt
  showAuthPrompt() {
    // Create and show a modal prompt
    const modal = document.createElement("div");
    modal.className =
      "fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50";
    modal.innerHTML = `
      <div class="bg-white rounded-2xl shadow-2xl p-8 max-w-md mx-4 text-center">
        <div class="w-16 h-16 mx-auto bg-gradient-to-br from-blue-500 to-purple-600 rounded-full flex items-center justify-center mb-6">
          <svg class="w-8 h-8 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" d="M16.5 10.5V6.75a4.5 4.5 0 1 0-9 0v3.75m-.75 11.25h10.5a2.25 2.25 0 0 0 2.25-2.25v-6.75a2.25 2.25 0 0 0-2.25-2.25H6.75a2.25 2.25 0 0 0-2.25 2.25v6.75a2.25 2.25 0 0 0 2.25 2.25Z" />
          </svg>
        </div>
        <h2 class="text-xl font-bold text-slate-800 mb-4">Authentication Required</h2>
        <p class="text-slate-600 mb-6">Please log in to access this security tool.</p>
        <div class="flex gap-4">
          <a href="login.html" class="flex-1 cyber-btn-ghost text-white font-semibold py-3 px-4 rounded-xl transition-colors flex items-center justify-center gap-2">
            <svg class="w-5 h-5" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor">
              <path stroke-linecap="round" stroke-linejoin="round" d="M15.75 6a3.75 3.75 0 1 1-7.5 0 3.75 3.75 0 0 1 7.5 0ZM4.501 20.118a7.5 7.5 0 0 1 14.998 0A17.933 17.933 0 0 1 12 21.75c-2.676 0-5.216-.584-7.499-1.632Z" />
            </svg>
            Login
          </a>
          <a href="signup.html" class="flex-1 cyber-btn-primary text-white font-semibold py-3 px-4 rounded-xl transition-colors flex items-center justify-center gap-2">
            <svg class="w-5 h-5" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor">
              <path stroke-linecap="round" stroke-linejoin="round" d="M18 7.5v3m0 0v3m0-3h3m-3 0h-3m-2.25-4.125a3.375 3.375 0 1 1-6.75 0 3.375 3.375 0 0 1 6.75 0ZM3 19.235v-.11a6.375 6.375 0 0 1 12.75 0v.109A12.318 12.318 0 0 1 9.374 21c-2.331 0-4.512-.645-6.374-1.766Z" />
            </svg>
            Sign Up
          </a>
        </div>
        <button class="mt-4 text-slate-500 hover:text-slate-700 transition-colors" onclick="this.parentElement.parentElement.remove()">
          Cancel
        </button>
      </div>
    `;

    document.body.appendChild(modal);

    // Auto-remove after 10 seconds
    setTimeout(() => {
      if (modal.parentElement) {
        modal.remove();
      }
    }, 10000);
  }

  // Show feature limitation message
  showFeatureLimitation() {
    // Create a toast notification instead of a blocking modal
    const toast = document.createElement("div");
    toast.className =
      "fixed top-4 right-4 bg-orange-50 border border-orange-200 rounded-lg p-4 max-w-sm z-50 shadow-lg";
    toast.innerHTML = `
      <div class="flex items-start gap-3">
        <div class="w-8 h-8 bg-orange-100 rounded-full flex items-center justify-center flex-shrink-0">
          <svg class="w-4 h-4 text-orange-600" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126ZM12 15.75h.007v.008H12v-.008Z" />
          </svg>
        </div>
        <div class="flex-1">
          <h4 class="text-sm font-semibold text-orange-800 mb-1">Feature Limitation</h4>
          <p class="text-xs text-orange-700 mb-2">This feature requires authentication for full functionality. You can still explore the interface!</p>
          <div class="flex gap-2">
            <a href="login.html" class="text-xs bg-orange-500 hover:bg-orange-600 text-white font-semibold py-1 px-2 rounded transition-colors">
              Login
            </a>
            <a href="signup.html" class="text-xs bg-green-500 hover:bg-green-600 text-white font-semibold py-1 px-2 rounded transition-colors">
              Sign Up
            </a>
          </div>
        </div>
        <button class="text-orange-400 hover:text-orange-600 transition-colors" onclick="this.parentElement.parentElement.remove()">
          <svg class="w-4 h-4" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12" />
          </svg>
        </button>
      </div>
    `;

    document.body.appendChild(toast);

    // Auto-remove after 8 seconds
    setTimeout(() => {
      if (toast.parentElement) {
        toast.remove();
      }
    }, 8000);
  }

  // Show API Keys restriction message
  showApiKeysRestriction() {
    // Create a modal specifically for API Keys restriction
    const modal = document.createElement("div");
    modal.className =
      "fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50";
    modal.innerHTML = `
      <div class="bg-white rounded-2xl shadow-2xl p-8 max-w-md mx-4 text-center">
        <div class="w-20 h-20 mx-auto bg-gradient-to-br from-blue-500 to-purple-600 rounded-full flex items-center justify-center mb-6">
          <svg class="w-10 h-10 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" d="M15.75 5.25a3 3 0 0 1 3 3m3 0a6 6 0 0 1-7.029 5.912c-.563-.097-1.159.026-1.563.43L10.5 17.25H8.25v2.25H6v2.25H2.25v-2.818c0-.597.237-1.17.659-1.591l6.499-6.499c.404-.404.527-1 .43-1.563A6 6 0 1 1 21.75 8.25Z" />
          </svg>
        </div>
        <h2 class="text-2xl font-bold text-slate-800 mb-4">Authentication Required</h2>
        <p class="text-slate-600 mb-6">API Key configuration requires authentication. Please log in to configure your API keys.</p>
        <div class="flex gap-4">
          <a href="login.html" class="flex-1 cyber-btn-ghost text-white font-semibold py-3 px-4 rounded-xl transition-colors flex items-center justify-center gap-2">
            <svg class="w-5 h-5" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor">
              <path stroke-linecap="round" stroke-linejoin="round" d="M15.75 6a3.75 3.75 0 1 1-7.5 0 3.75 3.75 0 0 1 7.5 0ZM4.501 20.118a7.5 7.5 0 0 1 14.998 0A17.933 17.933 0 0 1 12 21.75c-2.676 0-5.216-.584-7.499-1.632Z" />
            </svg>
            Login
          </a>
          <a href="signup.html" class="flex-1 cyber-btn-primary text-white font-semibold py-3 px-4 rounded-xl transition-colors flex items-center justify-center gap-2">
            <svg class="w-5 h-5" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor">
              <path stroke-linecap="round" stroke-linejoin="round" d="M18 7.5v3m0 0v3m0-3h3m-3 0h-3m-2.25-4.125a3.375 3.375 0 1 1-6.75 0 3.375 3.375 0 0 1 6.75 0ZM3 19.235v-.11a6.375 6.375 0 0 1 12.75 0v.109A12.318 12.318 0 0 1 9.374 21c-2.331 0-4.512-.645-6.374-1.766Z" />
            </svg>
            Sign Up
          </a>
        </div>
        <button class="mt-4 text-slate-500 hover:text-slate-700 transition-colors" onclick="this.parentElement.parentElement.remove()">
          Cancel
        </button>
      </div>
    `;

    document.body.appendChild(modal);

    // Auto-remove after 15 seconds
    setTimeout(() => {
      if (modal.parentElement) {
        modal.remove();
      }
    }, 15000);
  }

  // Update session activity
  updateSessionActivity() {
    if (this.isAuthenticated()) {
      const sessionData = localStorage.getItem("cyberguard_session");
      if (sessionData) {
        const session = JSON.parse(sessionData);
        session.timestamp = Date.now();
        localStorage.setItem("cyberguard_session", JSON.stringify(session));
      }
    }
  }

  // Simulate API authentication
  async authenticateUser(email, password) {
    // Simulate network delay
    await new Promise((resolve) => setTimeout(resolve, 1000));

    // Demo credentials
    const demoUsers = [
      {
        email: "admin@cyberguard.com",
        password: "admin123",
        name: "Admin User",
        company: "CyberGuard Inc.",
      },
      {
        email: "user@cyberguard.com",
        password: "user123",
        name: "John Doe",
        company: "Security Corp",
      },
      {
        email: "demo@cyberguard.com",
        password: "demo123",
        name: "Demo User",
        company: "Demo Company",
      },
    ];

    // Check demo users first
    let user = demoUsers.find(
      (u) => u.email === email && u.password === password,
    );

    // If not found in demo users, check localStorage users
    let storedUser = null;
    if (!user) {
      const existingUsers = JSON.parse(
        localStorage.getItem("cyberguard_users") || "[]",
      );
      storedUser = existingUsers.find(
        (u) => u.email === email && u.password === password,
      );

      if (storedUser) {
        user = {
          id: storedUser.id,
          email: storedUser.email,
          password: storedUser.password,
          name: storedUser.name,
          company: storedUser.company || "",
        };
      }
    }

    if (user) {
      // Determine role - check if admin
      let role = "user";
      if (
        email === "admin@cyberguard.com" ||
        email.toLowerCase().includes("admin")
      ) {
        role = "admin";
      } else if (storedUser && storedUser.role === "admin") {
        role = "admin";
      }

      return {
        success: true,
        user: {
          id: user.id || Math.random().toString(36).substr(2, 9),
          email: user.email,
          name: user.name,
          company: user.company,
          role: role,
        },
      };
    } else {
      return {
        success: false,
        message: "Invalid email or password",
      };
    }
  }

  // Simulate API user creation
  async createUser(userData) {
    // Simulate network delay
    await new Promise((resolve) => setTimeout(resolve, 1500));

    // Check if email already exists
    const existingUsers = JSON.parse(
      localStorage.getItem("cyberguard_users") || "[]",
    );
    if (existingUsers.find((u) => u.email === userData.email)) {
      return {
        success: false,
        message: "Email already exists",
      };
    }

    // Create new user (store password for authentication)
    const newUser = {
      id: Math.random().toString(36).substr(2, 9),
      email: userData.email,
      name: userData.fullName,
      company: userData.company || "",
      password: userData.password, // Store password for authentication
      role: "user",
      preferences: {
        notifications: true,
        reports: true,
        updates: false,
      },
    };

    // Save to localStorage (in a real app, this would be sent to server)
    existingUsers.push(newUser);
    localStorage.setItem("cyberguard_users", JSON.stringify(existingUsers));

    return {
      success: true,
      user: newUser,
    };
  }

  // Initialize admin account if it doesn't exist
  initializeAdminAccount() {
    const existingUsers = JSON.parse(
      localStorage.getItem("cyberguard_users") || "[]",
    );

    // Check if admin account already exists
    const adminExists = existingUsers.find(
      (u) => u.email === "admin@test.com" || u.role === "admin",
    );

    if (!adminExists) {
      // Create admin account
      const adminUser = {
        id: "admin_" + Math.random().toString(36).substr(2, 9),
        email: "admin@test.com",
        name: "Admin User",
        company: "CyberGuard Pro",
        password: "admin123", // Simple password for testing
        role: "admin",
        preferences: {
          notifications: true,
          reports: true,
          updates: true,
        },
        createdAt: new Date().toISOString(),
      };

      existingUsers.push(adminUser);
      localStorage.setItem("cyberguard_users", JSON.stringify(existingUsers));

      console.log("✅ Admin account created!");
      console.log("📧 Email: admin@test.com");
      console.log("👤 Role: admin");

      return adminUser;
    }

    return null;
  }

  // Track login attempts
  trackLoginAttempt(email, success) {
    const attempts = JSON.parse(
      localStorage.getItem("cyberguard_login_attempts") || "[]",
    );
    attempts.push({
      email: email,
      success: success,
      timestamp: new Date().toISOString(),
      ip: "127.0.0.1",
      userAgent: navigator.userAgent,
    });

    // Keep only last 100 attempts
    if (attempts.length > 100) {
      attempts.splice(0, attempts.length - 100);
    }

    localStorage.setItem("cyberguard_login_attempts", JSON.stringify(attempts));
  }

  // Track registration
  trackRegistration(email) {
    const registrations = JSON.parse(
      localStorage.getItem("cyberguard_registrations") || "[]",
    );
    registrations.push({
      email: email,
      timestamp: new Date().toISOString(),
      ip: "127.0.0.1",
    });

    localStorage.setItem(
      "cyberguard_registrations",
      JSON.stringify(registrations),
    );
  }

  // Track logout
  trackLogout(email) {
    const logouts = JSON.parse(
      localStorage.getItem("cyberguard_logouts") || "[]",
    );
    logouts.push({
      email: email,
      timestamp: new Date().toISOString(),
      ip: "127.0.0.1",
    });

    localStorage.setItem("cyberguard_logouts", JSON.stringify(logouts));
  }

  // Password strength checker
  checkPasswordStrength(password) {
    let score = 0;
    const checks = {
      length: password.length >= 8,
      lowercase: /[a-z]/.test(password),
      uppercase: /[A-Z]/.test(password),
      numbers: /[0-9]/.test(password),
      symbols: /[^A-Za-z0-9]/.test(password),
    };

    score = Object.values(checks).filter(Boolean).length;

    return {
      score: score,
      maxScore: 5,
      percentage: (score / 5) * 100,
      checks: checks,
      strength:
        score < 2 ? "weak" : score < 4 ? "fair" : score < 5 ? "good" : "strong",
    };
  }

  // Validate email format
  validateEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  }

  // Validate password requirements
  validatePassword(password) {
    const requirements = {
      length: password.length >= 8,
      lowercase: /[a-z]/.test(password),
      uppercase: /[A-Z]/.test(password),
      numbers: /[0-9]/.test(password),
      symbols: /[^A-Za-z0-9]/.test(password),
    };

    return {
      valid: Object.values(requirements).every(Boolean),
      requirements: requirements,
    };
  }

  // Get security statistics
  getSecurityStats() {
    const attempts = JSON.parse(
      localStorage.getItem("cyberguard_login_attempts") || "[]",
    );
    const registrations = JSON.parse(
      localStorage.getItem("cyberguard_registrations") || "[]",
    );
    const logouts = JSON.parse(
      localStorage.getItem("cyberguard_logouts") || "[]",
    );

    return {
      totalLoginAttempts: attempts.length,
      successfulLogins: attempts.filter((a) => a.success).length,
      failedLogins: attempts.filter((a) => !a.success).length,
      totalRegistrations: registrations.length,
      totalLogouts: logouts.length,
      lastLogin: attempts.filter((a) => a.success).pop()?.timestamp,
      lastRegistration: registrations.pop()?.timestamp,
    };
  }
}

// Initialize authentication manager
const authManager = new AuthManager();

// Export for use in other scripts
window.AuthManager = AuthManager;
window.authManager = authManager;

// ===== AUTHENTICATION GUARD HELPERS =====

/**
 * isAuthenticated() — checks ALL known token keys in BOTH storages.
 * The canonical key used by APIClient.setToken() is "cyberguard_jwt".
 * Legacy / alternate keys are also checked for backward compatibility.
 * Returns true if ANY non-empty token string is found.
 */
window.isAuthenticated = function() {
  // All known key names used across the app (canonical key first)
  const keys = [
    'cyberguard_jwt',   // canonical — written by APIClient.setToken()
    'auth_token',       // legacy fallback
    'access_token',     // possible backend alias
    'token',            // generic fallback
    'authToken',        // camelCase variant
  ];

  for (const key of keys) {
    const value = localStorage.getItem(key) || sessionStorage.getItem(key);
    if (!value) continue;

    // Handle JSON-wrapped tokens: { token: '...' } or { access_token: '...' }
    try {
      const parsed = JSON.parse(value);
      const inner = parsed?.token || parsed?.access_token || parsed?.data?.token;
      if (inner && inner.length > 10) return true;
    } catch {
      // Plain string token — valid if it has meaningful length
      if (value.length > 10) return true;
    }
  }

  return false;
};

/**
 * isTokenExpired() — returns true only for provably expired standard JWTs.
 * Returns FALSE (not expired) for non-JWT / opaque tokens so that valid
 * sessions using non-standard token formats are never accidentally blocked.
 */
window.isTokenExpired = function(token) {
  if (!token) return true;
  try {
    const parts = token.split('.');
    // Only treat as JWT if it has exactly 3 parts (header.payload.signature)
    if (parts.length !== 3) return false; // opaque token — assume valid
    const payload = JSON.parse(atob(parts[1]));
    if (!payload.exp) return false; // no expiry claim — assume valid
    return payload.exp * 1000 < Date.now();
  } catch {
    // Parse failure — do NOT assume expired; treat token as valid
    return false;
  }
};

window.clearAuthStorage = function() {
  localStorage.removeItem("cyberguard_jwt");
  localStorage.removeItem("auth_token");
  sessionStorage.removeItem("auth_token");
  localStorage.removeItem("cyberguard_user");
  localStorage.removeItem("cyberguard_session");
};

window.showLoginRequiredModal = function() {
  if (typeof CyberNotify !== 'undefined' && CyberNotify.confirm) {
    CyberNotify.confirm("You must log in first before using CyberGuard Pro tools.", () => {
      window.location.href = '/login.html';
    });
  } else {
    alert("You must log in first before using CyberGuard Pro tools.");
    window.location.href = '/login.html';
  }
};

/**
 * runAuthGuard() — the page-level auth gate.
 *
 * BUG FIXED: Previously, a token that failed JWT parsing (opaque/non-standard
 * tokens) caused isTokenExpired() to return true, triggering clearAuthStorage()
 * + modal even for a fully authenticated user.
 *
 * Fix: Two separate guard stages.
 *   1. If no token exists at all → guest, show modal.
 *   2. Only if token IS a parseable JWT with an exp claim AND that exp has
 *      passed → treat as expired session and show modal.
 *   Non-JWT opaque tokens pass stage 2 unconditionally.
 */
window.runAuthGuard = function() {
  // Stage 1 — Must have a token in storage
  if (!window.isAuthenticated()) {
    window.showLoginRequiredModal();
    return false;
  }

  // Stage 2 — Only enforce expiry on provably expired standard JWTs
  const currentToken =
    localStorage.getItem('cyberguard_jwt') ||
    localStorage.getItem('auth_token') ||
    sessionStorage.getItem('auth_token');

  if (currentToken && window.isTokenExpired(currentToken)) {
    // Token is a JWT and provably expired — clear session and prompt login
    window.clearAuthStorage();
    window.showLoginRequiredModal();
    return false;
  }

  // Authenticated and token is valid (or non-JWT opaque) → allow access
  return true;
};
