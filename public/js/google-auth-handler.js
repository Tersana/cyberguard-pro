/**
 * CyberGuard — Google OAuth Authentication Handler
 *
 * Extracted from AuthManager following SOLID principles:
 *   - Single Responsibility: Only handles Google OAuth (redirect + callback)
 *   - Open/Closed: Pattern can be replicated for GitHub, Microsoft, etc.
 *   - Dependency Inversion: Depends on APIClient / AuthManager abstractions
 *
 * Backend contract (server-side redirect, token-only):
 *   1. Frontend calls GET /api/auth/google/redirect → { redirect_url }
 *   2. Browser navigates to Google consent screen
 *   3. Google redirects to backend GET /api/auth/google/callback
 *   4. Backend processes code, creates/links user, issues Sanctum token
 *   5. Backend redirects browser to:
 *        /google-callback?token=<url-encoded Sanctum token>
 *   6. This handler reads token, saves it, calls GET /api/auth/me
 *      to fetch user profile, saves session, redirects to /dashboard.
 *
 * Requires: APIClient, AuthManager (auth.js), normalizeUserData (data-normalizer.js)
 * Globals: window.APIClient, window.authManager, window.normalizeUserData,
 *          window.CyberNotify (optional), window.ErrorHandler (optional)
 *
 * @version 1.0.0
 */

(function () {
  "use strict";

  /**
   * GoogleAuthHandler — manages the Google OAuth redirect + callback lifecycle.
   *
   * Usage:
   *   // Instantiated automatically at bottom of this file
   *   window.googleAuthHandler.redirectToGoogle();
   *   window.googleAuthHandler.handleCallback();
   */
  class GoogleAuthHandler {
    /**
     * @param {APIClient} apiClient  — API client instance for HTTP calls
     * @param {AuthManager} authManager — Auth manager for session persistence
     */
    constructor(apiClient, authManager) {
      /** @private */
      this._apiClient = apiClient;
      /** @private */
      this._authManager = authManager;
    }

    // ═══════════════════════════════════════════════════════════════════
    //  PUBLIC API
    // ═══════════════════════════════════════════════════════════════════

    /**
     * Redirect the browser to the Google OAuth consent screen.
     *
     * Flow:
     *   1. Call GET /api/auth/google/redirect (no auth required)
     *   2. Validate the returned URL is a genuine Google domain
     *   3. Navigate browser to the consent URL
     *
     * @returns {Promise<void>}
     */
    async redirectToGoogle() {
      try {
        if (typeof showLoading === "function") {
          showLoading("Connecting to Google...");
        }

        // Fetch the OAuth redirect URL from the backend
        const response = await this._apiClient.get("auth/google/redirect", {
          skipAuth: true,
        });

        const redirectUrl = response.redirect_url || response.redirectUrl;

        if (!redirectUrl) {
          throw new Error("No redirect URL received from server.");
        }

        // Security: validate the URL points to Google
        if (!this._isValidGoogleUrl(redirectUrl)) {
          throw new Error(
            "Invalid redirect URL received. Expected a Google domain.",
          );
        }

        // Navigate to Google consent screen
        window.location.href = redirectUrl;
      } catch (error) {
        console.error("[GoogleAuth] Redirect error:", error);

        // Detect ad-blocker interference
        if (this._isBlockedByClient(error)) {
          this._showAdBlockerWarning();
          return;
        }

        // Show user-facing error via CyberNotify or fallback
        const message =
          error.message || "Failed to connect to Google. Please try again.";

        if (window.CyberNotify) {
          window.CyberNotify.alert(message, { type: "error" });
        } else if (typeof showMessage === "function") {
          showMessage("error", "Google Sign-In Failed", message);
        }

        // Route through ErrorHandler if available
        if (window.ErrorHandler) {
          window.ErrorHandler.handle(error, { context: "Google OAuth redirect" });
        }
      } finally {
        if (typeof hideLoading === "function") {
          hideLoading();
        }
      }
    }

    /**
     * Process the OAuth callback on the /google-callback page.
     *
     * The backend redirects to:
     *   /google-callback?token=<urlencoded sanctum token>
     * Or on error:
     *   /google-callback?error=<code>&message=<text>
     *
     * Flow:
     *   1. Extract token from URL query string
     *   2. Save token via APIClient.setToken()
     *   3. Call GET /api/auth/me to fetch user profile
     *   4. Normalize user data
     *   5. Save session via authManager.saveUserSession()
     *   6. Clean URL params
     *   7. Return result object for the callback page to handle UI
     *
     * @returns {Promise<{success: boolean, user?: Object, error?: string}>}
     */
    async handleCallback() {
      try {
        const params = new URLSearchParams(window.location.search);

        // ── Check for error params first ──────────────────────────────
        const errorCode = params.get("error") || params.get("error_code");
        const errorMessage =
          params.get("message") ||
          params.get("error_description") ||
          params.get("error_message");

        if (errorCode || errorMessage) {
          const msg =
            errorMessage || errorCode || "Google authentication failed.";
          this._cleanUrlParams();
          return { success: false, error: msg };
        }

        // ── Extract token ─────────────────────────────────────────────
        const token = this._extractToken(params);

        if (!token) {
          return {
            success: false,
            error: "No authentication token found in the callback URL.",
          };
        }

        // ── Save token ────────────────────────────────────────────────
        this._apiClient.setToken(token);

        // ── Fetch user profile from backend ───────────────────────────
        let userProfile;
        try {
          const profileResponse = await this._apiClient.get("auth/me");
          const rawUser =
            profileResponse.data?.user ||
            profileResponse.user ||
            profileResponse.data ||
            profileResponse;
          userProfile = this._normalizeUser(rawUser);
        } catch (profileError) {
          console.error(
            "[GoogleAuth] Failed to fetch user profile:",
            profileError,
          );

          // Token might be invalid — clear it
          this._apiClient.clearToken();

          // Detect ad-blocker interference
          if (this._isBlockedByClient(profileError)) {
            return {
              success: false,
              error:
                "A browser extension is blocking the authentication request. " +
                "Please disable your ad-blocker for this site and try again.",
            };
          }

          return {
            success: false,
            error:
              profileError.message ||
              "Failed to verify your account. Please try again.",
          };
        }

        if (!userProfile) {
          this._apiClient.clearToken();
          return {
            success: false,
            error: "Could not retrieve your account information.",
          };
        }

        // ── Save user session ─────────────────────────────────────────
        this._authManager.saveUserSession(userProfile);

        // ── Track successful login ────────────────────────────────────
        if (
          typeof this._authManager.trackLoginAttempt === "function" &&
          userProfile.email
        ) {
          this._authManager.trackLoginAttempt(userProfile.email, true);
        }

        // ── Clean URL params ──────────────────────────────────────────
        this._cleanUrlParams();

        return { success: true, user: userProfile };
      } catch (error) {
        console.error("[GoogleAuth] Callback error:", error);

        // Route through ErrorHandler if available
        if (window.ErrorHandler) {
          window.ErrorHandler.handle(error, {
            context: "Google OAuth callback",
          });
        }

        return {
          success: false,
          error: error.message || "An unexpected error occurred during sign-in.",
        };
      }
    }

    /**
     * Check whether the current page is the Google OAuth callback page.
     * @returns {boolean}
     */
    isCallbackPage() {
      if (typeof window === "undefined" || !window.location) return false;
      return window.location.pathname.includes("google-callback");
    }

    // ═══════════════════════════════════════════════════════════════════
    //  PRIVATE HELPERS
    // ═══════════════════════════════════════════════════════════════════

    /**
     * Extract the authentication token from URL query parameters.
     * Supports multiple param name conventions for resilience.
     *
     * @private
     * @param {URLSearchParams} params
     * @returns {string|null}
     */
    _extractToken(params) {
      return (
        params.get("token") ||
        params.get("auth_token") ||
        params.get("access_token") ||
        null
      );
    }

    /**
     * Normalize raw user data using the global normalizeUserData utility.
     *
     * @private
     * @param {Object} rawUser
     * @returns {Object|null}
     */
    _normalizeUser(rawUser) {
      if (typeof normalizeUserData === "function") {
        return normalizeUserData(rawUser);
      }
      // Minimal fallback if data-normalizer.js is not loaded
      if (!rawUser || typeof rawUser !== "object") return null;
      return {
        id: rawUser.id || null,
        email: rawUser.email || "",
        fullName: rawUser.full_name || rawUser.name || "",
        avatarUrl: rawUser.avatar_url || rawUser.avatarUrl || "",
        authProvider: rawUser.auth_provider || rawUser.authProvider || "google",
        emailVerified: rawUser.email_verified ?? !!rawUser.email_verified_at,
        emailVerifiedAt: rawUser.email_verified_at || null,
        jobTitle: rawUser.job_title || rawUser.job_tittle || "",
        twoFactorEnabled: rawUser.two_factor_enabled ?? false,
        role: rawUser.role || "user",
        preferences: rawUser.preferences || {},
      };
    }

    /**
     * Validate that a URL is a legitimate Google OAuth endpoint.
     * Prevents open-redirect attacks by ensuring the domain is *.google.com.
     *
     * @private
     * @param {string} url
     * @returns {boolean}
     */
    _isValidGoogleUrl(url) {
      try {
        const parsed = new URL(url);

        // Must be HTTPS
        if (parsed.protocol !== "https:") return false;

        // Must be a Google domain
        const hostname = parsed.hostname.toLowerCase();
        return (
          hostname === "accounts.google.com" ||
          hostname.endsWith(".google.com") ||
          hostname.endsWith(".googleapis.com")
        );
      } catch {
        return false;
      }
    }

    /**
     * Detect if a network error was caused by an ad-blocker or browser extension.
     *
     * @private
     * @param {Error} error
     * @returns {boolean}
     */
    _isBlockedByClient(error) {
      if (!error) return false;
      const msg = (error.message || "").toLowerCase();
      return (
        msg.includes("blocked") ||
        msg.includes("err_blocked_by_client") ||
        msg.includes("net::err_blocked") ||
        msg.includes("failed to fetch") ||
        (error instanceof TypeError && msg.includes("fetch"))
      );
    }

    /**
     * Show a user-friendly warning about ad-blocker interference.
     *
     * @private
     */
    _showAdBlockerWarning() {
      const message =
        "A browser extension (such as an ad-blocker) is preventing Google Sign-In. " +
        "Please disable it for this site and try again.";

      if (window.CyberNotify) {
        window.CyberNotify.alert(message, { type: "warning" });
      } else if (typeof showMessage === "function") {
        showMessage("warning", "Extension Conflict", message);
      }
    }

    /**
     * Remove OAuth query parameters from the browser's URL bar
     * to prevent token leakage via URL sharing / bookmarks / Referer header.
     *
     * @private
     */
    _cleanUrlParams() {
      try {
        if (window.history && window.history.replaceState) {
          window.history.replaceState(
            {},
            document.title,
            window.location.pathname,
          );
        }
      } catch (e) {
        // Silently ignore — non-critical
        console.warn("[GoogleAuth] Could not clean URL params:", e);
      }
    }
  }

  // ═══════════════════════════════════════════════════════════════════════
  //  AUTO-INITIALIZATION
  // ═══════════════════════════════════════════════════════════════════════

  /**
   * Initialize the handler once all dependencies are available.
   * Dependencies: window.APIClient (constructor), window.authManager (instance)
   *
   * If auth.js is loaded before this file (expected), authManager already exists
   * and has its own apiClient instance we can reuse.
   */
  function _init() {
    // Prefer reusing authManager's apiClient for consistency
    const apiClient =
      (window.authManager && window.authManager.apiClient) ||
      (typeof APIClient !== "undefined" ? new APIClient() : null);

    const authMgr = window.authManager || null;

    if (!apiClient) {
      console.error(
        "[GoogleAuth] APIClient not found — GoogleAuthHandler not initialized.",
      );
      return;
    }

    if (!authMgr) {
      console.warn(
        "[GoogleAuth] authManager not found — session save will be unavailable.",
      );
    }

    const handler = new GoogleAuthHandler(apiClient, authMgr);

    // Expose on window for global access
    window.googleAuthHandler = handler;
    window.GoogleAuthHandler = GoogleAuthHandler;

    console.log("[GoogleAuth] GoogleAuthHandler initialized.");
  }

  // Run init immediately — this file should be loaded after auth.js
  _init();
})();
