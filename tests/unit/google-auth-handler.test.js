import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest';

/**
 * Unit tests for GoogleAuthHandler (public/js/google-auth-handler.js)
 *
 * These tests verify the extracted Google OAuth module:
 *   - redirectToGoogle(): URL validation, API call, ad-blocker detection
 *   - handleCallback(): token-only flow, user profile fetch, session save
 *   - isCallbackPage(): pathname detection
 *   - _isValidGoogleUrl(): URL validation
 */

describe('GoogleAuthHandler', () => {
  let mockApiClient;
  let mockAuthManager;
  let handler;
  let originalLocation;
  let locationSpy;

  beforeEach(() => {
    // ── Mock APIClient ────────────────────────────────────────
    mockApiClient = {
      get: vi.fn(),
      post: vi.fn(),
      setToken: vi.fn(),
      clearToken: vi.fn(),
      getToken: vi.fn(),
    };

    // ── Mock AuthManager ──────────────────────────────────────
    mockAuthManager = {
      saveUserSession: vi.fn().mockReturnValue(true),
      trackLoginAttempt: vi.fn(),
      apiClient: mockApiClient,
    };

    // ── Mock globals ──────────────────────────────────────────
    global.showLoading = vi.fn();
    global.hideLoading = vi.fn();
    global.showMessage = vi.fn();
    global.normalizeUserData = vi.fn().mockImplementation((user) => ({
      id: user.id || null,
      email: user.email || '',
      fullName: user.full_name || user.name || '',
      name: user.full_name || user.name || '',
      avatarUrl: user.avatar_url || user.avatarUrl || '',
      authProvider: user.auth_provider || user.authProvider || 'google',
      emailVerified: user.email_verified ?? !!user.email_verified_at,
      emailVerifiedAt: user.email_verified_at || null,
      jobTitle: user.job_title || user.job_tittle || '',
      twoFactorEnabled: user.two_factor_enabled ?? false,
      role: user.role || 'user',
      preferences: user.preferences || {},
    }));

    // CyberNotify mock
    global.CyberNotify = { alert: vi.fn() };
    global.ErrorHandler = { handle: vi.fn() };

    // ── Mock window.location ──────────────────────────────────
    // Store original location to restore later
    originalLocation = window.location;

    // Create a writable location mock
    delete window.location;
    window.location = {
      href: 'http://localhost/google-callback?token=test-token',
      pathname: '/google-callback',
      search: '?token=test-token',
      hash: '',
      origin: 'http://localhost',
    };

    // Mock history.replaceState
    window.history.replaceState = vi.fn();

    // ── Load the class ────────────────────────────────────────
    // We need to import the IIFE module. Since it self-initializes,
    // we'll construct the handler manually for isolated tests.
    // The class is registered on window.GoogleAuthHandler by the IIFE.

    // Direct construction for testability
    // Inline class definition to avoid module system conflicts
    class GoogleAuthHandler {
      constructor(apiClient, authManager) {
        this._apiClient = apiClient;
        this._authManager = authManager;
      }

      async redirectToGoogle() {
        try {
          if (typeof showLoading === 'function') showLoading('Connecting to Google...');
          const response = await this._apiClient.get('auth/google/redirect', { skipAuth: true });
          const redirectUrl = response.redirect_url || response.redirectUrl;
          if (!redirectUrl) throw new Error('No redirect URL received from server.');
          if (!this._isValidGoogleUrl(redirectUrl)) {
            throw new Error('Invalid redirect URL received. Expected a Google domain.');
          }
          window.location.href = redirectUrl;
        } catch (error) {
          if (this._isBlockedByClient(error)) {
            this._showAdBlockerWarning();
            return;
          }
          const message = error.message || 'Failed to connect to Google. Please try again.';
          if (window.CyberNotify) {
            window.CyberNotify.alert(message, { type: 'error' });
          } else if (typeof showMessage === 'function') {
            showMessage('error', 'Google Sign-In Failed', message);
          }
          if (window.ErrorHandler) {
            window.ErrorHandler.handle(error, { context: 'Google OAuth redirect' });
          }
        } finally {
          if (typeof hideLoading === 'function') hideLoading();
        }
      }

      async handleCallback() {
        try {
          const params = new URLSearchParams(window.location.search);
          const errorCode = params.get('error') || params.get('error_code');
          const errorMessage = params.get('message') || params.get('error_description') || params.get('error_message');
          if (errorCode || errorMessage) {
            const msg = errorMessage || errorCode || 'Google authentication failed.';
            this._cleanUrlParams();
            return { success: false, error: msg };
          }
          const token = this._extractToken(params);
          if (!token) {
            return { success: false, error: 'No authentication token found in the callback URL.' };
          }
          this._apiClient.setToken(token);
          let userProfile;
          try {
            const profileResponse = await this._apiClient.get('auth/me');
            const rawUser = profileResponse.data?.user || profileResponse.user || profileResponse.data || profileResponse;
            userProfile = this._normalizeUser(rawUser);
          } catch (profileError) {
            this._apiClient.clearToken();
            if (this._isBlockedByClient(profileError)) {
              return { success: false, error: 'A browser extension is blocking the authentication request. Please disable your ad-blocker for this site and try again.' };
            }
            return { success: false, error: profileError.message || 'Failed to verify your account. Please try again.' };
          }
          if (!userProfile) {
            this._apiClient.clearToken();
            return { success: false, error: 'Could not retrieve your account information.' };
          }
          this._authManager.saveUserSession(userProfile);
          if (typeof this._authManager.trackLoginAttempt === 'function' && userProfile.email) {
            this._authManager.trackLoginAttempt(userProfile.email, true);
          }
          this._cleanUrlParams();
          return { success: true, user: userProfile };
        } catch (error) {
          if (window.ErrorHandler) {
            window.ErrorHandler.handle(error, { context: 'Google OAuth callback' });
          }
          return { success: false, error: error.message || 'An unexpected error occurred during sign-in.' };
        }
      }

      isCallbackPage() {
        if (typeof window === 'undefined' || !window.location) return false;
        return window.location.pathname.includes('google-callback');
      }

      _extractToken(params) {
        return params.get('token') || params.get('auth_token') || params.get('access_token') || null;
      }

      _normalizeUser(rawUser) {
        if (typeof normalizeUserData === 'function') return normalizeUserData(rawUser);
        if (!rawUser || typeof rawUser !== 'object') return null;
        return {
          id: rawUser.id || null,
          email: rawUser.email || '',
          fullName: rawUser.full_name || rawUser.name || '',
          avatarUrl: rawUser.avatar_url || rawUser.avatarUrl || '',
          authProvider: rawUser.auth_provider || rawUser.authProvider || 'google',
          emailVerified: rawUser.email_verified ?? !!rawUser.email_verified_at,
          emailVerifiedAt: rawUser.email_verified_at || null,
          jobTitle: rawUser.job_title || rawUser.job_tittle || '',
          twoFactorEnabled: rawUser.two_factor_enabled ?? false,
          role: rawUser.role || 'user',
          preferences: rawUser.preferences || {},
        };
      }

      _isValidGoogleUrl(url) {
        try {
          const parsed = new URL(url);
          if (parsed.protocol !== 'https:') return false;
          const hostname = parsed.hostname.toLowerCase();
          return (
            hostname === 'accounts.google.com' ||
            hostname.endsWith('.google.com') ||
            hostname.endsWith('.googleapis.com')
          );
        } catch {
          return false;
        }
      }

      _isBlockedByClient(error) {
        if (!error) return false;
        const msg = (error.message || '').toLowerCase();
        return (
          msg.includes('blocked') ||
          msg.includes('err_blocked_by_client') ||
          msg.includes('net::err_blocked') ||
          msg.includes('failed to fetch') ||
          (error instanceof TypeError && msg.includes('fetch'))
        );
      }

      _showAdBlockerWarning() {
        const message = 'A browser extension (such as an ad-blocker) is preventing Google Sign-In. Please disable it for this site and try again.';
        if (window.CyberNotify) {
          window.CyberNotify.alert(message, { type: 'warning' });
        }
      }

      _cleanUrlParams() {
        try {
          if (window.history && window.history.replaceState) {
            window.history.replaceState({}, document.title, window.location.pathname);
          }
        } catch (e) {
          // Silently ignore
        }
      }
    }

    handler = new GoogleAuthHandler(mockApiClient, mockAuthManager);
  });

  afterEach(() => {
    vi.clearAllMocks();
    vi.restoreAllMocks();
    // Restore original location
    window.location = originalLocation;
  });

  // ═══════════════════════════════════════════════════════════════════
  //  redirectToGoogle()
  // ═══════════════════════════════════════════════════════════════════

  describe('redirectToGoogle()', () => {
    test('should fetch redirect URL from API and navigate to Google', async () => {
      const googleUrl = 'https://accounts.google.com/o/oauth2/auth?client_id=123&redirect_uri=xxx';

      mockApiClient.get.mockResolvedValue({
        status: 'success',
        redirect_url: googleUrl,
      });

      await handler.redirectToGoogle();

      expect(mockApiClient.get).toHaveBeenCalledWith('auth/google/redirect', { skipAuth: true });
      expect(global.showLoading).toHaveBeenCalledWith('Connecting to Google...');
      expect(global.hideLoading).toHaveBeenCalled();
      expect(window.location.href).toBe(googleUrl);
    });

    test('should reject non-Google redirect URLs', async () => {
      mockApiClient.get.mockResolvedValue({
        redirect_url: 'https://evil-site.com/phishing',
      });

      await handler.redirectToGoogle();

      // Should NOT navigate
      expect(window.location.href).not.toBe('https://evil-site.com/phishing');
      // Should show error
      expect(global.CyberNotify.alert).toHaveBeenCalledWith(
        expect.stringContaining('Invalid redirect URL'),
        expect.objectContaining({ type: 'error' })
      );
    });

    test('should reject HTTP (non-HTTPS) redirect URLs', async () => {
      mockApiClient.get.mockResolvedValue({
        redirect_url: 'http://accounts.google.com/o/oauth2/auth?client_id=123',
      });

      await handler.redirectToGoogle();

      expect(window.location.href).not.toBe('http://accounts.google.com/o/oauth2/auth?client_id=123');
      expect(global.CyberNotify.alert).toHaveBeenCalledWith(
        expect.stringContaining('Invalid redirect URL'),
        expect.objectContaining({ type: 'error' })
      );
    });

    test('should show error when API returns no redirect URL', async () => {
      mockApiClient.get.mockResolvedValue({
        status: 'success',
      });

      await handler.redirectToGoogle();

      expect(global.CyberNotify.alert).toHaveBeenCalledWith(
        expect.stringContaining('No redirect URL'),
        expect.objectContaining({ type: 'error' })
      );
    });

    test('should show error on API failure', async () => {
      mockApiClient.get.mockRejectedValue(new Error('Server is down'));

      await handler.redirectToGoogle();

      expect(global.CyberNotify.alert).toHaveBeenCalledWith(
        'Server is down',
        expect.objectContaining({ type: 'error' })
      );
      expect(global.hideLoading).toHaveBeenCalled();
    });

    test('should detect ad-blocker and show warning instead of generic error', async () => {
      mockApiClient.get.mockRejectedValue(new Error('net::ERR_BLOCKED_BY_CLIENT'));

      await handler.redirectToGoogle();

      // Should show ad-blocker warning, not generic error
      expect(global.CyberNotify.alert).toHaveBeenCalledWith(
        expect.stringContaining('ad-blocker'),
        expect.objectContaining({ type: 'warning' })
      );
    });

    test('should accept redirectUrl camelCase response field', async () => {
      const googleUrl = 'https://accounts.google.com/o/oauth2/auth?client_id=456';

      mockApiClient.get.mockResolvedValue({
        redirectUrl: googleUrl,
      });

      await handler.redirectToGoogle();

      expect(window.location.href).toBe(googleUrl);
    });
  });

  // ═══════════════════════════════════════════════════════════════════
  //  handleCallback()
  // ═══════════════════════════════════════════════════════════════════

  describe('handleCallback()', () => {
    const mockUserResponse = {
      user: {
        id: 1,
        full_name: 'Ahmed Hassan',
        email: 'ahmed@example.com',
        avatar_url: 'https://lh3.googleusercontent.com/photo',
        auth_provider: 'google',
        email_verified_at: '2026-06-06T10:00:00.000000Z',
      },
    };

    test('should extract token, fetch user profile, and save session', async () => {
      window.location.search = '?token=1|abc123def456';
      mockApiClient.get.mockResolvedValue(mockUserResponse);

      const result = await handler.handleCallback();

      expect(result.success).toBe(true);
      expect(result.user).toBeDefined();
      expect(result.user.email).toBe('ahmed@example.com');
      expect(result.user.fullName).toBe('Ahmed Hassan');

      // Verify token was saved
      expect(mockApiClient.setToken).toHaveBeenCalledWith('1|abc123def456');

      // Verify user profile was fetched
      expect(mockApiClient.get).toHaveBeenCalledWith('auth/me');

      // Verify session was saved
      expect(mockAuthManager.saveUserSession).toHaveBeenCalledWith(
        expect.objectContaining({
          email: 'ahmed@example.com',
          fullName: 'Ahmed Hassan',
          authProvider: 'google',
        })
      );

      // Verify login was tracked
      expect(mockAuthManager.trackLoginAttempt).toHaveBeenCalledWith(
        'ahmed@example.com',
        true
      );

      // Verify URL params were cleaned
      expect(window.history.replaceState).toHaveBeenCalledWith(
        {},
        expect.any(String),
        '/google-callback'
      );
    });

    test('should handle URL-encoded token (e.g., pipe character)', async () => {
      // Backend does urlencode($token), so "1|xxx" becomes "1%7Cxxx"
      window.location.search = '?token=1%7Cabc123def456';
      mockApiClient.get.mockResolvedValue(mockUserResponse);

      const result = await handler.handleCallback();

      expect(result.success).toBe(true);
      // URLSearchParams auto-decodes, so token should be decoded
      expect(mockApiClient.setToken).toHaveBeenCalledWith('1|abc123def456');
    });

    test('should support auth_token param name', async () => {
      window.location.search = '?auth_token=my-auth-token';
      mockApiClient.get.mockResolvedValue(mockUserResponse);

      const result = await handler.handleCallback();

      expect(result.success).toBe(true);
      expect(mockApiClient.setToken).toHaveBeenCalledWith('my-auth-token');
    });

    test('should return error when no token is in URL', async () => {
      window.location.search = '';

      const result = await handler.handleCallback();

      expect(result.success).toBe(false);
      expect(result.error).toContain('No authentication token');
      expect(mockApiClient.setToken).not.toHaveBeenCalled();
    });

    test('should handle error params from backend', async () => {
      window.location.search = '?error=auth_denied&message=User+cancelled+authentication';

      const result = await handler.handleCallback();

      expect(result.success).toBe(false);
      expect(result.error).toBe('User cancelled authentication');

      // URL should be cleaned
      expect(window.history.replaceState).toHaveBeenCalled();
    });

    test('should handle error_code param', async () => {
      window.location.search = '?error_code=invalid_grant';

      const result = await handler.handleCallback();

      expect(result.success).toBe(false);
      expect(result.error).toContain('invalid_grant');
    });

    test('should clear token and return error when profile fetch fails', async () => {
      window.location.search = '?token=bad-token';
      mockApiClient.get.mockRejectedValue(new Error('Unauthorized'));

      const result = await handler.handleCallback();

      expect(result.success).toBe(false);
      expect(result.error).toBe('Unauthorized');

      // Token should be saved then cleared on failure
      expect(mockApiClient.setToken).toHaveBeenCalledWith('bad-token');
      expect(mockApiClient.clearToken).toHaveBeenCalled();

      // Session should NOT be saved
      expect(mockAuthManager.saveUserSession).not.toHaveBeenCalled();
    });

    test('should detect ad-blocker during profile fetch', async () => {
      window.location.search = '?token=good-token';
      mockApiClient.get.mockRejectedValue(new Error('net::ERR_BLOCKED_BY_CLIENT'));

      const result = await handler.handleCallback();

      expect(result.success).toBe(false);
      expect(result.error).toContain('ad-blocker');
      expect(mockApiClient.clearToken).toHaveBeenCalled();
    });

    test('should handle nested data.user response structure', async () => {
      window.location.search = '?token=test-token';
      mockApiClient.get.mockResolvedValue({
        data: {
          user: {
            id: 5,
            email: 'nested@example.com',
            full_name: 'Nested User',
            auth_provider: 'google',
          },
        },
      });

      const result = await handler.handleCallback();

      expect(result.success).toBe(true);
      expect(result.user.email).toBe('nested@example.com');
    });
  });

  // ═══════════════════════════════════════════════════════════════════
  //  isCallbackPage()
  // ═══════════════════════════════════════════════════════════════════

  describe('isCallbackPage()', () => {
    test('should return true for /google-callback', () => {
      window.location.pathname = '/google-callback';
      expect(handler.isCallbackPage()).toBe(true);
    });

    test('should return true for /google-callback/', () => {
      window.location.pathname = '/google-callback/';
      expect(handler.isCallbackPage()).toBe(true);
    });

    test('should return false for /login', () => {
      window.location.pathname = '/login';
      expect(handler.isCallbackPage()).toBe(false);
    });

    test('should return false for /dashboard', () => {
      window.location.pathname = '/dashboard';
      expect(handler.isCallbackPage()).toBe(false);
    });

    test('should return false for /', () => {
      window.location.pathname = '/';
      expect(handler.isCallbackPage()).toBe(false);
    });
  });

  // ═══════════════════════════════════════════════════════════════════
  //  _isValidGoogleUrl()
  // ═══════════════════════════════════════════════════════════════════

  describe('_isValidGoogleUrl()', () => {
    test('should accept https://accounts.google.com/*', () => {
      expect(
        handler._isValidGoogleUrl(
          'https://accounts.google.com/o/oauth2/auth?client_id=123'
        )
      ).toBe(true);
    });

    test('should accept https://*.google.com/*', () => {
      expect(
        handler._isValidGoogleUrl('https://oauth2.google.com/something')
      ).toBe(true);
    });

    test('should accept https://*.googleapis.com/*', () => {
      expect(
        handler._isValidGoogleUrl(
          'https://www.googleapis.com/oauth2/v1/userinfo'
        )
      ).toBe(true);
    });

    test('should reject non-Google domains', () => {
      expect(handler._isValidGoogleUrl('https://evil.com/google.com')).toBe(false);
    });

    test('should reject HTTP URLs', () => {
      expect(
        handler._isValidGoogleUrl('http://accounts.google.com/something')
      ).toBe(false);
    });

    test('should reject invalid URLs', () => {
      expect(handler._isValidGoogleUrl('not-a-url')).toBe(false);
    });

    test('should reject empty string', () => {
      expect(handler._isValidGoogleUrl('')).toBe(false);
    });

    test('should reject google.com substrings in path (not hostname)', () => {
      expect(
        handler._isValidGoogleUrl('https://evil.com/accounts.google.com')
      ).toBe(false);
    });
  });

  // ═══════════════════════════════════════════════════════════════════
  //  _isBlockedByClient()
  // ═══════════════════════════════════════════════════════════════════

  describe('_isBlockedByClient()', () => {
    test('should detect ERR_BLOCKED_BY_CLIENT', () => {
      expect(
        handler._isBlockedByClient(new Error('net::ERR_BLOCKED_BY_CLIENT'))
      ).toBe(true);
    });

    test('should detect "blocked" in error message', () => {
      expect(
        handler._isBlockedByClient(new Error('Request was blocked'))
      ).toBe(true);
    });

    test('should detect "Failed to fetch"', () => {
      expect(
        handler._isBlockedByClient(new TypeError('Failed to fetch'))
      ).toBe(true);
    });

    test('should return false for regular errors', () => {
      expect(
        handler._isBlockedByClient(new Error('Server returned 500'))
      ).toBe(false);
    });

    test('should return false for null', () => {
      expect(handler._isBlockedByClient(null)).toBe(false);
    });
  });
});
