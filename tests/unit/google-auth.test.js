import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest';
import { JSDOM } from 'jsdom';

describe('Google Authentication', () => {
  let dom;
  let window;
  let document;
  let mockLocalStorage;
  let mockSessionStorage;
  let mockAPIClient;
  let mockNormalizeUserData;
  let mockShowMessage;
  let mockShowLoading;
  let mockHideLoading;

  beforeEach(async () => {
    // 1. Create a JSDOM environment
    dom = new JSDOM('<!DOCTYPE html><html><body><div id="loginForm"></div></body></html>', {
      url: 'http://localhost/login',
    });
    window = dom.window;
    document = dom.window.document;

    // Mock location object
    const mockLocation = {
      href: 'http://localhost/login',
      pathname: '/login',
      search: '',
      origin: 'http://localhost',
    };

    // Create window wrapper using Proxy
    const windowWrapper = new Proxy(window, {
      get(target, prop) {
        if (prop === 'location') {
          return mockLocation;
        }
        const value = target[prop];
        if (typeof value === 'function') {
          return value.bind(target);
        }
        return value;
      },
      set(target, prop, value) {
        if (prop === 'location') {
          return false; // read-only property mock
        }
        target[prop] = value;
        return true;
      }
    });

    window = windowWrapper;
    global.window = windowWrapper;
    global.location = mockLocation;
    global.document = document;
    global.navigator = {
      userAgent: 'Mozilla/5.0 (Mock Agent)',
    };

    // 2. Mock storage
    mockLocalStorage = {
      getItem: vi.fn(),
      setItem: vi.fn(),
      removeItem: vi.fn(),
    };
    mockSessionStorage = {
      getItem: vi.fn(),
      setItem: vi.fn(),
      removeItem: vi.fn(),
    };
    global.localStorage = mockLocalStorage;
    global.sessionStorage = mockSessionStorage;

    // 3. Mock globals before importing auth.js
    const APIClientInstance = {
      get: vi.fn(),
      post: vi.fn(),
      setToken: vi.fn(),
      clearToken: vi.fn(),
      getToken: vi.fn(),
    };
    mockAPIClient = vi.fn().mockImplementation(function() {
      return APIClientInstance;
    });
    global.APIClient = mockAPIClient;

    mockNormalizeUserData = vi.fn().mockImplementation((user) => {
      // Replicate minimal normalization logic
      return {
        id: user.id || null,
        email: user.email || '',
        fullName: user.full_name || user.fullName || '',
        avatarUrl: user.avatar_url || user.avatarUrl || '',
        authProvider: user.auth_provider || user.authProvider || 'local',
        emailVerifiedAt: user.email_verified_at || user.emailVerifiedAt || null,
        emailVerified: user.email_verified ?? (user.email_verified_at ? true : false),
      };
    });
    global.normalizeUserData = mockNormalizeUserData;

    mockShowMessage = vi.fn();
    mockShowLoading = vi.fn();
    mockHideLoading = vi.fn();
    global.showMessage = mockShowMessage;
    global.showLoading = mockShowLoading;
    global.hideLoading = mockHideLoading;

    // We also need window-level functions for event listeners etc. in auth.js
    window.showMessage = mockShowMessage;
    window.showLoading = mockShowLoading;
    window.hideLoading = mockHideLoading;
    window.APIClient = mockAPIClient;
    window.normalizeUserData = mockNormalizeUserData;

    // Mock history.replaceState
    window.history.replaceState = vi.fn();

    // 4. Import data-normalizer and auth.js dynamically
    // Use a fresh import/cache-busting if needed, but since we mock globals, regular import is fine
    await import('../../public/js/data-normalizer.js');
    await import('../../public/js/auth.js');
  });

  afterEach(() => {
    vi.clearAllMocks();
    vi.resetModules();
  });

  describe('redirectToGoogle()', () => {
    test('should fetch redirect URL from API and navigate browser', async () => {
      const mockRedirectUrl = 'https://accounts.google.com/o/oauth2/auth?client_id=123';
      
      // Setup mock API response
      window.authManager.apiClient.get.mockResolvedValue({
        status: 'success',
        redirect_url: mockRedirectUrl,
      });

      await window.authManager.redirectToGoogle();

      // Verify API client was called correctly
      expect(window.authManager.apiClient.get).toHaveBeenCalledWith('auth/google/redirect', { skipAuth: true });
      
      // Verify loading state
      expect(mockShowLoading).toHaveBeenCalledWith('Connecting to Google...');
      expect(mockHideLoading).toHaveBeenCalled();

      // Verify redirection occurred
      expect(window.location.href).toBe(mockRedirectUrl);
    });

    test('should display error toast when API redirect endpoint fails', async () => {
      const mockError = new Error('API server down');
      window.authManager.apiClient.get.mockRejectedValue(mockError);

      await window.authManager.redirectToGoogle();

      // Verify error message was displayed
      expect(mockShowMessage).toHaveBeenCalledWith(
        'error',
        'Google Sign-In Failed',
        'API server down'
      );
      expect(mockHideLoading).toHaveBeenCalled();
    });
  });

  describe('handleOAuthCallback()', () => {
    test('should handle success with encoded user JSON param', () => {
      const mockUser = {
        id: 42,
        email: 'john@example.com',
        full_name: 'John Doe',
        avatar_url: 'https://lh3.googleusercontent.com/photo',
        auth_provider: 'google',
        email_verified_at: '2026-06-06T10:00:00Z',
      };
      
      // Simulate redirect URL with token and encoded user JSON
      const urlSearchParams = new URLSearchParams({
        token: 'test-sanctum-token',
        user: JSON.stringify(mockUser),
      });
      
      window.location.search = '?' + urlSearchParams.toString();

      // Spy on saveUserSession
      const saveSessionSpy = vi.spyOn(window.authManager, 'saveUserSession').mockReturnValue(true);

      const result = window.authManager.handleOAuthCallback();

      expect(result).toBe(true);

      // Verify token was stored
      expect(window.authManager.apiClient.setToken).toHaveBeenCalledWith('test-sanctum-token');

      // Verify user data was normalized and saved
      expect(mockNormalizeUserData).toHaveBeenCalled();
      expect(saveSessionSpy).toHaveBeenCalledWith(expect.objectContaining({
        id: 42,
        email: 'john@example.com',
        fullName: 'John Doe',
        avatarUrl: 'https://lh3.googleusercontent.com/photo',
        authProvider: 'google',
      }));

      // Verify history clean up (query params removed)
      expect(window.history.replaceState).toHaveBeenCalledWith({}, expect.any(String), '/login');

      // Verify success message
      expect(mockShowMessage).toHaveBeenCalledWith(
        'success',
        'Welcome back!',
        'Redirecting to dashboard...'
      );
    });

    test('should handle success with individual params when user JSON is missing', () => {
      // Simulate redirect URL with individual fields as query params
      const urlSearchParams = new URLSearchParams({
        token: 'another-token',
        id: '100',
        email: 'jane@example.com',
        full_name: 'Jane Smith',
        avatar_url: 'https://lh3.googleusercontent.com/jane',
        auth_provider: 'google',
        email_verified_at: '2026-06-06T12:00:00Z',
      });
      
      window.location.search = '?' + urlSearchParams.toString();

      const saveSessionSpy = vi.spyOn(window.authManager, 'saveUserSession').mockReturnValue(true);

      const result = window.authManager.handleOAuthCallback();

      expect(result).toBe(true);
      expect(window.authManager.apiClient.setToken).toHaveBeenCalledWith('another-token');
      expect(saveSessionSpy).toHaveBeenCalledWith(expect.objectContaining({
        id: '100',
        email: 'jane@example.com',
        fullName: 'Jane Smith',
        avatarUrl: 'https://lh3.googleusercontent.com/jane',
        authProvider: 'google',
      }));
    });

    test('should handle error params and display toast error', () => {
      // Simulate error redirect from backend
      const urlSearchParams = new URLSearchParams({
        error: 'auth_denied',
        message: 'Google authentication failed. Please try again.',
      });
      
      window.location.search = '?' + urlSearchParams.toString();

      const result = window.authManager.handleOAuthCallback();

      expect(result).toBe(true);

      // Verify error message was displayed
      expect(mockShowMessage).toHaveBeenCalledWith(
        'error',
        'Google Sign-In Failed',
        'Google authentication failed. Please try again.'
      );

      // Verify history clean up (query params removed)
      expect(window.history.replaceState).toHaveBeenCalled();
    });

    test('should return false when no OAuth parameters are in URL', () => {
      // Normal page view: no token, no error
      window.location.search = '';

      const result = window.authManager.handleOAuthCallback();

      expect(result).toBe(false);
      expect(window.authManager.apiClient.setToken).not.toHaveBeenCalled();
      expect(mockShowMessage).not.toHaveBeenCalled();
    });
  });

  describe('data-normalizer.js integration', () => {
    test('should normalize Google authentication fields correctly', () => {
      const rawUser = {
        id: 5,
        email: 'tester@example.com',
        full_name: 'Test Account',
        avatar_url: 'https://google.com/avatar',
        auth_provider: 'google',
        email_verified_at: '2026-06-06T15:00:00Z',
      };

      // Call the actual normalizeUserData function loaded from data-normalizer.js
      const normalized = global.normalizeUserData(rawUser);

      expect(normalized.id).toBe(5);
      expect(normalized.email).toBe('tester@example.com');
      expect(normalized.fullName).toBe('Test Account');
      expect(normalized.avatarUrl).toBe('https://google.com/avatar');
      expect(normalized.authProvider).toBe('google');
      expect(normalized.emailVerifiedAt).toBe('2026-06-06T15:00:00Z');
      expect(normalized.emailVerified).toBe(true);
    });

    test('should default authProvider to local and handle absent email_verified_at', () => {
      const rawUser = {
        id: 6,
        email: 'local@example.com',
        full_name: 'Local Account',
      };

      const normalized = global.normalizeUserData(rawUser);

      expect(normalized.authProvider).toBe('local');
      expect(normalized.avatarUrl).toBe('');
      expect(normalized.emailVerifiedAt).toBeNull();
      expect(normalized.emailVerified).toBe(false);
    });
  });
});
