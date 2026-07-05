import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest';
import { JSDOM } from 'jsdom';

describe('Backend-Driven Session Validation', () => {
  let dom;
  let window;
  let document;
  let mockLocalStorage;
  let mockSessionStorage;
  let mockAPIClient;
  let mockNormalizeUserData;
  let mockShowLoading;
  let mockHideLoading;

  beforeEach(async () => {
    // 1. Create JSDOM environment
    dom = new JSDOM('<!DOCTYPE html><html><body><div id="loginForm"></div></body></html>', {
      url: 'http://localhost/dashboard',
    });
    window = dom.window;
    document = dom.window.document;

    const mockLocation = {
      href: 'http://localhost/dashboard',
      pathname: '/dashboard',
      search: '',
      origin: 'http://localhost',
    };

    const windowWrapper = new Proxy(window, {
      get(target, prop) {
        if (prop === 'location') return mockLocation;
        const value = target[prop];
        if (typeof value === 'function') return value.bind(target);
        return value;
      },
      set(target, prop, value) {
        if (prop === 'location') return false;
        target[prop] = value;
        return true;
      }
    });

    window = windowWrapper;
    global.window = windowWrapper;
    global.location = mockLocation;
    global.document = document;
    global.navigator = { userAgent: 'Mozilla/5.0 (Mock Agent)' };
    global.CustomEvent = window.CustomEvent;

    // 2. Clear and set up real JSDOM storages
    window.localStorage.clear();
    window.sessionStorage.clear();
    global.localStorage = window.localStorage;
    global.sessionStorage = window.sessionStorage;

    // 3. Mock globals
    const APIClientInstance = {
      get: vi.fn(),
      post: vi.fn(),
      setToken: vi.fn((token) => {
        if (token) localStorage.setItem('cyberguard_jwt', token);
      }),
      clearToken: vi.fn(() => {
        localStorage.removeItem('cyberguard_jwt');
      }),
      getToken: vi.fn(() => localStorage.getItem('cyberguard_jwt')),
    };
    mockAPIClient = vi.fn().mockImplementation(function() {
      return APIClientInstance;
    });
    global.APIClient = mockAPIClient;

    mockNormalizeUserData = vi.fn().mockImplementation((user) => ({
      id: user.id || null,
      email: user.email || '',
      fullName: user.full_name || user.fullName || '',
      avatarUrl: user.avatar_url || user.avatarUrl || '',
      authProvider: user.auth_provider || user.authProvider || 'local',
      emailVerifiedAt: user.email_verified_at || user.emailVerifiedAt || null,
      emailVerified: user.email_verified ?? (user.email_verified_at ? true : false),
    }));
    global.normalizeUserData = mockNormalizeUserData;

    mockShowLoading = vi.fn();
    mockHideLoading = vi.fn();
    global.showLoading = mockShowLoading;
    global.hideLoading = mockHideLoading;

    window.APIClient = mockAPIClient;
    window.normalizeUserData = mockNormalizeUserData;
    window.showLoading = mockShowLoading;
    window.hideLoading = mockHideLoading;

    // Dynamic import to load code in JSDOM context
    await import('../../public/js/data-normalizer.js');
    await import('../../public/js/auth.js');
  });

  afterEach(() => {
    vi.clearAllMocks();
    vi.resetModules();
  });

  test('should restore session from backend if token exists', async () => {
    // Setup token in mock storage
    localStorage.setItem('cyberguard_jwt', 'valid-mock-token');

    // Mock backend user profile response
    const mockUser = { id: 1, email: 'user@test.com', full_name: 'Test User' };
    window.authManager.apiClient.get.mockResolvedValue({ user: mockUser });

    const result = await window.authManager.loadUserSession();

    expect(result).toBe(true);
    expect(window.authManager.currentUser).toBeDefined();
    expect(window.authManager.currentUser.email).toBe('user@test.com');
    expect(window.authManager.apiClient.get).toHaveBeenCalledWith('auth/me');
  });

  test('should logout and return false if token exists but backend explicitly rejects it', async () => {
    // Setup token in mock storage
    localStorage.setItem('cyberguard_jwt', 'invalid-token');

    // Mock backend auth failure
    const unauthorizedError = new Error('Unauthorized');
    unauthorizedError.status = 401;
    window.authManager.apiClient.get.mockRejectedValue(unauthorizedError);

    const result = await window.authManager.loadUserSession();

    expect(result).toBe(false);
    expect(window.authManager.currentUser).toBeNull();
    // Verify token was cleared
    expect(localStorage.getItem('cyberguard_jwt')).toBeNull();
  });

  test('should keep token if backend validation is temporarily unreachable', async () => {
    localStorage.setItem('cyberguard_jwt', 'valid-token');
    const cachedUser = { id: 1, email: 'cached@test.com', fullName: 'Cached User' };
    localStorage.setItem('cyberguard_user', JSON.stringify(cachedUser));

    window.authManager.apiClient.get.mockRejectedValue(new Error('Network unavailable'));

    const result = await window.authManager.loadUserSession();

    expect(result).toBe(true);
    expect(window.authManager.currentUser.email).toBe('cached@test.com');
    expect(localStorage.getItem('cyberguard_jwt')).toBe('valid-token');
  });

  test('should restore session from legacy storage without client inactivity checks', async () => {
    // Setup legacy user data but NO token
    const legacyUser = { id: 2, email: 'legacy@test.com', fullName: 'Legacy User' };
    localStorage.setItem('cyberguard_user', JSON.stringify(legacyUser));

    // Wait some time to simulate inactivity (older than standard 30 minutes)
    const oldSession = { timestamp: Date.now() - (60 * 60 * 1000) }; // 1 hour ago
    localStorage.setItem('cyberguard_session', JSON.stringify(oldSession));

    const result = await window.authManager.loadUserSession();

    // Verify it restores successfully despite being older than 30 minutes
    expect(result).toBe(true);
    expect(window.authManager.currentUser.email).toBe('legacy@test.com');
  });

  test('validateSessionOnPageLoad() should NOT expire session locally when session is older than sessionTimeout', async () => {
    // Setup session and active user
    localStorage.setItem('cyberguard_jwt', 'valid-mock-token');
    const user = { id: 1, email: 'user@test.com', fullName: 'Test User' };
    window.authManager.currentUser = user;

    // Set old timestamp in session
    const oldSession = { timestamp: Date.now() - (60 * 60 * 1000) }; // 1 hour ago
    localStorage.setItem('cyberguard_session', JSON.stringify(oldSession));

    // Mock backend to return active status
    window.authManager.apiClient.get.mockResolvedValue({ email_verified: true, two_factor_enabled: false });

    const handleSessionExpirationSpy = vi.spyOn(window.authManager, 'handleSessionExpiration');

    await window.authManager.validateSessionOnPageLoad();

    // Verify handleSessionExpiration was NOT called (no client-side timeout)
    expect(handleSessionExpirationSpy).not.toHaveBeenCalled();
    expect(window.authManager.currentUser).not.toBeNull();
  });

  test('validateSessionOnPageLoad() should handle session expiration if backend returns 401', async () => {
    // Setup session and active user
    localStorage.setItem('cyberguard_jwt', 'invalid-token');
    const user = { id: 1, email: 'user@test.com', fullName: 'Test User' };
    window.authManager.currentUser = user;

    // Mock backend auth failure (e.g. token expired on backend)
    const sessionInvalidError = new Error('Session invalid');
    sessionInvalidError.status = 401;
    window.authManager.apiClient.get.mockRejectedValue(sessionInvalidError);

    const handleSessionExpirationSpy = vi.spyOn(window.authManager, 'handleSessionExpiration');

    await window.authManager.validateSessionOnPageLoad();

    // Verify expiration was handled because backend explicitly rejected the session
    expect(handleSessionExpirationSpy).toHaveBeenCalled();
    expect(window.authManager.currentUser).toBeNull();
  });

  test('validateSessionOnPageLoad() should keep session on non-auth validation errors', async () => {
    localStorage.setItem('cyberguard_jwt', 'valid-token');
    const user = { id: 1, email: 'user@test.com', fullName: 'Test User' };
    window.authManager.currentUser = user;

    window.authManager.apiClient.get.mockRejectedValue(new Error('Network unavailable'));

    const handleSessionExpirationSpy = vi.spyOn(window.authManager, 'handleSessionExpiration');

    await window.authManager.validateSessionOnPageLoad();

    expect(handleSessionExpirationSpy).not.toHaveBeenCalled();
    expect(window.authManager.currentUser).toBe(user);
    expect(localStorage.getItem('cyberguard_jwt')).toBe('valid-token');
  });
});
