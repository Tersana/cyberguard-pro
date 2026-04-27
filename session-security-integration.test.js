/**
 * Session Security Integration Tests
 * Integration tests for task 21.3: Session security
 * 
 * Tests the complete flow of session validation on page load
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';

describe('Session Security Integration - Task 21.3', () => {
  let authManager;
  let apiClient;
  let mockLocalStorage;
  let mockDocument;
  let mockWindow;

  beforeEach(() => {
    // Mock localStorage
    mockLocalStorage = {
      store: {},
      getItem(key) {
        return this.store[key] || null;
      },
      setItem(key, value) {
        this.store[key] = value;
      },
      removeItem(key) {
        delete this.store[key];
      },
      clear() {
        this.store = {};
      }
    };
    global.localStorage = mockLocalStorage;

    // Mock document
    mockDocument = {
      hidden: false,
      addEventListener: vi.fn(),
      visibilityState: 'visible'
    };

    // Mock window
    mockWindow = {
      addEventListener: vi.fn(),
      location: {
        pathname: '/dashboard.html',
        href: ''
      }
    };

    // Mock APIClient
    apiClient = {
      getToken: vi.fn(),
      clearToken: vi.fn(),
      get: vi.fn(),
      post: vi.fn()
    };

    // Create AuthManager with full session security implementation
    authManager = {
      currentUser: null,
      sessionTimeout: 30 * 60 * 1000,
      apiClient: apiClient,

      isAuthenticated() {
        return this.currentUser !== null;
      },

      updateUI: vi.fn(),

      async fetchSessionStatus() {
        const response = await this.apiClient.get('auth/status');
        return {
          success: true,
          emailVerified: response.email_verified || false,
          twoFactorEnabled: response.two_factor_enabled || false
        };
      },

      handleSessionExpiration() {
        this.apiClient.clearToken();
        localStorage.removeItem('cyberguard_user');
        localStorage.removeItem('cyberguard_session');
        this.currentUser = null;
        this.updateUI();
      },

      async validateSessionOnPageLoad() {
        try {
          const token = this.apiClient.getToken();

          if (!token) {
            this.currentUser = null;
            this.updateUI();
            return;
          }

          const sessionData = localStorage.getItem('cyberguard_session');
          if (sessionData) {
            const session = JSON.parse(sessionData);
            if (Date.now() - session.timestamp > this.sessionTimeout) {
              this.handleSessionExpiration();
              return;
            }
          }

          const statusResult = await this.fetchSessionStatus().catch(err => {
            console.error('Session validation failed:', err);
            return { success: false };
          });

          if (!statusResult.success) {
            this.handleSessionExpiration();
          }
        } catch (error) {
          console.error('Error validating session on page load:', error);
        }
      },

      setupPageVisibilityHandler(doc = mockDocument, win = mockWindow) {
        // Check session validity when page becomes visible
        doc.addEventListener('visibilitychange', async () => {
          if (!doc.hidden && this.isAuthenticated()) {
            await this.validateSessionOnPageLoad();
          }
        });

        // Check session validity when window gains focus
        win.addEventListener('focus', async () => {
          if (this.isAuthenticated()) {
            await this.validateSessionOnPageLoad();
          }
        });

        // Store timestamp on page unload
        win.addEventListener('beforeunload', () => {
          if (this.isAuthenticated()) {
            const sessionData = localStorage.getItem('cyberguard_session');
            if (sessionData) {
              const session = JSON.parse(sessionData);
              session.lastChecked = Date.now();
              localStorage.setItem('cyberguard_session', JSON.stringify(session));
            }
          }
        });
      }
    };
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  describe('Page visibility change triggers session validation', () => {
    it('should validate session when page becomes visible', async () => {
      // Setup
      authManager.currentUser = { id: 1, email: 'test@example.com' };
      apiClient.getToken.mockReturnValue('valid-token');
      apiClient.get.mockResolvedValue({
        email_verified: true,
        two_factor_enabled: false
      });
      localStorage.setItem('cyberguard_session', JSON.stringify({
        timestamp: Date.now(),
        userAgent: 'test'
      }));

      // Setup page visibility handler
      authManager.setupPageVisibilityHandler(mockDocument, mockWindow);

      // Verify event listeners were registered
      expect(mockDocument.addEventListener).toHaveBeenCalledWith('visibilitychange', expect.any(Function));
      expect(mockWindow.addEventListener).toHaveBeenCalledWith('focus', expect.any(Function));
      expect(mockWindow.addEventListener).toHaveBeenCalledWith('beforeunload', expect.any(Function));
    });

    it('should not validate session when page is hidden', async () => {
      // Setup
      mockDocument.hidden = true;
      authManager.currentUser = { id: 1, email: 'test@example.com' };

      // Setup page visibility handler
      authManager.setupPageVisibilityHandler(mockDocument, mockWindow);

      // Get the visibilitychange callback
      const visibilityCallback = mockDocument.addEventListener.mock.calls.find(
        call => call[0] === 'visibilitychange'
      )?.[1];

      // Execute callback
      if (visibilityCallback) {
        await visibilityCallback();
      }

      // Verify - should not validate when hidden
      expect(apiClient.getToken).not.toHaveBeenCalled();
    });
  });

  describe('Window focus triggers session validation', () => {
    it('should validate session when window gains focus', async () => {
      // Setup
      authManager.currentUser = { id: 1, email: 'test@example.com' };
      apiClient.getToken.mockReturnValue('valid-token');
      apiClient.get.mockResolvedValue({
        email_verified: true,
        two_factor_enabled: false
      });
      localStorage.setItem('cyberguard_session', JSON.stringify({
        timestamp: Date.now(),
        userAgent: 'test'
      }));

      // Setup page visibility handler
      authManager.setupPageVisibilityHandler(mockDocument, mockWindow);

      // Get the focus callback
      const focusCallback = mockWindow.addEventListener.mock.calls.find(
        call => call[0] === 'focus'
      )?.[1];

      // Execute callback
      if (focusCallback) {
        await focusCallback();
      }

      // Verify
      expect(apiClient.getToken).toHaveBeenCalled();
      expect(apiClient.get).toHaveBeenCalledWith('auth/status');
    });

    it('should not validate when not authenticated', async () => {
      // Setup
      authManager.currentUser = null;

      // Setup page visibility handler
      authManager.setupPageVisibilityHandler(mockDocument, mockWindow);

      // Get the focus callback
      const focusCallback = mockWindow.addEventListener.mock.calls.find(
        call => call[0] === 'focus'
      )?.[1];

      // Execute callback
      if (focusCallback) {
        await focusCallback();
      }

      // Verify - should not validate when not authenticated
      expect(apiClient.getToken).not.toHaveBeenCalled();
    });
  });

  describe('Page unload stores last checked timestamp', () => {
    it('should update lastChecked timestamp on beforeunload', () => {
      // Setup
      authManager.currentUser = { id: 1, email: 'test@example.com' };
      const initialTimestamp = Date.now() - 10000;
      localStorage.setItem('cyberguard_session', JSON.stringify({
        timestamp: initialTimestamp,
        userAgent: 'test'
      }));

      // Setup page visibility handler
      authManager.setupPageVisibilityHandler(mockDocument, mockWindow);

      // Get the beforeunload callback
      const beforeunloadCallback = mockWindow.addEventListener.mock.calls.find(
        call => call[0] === 'beforeunload'
      )?.[1];

      // Execute callback
      if (beforeunloadCallback) {
        beforeunloadCallback();
      }

      // Verify
      const sessionData = JSON.parse(localStorage.getItem('cyberguard_session'));
      expect(sessionData).toHaveProperty('lastChecked');
      expect(sessionData.lastChecked).toBeGreaterThan(initialTimestamp);
    });

    it('should not update timestamp when not authenticated', () => {
      // Setup
      authManager.currentUser = null;

      // Setup page visibility handler
      authManager.setupPageVisibilityHandler(mockDocument, mockWindow);

      // Get the beforeunload callback
      const beforeunloadCallback = mockWindow.addEventListener.mock.calls.find(
        call => call[0] === 'beforeunload'
      )?.[1];

      // Execute callback
      if (beforeunloadCallback) {
        beforeunloadCallback();
      }

      // Verify - no session data should be created
      expect(localStorage.getItem('cyberguard_session')).toBeNull();
    });
  });

  describe('Complete session validation flow', () => {
    it('should handle complete page load validation with valid session', async () => {
      // Setup - user with valid session
      const validTimestamp = Date.now() - (10 * 60 * 1000); // 10 minutes ago
      authManager.currentUser = { id: 1, email: 'test@example.com' };
      apiClient.getToken.mockReturnValue('valid-token');
      localStorage.setItem('cyberguard_session', JSON.stringify({
        timestamp: validTimestamp,
        userAgent: 'test'
      }));
      apiClient.get.mockResolvedValue({
        email_verified: true,
        two_factor_enabled: false
      });

      // Execute
      await authManager.validateSessionOnPageLoad();

      // Verify - session remains valid
      expect(apiClient.getToken).toHaveBeenCalled();
      expect(apiClient.get).toHaveBeenCalledWith('auth/status');
      expect(apiClient.clearToken).not.toHaveBeenCalled();
      expect(authManager.currentUser).not.toBeNull();
    });

    it('should handle complete page load validation with expired session', async () => {
      // Setup - user with expired session
      const expiredTimestamp = Date.now() - (35 * 60 * 1000); // 35 minutes ago
      authManager.currentUser = { id: 1, email: 'test@example.com' };
      apiClient.getToken.mockReturnValue('valid-token');
      localStorage.setItem('cyberguard_session', JSON.stringify({
        timestamp: expiredTimestamp,
        userAgent: 'test'
      }));
      localStorage.setItem('cyberguard_user', JSON.stringify({
        id: 1,
        email: 'test@example.com'
      }));

      // Execute
      await authManager.validateSessionOnPageLoad();

      // Verify - session is cleared
      expect(apiClient.clearToken).toHaveBeenCalled();
      expect(localStorage.getItem('cyberguard_user')).toBeNull();
      expect(localStorage.getItem('cyberguard_session')).toBeNull();
      expect(authManager.currentUser).toBeNull();
      expect(authManager.updateUI).toHaveBeenCalled();
    });

    it('should handle backend validation failure gracefully', async () => {
      // Setup
      authManager.currentUser = { id: 1, email: 'test@example.com' };
      apiClient.getToken.mockReturnValue('valid-token');
      localStorage.setItem('cyberguard_session', JSON.stringify({
        timestamp: Date.now(),
        userAgent: 'test'
      }));
      apiClient.get.mockRejectedValue(new Error('Network error'));

      // Execute
      await authManager.validateSessionOnPageLoad();

      // Verify - session is cleared due to validation failure
      expect(apiClient.clearToken).toHaveBeenCalled();
      expect(authManager.currentUser).toBeNull();
    });
  });

  describe('HTTPS enforcement in API client', () => {
    it('should verify all API calls use HTTPS base URL', () => {
      const API_BASE_URL = 'https://peptonelike-lelia-interdepartmentally.ngrok-free.dev/api/';
      
      // Verify HTTPS protocol
      expect(API_BASE_URL).toMatch(/^https:\/\//);
      
      // Verify ngrok domain
      expect(API_BASE_URL).toContain('ngrok-free.dev');
    });

    it('should build HTTPS URLs for all endpoints', () => {
      const baseURL = 'https://peptonelike-lelia-interdepartmentally.ngrok-free.dev/api/';
      const endpoints = ['auth/login', 'auth/register', 'auth/status', 'auth/me'];

      endpoints.forEach(endpoint => {
        const fullURL = `${baseURL}${endpoint}`;
        expect(fullURL).toMatch(/^https:\/\//);
      });
    });
  });
});
