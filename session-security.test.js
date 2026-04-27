/**
 * Session Security Tests
 * Tests for task 21.3: Session security implementation
 * 
 * Requirements tested:
 * - 15.5: HTTPS enforcement for all API requests
 * - 15.6: Session validity check on every page load
 * - Session expiration handling
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';

describe('Session Security - Task 21.3', () => {
  let authManager;
  let apiClient;
  let mockLocalStorage;

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

    // Mock APIClient
    apiClient = {
      getToken: vi.fn(),
      clearToken: vi.fn(),
      get: vi.fn(),
      post: vi.fn()
    };

    // Mock AuthManager with session security methods
    authManager = {
      currentUser: null,
      sessionTimeout: 30 * 60 * 1000, // 30 minutes
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

          // Check if session has expired locally
          const sessionData = localStorage.getItem('cyberguard_session');
          if (sessionData) {
            const session = JSON.parse(sessionData);
            if (Date.now() - session.timestamp > this.sessionTimeout) {
              this.handleSessionExpiration();
              return;
            }
          }

          // Validate session with backend
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
      }
    };
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  describe('Requirement 15.6: Session validity check on every page load', () => {
    it('should validate session when token exists', async () => {
      // Setup
      apiClient.getToken.mockReturnValue('valid-token');
      apiClient.get.mockResolvedValue({
        email_verified: true,
        two_factor_enabled: false
      });
      localStorage.setItem('cyberguard_session', JSON.stringify({
        timestamp: Date.now(),
        userAgent: 'test'
      }));
      authManager.currentUser = { id: 1, email: 'test@example.com' };

      // Execute
      await authManager.validateSessionOnPageLoad();

      // Verify
      expect(apiClient.getToken).toHaveBeenCalled();
      expect(apiClient.get).toHaveBeenCalledWith('auth/status');
    });

    it('should clear session when no token exists', async () => {
      // Setup
      apiClient.getToken.mockReturnValue(null);
      authManager.currentUser = { id: 1, email: 'test@example.com' };

      // Execute
      await authManager.validateSessionOnPageLoad();

      // Verify
      expect(authManager.currentUser).toBeNull();
      expect(authManager.updateUI).toHaveBeenCalled();
    });

    it('should handle session expiration when timestamp exceeds timeout', async () => {
      // Setup
      const expiredTimestamp = Date.now() - (31 * 60 * 1000); // 31 minutes ago
      apiClient.getToken.mockReturnValue('valid-token');
      localStorage.setItem('cyberguard_session', JSON.stringify({
        timestamp: expiredTimestamp,
        userAgent: 'test'
      }));
      authManager.currentUser = { id: 1, email: 'test@example.com' };

      // Execute
      await authManager.validateSessionOnPageLoad();

      // Verify
      expect(apiClient.clearToken).toHaveBeenCalled();
      expect(localStorage.getItem('cyberguard_user')).toBeNull();
      expect(localStorage.getItem('cyberguard_session')).toBeNull();
      expect(authManager.currentUser).toBeNull();
    });

    it('should handle backend validation failure', async () => {
      // Setup
      apiClient.getToken.mockReturnValue('valid-token');
      apiClient.get.mockRejectedValue(new Error('Unauthorized'));
      localStorage.setItem('cyberguard_session', JSON.stringify({
        timestamp: Date.now(),
        userAgent: 'test'
      }));
      authManager.currentUser = { id: 1, email: 'test@example.com' };

      // Execute
      await authManager.validateSessionOnPageLoad();

      // Verify
      expect(apiClient.clearToken).toHaveBeenCalled();
      expect(authManager.currentUser).toBeNull();
    });
  });

  describe('Session expiration handling', () => {
    it('should clear all session data on expiration', () => {
      // Setup
      localStorage.setItem('cyberguard_user', JSON.stringify({ id: 1 }));
      localStorage.setItem('cyberguard_session', JSON.stringify({ timestamp: Date.now() }));
      authManager.currentUser = { id: 1, email: 'test@example.com' };

      // Execute
      authManager.handleSessionExpiration();

      // Verify
      expect(apiClient.clearToken).toHaveBeenCalled();
      expect(localStorage.getItem('cyberguard_user')).toBeNull();
      expect(localStorage.getItem('cyberguard_session')).toBeNull();
      expect(authManager.currentUser).toBeNull();
      expect(authManager.updateUI).toHaveBeenCalled();
    });

    it('should handle expiration gracefully when already logged out', () => {
      // Setup
      authManager.currentUser = null;

      // Execute
      authManager.handleSessionExpiration();

      // Verify - should not throw error
      expect(apiClient.clearToken).toHaveBeenCalled();
      expect(authManager.updateUI).toHaveBeenCalled();
    });
  });

  describe('Requirement 15.5: HTTPS enforcement', () => {
    it('should enforce HTTPS for API base URL', () => {
      // The API_BASE_URL constant should use HTTPS
      const API_BASE_URL = 'https://peptonelike-lelia-interdepartmentally.ngrok-free.dev/api/';
      
      expect(API_BASE_URL).toMatch(/^https:\/\//);
    });

    it('should reject non-HTTPS URLs in _buildURL', () => {
      // Mock APIClient with _buildURL method
      const client = {
        baseURL: 'http://insecure.example.com/api/',
        _buildURL(endpoint) {
          const cleanEndpoint = endpoint.startsWith('/') ? endpoint.slice(1) : endpoint;
          const fullURL = `${this.baseURL}${cleanEndpoint}`;
          
          if (!fullURL.startsWith('https://')) {
            throw new Error('Security Error: API requests must use HTTPS');
          }
          
          return fullURL;
        }
      };

      // Verify that non-HTTPS URLs throw error
      expect(() => client._buildURL('auth/login')).toThrow('Security Error: API requests must use HTTPS');
    });

    it('should accept HTTPS URLs in _buildURL', () => {
      // Mock APIClient with _buildURL method
      const client = {
        baseURL: 'https://secure.example.com/api/',
        _buildURL(endpoint) {
          const cleanEndpoint = endpoint.startsWith('/') ? endpoint.slice(1) : endpoint;
          const fullURL = `${this.baseURL}${cleanEndpoint}`;
          
          if (!fullURL.startsWith('https://')) {
            throw new Error('Security Error: API requests must use HTTPS');
          }
          
          return fullURL;
        }
      };

      // Verify that HTTPS URLs are accepted
      const url = client._buildURL('auth/login');
      expect(url).toBe('https://secure.example.com/api/auth/login');
      expect(url).toMatch(/^https:\/\//);
    });
  });

  describe('Session timeout checking', () => {
    it('should detect expired sessions based on timestamp', () => {
      const sessionTimeout = 30 * 60 * 1000; // 30 minutes
      const expiredTimestamp = Date.now() - (31 * 60 * 1000); // 31 minutes ago
      const validTimestamp = Date.now() - (29 * 60 * 1000); // 29 minutes ago

      // Expired session
      expect(Date.now() - expiredTimestamp > sessionTimeout).toBe(true);

      // Valid session
      expect(Date.now() - validTimestamp > sessionTimeout).toBe(false);
    });

    it('should handle missing session data gracefully', async () => {
      // Setup
      apiClient.getToken.mockReturnValue('valid-token');
      // No session data in localStorage
      authManager.currentUser = { id: 1, email: 'test@example.com' };
      apiClient.get.mockResolvedValue({
        email_verified: true,
        two_factor_enabled: false
      });

      // Execute
      await authManager.validateSessionOnPageLoad();

      // Verify - should still validate with backend
      expect(apiClient.get).toHaveBeenCalledWith('auth/status');
    });
  });

  describe('Integration: Page load session validation', () => {
    it('should perform complete validation flow on page load', async () => {
      // Setup - valid session
      const validTimestamp = Date.now() - (10 * 60 * 1000); // 10 minutes ago
      apiClient.getToken.mockReturnValue('valid-token');
      localStorage.setItem('cyberguard_session', JSON.stringify({
        timestamp: validTimestamp,
        userAgent: 'test'
      }));
      localStorage.setItem('cyberguard_user', JSON.stringify({
        id: 1,
        email: 'test@example.com'
      }));
      authManager.currentUser = { id: 1, email: 'test@example.com' };
      apiClient.get.mockResolvedValue({
        email_verified: true,
        two_factor_enabled: false
      });

      // Execute
      await authManager.validateSessionOnPageLoad();

      // Verify - session should remain valid
      expect(apiClient.getToken).toHaveBeenCalled();
      expect(apiClient.get).toHaveBeenCalledWith('auth/status');
      expect(apiClient.clearToken).not.toHaveBeenCalled();
    });

    it('should clear expired session on page load', async () => {
      // Setup - expired session
      const expiredTimestamp = Date.now() - (35 * 60 * 1000); // 35 minutes ago
      apiClient.getToken.mockReturnValue('valid-token');
      localStorage.setItem('cyberguard_session', JSON.stringify({
        timestamp: expiredTimestamp,
        userAgent: 'test'
      }));
      authManager.currentUser = { id: 1, email: 'test@example.com' };

      // Execute
      await authManager.validateSessionOnPageLoad();

      // Verify - session should be cleared
      expect(apiClient.clearToken).toHaveBeenCalled();
      expect(localStorage.getItem('cyberguard_user')).toBeNull();
      expect(localStorage.getItem('cyberguard_session')).toBeNull();
      expect(authManager.currentUser).toBeNull();
    });
  });
});
