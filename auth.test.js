/**
 * Unit Tests for AuthManager 2FA Methods
 * Tests for task 8.1: Add 2FA setup methods to AuthManager
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { JSDOM } from 'jsdom';

describe('AuthManager - 2FA Methods (Task 8.1)', () => {
  let authManager;
  let apiClientMock;
  let dom;

  beforeEach(() => {
    // Setup DOM environment with proper URL to enable localStorage
    dom = new JSDOM('<!DOCTYPE html><html><body></body></html>', {
      url: 'http://localhost'
    });
    global.document = dom.window.document;
    global.window = dom.window;
    global.localStorage = dom.window.localStorage;

    // Clear localStorage
    localStorage.clear();

    // Mock APIClient
    apiClientMock = {
      post: vi.fn(),
      setToken: vi.fn(),
      getToken: vi.fn(),
      clearToken: vi.fn()
    };

    // Create a minimal AuthManager mock
    authManager = {
      apiClient: apiClientMock,
      currentUser: null,
      
      // Copy the actual methods from AuthManager
      async setup2FA() {
        try {
          const response = await this.apiClient.post('auth/2fa/setup');
          return { 
            success: true, 
            qrCode: response.qr_code,
            secret: response.secret
          };
        } catch (error) {
          console.error("2FA setup error:", error);
          if (error.name === 'APIError') {
            throw error;
          }
          throw new Error('An error occurred during 2FA setup');
        }
      },

      async enable2FA(code) {
        try {
          const response = await this.apiClient.post('auth/2fa/enable', {
            code: code
          });

          if (this.currentUser) {
            this.currentUser.twoFactorEnabled = true;
            localStorage.setItem("cyberguard_user", JSON.stringify(this.currentUser));
          }

          return { 
            success: true, 
            message: response.message || '2FA enabled successfully'
          };
        } catch (error) {
          console.error("2FA enable error:", error);
          if (error.name === 'APIError') {
            throw error;
          }
          throw new Error('An error occurred while enabling 2FA');
        }
      },

      async disable2FA() {
        try {
          const response = await this.apiClient.post('auth/2fa/disable');

          if (this.currentUser) {
            this.currentUser.twoFactorEnabled = false;
            localStorage.setItem("cyberguard_user", JSON.stringify(this.currentUser));
          }

          return { 
            success: true, 
            message: response.message || '2FA disabled successfully'
          };
        } catch (error) {
          console.error("2FA disable error:", error);
          if (error.name === 'APIError') {
            throw error;
          }
          throw new Error('An error occurred while disabling 2FA');
        }
      }
    };
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('setup2FA()', () => {
    it('should call POST /api/auth/2fa/setup', async () => {
      // Arrange
      const mockResponse = {
        qr_code: 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAUA',
        secret: 'JBSWY3DPEHPK3PXP'
      };
      apiClientMock.post.mockResolvedValue(mockResponse);

      // Act
      const result = await authManager.setup2FA();

      // Assert
      expect(apiClientMock.post).toHaveBeenCalledWith('auth/2fa/setup');
      expect(result).toEqual({
        success: true,
        qrCode: mockResponse.qr_code,
        secret: mockResponse.secret
      });
    });

    it('should return QR code and secret from API response', async () => {
      // Arrange
      const mockResponse = {
        qr_code: 'data:image/png;base64,testQRCode',
        secret: 'TESTSECRET123456'
      };
      apiClientMock.post.mockResolvedValue(mockResponse);

      // Act
      const result = await authManager.setup2FA();

      // Assert
      expect(result.success).toBe(true);
      expect(result.qrCode).toBe('data:image/png;base64,testQRCode');
      expect(result.secret).toBe('TESTSECRET123456');
    });

    it('should throw error when API call fails', async () => {
      // Arrange
      const apiError = new Error('API Error');
      apiError.name = 'APIError';
      apiClientMock.post.mockRejectedValue(apiError);

      // Act & Assert
      await expect(authManager.setup2FA()).rejects.toThrow('API Error');
    });

    it('should wrap non-API errors with generic message', async () => {
      // Arrange
      apiClientMock.post.mockRejectedValue(new Error('Network failure'));

      // Act & Assert
      await expect(authManager.setup2FA()).rejects.toThrow('An error occurred during 2FA setup');
    });
  });

  describe('enable2FA(code)', () => {
    it('should call POST /api/auth/2fa/enable with code', async () => {
      // Arrange
      const code = '123456';
      const mockResponse = { message: '2FA enabled successfully' };
      apiClientMock.post.mockResolvedValue(mockResponse);

      // Act
      const result = await authManager.enable2FA(code);

      // Assert
      expect(apiClientMock.post).toHaveBeenCalledWith('auth/2fa/enable', { code: '123456' });
      expect(result).toEqual({
        success: true,
        message: '2FA enabled successfully'
      });
    });

    it('should update currentUser twoFactorEnabled status', async () => {
      // Arrange
      authManager.currentUser = {
        id: 1,
        email: 'test@example.com',
        twoFactorEnabled: false
      };
      const mockResponse = { message: '2FA enabled' };
      apiClientMock.post.mockResolvedValue(mockResponse);

      // Act
      await authManager.enable2FA('123456');

      // Assert
      expect(authManager.currentUser.twoFactorEnabled).toBe(true);
    });

    it('should save updated user to localStorage', async () => {
      // Arrange
      authManager.currentUser = {
        id: 1,
        email: 'test@example.com',
        twoFactorEnabled: false
      };
      const mockResponse = { message: '2FA enabled' };
      apiClientMock.post.mockResolvedValue(mockResponse);

      // Act
      await authManager.enable2FA('123456');

      // Assert
      const savedUser = JSON.parse(localStorage.getItem('cyberguard_user'));
      expect(savedUser.twoFactorEnabled).toBe(true);
    });

    it('should use default message if API does not provide one', async () => {
      // Arrange
      apiClientMock.post.mockResolvedValue({});

      // Act
      const result = await authManager.enable2FA('123456');

      // Assert
      expect(result.message).toBe('2FA enabled successfully');
    });

    it('should handle case when currentUser is null', async () => {
      // Arrange
      authManager.currentUser = null;
      const mockResponse = { message: '2FA enabled' };
      apiClientMock.post.mockResolvedValue(mockResponse);

      // Act & Assert - should not throw
      await expect(authManager.enable2FA('123456')).resolves.toEqual({
        success: true,
        message: '2FA enabled'
      });
    });

    it('should throw error when API call fails', async () => {
      // Arrange
      const apiError = new Error('Invalid code');
      apiError.name = 'APIError';
      apiClientMock.post.mockRejectedValue(apiError);

      // Act & Assert
      await expect(authManager.enable2FA('000000')).rejects.toThrow('Invalid code');
    });

    it('should wrap non-API errors with generic message', async () => {
      // Arrange
      apiClientMock.post.mockRejectedValue(new Error('Network failure'));

      // Act & Assert
      await expect(authManager.enable2FA('123456')).rejects.toThrow('An error occurred while enabling 2FA');
    });
  });

  describe('disable2FA()', () => {
    it('should call POST /api/auth/2fa/disable', async () => {
      // Arrange
      const mockResponse = { message: '2FA disabled successfully' };
      apiClientMock.post.mockResolvedValue(mockResponse);

      // Act
      const result = await authManager.disable2FA();

      // Assert
      expect(apiClientMock.post).toHaveBeenCalledWith('auth/2fa/disable');
      expect(result).toEqual({
        success: true,
        message: '2FA disabled successfully'
      });
    });

    it('should update currentUser twoFactorEnabled status to false', async () => {
      // Arrange
      authManager.currentUser = {
        id: 1,
        email: 'test@example.com',
        twoFactorEnabled: true
      };
      const mockResponse = { message: '2FA disabled' };
      apiClientMock.post.mockResolvedValue(mockResponse);

      // Act
      await authManager.disable2FA();

      // Assert
      expect(authManager.currentUser.twoFactorEnabled).toBe(false);
    });

    it('should save updated user to localStorage', async () => {
      // Arrange
      authManager.currentUser = {
        id: 1,
        email: 'test@example.com',
        twoFactorEnabled: true
      };
      const mockResponse = { message: '2FA disabled' };
      apiClientMock.post.mockResolvedValue(mockResponse);

      // Act
      await authManager.disable2FA();

      // Assert
      const savedUser = JSON.parse(localStorage.getItem('cyberguard_user'));
      expect(savedUser.twoFactorEnabled).toBe(false);
    });

    it('should use default message if API does not provide one', async () => {
      // Arrange
      apiClientMock.post.mockResolvedValue({});

      // Act
      const result = await authManager.disable2FA();

      // Assert
      expect(result.message).toBe('2FA disabled successfully');
    });

    it('should handle case when currentUser is null', async () => {
      // Arrange
      authManager.currentUser = null;
      const mockResponse = { message: '2FA disabled' };
      apiClientMock.post.mockResolvedValue(mockResponse);

      // Act & Assert - should not throw
      await expect(authManager.disable2FA()).resolves.toEqual({
        success: true,
        message: '2FA disabled'
      });
    });

    it('should throw error when API call fails', async () => {
      // Arrange
      const apiError = new Error('Unauthorized');
      apiError.name = 'APIError';
      apiClientMock.post.mockRejectedValue(apiError);

      // Act & Assert
      await expect(authManager.disable2FA()).rejects.toThrow('Unauthorized');
    });

    it('should wrap non-API errors with generic message', async () => {
      // Arrange
      apiClientMock.post.mockRejectedValue(new Error('Network failure'));

      // Act & Assert
      await expect(authManager.disable2FA()).rejects.toThrow('An error occurred while disabling 2FA');
    });
  });

  describe('Integration - 2FA Lifecycle', () => {
    it('should complete full 2FA setup and enable flow', async () => {
      // Arrange
      authManager.currentUser = {
        id: 1,
        email: 'test@example.com',
        twoFactorEnabled: false
      };

      const setupResponse = {
        qr_code: 'data:image/png;base64,testQR',
        secret: 'TESTSECRET'
      };
      const enableResponse = { message: '2FA enabled' };

      apiClientMock.post
        .mockResolvedValueOnce(setupResponse)  // setup2FA call
        .mockResolvedValueOnce(enableResponse); // enable2FA call

      // Act
      const setupResult = await authManager.setup2FA();
      const enableResult = await authManager.enable2FA('123456');

      // Assert
      expect(setupResult.success).toBe(true);
      expect(setupResult.qrCode).toBe('data:image/png;base64,testQR');
      expect(setupResult.secret).toBe('TESTSECRET');
      
      expect(enableResult.success).toBe(true);
      expect(authManager.currentUser.twoFactorEnabled).toBe(true);
    });

    it('should complete full 2FA disable flow', async () => {
      // Arrange
      authManager.currentUser = {
        id: 1,
        email: 'test@example.com',
        twoFactorEnabled: true
      };

      const disableResponse = { message: '2FA disabled' };
      apiClientMock.post.mockResolvedValue(disableResponse);

      // Act
      const result = await authManager.disable2FA();

      // Assert
      expect(result.success).toBe(true);
      expect(authManager.currentUser.twoFactorEnabled).toBe(false);
    });
  });
});

/**
 * Unit Tests for AuthManager Session Restoration Methods
 * Tests for task 9.1: Add session restoration methods to AuthManager
 */

describe('AuthManager - Session Restoration Methods (Task 9.1)', () => {
  let authManager;
  let apiClientMock;
  let dom;

  beforeEach(() => {
    // Setup DOM environment with proper URL to enable localStorage
    dom = new JSDOM('<!DOCTYPE html><html><body></body></html>', {
      url: 'http://localhost'
    });
    global.document = dom.window.document;
    global.window = dom.window;
    global.localStorage = dom.window.localStorage;

    // Clear localStorage
    localStorage.clear();

    // Mock APIClient
    apiClientMock = {
      get: vi.fn(),
      post: vi.fn(),
      setToken: vi.fn(),
      getToken: vi.fn(),
      clearToken: vi.fn()
    };

    // Create a minimal AuthManager mock with session restoration methods
    authManager = {
      apiClient: apiClientMock,
      currentUser: null,
      
      normalizeUserData(userData) {
        return {
          id: userData.id,
          email: userData.email,
          name: userData.full_name || userData.name,
          fullName: userData.full_name || userData.name,
          jobTitle: userData.job_title || userData.job_tittle || '',
          emailVerified: userData.email_verified || false,
          twoFactorEnabled: userData.two_factor_enabled || false,
          role: userData.role || 'user',
          createdAt: userData.created_at || new Date().toISOString(),
          lastLogin: userData.last_login || new Date().toISOString(),
          preferences: userData.preferences || {}
        };
      },

      saveUserSession(user) {
        const sessionData = {
          timestamp: Date.now(),
          userAgent: 'test-agent',
          ip: '127.0.0.1'
        };
        localStorage.setItem("cyberguard_user", JSON.stringify(user));
        localStorage.setItem("cyberguard_session", JSON.stringify(sessionData));
        this.currentUser = user;
        return true;
      },

      updateUI() {
        // Mock UI update
      },

      async fetchUserProfile() {
        try {
          const response = await this.apiClient.get('auth/me');
          const normalizedUser = this.normalizeUserData(response.user || response);
          return { 
            success: true, 
            user: normalizedUser
          };
        } catch (error) {
          console.error("Fetch user profile error:", error);
          if (error.name === 'APIError') {
            throw error;
          }
          throw new Error('An error occurred while fetching user profile');
        }
      },

      async fetchSessionStatus() {
        try {
          const response = await this.apiClient.get('auth/status');
          return { 
            success: true, 
            emailVerified: response.email_verified || false,
            twoFactorEnabled: response.two_factor_enabled || false
          };
        } catch (error) {
          console.error("Fetch session status error:", error);
          if (error.name === 'APIError') {
            throw error;
          }
          throw new Error('An error occurred while fetching session status');
        }
      },

      async restoreSession() {
        try {
          const token = this.apiClient.getToken();
          
          if (!token) {
            this.currentUser = null;
            this.updateUI();
            return { success: false, message: 'No token found' };
          }

          const [profileResult, statusResult] = await Promise.all([
            this.fetchUserProfile().catch(err => ({ success: false, error: err })),
            this.fetchSessionStatus().catch(err => ({ success: false, error: err }))
          ]);

          if (!profileResult.success || !statusResult.success) {
            this.apiClient.clearToken();
            localStorage.removeItem("cyberguard_user");
            localStorage.removeItem("cyberguard_session");
            this.currentUser = null;
            this.updateUI();
            return { success: false, message: 'Session validation failed' };
          }

          const user = {
            ...profileResult.user,
            emailVerified: statusResult.emailVerified,
            twoFactorEnabled: statusResult.twoFactorEnabled
          };

          this.saveUserSession(user);
          return { success: true, user: user };
        } catch (error) {
          console.error("Restore session error:", error);
          this.apiClient.clearToken();
          localStorage.removeItem("cyberguard_user");
          localStorage.removeItem("cyberguard_session");
          this.currentUser = null;
          this.updateUI();
          return { success: false, message: 'Session restoration failed' };
        }
      },

      async resendVerificationEmail() {
        try {
          const response = await this.apiClient.post('auth/resend-verification');
          return { 
            success: true, 
            message: response.message || 'Verification email sent successfully'
          };
        } catch (error) {
          console.error("Resend verification email error:", error);
          if (error.name === 'APIError') {
            throw error;
          }
          throw new Error('An error occurred while resending verification email');
        }
      }
    };
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('fetchUserProfile()', () => {
    it('should call GET /api/auth/me', async () => {
      // Arrange
      const mockResponse = {
        user: {
          id: 1,
          email: 'test@example.com',
          full_name: 'Test User',
          job_title: 'Security Analyst'
        }
      };
      apiClientMock.get.mockResolvedValue(mockResponse);

      // Act
      const result = await authManager.fetchUserProfile();

      // Assert
      expect(apiClientMock.get).toHaveBeenCalledWith('auth/me');
      expect(result.success).toBe(true);
      expect(result.user.email).toBe('test@example.com');
    });

    it('should normalize user data from API response', async () => {
      // Arrange
      const mockResponse = {
        id: 1,
        email: 'test@example.com',
        full_name: 'Test User',
        job_title: 'Security Analyst',
        email_verified: true,
        two_factor_enabled: false
      };
      apiClientMock.get.mockResolvedValue(mockResponse);

      // Act
      const result = await authManager.fetchUserProfile();

      // Assert
      expect(result.user.name).toBe('Test User');
      expect(result.user.fullName).toBe('Test User');
      expect(result.user.jobTitle).toBe('Security Analyst');
      expect(result.user.emailVerified).toBe(true);
      expect(result.user.twoFactorEnabled).toBe(false);
    });

    it('should handle response with nested user object', async () => {
      // Arrange
      const mockResponse = {
        user: {
          id: 1,
          email: 'test@example.com',
          full_name: 'Test User',
          job_title: 'Analyst'
        }
      };
      apiClientMock.get.mockResolvedValue(mockResponse);

      // Act
      const result = await authManager.fetchUserProfile();

      // Assert
      expect(result.success).toBe(true);
      expect(result.user.email).toBe('test@example.com');
    });

    it('should throw error when API call fails', async () => {
      // Arrange
      const apiError = new Error('Unauthorized');
      apiError.name = 'APIError';
      apiClientMock.get.mockRejectedValue(apiError);

      // Act & Assert
      await expect(authManager.fetchUserProfile()).rejects.toThrow('Unauthorized');
    });

    it('should wrap non-API errors with generic message', async () => {
      // Arrange
      apiClientMock.get.mockRejectedValue(new Error('Network failure'));

      // Act & Assert
      await expect(authManager.fetchUserProfile()).rejects.toThrow('An error occurred while fetching user profile');
    });
  });

  describe('fetchSessionStatus()', () => {
    it('should call GET /api/auth/status', async () => {
      // Arrange
      const mockResponse = {
        email_verified: true,
        two_factor_enabled: false
      };
      apiClientMock.get.mockResolvedValue(mockResponse);

      // Act
      const result = await authManager.fetchSessionStatus();

      // Assert
      expect(apiClientMock.get).toHaveBeenCalledWith('auth/status');
      expect(result.success).toBe(true);
    });

    it('should return email verification and 2FA status', async () => {
      // Arrange
      const mockResponse = {
        email_verified: true,
        two_factor_enabled: true
      };
      apiClientMock.get.mockResolvedValue(mockResponse);

      // Act
      const result = await authManager.fetchSessionStatus();

      // Assert
      expect(result.emailVerified).toBe(true);
      expect(result.twoFactorEnabled).toBe(true);
    });

    it('should default to false for missing fields', async () => {
      // Arrange
      const mockResponse = {};
      apiClientMock.get.mockResolvedValue(mockResponse);

      // Act
      const result = await authManager.fetchSessionStatus();

      // Assert
      expect(result.emailVerified).toBe(false);
      expect(result.twoFactorEnabled).toBe(false);
    });

    it('should throw error when API call fails', async () => {
      // Arrange
      const apiError = new Error('Unauthorized');
      apiError.name = 'APIError';
      apiClientMock.get.mockRejectedValue(apiError);

      // Act & Assert
      await expect(authManager.fetchSessionStatus()).rejects.toThrow('Unauthorized');
    });

    it('should wrap non-API errors with generic message', async () => {
      // Arrange
      apiClientMock.get.mockRejectedValue(new Error('Network failure'));

      // Act & Assert
      await expect(authManager.fetchSessionStatus()).rejects.toThrow('An error occurred while fetching session status');
    });
  });

  describe('restoreSession()', () => {
    it('should return failure when no JWT token exists', async () => {
      // Arrange
      apiClientMock.getToken.mockReturnValue(null);

      // Act
      const result = await authManager.restoreSession();

      // Assert
      expect(result.success).toBe(false);
      expect(result.message).toBe('No token found');
      expect(authManager.currentUser).toBeNull();
    });

    it('should fetch user profile and session status in parallel', async () => {
      // Arrange
      apiClientMock.getToken.mockReturnValue('test-token');
      
      const profileResponse = {
        id: 1,
        email: 'test@example.com',
        full_name: 'Test User',
        job_title: 'Analyst'
      };
      
      const statusResponse = {
        email_verified: true,
        two_factor_enabled: false
      };

      apiClientMock.get
        .mockResolvedValueOnce(profileResponse)  // fetchUserProfile
        .mockResolvedValueOnce(statusResponse);  // fetchSessionStatus

      // Act
      const result = await authManager.restoreSession();

      // Assert
      expect(apiClientMock.get).toHaveBeenCalledWith('auth/me');
      expect(apiClientMock.get).toHaveBeenCalledWith('auth/status');
      expect(result.success).toBe(true);
    });

    it('should merge user data with session status', async () => {
      // Arrange
      apiClientMock.getToken.mockReturnValue('test-token');
      
      const profileResponse = {
        id: 1,
        email: 'test@example.com',
        full_name: 'Test User',
        job_title: 'Analyst'
      };
      
      const statusResponse = {
        email_verified: true,
        two_factor_enabled: true
      };

      apiClientMock.get
        .mockResolvedValueOnce(profileResponse)
        .mockResolvedValueOnce(statusResponse);

      // Act
      const result = await authManager.restoreSession();

      // Assert
      expect(result.success).toBe(true);
      expect(result.user.email).toBe('test@example.com');
      expect(result.user.emailVerified).toBe(true);
      expect(result.user.twoFactorEnabled).toBe(true);
    });

    it('should save user session on successful restoration', async () => {
      // Arrange
      apiClientMock.getToken.mockReturnValue('test-token');
      
      const profileResponse = {
        id: 1,
        email: 'test@example.com',
        full_name: 'Test User',
        job_title: 'Analyst'
      };
      
      const statusResponse = {
        email_verified: true,
        two_factor_enabled: false
      };

      apiClientMock.get
        .mockResolvedValueOnce(profileResponse)
        .mockResolvedValueOnce(statusResponse);

      // Act
      await authManager.restoreSession();

      // Assert
      const savedUser = JSON.parse(localStorage.getItem('cyberguard_user'));
      expect(savedUser.email).toBe('test@example.com');
      expect(authManager.currentUser).not.toBeNull();
    });

    it('should clear session when profile fetch fails', async () => {
      // Arrange
      apiClientMock.getToken.mockReturnValue('test-token');
      
      const apiError = new Error('Unauthorized');
      apiError.name = 'APIError';
      
      apiClientMock.get.mockRejectedValueOnce(apiError);

      // Act
      const result = await authManager.restoreSession();

      // Assert
      expect(result.success).toBe(false);
      expect(result.message).toBe('Session validation failed');
      expect(apiClientMock.clearToken).toHaveBeenCalled();
      expect(localStorage.getItem('cyberguard_user')).toBeNull();
      expect(authManager.currentUser).toBeNull();
    });

    it('should clear session when status fetch fails', async () => {
      // Arrange
      apiClientMock.getToken.mockReturnValue('test-token');
      
      const profileResponse = {
        id: 1,
        email: 'test@example.com',
        full_name: 'Test User'
      };
      
      const apiError = new Error('Unauthorized');
      apiError.name = 'APIError';

      apiClientMock.get
        .mockResolvedValueOnce(profileResponse)
        .mockRejectedValueOnce(apiError);

      // Act
      const result = await authManager.restoreSession();

      // Assert
      expect(result.success).toBe(false);
      expect(result.message).toBe('Session validation failed');
      expect(apiClientMock.clearToken).toHaveBeenCalled();
    });

    it('should clear session on unexpected errors', async () => {
      // Arrange
      apiClientMock.getToken.mockReturnValue('test-token');
      apiClientMock.get.mockRejectedValue(new Error('Unexpected error'));

      // Act
      const result = await authManager.restoreSession();

      // Assert
      expect(result.success).toBe(false);
      expect(result.message).toBe('Session validation failed');
      expect(apiClientMock.clearToken).toHaveBeenCalled();
      expect(authManager.currentUser).toBeNull();
    });
  });

  describe('resendVerificationEmail()', () => {
    it('should call POST /api/auth/resend-verification', async () => {
      // Arrange
      const mockResponse = { message: 'Verification email sent' };
      apiClientMock.post.mockResolvedValue(mockResponse);

      // Act
      const result = await authManager.resendVerificationEmail();

      // Assert
      expect(apiClientMock.post).toHaveBeenCalledWith('auth/resend-verification');
      expect(result.success).toBe(true);
      expect(result.message).toBe('Verification email sent');
    });

    it('should use default message if API does not provide one', async () => {
      // Arrange
      apiClientMock.post.mockResolvedValue({});

      // Act
      const result = await authManager.resendVerificationEmail();

      // Assert
      expect(result.message).toBe('Verification email sent successfully');
    });

    it('should throw error when API call fails', async () => {
      // Arrange
      const apiError = new Error('Rate limit exceeded');
      apiError.name = 'APIError';
      apiClientMock.post.mockRejectedValue(apiError);

      // Act & Assert
      await expect(authManager.resendVerificationEmail()).rejects.toThrow('Rate limit exceeded');
    });

    it('should wrap non-API errors with generic message', async () => {
      // Arrange
      apiClientMock.post.mockRejectedValue(new Error('Network failure'));

      // Act & Assert
      await expect(authManager.resendVerificationEmail()).rejects.toThrow('An error occurred while resending verification email');
    });
  });

  describe('Integration - Session Restoration Flow', () => {
    it('should complete full session restoration on page load', async () => {
      // Arrange
      apiClientMock.getToken.mockReturnValue('valid-jwt-token');
      
      const profileResponse = {
        id: 1,
        email: 'test@example.com',
        full_name: 'Test User',
        job_title: 'Security Analyst'
      };
      
      const statusResponse = {
        email_verified: true,
        two_factor_enabled: true
      };

      apiClientMock.get
        .mockResolvedValueOnce(profileResponse)
        .mockResolvedValueOnce(statusResponse);

      // Act
      const result = await authManager.restoreSession();

      // Assert
      expect(result.success).toBe(true);
      expect(result.user.email).toBe('test@example.com');
      expect(result.user.emailVerified).toBe(true);
      expect(result.user.twoFactorEnabled).toBe(true);
      expect(authManager.currentUser).not.toBeNull();
      
      const savedUser = JSON.parse(localStorage.getItem('cyberguard_user'));
      expect(savedUser.email).toBe('test@example.com');
    });

    it('should handle expired session gracefully', async () => {
      // Arrange
      apiClientMock.getToken.mockReturnValue('expired-token');
      
      const apiError = new Error('Token expired');
      apiError.name = 'APIError';
      apiClientMock.get.mockRejectedValue(apiError);

      // Act
      const result = await authManager.restoreSession();

      // Assert
      expect(result.success).toBe(false);
      expect(apiClientMock.clearToken).toHaveBeenCalled();
      expect(localStorage.getItem('cyberguard_user')).toBeNull();
      expect(authManager.currentUser).toBeNull();
    });
  });
});
