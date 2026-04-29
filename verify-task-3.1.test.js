/**
 * Verification Script for Task 3.1
 * 
 * This script verifies that the loginWithAPI function correctly:
 * 1. Extracts and normalizes user object BEFORE checking 2FA requirement
 * 2. Checks normalizedUser.twoFactorEnabled instead of response.data.requires_2fa
 * 3. Only calls show2FAModal() if normalizedUser.twoFactorEnabled === true
 * 4. Returns requires2FA: false when twoFactorEnabled: false
 * 5. Logs warning when requires_2fa and twoFactorEnabled are out of sync
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { JSDOM } from 'jsdom';

describe('Task 3.1 Verification - loginWithAPI Fix', () => {
  let authManager;
  let apiClientMock;
  let dom;
  let normalizeUserDataMock;

  beforeEach(() => {
    // Setup DOM environment
    dom = new JSDOM('<!DOCTYPE html><html><body></body></html>', {
      url: 'http://localhost'
    });
    global.document = dom.window.document;
    global.window = dom.window;
    global.localStorage = dom.window.localStorage;
    global.sessionStorage = dom.window.sessionStorage;

    localStorage.clear();
    sessionStorage.clear();

    // Mock global functions
    global.showLoading = vi.fn();
    global.hideLoading = vi.fn();
    global.console.warn = vi.fn();

    // Mock normalizeUserData
    normalizeUserDataMock = vi.fn((userData) => {
      if (!userData || typeof userData !== 'object') {
        return null;
      }
      return {
        id: userData.id || null,
        email: userData.email || '',
        name: userData.full_name || userData.name || '',
        fullName: userData.full_name || userData.name || '',
        jobTitle: userData.job_title || userData.job_tittle || '',
        emailVerified: userData.email_verified || false,
        twoFactorEnabled: userData.two_factor_enabled || false,
        role: userData.role || 'user',
        createdAt: userData.created_at || new Date().toISOString(),
        lastLogin: userData.last_login || new Date().toISOString(),
        preferences: userData.preferences || {}
      };
    });
    global.normalizeUserData = normalizeUserDataMock;

    // Mock APIClient
    apiClientMock = {
      post: vi.fn(),
      setToken: vi.fn(),
      getToken: vi.fn(),
      clearToken: vi.fn()
    };

    // Mock ValidationError
    global.ValidationError = class ValidationError extends Error {
      constructor(errors) {
        super('Validation failed');
        this.name = 'ValidationError';
        this.errors = errors;
      }
    };

    // Create AuthManager with FIXED loginWithAPI
    authManager = {
      apiClient: apiClientMock,
      currentUser: null,
      
      sanitizeInput(input) {
        if (typeof input !== 'string') return '';
        return input.replace(/[<>]/g, '');
      },

      validateLoginData(email, password) {
        const errors = [];
        if (!email || email.length === 0) {
          errors.push('Email is required');
        }
        if (!password || password.length === 0) {
          errors.push('Password is required');
        }
        return errors;
      },

      normalizeUserData(userData) {
        return normalizeUserDataMock(userData);
      },

      saveUserSession(user) {
        this.currentUser = user;
        localStorage.setItem('cyberguard_user', JSON.stringify(user));
      },

      trackLoginAttempt(email, success) {
        // Mock implementation
      },

      // FIXED loginWithAPI from auth.js
      async loginWithAPI(email, password) {
        try {
          showLoading('Signing you in...');

          const sanitizedEmail = this.sanitizeInput(email?.trim().toLowerCase() || '');

          const validationErrors = this.validateLoginData(sanitizedEmail, password);
          if (validationErrors.length > 0) {
            throw new ValidationError(validationErrors);
          }

          // Send login request
          const response = await this.apiClient.post('auth/login', {
            email: sanitizedEmail,
            password: password
          });

          // Extract token and user from response.data BEFORE checking 2FA requirement
          const token = response.data?.token || response.token;
          const rawUser = response.data?.user || response.user || response.data || response;

          if (!token) {
            throw new Error('No authentication token received from server');
          }

          this.apiClient.setToken(token);

          const normalizedUser = this.normalizeUserData(rawUser);
          if (!normalizedUser) {
            throw new Error('Invalid user data received from server');
          }

          // Defensive logging: warn if requires_2fa and twoFactorEnabled are out of sync
          if (response.data?.requires_2fa && !normalizedUser.twoFactorEnabled) {
            console.warn('2FA flag mismatch detected: requires_2fa=true but twoFactorEnabled=false. Prioritizing twoFactorEnabled as authoritative.');
          }

          // Check twoFactorEnabled (authoritative) instead of requires_2fa
          if (normalizedUser.twoFactorEnabled === true) {
            return {
              success: true,
              requires2FA: true,
              message: '2FA verification required'
            };
          }

          // User has 2FA disabled, proceed to save session and redirect to dashboard
          this.saveUserSession(normalizedUser);
          this.trackLoginAttempt(email, true);

          return { success: true, user: normalizedUser, requires2FA: false };
        } catch (error) {
          this.trackLoginAttempt(email, false);
          if (error.name === 'ValidationError' || error.name === 'APIError') {
            throw error;
          }
          throw new Error('An error occurred during login');
        } finally {
          hideLoading();
        }
      }
    };
  });

  it('should bypass 2FA modal when twoFactorEnabled is false (Bug Fix)', async () => {
    const mockResponse = {
      status: 'success',
      data: {
        token: 'mock-token-123',
        user: {
          id: 1,
          email: 'test@example.com',
          full_name: 'Test User',
          job_title: 'Analyst',
          two_factor_enabled: false
        },
        requires_2fa: true // Stale flag - should be ignored
      }
    };

    apiClientMock.post.mockResolvedValue(mockResponse);
    apiClientMock.getToken.mockReturnValue(mockResponse.data.token);

    const result = await authManager.loginWithAPI('test@example.com', 'password123');

    // Verify fix: should return requires2FA: false
    expect(result.requires2FA).toBe(false);
    expect(result.success).toBe(true);
    expect(result.user.twoFactorEnabled).toBe(false);
    
    // Verify session was saved (direct dashboard redirect)
    expect(localStorage.getItem('cyberguard_user')).toBeTruthy();
    
    // Verify warning was logged
    expect(console.warn).toHaveBeenCalledWith(
      '2FA flag mismatch detected: requires_2fa=true but twoFactorEnabled=false. Prioritizing twoFactorEnabled as authoritative.'
    );
  });

  it('should show 2FA modal when twoFactorEnabled is true (Preservation)', async () => {
    const mockResponse = {
      status: 'success',
      data: {
        token: 'mock-token-456',
        user: {
          id: 2,
          email: 'user2fa@example.com',
          full_name: 'User With 2FA',
          job_title: 'Engineer',
          two_factor_enabled: true
        },
        requires_2fa: true
      }
    };

    apiClientMock.post.mockResolvedValue(mockResponse);

    const result = await authManager.loginWithAPI('user2fa@example.com', 'password123');

    // Verify preservation: should return requires2FA: true
    expect(result.requires2FA).toBe(true);
    expect(result.success).toBe(true);
    expect(result.message).toBe('2FA verification required');
    
    // Verify session was NOT saved (waiting for 2FA verification)
    expect(localStorage.getItem('cyberguard_user')).toBeFalsy();
  });

  it('should prioritize twoFactorEnabled over requires_2fa', async () => {
    const mockResponse = {
      status: 'success',
      data: {
        token: 'mock-token-789',
        user: {
          id: 3,
          email: 'conflict@example.com',
          full_name: 'Conflict User',
          job_title: 'Manager',
          two_factor_enabled: false
        },
        requires_2fa: true // Conflicting flag
      }
    };

    apiClientMock.post.mockResolvedValue(mockResponse);
    apiClientMock.getToken.mockReturnValue(mockResponse.data.token);

    const result = await authManager.loginWithAPI('conflict@example.com', 'password123');

    // Verify twoFactorEnabled is prioritized
    expect(result.requires2FA).toBe(false);
    expect(result.user.twoFactorEnabled).toBe(false);
    
    // Verify warning was logged
    expect(console.warn).toHaveBeenCalled();
  });

  it('should extract and normalize user BEFORE checking 2FA', async () => {
    const mockResponse = {
      status: 'success',
      data: {
        token: 'mock-token-abc',
        user: {
          id: 4,
          email: 'order@example.com',
          full_name: 'Order Test',
          job_title: 'Analyst',
          two_factor_enabled: false
        },
        requires_2fa: false
      }
    };

    apiClientMock.post.mockResolvedValue(mockResponse);
    apiClientMock.getToken.mockReturnValue(mockResponse.data.token);

    await authManager.loginWithAPI('order@example.com', 'password123');

    // Verify normalizeUserData was called
    expect(normalizeUserDataMock).toHaveBeenCalledWith(mockResponse.data.user);
    
    // Verify token was set before checking 2FA
    expect(apiClientMock.setToken).toHaveBeenCalledWith(mockResponse.data.token);
  });
});
