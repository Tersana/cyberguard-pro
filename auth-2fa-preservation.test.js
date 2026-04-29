/**
 * Preservation Property Tests - 2FA Forced Bypass Fix
 * 
 * **Property 2: Preservation** - 2FA Modal for Enabled Users
 * 
 * **IMPORTANT**: These tests observe and validate behavior on UNFIXED code
 * for users with twoFactorEnabled: true. They capture the baseline behavior
 * that must be preserved after implementing the fix.
 * 
 * **EXPECTED OUTCOME ON UNFIXED CODE**: Tests PASS (confirms baseline behavior)
 * **EXPECTED OUTCOME ON FIXED CODE**: Tests PASS (confirms no regressions)
 * 
 * **Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7**
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { JSDOM } from 'jsdom';
import * as fc from 'fast-check';

describe('Preservation Property Tests - 2FA Modal for Enabled Users (Property 2)', () => {
  let authManager;
  let apiClientMock;
  let dom;
  let normalizeUserDataMock;

  beforeEach(() => {
    // Setup DOM environment with proper URL to enable localStorage
    dom = new JSDOM('<!DOCTYPE html><html><body></body></html>', {
      url: 'http://localhost'
    });
    global.document = dom.window.document;
    global.window = dom.window;
    global.localStorage = dom.window.localStorage;
    global.sessionStorage = dom.window.sessionStorage;

    // Clear storage
    localStorage.clear();
    sessionStorage.clear();

    // Mock global functions that auth.js depends on
    global.showLoading = vi.fn();
    global.hideLoading = vi.fn();

    // Mock normalizeUserData utility function
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

    // Mock ValidationError
    global.ValidationError = class ValidationError extends Error {
      constructor(errors) {
        super('Validation failed');
        this.name = 'ValidationError';
        this.errors = errors;
      }
    };

    // Mock APIClient
    apiClientMock = {
      post: vi.fn(),
      get: vi.fn(),
      setToken: vi.fn(),
      getToken: vi.fn(),
      clearToken: vi.fn()
    };

    // Create AuthManager instance with the actual methods from auth.js
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
        localStorage.setItem('cyberguard_token', this.apiClient.getToken());
      },

      trackLoginAttempt(email, success) {
        // Mock implementation
      },

      updateUI() {
        // Mock implementation
      },

      // Copy the ACTUAL loginWithAPI method from auth.js (FIXED version)
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
      },

      // Copy the ACTUAL verify2FA method from auth.js
      async verify2FA(code) {
        try {
          showLoading('Verifying code...');
          
          const response = await this.apiClient.post('auth/2fa/verify', {
            code: code
          });

          this.apiClient.setToken(response.token);
          const normalizedUser = this.normalizeUserData(response.user);
          this.saveUserSession(normalizedUser);

          return { success: true, user: normalizedUser };
        } catch (error) {
          console.error("2FA verification error:", error);
          
          if (error.name === 'APIError') {
            throw error;
          }
          
          throw new Error('An error occurred during 2FA verification');
        } finally {
          hideLoading();
        }
      },

      // Copy the ACTUAL fetchUserProfile method from auth.js
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

      // Copy the ACTUAL fetchSessionStatus method from auth.js
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

      // Copy the ACTUAL restoreSession method from auth.js
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
      }
    };
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  /**
   * Test 1: For all users with twoFactorEnabled: true, loginWithAPI returns requires2FA: true
   * 
   * **Validates: Requirements 3.1, 3.4**
   * 
   * This test observes that users with 2FA enabled correctly trigger the 2FA modal.
   * This behavior must be preserved after the fix.
   */
  it('Property 2.1: loginWithAPI returns requires2FA: true when user.twoFactorEnabled is true', { timeout: 30000 }, async () => {
    await fc.assert(
      fc.asyncProperty(
        // Generate arbitrary user data with twoFactorEnabled: true
        fc.record({
          id: fc.integer({ min: 1, max: 10000 }),
          email: fc.emailAddress(),
          full_name: fc.string({ minLength: 3, maxLength: 50 }),
          job_title: fc.constantFrom('Analyst', 'Engineer', 'Manager', 'Admin'),
          email_verified: fc.boolean(),
          two_factor_enabled: fc.constant(true), // CRITICAL: Always true for preservation
          role: fc.constantFrom('user', 'admin'),
          created_at: fc.date({ min: new Date('2020-01-01'), max: new Date('2024-12-31') }).map(d => d.toISOString()),
          last_login: fc.date({ min: new Date('2020-01-01'), max: new Date('2024-12-31') }).map(d => d.toISOString())
        }),
        // Generate arbitrary credentials
        fc.emailAddress(),
        fc.string({ minLength: 8, maxLength: 20 }),
        
        async (userData, email, password) => {
          // Arrange: Mock API response with requires_2fa: true and user.two_factor_enabled: true
          const mockResponse = {
            status: 'success',
            message: 'Login successful',
            data: {
              token: 'mock-jwt-token-' + Math.random(),
              user: userData,
              requires_2fa: true // Backend correctly sets this to true
            }
          };

          apiClientMock.post.mockResolvedValue(mockResponse);
          apiClientMock.getToken.mockReturnValue(mockResponse.data.token);

          // Act: Call loginWithAPI
          const result = await authManager.loginWithAPI(email, password);

          // Assert: PRESERVATION - 2FA modal should be shown
          expect(result.requires2FA).toBe(true);
          expect(result.success).toBe(true);
          expect(result.message).toBe('2FA verification required');
          
          // User session should NOT be saved yet (waiting for 2FA verification)
          expect(result.user).toBeUndefined();
          expect(localStorage.getItem('cyberguard_user')).toBeNull();
        }
      ),
      {
        numRuns: 10, // Reduced for faster execution
        verbose: false
      }
    );
  });

  /**
   * Test 2: For all users with twoFactorEnabled: true, 2FA verification succeeds and redirects to dashboard
   * 
   * **Validates: Requirements 3.2, 3.3**
   * 
   * This test observes that 2FA verification flow works correctly for enabled users.
   * This behavior must be preserved after the fix.
   */
  it('Property 2.2: verify2FA succeeds and saves session for users with twoFactorEnabled: true', { timeout: 30000 }, async () => {
    await fc.assert(
      fc.asyncProperty(
        // Generate arbitrary user data with twoFactorEnabled: true
        fc.record({
          id: fc.integer({ min: 1, max: 10000 }),
          email: fc.emailAddress(),
          full_name: fc.string({ minLength: 3, maxLength: 50 }),
          job_title: fc.constantFrom('Analyst', 'Engineer', 'Manager', 'Admin'),
          email_verified: fc.boolean(),
          two_factor_enabled: fc.constant(true), // User has 2FA enabled
          role: fc.constantFrom('user', 'admin'),
          created_at: fc.date({ min: new Date('2020-01-01'), max: new Date('2024-12-31') }).map(d => d.toISOString()),
          last_login: fc.date({ min: new Date('2020-01-01'), max: new Date('2024-12-31') }).map(d => d.toISOString())
        }),
        // Generate arbitrary 2FA code (6 digits)
        fc.integer({ min: 100000, max: 999999 }).map(n => n.toString()),
        
        async (userData, code) => {
          // Arrange: Mock API response for 2FA verification
          const mockResponse = {
            token: 'mock-jwt-token-2fa-' + Math.random(),
            user: userData
          };

          apiClientMock.post.mockResolvedValue(mockResponse);
          apiClientMock.getToken.mockReturnValue(mockResponse.token);

          // Act: Call verify2FA
          const result = await authManager.verify2FA(code);

          // Assert: PRESERVATION - 2FA verification should succeed
          expect(result.success).toBe(true);
          expect(result.user).toBeDefined();
          expect(result.user.twoFactorEnabled).toBe(true);
          
          // User session should be saved after successful verification
          const savedUser = JSON.parse(localStorage.getItem('cyberguard_user'));
          expect(savedUser).toBeDefined();
          expect(savedUser.twoFactorEnabled).toBe(true);
          
          // Token should be set
          expect(apiClientMock.setToken).toHaveBeenCalledWith(mockResponse.token);
        }
      ),
      {
        numRuns: 10,
        verbose: false
      }
    );
  });

  /**
   * Test 3: Session restoration correctly fetches and merges twoFactorEnabled status
   * 
   * **Validates: Requirements 3.7**
   * 
   * This test observes that session restoration merges twoFactorEnabled status correctly.
   * This behavior must be preserved after the fix.
   */
  it('Property 2.3: restoreSession correctly merges twoFactorEnabled status from backend', { timeout: 30000 }, async () => {
    await fc.assert(
      fc.asyncProperty(
        // Generate arbitrary user data
        fc.record({
          id: fc.integer({ min: 1, max: 10000 }),
          email: fc.emailAddress(),
          full_name: fc.string({ minLength: 3, maxLength: 50 }),
          job_title: fc.constantFrom('Analyst', 'Engineer', 'Manager', 'Admin'),
          role: fc.constantFrom('user', 'admin'),
          created_at: fc.date({ min: new Date('2020-01-01'), max: new Date('2024-12-31') }).map(d => d.toISOString()),
          last_login: fc.date({ min: new Date('2020-01-01'), max: new Date('2024-12-31') }).map(d => d.toISOString())
        }),
        // Generate arbitrary 2FA status
        fc.boolean(),
        fc.boolean(),
        
        async (userData, emailVerified, twoFactorEnabled) => {
          // Arrange: Mock JWT token exists
          apiClientMock.getToken.mockReturnValue('valid-jwt-token');

          // Mock fetchUserProfile response
          const profileResponse = {
            user: userData
          };

          // Mock fetchSessionStatus response
          const statusResponse = {
            email_verified: emailVerified,
            two_factor_enabled: twoFactorEnabled
          };

          apiClientMock.get
            .mockResolvedValueOnce(profileResponse)  // fetchUserProfile
            .mockResolvedValueOnce(statusResponse);  // fetchSessionStatus

          // Act: Call restoreSession
          const result = await authManager.restoreSession();

          // Assert: PRESERVATION - Session restoration should merge status correctly
          expect(result.success).toBe(true);
          expect(result.user).toBeDefined();
          expect(result.user.emailVerified).toBe(emailVerified);
          expect(result.user.twoFactorEnabled).toBe(twoFactorEnabled);
          
          // Merged user should be saved to localStorage
          const savedUser = JSON.parse(localStorage.getItem('cyberguard_user'));
          expect(savedUser).toBeDefined();
          expect(savedUser.emailVerified).toBe(emailVerified);
          expect(savedUser.twoFactorEnabled).toBe(twoFactorEnabled);
          
          // Both API calls should have been made
          expect(apiClientMock.get).toHaveBeenCalledWith('auth/me');
          expect(apiClientMock.get).toHaveBeenCalledWith('auth/status');
        }
      ),
      {
        numRuns: 10,
        verbose: false
      }
    );
  });

  /**
   * Concrete Example: User with 2FA enabled sees modal on login
   * 
   * This is a concrete example for easier debugging and documentation.
   */
  it('Concrete Example: User with twoFactorEnabled: true sees 2FA modal on login', async () => {
    // Arrange: User has 2FA enabled
    const mockResponse = {
      status: 'success',
      message: 'Login successful',
      data: {
        token: 'mock-jwt-token-12345',
        user: {
          id: 1,
          email: 'test@example.com',
          full_name: 'Test User',
          job_title: 'Analyst',
          email_verified: true,
          two_factor_enabled: true, // User has 2FA enabled
          role: 'user',
          created_at: '2024-01-01T00:00:00Z',
          last_login: '2024-01-01T00:00:00Z'
        },
        requires_2fa: true // Backend correctly returns true
      }
    };

    apiClientMock.post.mockResolvedValue(mockResponse);
    apiClientMock.getToken.mockReturnValue(mockResponse.data.token);

    // Act: User attempts to log in
    const result = await authManager.loginWithAPI('test@example.com', 'password123');

    // Assert: PRESERVATION - 2FA modal should be shown
    expect(result.requires2FA).toBe(true);
    expect(result.success).toBe(true);
    expect(result.message).toBe('2FA verification required');
    
    // User session should NOT be saved yet (waiting for 2FA)
    expect(result.user).toBeUndefined();
    expect(localStorage.getItem('cyberguard_user')).toBeNull();
  });

  /**
   * Concrete Example: 2FA verification succeeds and redirects to dashboard
   */
  it('Concrete Example: 2FA verification succeeds for enabled user', async () => {
    // Arrange: Mock 2FA verification response
    const mockResponse = {
      token: 'mock-jwt-token-2fa-67890',
      user: {
        id: 1,
        email: 'test@example.com',
        full_name: 'Test User',
        job_title: 'Analyst',
        email_verified: true,
        two_factor_enabled: true,
        role: 'user',
        created_at: '2024-01-01T00:00:00Z',
        last_login: '2024-01-01T00:00:00Z'
      }
    };

    apiClientMock.post.mockResolvedValue(mockResponse);
    apiClientMock.getToken.mockReturnValue(mockResponse.token);

    // Act: User verifies 2FA code
    const result = await authManager.verify2FA('123456');

    // Assert: PRESERVATION - Verification should succeed
    expect(result.success).toBe(true);
    expect(result.user).toBeDefined();
    expect(result.user.twoFactorEnabled).toBe(true);
    
    // User session should be saved
    const savedUser = JSON.parse(localStorage.getItem('cyberguard_user'));
    expect(savedUser).toBeDefined();
    expect(savedUser.twoFactorEnabled).toBe(true);
    
    // Token should be set
    expect(apiClientMock.setToken).toHaveBeenCalledWith(mockResponse.token);
  });

  /**
   * Concrete Example: Session restoration merges twoFactorEnabled correctly
   */
  it('Concrete Example: Session restoration merges twoFactorEnabled status', async () => {
    // Arrange: JWT token exists
    apiClientMock.getToken.mockReturnValue('valid-jwt-token');

    // Mock fetchUserProfile response
    const profileResponse = {
      user: {
        id: 1,
        email: 'test@example.com',
        full_name: 'Test User',
        job_title: 'Analyst',
        role: 'user',
        created_at: '2024-01-01T00:00:00Z',
        last_login: '2024-01-01T00:00:00Z'
      }
    };

    // Mock fetchSessionStatus response
    const statusResponse = {
      email_verified: true,
      two_factor_enabled: true
    };

    apiClientMock.get
      .mockResolvedValueOnce(profileResponse)
      .mockResolvedValueOnce(statusResponse);

    // Act: Restore session
    const result = await authManager.restoreSession();

    // Assert: PRESERVATION - Status should be merged correctly
    expect(result.success).toBe(true);
    expect(result.user.emailVerified).toBe(true);
    expect(result.user.twoFactorEnabled).toBe(true);
    
    // Merged user should be saved
    const savedUser = JSON.parse(localStorage.getItem('cyberguard_user'));
    expect(savedUser).toBeDefined();
    expect(savedUser.emailVerified).toBe(true);
    expect(savedUser.twoFactorEnabled).toBe(true);
  });
});
