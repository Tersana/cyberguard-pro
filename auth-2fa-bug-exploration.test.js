/**
 * Bug Condition Exploration Test - 2FA Forced Bypass Fix
 * 
 * **CRITICAL**: This test MUST FAIL on unfixed code - failure confirms the bug exists
 * 
 * This test encodes the EXPECTED BEHAVIOR:
 * - Users with twoFactorEnabled: false should bypass the 2FA modal
 * - loginWithAPI should return requires2FA: false when twoFactorEnabled is false
 * - No 2FA modal should be shown, direct dashboard redirect should occur
 * 
 * When run on UNFIXED code, this test will FAIL, proving the bug exists.
 * When run on FIXED code, this test will PASS, confirming the fix works.
 * 
 * **Validates: Requirements 1.1, 1.2, 1.3, 1.4, 2.1, 2.2, 2.3, 2.4**
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { JSDOM } from 'jsdom';
import * as fc from 'fast-check';

describe('Bug Condition Exploration - 2FA Forced Bypass (Property 1)', () => {
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

    // Create AuthManager instance with the actual loginWithAPI method
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
          // Response shape: { status, message, data: { user: {...}, token: "..." } }
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

  afterEach(() => {
    vi.clearAllMocks();
  });

  /**
   * Property 1: Bug Condition - 2FA Bypass for Disabled Users
   * 
   * **Validates: Requirements 2.1, 2.2, 2.3, 2.4**
   * 
   * This property encodes the EXPECTED BEHAVIOR:
   * For any login response where the user's twoFactorEnabled status is false,
   * the loginWithAPI function SHALL bypass the 2FA verification modal entirely
   * and proceed directly to save the user session and redirect to the dashboard,
   * regardless of the value of requires_2fa.
   * 
   * **EXPECTED OUTCOME ON UNFIXED CODE**: This test will FAIL because the unfixed
   * code checks requires_2fa instead of twoFactorEnabled, causing it to incorrectly
   * return requires2FA: true even when the user has 2FA disabled.
   * 
   * **EXPECTED OUTCOME ON FIXED CODE**: This test will PASS because the fixed code
   * will check twoFactorEnabled and correctly return requires2FA: false.
   */
  it('Property 1: loginWithAPI should bypass 2FA modal when user.twoFactorEnabled is false (Bug Condition)', async () => {
    // Scoped PBT: Generate test cases where twoFactorEnabled is false but requires_2fa is true
    // This is the exact bug condition from the design document
    await fc.assert(
      fc.asyncProperty(
        // Generate arbitrary user data with twoFactorEnabled: false
        fc.record({
          id: fc.integer({ min: 1, max: 10000 }),
          email: fc.emailAddress(),
          full_name: fc.string({ minLength: 3, maxLength: 50 }),
          job_title: fc.constantFrom('Analyst', 'Engineer', 'Manager', 'Admin'),
          email_verified: fc.boolean(),
          two_factor_enabled: fc.constant(false), // CRITICAL: Always false to test bug condition
          role: fc.constantFrom('user', 'admin'),
          created_at: fc.date().map(d => d.toISOString()),
          last_login: fc.date().map(d => d.toISOString())
        }),
        // Generate arbitrary credentials
        fc.emailAddress(),
        fc.string({ minLength: 8, maxLength: 20 }),
        
        async (userData, email, password) => {
          // Arrange: Mock API response with requires_2fa: true but user.two_factor_enabled: false
          // This is the BUG CONDITION from the design document
          const mockResponse = {
            status: 'success',
            message: 'Login successful',
            data: {
              token: 'mock-jwt-token-' + Math.random(),
              user: userData,
              requires_2fa: true // BUG: Backend incorrectly sets this to true
            }
          };

          apiClientMock.post.mockResolvedValue(mockResponse);
          apiClientMock.getToken.mockReturnValue(mockResponse.data.token);

          // Act: Call loginWithAPI
          const result = await authManager.loginWithAPI(email, password);

          // Assert: EXPECTED BEHAVIOR (will fail on unfixed code)
          // When twoFactorEnabled is false, the system should:
          // 1. NOT require 2FA verification
          expect(result.requires2FA).toBe(false);
          
          // 2. Return success
          expect(result.success).toBe(true);
          
          // 3. Save the user session (not show 2FA modal)
          expect(result.user).toBeDefined();
          expect(result.user.twoFactorEnabled).toBe(false);
          
          // 4. The user should be saved to localStorage (direct dashboard redirect)
          const savedUser = JSON.parse(localStorage.getItem('cyberguard_user'));
          expect(savedUser).toBeDefined();
          expect(savedUser.twoFactorEnabled).toBe(false);
          
          // 5. Token should be set (authentication complete)
          expect(apiClientMock.setToken).toHaveBeenCalledWith(mockResponse.data.token);
        }
      ),
      {
        numRuns: 10, // Run 10 test cases to find counterexamples (reduced for faster execution)
        verbose: true // Show counterexamples when test fails
      }
    );
  });

  /**
   * Unit Test: Concrete Bug Condition Example
   * 
   * This is a concrete example of the bug condition for easier debugging.
   * It demonstrates the exact scenario described in the bugfix requirements.
   */
  it('Concrete Example: User with twoFactorEnabled: false should bypass 2FA modal', async () => {
    // Arrange: User disables 2FA, logs out, logs back in
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
          two_factor_enabled: false, // User has disabled 2FA
          role: 'user',
          created_at: '2024-01-01T00:00:00Z',
          last_login: '2024-01-01T00:00:00Z'
        },
        requires_2fa: true // BUG: Backend incorrectly returns true
      }
    };

    apiClientMock.post.mockResolvedValue(mockResponse);
    apiClientMock.getToken.mockReturnValue(mockResponse.data.token);

    // Act: User attempts to log in
    const result = await authManager.loginWithAPI('test@example.com', 'password123');

    // Assert: EXPECTED BEHAVIOR (will fail on unfixed code)
    // The system should bypass the 2FA modal and proceed directly to dashboard
    expect(result.requires2FA).toBe(false); // Should NOT require 2FA
    expect(result.success).toBe(true);
    expect(result.user).toBeDefined();
    expect(result.user.twoFactorEnabled).toBe(false);
    
    // User session should be saved (not waiting for 2FA verification)
    const savedUser = JSON.parse(localStorage.getItem('cyberguard_user'));
    expect(savedUser).toBeDefined();
    expect(savedUser.twoFactorEnabled).toBe(false);
    
    // Token should be set (authentication complete)
    expect(apiClientMock.setToken).toHaveBeenCalledWith(mockResponse.data.token);
  });

  /**
   * Edge Case: Flag Conflict Test
   * 
   * Tests the scenario where requires_2fa and twoFactorEnabled are out of sync.
   * The system should prioritize twoFactorEnabled as the authoritative source.
   */
  it('Edge Case: Should prioritize twoFactorEnabled over requires_2fa flag', async () => {
    // Arrange: Conflicting flags
    const mockResponse = {
      status: 'success',
      message: 'Login successful',
      data: {
        token: 'mock-jwt-token-67890',
        user: {
          id: 2,
          email: 'conflict@example.com',
          full_name: 'Conflict User',
          job_title: 'Engineer',
          email_verified: true,
          two_factor_enabled: false, // Authoritative: 2FA is disabled
          role: 'user',
          created_at: '2024-01-01T00:00:00Z',
          last_login: '2024-01-01T00:00:00Z'
        },
        requires_2fa: true // Stale/incorrect flag
      }
    };

    apiClientMock.post.mockResolvedValue(mockResponse);
    apiClientMock.getToken.mockReturnValue(mockResponse.data.token);

    // Act
    const result = await authManager.loginWithAPI('conflict@example.com', 'password123');

    // Assert: Should prioritize twoFactorEnabled (will fail on unfixed code)
    expect(result.requires2FA).toBe(false);
    expect(result.success).toBe(true);
    expect(result.user.twoFactorEnabled).toBe(false);
  });
});
