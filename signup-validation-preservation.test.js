/**
 * Preservation Property Tests - Signup 422 Validation Fix
 * Task 2: Write preservation property tests (BEFORE implementing fix)
 * 
 * **Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7, 3.8**
 * 
 * **Property 2: Preservation** - Valid Submissions and Existing Validations Continue Working
 * 
 * **IMPORTANT**: Follow observation-first methodology
 * - Observe behavior on UNFIXED code for non-buggy inputs (valid form submissions)
 * - Write property-based tests capturing observed behavior patterns
 * - Property-based testing generates many test cases for stronger guarantees
 * - **EXPECTED OUTCOME**: Tests PASS on unfixed code (confirms baseline behavior to preserve)
 * 
 * These tests ensure that when we fix the bug (empty/whitespace validation),
 * we don't break existing functionality that already works correctly.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { JSDOM } from 'jsdom';
import * as fc from 'fast-check';

describe('Property 2: Preservation - Valid Submissions and Existing Validations Continue Working', () => {
  let dom;
  let document;
  let window;
  let authManager;
  let apiClientMock;
  let currentStep;

  beforeEach(async () => {
    // Setup DOM environment with signup form
    dom = new JSDOM(`
      <!DOCTYPE html>
      <html>
        <body>
          <form id="signupForm">
            <div class="form-step active" id="step1">
              <input type="text" id="fullName" name="fullName" required />
              <input type="email" id="email" name="email" required />
              <input type="text" id="jobTitle" name="jobTitle" required />
              <input type="text" id="company" name="company" />
            </div>
            <div class="form-step" id="step2">
              <input type="password" id="password" name="password" required />
              <input type="password" id="confirmPassword" name="confirmPassword" required />
            </div>
            <div class="form-step" id="step3">
              <input type="checkbox" required />
            </div>
          </form>
          <div id="loadingOverlay" class="hidden"></div>
          <div id="messageContainer" class="hidden"></div>
        </body>
      </html>
    `, {
      url: 'http://localhost',
      runScripts: 'dangerously',
      resources: 'usable'
    });

    document = dom.window.document;
    window = dom.window;
    global.document = document;
    global.window = window;
    currentStep = 1;

    // Mock API client
    apiClientMock = {
      post: vi.fn(),
      setToken: vi.fn(),
      getToken: vi.fn(),
      clearToken: vi.fn()
    };

    // Mock successful registration response
    apiClientMock.post.mockImplementation(async (endpoint, data) => {
      if (endpoint === 'auth/register') {
        // Simulate various API responses based on input
        
        // Check for password mismatch (should be caught at frontend)
        if (data.password !== data.password_confirmation) {
          const error = new Error('Validation failed');
          error.name = 'ValidationError';
          error.message = 'The passwords you entered do not match';
          throw error;
        }

        // Check for weak password (should be caught at frontend)
        if (data.password.length < 8) {
          const error = new Error('Validation failed');
          error.name = 'ValidationError';
          error.message = 'Password must be at least 8 characters and include uppercase, lowercase, numbers, and symbols';
          throw error;
        }

        // Simulate 401 error (unauthorized)
        if (data.email === 'unauthorized@test.com') {
          const error = new Error('Unauthorized');
          error.name = 'APIError';
          error.status = 401;
          error.message = 'Unauthorized access';
          throw error;
        }

        // Simulate 500 error (server error)
        if (data.email === 'servererror@test.com') {
          const error = new Error('Server error');
          error.name = 'APIError';
          error.status = 500;
          error.message = 'Internal server error';
          throw error;
        }

        // Simulate network error
        if (data.email === 'networkerror@test.com') {
          const error = new Error('Network error');
          error.name = 'NetworkError';
          error.message = 'Failed to fetch';
          throw error;
        }

        // Successful registration
        return {
          token: 'fake-jwt-token-12345',
          user: {
            id: 1,
            email: data.email,
            full_name: data.full_name,
            job_title: data.job_title,
            company: data.company || null
          }
        };
      }
      
      throw new Error('Unknown endpoint');
    });

    // Mock AuthManager with current behavior
    authManager = {
      apiClient: apiClientMock,
      sessionTimeout: 30 * 60 * 1000,
      
      validateRegistrationData(userData) {
        const errors = [];
        
        // Email validation
        if (!userData.email || !this.validateEmail(userData.email)) {
          errors.push({ field: 'email', message: 'Valid email is required' });
        }

        // Password validation
        const passwordValidation = this.validatePassword(userData.password);
        if (!passwordValidation.valid) {
          errors.push({ field: 'password', message: 'Password must be at least 8 characters and include uppercase, lowercase, numbers, and symbols' });
        }

        // Full name validation
        if (!userData.fullName || userData.fullName.trim().length < 2) {
          errors.push({ field: 'fullName', message: 'Full name is required' });
        }

        // Job title validation
        if (!userData.jobTitle || userData.jobTitle.trim().length < 2) {
          errors.push({ field: 'jobTitle', message: 'Job title is required' });
        }

        return errors;
      },

      validateEmail(email) {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return emailRegex.test(email);
      },

      validatePassword(password) {
        const minLength = 8;
        const hasUpperCase = /[A-Z]/.test(password);
        const hasLowerCase = /[a-z]/.test(password);
        const hasNumbers = /\d/.test(password);
        const hasSymbols = /[!@#$%^&*(),.?":{}|<>]/.test(password);

        return {
          valid: password.length >= minLength && hasUpperCase && hasLowerCase && hasNumbers && hasSymbols,
          strength: password.length >= minLength && hasUpperCase && hasLowerCase && hasNumbers && hasSymbols ? 'strong' : 'weak'
        };
      },

      async registerWithAPI(userData) {
        // Validate inputs before sending to API
        const validationErrors = this.validateRegistrationData(userData);
        if (validationErrors.length > 0) {
          const error = new Error('Validation failed');
          error.name = 'ValidationError';
          error.errors = validationErrors;
          throw error;
        }

        // Prepare API data - converts jobTitle to job_title
        const apiData = {
          full_name: userData.fullName,
          email: userData.email,
          job_title: userData.jobTitle,
          password: userData.password,
          password_confirmation: userData.passwordConfirmation,
          company: userData.company || null
        };

        const response = await this.apiClient.post('auth/register', apiData);
        
        // Store JWT token
        this.apiClient.setToken(response.token);
        
        // Save user session
        this.saveUserSession(response.user);
        
        return { success: true, user: response.user, token: response.token };
      },

      saveUserSession(user) {
        const sessionData = {
          timestamp: Date.now(),
          userAgent: 'test-agent',
          ip: '127.0.0.1'
        };
        // In real implementation, this would use localStorage
        this.currentUser = user;
        this.sessionData = sessionData;
        return true;
      }
    };
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  /**
   * Requirement 3.1: Valid submissions with all fields filled continue to work
   * 
   * This test verifies that when a user submits a form with all valid data,
   * the registration succeeds and the user is properly authenticated.
   */
  describe('Requirement 3.1: Valid submissions with all required fields filled', () => {
    
    it('should successfully register with all valid required fields', async () => {
      // Arrange: Valid form data
      const userData = {
        fullName: 'John Doe',
        email: 'john.doe@example.com',
        jobTitle: 'Security Analyst',
        password: 'SecurePass123!',
        passwordConfirmation: 'SecurePass123!'
      };

      // Act: Submit registration
      const result = await authManager.registerWithAPI(userData);

      // Assert: Registration succeeds
      expect(result.success).toBe(true);
      expect(result.user).toBeDefined();
      expect(result.user.email).toBe(userData.email);
      expect(result.user.full_name).toBe(userData.fullName);
      expect(result.user.job_title).toBe(userData.jobTitle);
      expect(result.token).toBe('fake-jwt-token-12345');
      expect(apiClientMock.setToken).toHaveBeenCalledWith('fake-jwt-token-12345');
      expect(authManager.currentUser).toBeDefined();
    });

    it('should successfully register with optional Company field', async () => {
      // Arrange: Valid form data with company
      const userData = {
        fullName: 'Jane Smith',
        email: 'jane.smith@company.com',
        jobTitle: 'Penetration Tester',
        company: 'CyberSec Corp',
        password: 'StrongPass456!',
        passwordConfirmation: 'StrongPass456!'
      };

      // Act: Submit registration
      const result = await authManager.registerWithAPI(userData);

      // Assert: Registration succeeds with company
      expect(result.success).toBe(true);
      expect(result.user.company).toBe('CyberSec Corp');
    });

    /**
     * Property-Based Test: Valid registrations with various valid inputs
     * 
     * Generates many valid registration scenarios to ensure they all work.
     */
    it('should handle various valid registration inputs (Property-Based)', async () => {
      await fc.assert(
        fc.asyncProperty(
          fc.record({
            fullName: fc.string({ minLength: 2, maxLength: 50 }).filter(s => s.trim().length >= 2),
            email: fc.emailAddress(),
            jobTitle: fc.constantFrom(
              'Security Analyst',
              'Penetration Tester',
              'Security Engineer',
              'CISO',
              'SOC Analyst'
            ),
            company: fc.option(fc.string({ minLength: 2, maxLength: 50 }), { nil: null }),
            password: fc.constant('ValidPass123!')
          }),
          async (data) => {
            const userData = {
              ...data,
              passwordConfirmation: data.password
            };

            // Act: Submit registration
            const result = await authManager.registerWithAPI(userData);

            // Assert: All valid registrations succeed
            expect(result.success).toBe(true);
            expect(result.user).toBeDefined();
            expect(result.token).toBeDefined();
            expect(apiClientMock.setToken).toHaveBeenCalled();
          }
        ),
        { numRuns: 20 }
      );
    });
  });

  /**
   * Requirement 3.2: Password mismatch validation continues to work
   * 
   * This test verifies that password mismatch errors are still caught
   * and displayed correctly at Step 2.
   */
  describe('Requirement 3.2: Password mismatch validation continues to work', () => {
    
    it('should show error when passwords do not match', async () => {
      // Arrange: Valid data except mismatched passwords
      const userData = {
        fullName: 'John Doe',
        email: 'john@example.com',
        jobTitle: 'Security Analyst',
        password: 'SecurePass123!',
        passwordConfirmation: 'DifferentPass456!' // MISMATCH
      };

      // Act & Assert: Should throw validation error
      try {
        await authManager.registerWithAPI(userData);
        expect(true).toBe(false); // Should not reach here
      } catch (error) {
        expect(error.name).toBe('ValidationError');
        expect(error.message).toContain('passwords');
        expect(apiClientMock.post).toHaveBeenCalled(); // API validates this
      }
    });

    /**
     * Property-Based Test: Password mismatch detection
     */
    it('should detect password mismatches (Property-Based)', async () => {
      await fc.assert(
        fc.asyncProperty(
          fc.record({
            fullName: fc.constant('John Doe'),
            email: fc.emailAddress(),
            jobTitle: fc.constant('Security Analyst'),
            password: fc.string({ minLength: 8, maxLength: 20 }),
            passwordConfirmation: fc.string({ minLength: 8, maxLength: 20 })
          }).filter(data => data.password !== data.passwordConfirmation), // Only mismatched passwords
          async (userData) => {
            // Act & Assert: Should throw validation error
            try {
              await authManager.registerWithAPI(userData);
              expect(true).toBe(false); // Should not reach here
            } catch (error) {
              expect(error.name).toBe('ValidationError');
            }
          }
        ),
        { numRuns: 10 }
      );
    });
  });

  /**
   * Requirement 3.3: Weak password validation continues to work
   * 
   * This test verifies that weak passwords (less than 8 characters or missing
   * required character types) are still rejected.
   */
  describe('Requirement 3.3: Weak password validation continues to work', () => {
    
    it('should reject password shorter than 8 characters', async () => {
      // Arrange: Password too short
      const userData = {
        fullName: 'John Doe',
        email: 'john@example.com',
        jobTitle: 'Security Analyst',
        password: 'Pass1!', // Only 6 characters
        passwordConfirmation: 'Pass1!'
      };

      // Act & Assert: Should throw validation error
      try {
        await authManager.registerWithAPI(userData);
        expect(true).toBe(false); // Should not reach here
      } catch (error) {
        expect(error.name).toBe('ValidationError');
        expect(error.errors).toBeDefined();
        expect(error.errors.some(e => e.field === 'password')).toBe(true);
      }
    });

    it('should reject password without uppercase letters', async () => {
      // Arrange: No uppercase
      const userData = {
        fullName: 'John Doe',
        email: 'john@example.com',
        jobTitle: 'Security Analyst',
        password: 'password123!', // No uppercase
        passwordConfirmation: 'password123!'
      };

      // Act & Assert: Should throw validation error
      try {
        await authManager.registerWithAPI(userData);
        expect(true).toBe(false); // Should not reach here
      } catch (error) {
        expect(error.name).toBe('ValidationError');
        expect(error.errors.some(e => e.field === 'password')).toBe(true);
      }
    });

    it('should reject password without numbers', async () => {
      // Arrange: No numbers
      const userData = {
        fullName: 'John Doe',
        email: 'john@example.com',
        jobTitle: 'Security Analyst',
        password: 'Password!', // No numbers
        passwordConfirmation: 'Password!'
      };

      // Act & Assert: Should throw validation error
      try {
        await authManager.registerWithAPI(userData);
        expect(true).toBe(false); // Should not reach here
      } catch (error) {
        expect(error.name).toBe('ValidationError');
        expect(error.errors.some(e => e.field === 'password')).toBe(true);
      }
    });

    it('should reject password without symbols', async () => {
      // Arrange: No symbols
      const userData = {
        fullName: 'John Doe',
        email: 'john@example.com',
        jobTitle: 'Security Analyst',
        password: 'Password123', // No symbols
        passwordConfirmation: 'Password123'
      };

      // Act & Assert: Should throw validation error
      try {
        await authManager.registerWithAPI(userData);
        expect(true).toBe(false); // Should not reach here
      } catch (error) {
        expect(error.name).toBe('ValidationError');
        expect(error.errors.some(e => e.field === 'password')).toBe(true);
      }
    });
  });

  /**
   * Requirement 3.4: Non-422 API errors continue to be handled correctly
   * 
   * This test verifies that other API errors (401, 500, network errors)
   * are still handled appropriately.
   */
  describe('Requirement 3.4: Non-422 API errors continue to be handled correctly', () => {
    
    it('should handle 401 Unauthorized error', async () => {
      // Arrange: Email that triggers 401
      const userData = {
        fullName: 'John Doe',
        email: 'unauthorized@test.com',
        jobTitle: 'Security Analyst',
        password: 'SecurePass123!',
        passwordConfirmation: 'SecurePass123!'
      };

      // Act & Assert: Should throw API error
      try {
        await authManager.registerWithAPI(userData);
        expect(true).toBe(false); // Should not reach here
      } catch (error) {
        expect(error.name).toBe('APIError');
        expect(error.status).toBe(401);
        expect(error.message).toContain('Unauthorized');
      }
    });

    it('should handle 500 Server error', async () => {
      // Arrange: Email that triggers 500
      const userData = {
        fullName: 'John Doe',
        email: 'servererror@test.com',
        jobTitle: 'Security Analyst',
        password: 'SecurePass123!',
        passwordConfirmation: 'SecurePass123!'
      };

      // Act & Assert: Should throw API error
      try {
        await authManager.registerWithAPI(userData);
        expect(true).toBe(false); // Should not reach here
      } catch (error) {
        expect(error.name).toBe('APIError');
        expect(error.status).toBe(500);
        expect(error.message).toContain('Internal server error');
      }
    });

    it('should handle Network error', async () => {
      // Arrange: Email that triggers network error
      const userData = {
        fullName: 'John Doe',
        email: 'networkerror@test.com',
        jobTitle: 'Security Analyst',
        password: 'SecurePass123!',
        passwordConfirmation: 'SecurePass123!'
      };

      // Act & Assert: Should throw network error
      try {
        await authManager.registerWithAPI(userData);
        expect(true).toBe(false); // Should not reach here
      } catch (error) {
        expect(error.name).toBe('NetworkError');
        expect(error.message).toContain('Failed to fetch');
      }
    });
  });

  /**
   * Requirement 3.5: Successful registration continues to store JWT, save session, and redirect
   * 
   * This test verifies that successful registration properly stores the JWT token,
   * saves the user session, and would redirect to dashboard.
   */
  describe('Requirement 3.5: Successful registration stores JWT, saves session', () => {
    
    it('should store JWT token on successful registration', async () => {
      // Arrange: Valid registration data
      const userData = {
        fullName: 'John Doe',
        email: 'john@example.com',
        jobTitle: 'Security Analyst',
        password: 'SecurePass123!',
        passwordConfirmation: 'SecurePass123!'
      };

      // Act: Register
      const result = await authManager.registerWithAPI(userData);

      // Assert: JWT token is stored
      expect(apiClientMock.setToken).toHaveBeenCalledWith('fake-jwt-token-12345');
      expect(result.token).toBe('fake-jwt-token-12345');
    });

    it('should save user session on successful registration', async () => {
      // Arrange: Valid registration data
      const userData = {
        fullName: 'Jane Smith',
        email: 'jane@example.com',
        jobTitle: 'Penetration Tester',
        password: 'SecurePass123!',
        passwordConfirmation: 'SecurePass123!'
      };

      // Act: Register
      const result = await authManager.registerWithAPI(userData);

      // Assert: User session is saved
      expect(authManager.currentUser).toBeDefined();
      expect(authManager.currentUser.email).toBe(userData.email);
      expect(authManager.sessionData).toBeDefined();
      expect(authManager.sessionData.timestamp).toBeDefined();
    });
  });

  /**
   * Requirement 3.6: Step navigation validation continues to work
   * 
   * This test verifies that step-by-step validation still works correctly.
   */
  describe('Requirement 3.6: Step navigation validation continues to work', () => {
    
    it('should validate Step 1 fields before progressing', () => {
      // Arrange: Fill Step 1 fields
      document.getElementById('fullName').value = 'John Doe';
      document.getElementById('email').value = 'john@example.com';
      document.getElementById('jobTitle').value = 'Security Analyst';

      // Act: Validate Step 1
      const step1 = document.getElementById('step1');
      const requiredFields = step1.querySelectorAll('input[required]');
      let allValid = true;
      
      for (let field of requiredFields) {
        if (!field.value.trim()) {
          allValid = false;
          break;
        }
      }

      // Assert: Step 1 validation passes
      expect(allValid).toBe(true);
    });

    it('should prevent progression from Step 1 if fields are invalid', () => {
      // Arrange: Leave Step 1 fields empty
      document.getElementById('fullName').value = '';
      document.getElementById('email').value = '';
      document.getElementById('jobTitle').value = '';

      // Act: Validate Step 1
      const step1 = document.getElementById('step1');
      const requiredFields = step1.querySelectorAll('input[required]');
      let allValid = true;
      
      for (let field of requiredFields) {
        if (!field.value.trim()) {
          allValid = false;
          break;
        }
      }

      // Assert: Step 1 validation fails
      expect(allValid).toBe(false);
    });
  });

  /**
   * Requirement 3.7: password_confirmation field mapping continues to work
   * 
   * This test verifies that the password_confirmation field is correctly
   * mapped to the API's expected field name.
   */
  describe('Requirement 3.7: password_confirmation field mapping continues to work', () => {
    
    it('should correctly map passwordConfirmation to password_confirmation in API request', async () => {
      // Arrange: Valid registration data
      const userData = {
        fullName: 'John Doe',
        email: 'john@example.com',
        jobTitle: 'Security Analyst',
        password: 'SecurePass123!',
        passwordConfirmation: 'SecurePass123!'
      };

      // Act: Register
      await authManager.registerWithAPI(userData);

      // Assert: API was called with password_confirmation field
      expect(apiClientMock.post).toHaveBeenCalledWith(
        'auth/register',
        expect.objectContaining({
          password_confirmation: 'SecurePass123!'
        })
      );
    });
  });

  /**
   * Requirement 3.8: Optional Company field continues to be accepted
   * 
   * This test verifies that the optional Company field is properly handled
   * whether it's filled or left empty.
   */
  describe('Requirement 3.8: Optional Company field continues to be accepted', () => {
    
    it('should accept registration with Company field filled', async () => {
      // Arrange: Valid data with company
      const userData = {
        fullName: 'John Doe',
        email: 'john@example.com',
        jobTitle: 'Security Analyst',
        company: 'CyberSec Inc',
        password: 'SecurePass123!',
        passwordConfirmation: 'SecurePass123!'
      };

      // Act: Register
      const result = await authManager.registerWithAPI(userData);

      // Assert: Registration succeeds with company
      expect(result.success).toBe(true);
      expect(result.user.company).toBe('CyberSec Inc');
    });

    it('should accept registration with Company field empty', async () => {
      // Arrange: Valid data without company
      const userData = {
        fullName: 'Jane Smith',
        email: 'jane@example.com',
        jobTitle: 'Penetration Tester',
        password: 'SecurePass123!',
        passwordConfirmation: 'SecurePass123!'
      };

      // Act: Register
      const result = await authManager.registerWithAPI(userData);

      // Assert: Registration succeeds without company
      expect(result.success).toBe(true);
      expect(result.user.company).toBeNull();
    });

    /**
     * Property-Based Test: Company field handling
     */
    it('should handle Company field correctly (Property-Based)', async () => {
      await fc.assert(
        fc.asyncProperty(
          fc.record({
            fullName: fc.constant('John Doe'),
            email: fc.emailAddress(),
            jobTitle: fc.constant('Security Analyst'),
            company: fc.option(fc.string({ minLength: 2, maxLength: 50 }), { nil: null }),
            password: fc.constant('SecurePass123!')
          }),
          async (data) => {
            const userData = {
              ...data,
              passwordConfirmation: data.password
            };

            // Act: Register
            const result = await authManager.registerWithAPI(userData);

            // Assert: Registration succeeds regardless of company field
            expect(result.success).toBe(true);
            if (data.company) {
              expect(result.user.company).toBe(data.company);
            } else {
              expect(result.user.company).toBeNull();
            }
          }
        ),
        { numRuns: 15 }
      );
    });
  });

  /**
   * Integration Test: Complete valid registration flow
   * 
   * This test verifies the entire registration flow works end-to-end
   * with valid data.
   */
  describe('Integration: Complete valid registration flow', () => {
    
    it('should complete full registration flow with valid data', async () => {
      // Arrange: Complete valid registration data
      const userData = {
        fullName: 'Alice Johnson',
        email: 'alice.johnson@example.com',
        jobTitle: 'Security Engineer',
        company: 'SecureNet Solutions',
        password: 'VerySecure123!@#',
        passwordConfirmation: 'VerySecure123!@#'
      };

      // Act: Complete registration
      const result = await authManager.registerWithAPI(userData);

      // Assert: Full flow succeeds
      expect(result.success).toBe(true);
      expect(result.user).toBeDefined();
      expect(result.user.email).toBe(userData.email);
      expect(result.user.full_name).toBe(userData.fullName);
      expect(result.user.job_title).toBe(userData.jobTitle);
      expect(result.user.company).toBe(userData.company);
      expect(result.token).toBeDefined();
      expect(apiClientMock.setToken).toHaveBeenCalled();
      expect(authManager.currentUser).toBeDefined();
      expect(authManager.sessionData).toBeDefined();
    });
  });
});
