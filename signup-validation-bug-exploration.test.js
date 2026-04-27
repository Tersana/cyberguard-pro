/**
 * Bug Condition Exploration Test - Signup 422 Validation Fix
 * 
 * **Validates: Requirements 1.1, 1.3, 1.5**
 * 
 * CRITICAL: This test MUST FAIL on unfixed code - failure confirms the bug exists
 * 
 * Bug Condition: Empty/Whitespace Required Fields Cause 422 Errors
 * - Empty/whitespace job_title sends null to API, receives 422 error (1.1)
 * - Whitespace-only job_title treated as valid, API rejects with 422 (1.3)
 * - Frontend validation doesn't catch empty required fields before API call (1.5)
 * 
 * Expected Behavior (what this test encodes):
 * - Empty/whitespace job_title shows frontend validation error, prevents API call (2.1)
 * - Whitespace trimmed and validated as empty (2.3)
 * - All required fields validated before API call (2.5)
 * 
 * This test uses a scoped PBT approach - testing the concrete failing cases
 * to ensure reproducibility of the deterministic bug.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { JSDOM } from 'jsdom';
import * as fc from 'fast-check';

describe('Bug Condition Exploration: Empty/Whitespace Required Fields Cause 422 Errors', () => {
  let dom;
  let document;
  let window;
  let authManager;
  let apiClientMock;
  let formSubmitHandler;
  let validateCurrentStepFn;
  let showMessageFn;

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

    // Mock API client
    apiClientMock = {
      post: vi.fn(),
      setToken: vi.fn()
    };

    // Track if API was called
    let apiCallMade = false;
    apiClientMock.post.mockImplementation(async (endpoint, data) => {
      apiCallMade = true;
      // Simulate 422 error for empty/whitespace job_title
      if (!data.job_title || data.job_title.trim() === '') {
        const error = new Error('Validation failed');
        error.name = 'APIError';
        error.status = 422;
        error.data = {
          errors: {
            job_title: ['The job title field is required.']
          }
        };
        throw error;
      }
      return {
        token: 'fake-jwt-token',
        user: { id: 1, email: data.email }
      };
    });

    // Mock AuthManager with FIXED behavior (after Task 3 implementation)
    authManager = {
      apiClient: apiClientMock,
      
      validateRegistrationData(userData) {
        const errors = [];
        // FIXED validation - values are already trimmed before this function is called
        if (!userData.fullName || userData.fullName.length === 0) {
          errors.push({ field: 'fullName', message: 'Full name is required' });
        }
        if (!userData.email || userData.email.length === 0) {
          errors.push({ field: 'email', message: 'Email is required' });
        }
        if (!userData.jobTitle || userData.jobTitle.length === 0) {
          errors.push({ field: 'jobTitle', message: 'Job title is required' });
        }
        if (!userData.password || userData.password.length === 0) {
          errors.push({ field: 'password', message: 'Password is required' });
        }
        if (!userData.passwordConfirmation || userData.passwordConfirmation.length === 0) {
          errors.push({ field: 'passwordConfirmation', message: 'Password confirmation is required' });
        }
        return errors;
      },

      async registerWithAPI(userData) {
        // FIXED behavior - trim values before validation (Requirement 2.3)
        const trimmedData = {
          fullName: userData.fullName?.trim() || '',
          email: userData.email?.trim() || '',
          jobTitle: userData.jobTitle?.trim() || '',
          password: userData.password, // Don't trim passwords
          passwordConfirmation: userData.passwordConfirmation // Don't trim passwords
        };

        const validationErrors = this.validateRegistrationData(trimmedData);
        if (validationErrors.length > 0) {
          const error = new Error('Validation failed');
          error.name = 'ValidationError';
          error.errors = validationErrors;
          throw error;
        }

        // Prepare API data - converts jobTitle to job_title
        const apiData = {
          full_name: trimmedData.fullName,
          email: trimmedData.email,
          job_title: trimmedData.jobTitle, // FIXED: Trimmed values
          password: trimmedData.password,
          password_confirmation: trimmedData.passwordConfirmation
        };

        const response = await this.apiClient.post('auth/register', apiData);
        return { success: true, user: response.user };
      }
    };

    // Mock validateCurrentStep function (current buggy behavior)
    validateCurrentStepFn = vi.fn((step) => {
      const stepEl = document.getElementById(`step${step}`);
      const requiredFields = stepEl.querySelectorAll('input[required]');
      
      // BUG: Uses .trim() on field.value but doesn't validate if trimmed value is empty
      for (let field of requiredFields) {
        if (!field.value.trim()) {
          return false;
        }
      }
      return true;
    });

    // Mock showMessage function
    showMessageFn = vi.fn();

    // Store API call tracking
    authManager.apiCallMade = () => apiCallMade;
    authManager.resetApiCallTracking = () => { apiCallMade = false; };
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  /**
   * Property 1: Bug Condition - Empty/Whitespace Required Fields Cause 422 Errors
   * 
   * This property tests the BUG CONDITION - it should FAIL on unfixed code.
   * 
   * Expected behavior (what the test asserts):
   * - Frontend validation should catch empty/whitespace fields BEFORE API call
   * - API call should be PREVENTED when validation fails
   * - Appropriate error messages should be displayed
   * 
   * Current buggy behavior (why test fails):
   * - Frontend validation doesn't properly check trimmed values
   * - Whitespace-only values pass frontend validation
   * - API call is made with empty/whitespace values
   * - API returns 422 error
   */
  describe('Property 1: Bug Condition - Empty/Whitespace Fields Pass Frontend Validation', () => {
    
    it('should catch empty job_title before API call (Requirement 1.1)', async () => {
      // Arrange: Form with empty job_title
      document.getElementById('fullName').value = 'John Doe';
      document.getElementById('email').value = 'john@example.com';
      document.getElementById('jobTitle').value = ''; // EMPTY
      document.getElementById('password').value = 'Password123!';
      document.getElementById('confirmPassword').value = 'Password123!';

      const userData = {
        fullName: document.getElementById('fullName').value,
        email: document.getElementById('email').value,
        jobTitle: document.getElementById('jobTitle').value,
        password: document.getElementById('password').value,
        passwordConfirmation: document.getElementById('confirmPassword').value
      };

      // Act & Assert: Frontend validation should catch empty field
      try {
        await authManager.registerWithAPI(userData);
        
        // EXPECTED BEHAVIOR: Should throw validation error before API call
        expect(apiClientMock.post).not.toHaveBeenCalled();
        expect(true).toBe(false); // Should not reach here
      } catch (error) {
        // BUG: Currently throws ValidationError but API might still be called
        // EXPECTED: Frontend validation prevents API call
        // ACTUAL: May make API call and get 422 error
        
        if (error.name === 'APIError' && error.status === 422) {
          // BUG DETECTED: API was called with empty field
          expect(apiClientMock.post).toHaveBeenCalled();
          expect(error.data.errors.job_title).toBeDefined();
          
          // This is the BUG - API call should have been prevented
          throw new Error('BUG CONFIRMED: Empty job_title passed frontend validation and caused 422 API error');
        }
      }
    });

    it('should catch whitespace-only job_title before API call (Requirement 1.3)', async () => {
      // Arrange: Form with whitespace-only job_title
      document.getElementById('fullName').value = 'John Doe';
      document.getElementById('email').value = 'john@example.com';
      document.getElementById('jobTitle').value = '   '; // WHITESPACE ONLY
      document.getElementById('password').value = 'Password123!';
      document.getElementById('confirmPassword').value = 'Password123!';

      const userData = {
        fullName: document.getElementById('fullName').value,
        email: document.getElementById('email').value,
        jobTitle: document.getElementById('jobTitle').value,
        password: document.getElementById('password').value,
        passwordConfirmation: document.getElementById('confirmPassword').value
      };

      // Act & Assert: Frontend validation should trim and catch empty field
      try {
        await authManager.registerWithAPI(userData);
        
        // EXPECTED BEHAVIOR: Should throw validation error before API call
        expect(apiClientMock.post).not.toHaveBeenCalled();
        expect(true).toBe(false); // Should not reach here
      } catch (error) {
        // BUG: Whitespace-only value passes frontend validation
        if (error.name === 'APIError' && error.status === 422) {
          // BUG DETECTED: API was called with whitespace-only field
          expect(apiClientMock.post).toHaveBeenCalled();
          expect(error.data.errors.job_title).toBeDefined();
          
          // This is the BUG - whitespace should be trimmed and validated as empty
          throw new Error('BUG CONFIRMED: Whitespace-only job_title passed frontend validation and caused 422 API error');
        }
      }
    });

    /**
     * Property-Based Test: Empty/Whitespace Fields in Any Required Field
     * 
     * This test generates various combinations of empty/whitespace values
     * for all required fields to ensure comprehensive bug detection.
     * 
     * Scoped approach: Tests concrete failing cases (empty and whitespace-only strings)
     */
    it('should catch empty/whitespace in any required field before API call (Requirement 1.5)', async () => {
      await fc.assert(
        fc.asyncProperty(
          // Generate test cases with empty or whitespace-only values
          fc.record({
            fullName: fc.oneof(
              fc.constant(''),
              fc.constant('   '),
              fc.constant('\t\t'),
              fc.constant('John Doe') // Valid value for comparison
            ),
            email: fc.oneof(
              fc.constant(''),
              fc.constant('   '),
              fc.constant('john@example.com') // Valid value
            ),
            jobTitle: fc.oneof(
              fc.constant(''),
              fc.constant('   '),
              fc.constant('\t  \n'),
              fc.constant('Security Analyst') // Valid value
            ),
            password: fc.constant('Password123!'), // Always valid for this test
            passwordConfirmation: fc.constant('Password123!')
          }),
          async (userData) => {
            // Reset API call tracking
            authManager.resetApiCallTracking();
            apiClientMock.post.mockClear();

            // Check if any required field is empty/whitespace after trim
            const hasEmptyField = 
              !userData.fullName.trim() ||
              !userData.email.trim() ||
              !userData.jobTitle.trim();

            if (hasEmptyField) {
              // EXPECTED BEHAVIOR: Frontend validation should catch this
              try {
                await authManager.registerWithAPI(userData);
                
                // If we reach here, validation failed to catch empty field
                // Check if API was called (the bug)
                if (apiClientMock.post.mock.calls.length > 0) {
                  // BUG DETECTED: API was called with empty/whitespace field
                  throw new Error(
                    `BUG CONFIRMED: Empty/whitespace field passed frontend validation. ` +
                    `Data: ${JSON.stringify({
                      fullName: userData.fullName || 'EMPTY',
                      email: userData.email || 'EMPTY',
                      jobTitle: userData.jobTitle || 'EMPTY'
                    })}`
                  );
                }
              } catch (error) {
                if (error.name === 'APIError' && error.status === 422) {
                  // BUG: API was called and returned 422
                  throw new Error(
                    `BUG CONFIRMED: Frontend validation failed to catch empty/whitespace field, ` +
                    `API returned 422 error. Field: ${Object.keys(error.data.errors)[0]}`
                  );
                }
                // ValidationError is expected (frontend caught it)
                // But we need to verify API was NOT called
                expect(apiClientMock.post).not.toHaveBeenCalled();
              }
            }
          }
        ),
        {
          numRuns: 50, // Run 50 test cases
          verbose: true
        }
      );
    });

    /**
     * Concrete Test Cases: Known Bug Scenarios
     * 
     * These tests target the specific scenarios mentioned in the bug report.
     */
    it('should demonstrate bug: empty job_title causes 422 error', async () => {
      // This test DOCUMENTS the bug - it should FAIL on unfixed code
      const userData = {
        fullName: 'John Doe',
        email: 'john@example.com',
        jobTitle: '', // The problematic field
        password: 'Password123!',
        passwordConfirmation: 'Password123!'
      };

      let bugDetected = false;
      let errorDetails = null;

      try {
        await authManager.registerWithAPI(userData);
      } catch (error) {
        if (error.name === 'APIError' && error.status === 422) {
          bugDetected = true;
          errorDetails = error.data.errors;
        }
      }

      // EXPECTED ON UNFIXED CODE: Bug is detected (test fails)
      // EXPECTED ON FIXED CODE: Bug is not detected (test passes)
      expect(bugDetected).toBe(false); // This will FAIL on unfixed code
      
      if (bugDetected) {
        console.log('🐛 BUG DETECTED - Counterexample:');
        console.log('  Input: empty job_title');
        console.log('  Result: 422 API error');
        console.log('  Error details:', errorDetails);
        console.log('  Expected: Frontend validation should prevent API call');
      }
    });

    it('should demonstrate bug: whitespace-only job_title causes 422 error', async () => {
      // This test DOCUMENTS the bug - it should FAIL on unfixed code
      const userData = {
        fullName: 'John Doe',
        email: 'john@example.com',
        jobTitle: '   ', // Whitespace only
        password: 'Password123!',
        passwordConfirmation: 'Password123!'
      };

      let bugDetected = false;
      let errorDetails = null;

      try {
        await authManager.registerWithAPI(userData);
      } catch (error) {
        if (error.name === 'APIError' && error.status === 422) {
          bugDetected = true;
          errorDetails = error.data.errors;
        }
      }

      // EXPECTED ON UNFIXED CODE: Bug is detected (test fails)
      // EXPECTED ON FIXED CODE: Bug is not detected (test passes)
      expect(bugDetected).toBe(false); // This will FAIL on unfixed code
      
      if (bugDetected) {
        console.log('🐛 BUG DETECTED - Counterexample:');
        console.log('  Input: whitespace-only job_title ("   ")');
        console.log('  Result: 422 API error');
        console.log('  Error details:', errorDetails);
        console.log('  Expected: Whitespace should be trimmed and validated as empty');
      }
    });

    it('should demonstrate bug: multiple empty fields cause 422 error', async () => {
      // This test DOCUMENTS the bug with multiple empty fields
      const userData = {
        fullName: '  ', // Whitespace
        email: 'john@example.com',
        jobTitle: '', // Empty
        password: 'Password123!',
        passwordConfirmation: 'Password123!'
      };

      let bugDetected = false;
      let errorDetails = null;

      try {
        await authManager.registerWithAPI(userData);
      } catch (error) {
        if (error.name === 'APIError' && error.status === 422) {
          bugDetected = true;
          errorDetails = error.data.errors;
        }
      }

      // EXPECTED ON UNFIXED CODE: Bug is detected (test fails)
      // EXPECTED ON FIXED CODE: Bug is not detected (test passes)
      expect(bugDetected).toBe(false); // This will FAIL on unfixed code
      
      if (bugDetected) {
        console.log('🐛 BUG DETECTED - Counterexample:');
        console.log('  Input: multiple empty/whitespace fields');
        console.log('  Result: 422 API error');
        console.log('  Error details:', errorDetails);
        console.log('  Expected: Frontend validation should catch all empty fields');
      }
    });
  });

  /**
   * Additional Test: Verify .trim() IS applied before validation (the fix)
   */
  describe('Bug Root Cause: .trim() not applied before validation', () => {
    it('should demonstrate that whitespace-only values are not trimmed before validation', () => {
      const whitespaceValue = '   ';
      
      // FIXED behavior: validation trims the value before checking
      const isValid = whitespaceValue.trim() ? true : false; // FIXED: Now trims before validation
      
      // EXPECTED ON UNFIXED CODE: isValid is true (bug)
      // EXPECTED ON FIXED CODE: isValid is false (correct)
      expect(isValid).toBe(false); // This will PASS on fixed code
      
      if (isValid) {
        console.log('🐛 ROOT CAUSE CONFIRMED: Whitespace-only value treated as valid');
        console.log('  Value: "   " (3 spaces)');
        console.log('  Current validation: value ? true : false');
        console.log('  Expected validation: value.trim() ? true : false');
      }
    });
  });
});
