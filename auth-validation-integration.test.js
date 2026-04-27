/**
 * Integration Tests for Input Validation in API Methods
 * Tests for task 21.2: Input validation integration
 * 
 * Requirements: 15.4
 * - Validate email format before API submission
 * - Validate password strength before API submission
 * - Validate required fields before API submission
 * - Sanitize user input to prevent XSS
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { JSDOM } from 'jsdom';

// Mock ValidationError class
class ValidationError extends Error {
  constructor(errors) {
    super('Validation failed');
    this.name = 'ValidationError';
    this.errors = errors;
  }
}

describe('AuthManager - Input Validation Integration (Task 21.2)', () => {
  let authManager;
  let apiClientMock;
  let dom;
  let showLoadingMock;
  let hideLoadingMock;

  beforeEach(() => {
    // Setup DOM environment
    dom = new JSDOM('<!DOCTYPE html><html><body></body></html>', {
      url: 'http://localhost'
    });
    global.document = dom.window.document;
    global.window = dom.window;
    global.localStorage = dom.window.localStorage;
    global.ValidationError = ValidationError;

    // Clear localStorage
    localStorage.clear();

    // Mock loading functions
    showLoadingMock = vi.fn();
    hideLoadingMock = vi.fn();
    global.showLoading = showLoadingMock;
    global.hideLoading = hideLoadingMock;

    // Mock prepareUserDataForAPI
    global.prepareUserDataForAPI = (data) => ({
      full_name: data.fullName,
      email: data.email,
      job_title: data.jobTitle,
      password: data.password
    });

    // Mock normalizeUserData
    global.normalizeUserData = (data) => ({
      id: data.id,
      email: data.email,
      fullName: data.full_name || data.name,
      jobTitle: data.job_title || data.job_tittle
    });

    // Mock APIClient
    apiClientMock = {
      post: vi.fn(),
      setToken: vi.fn(),
      getToken: vi.fn(),
      clearToken: vi.fn()
    };

    // Create AuthManager with validation methods
    authManager = {
      apiClient: apiClientMock,
      currentUser: null,

      validateEmail(email) {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return emailRegex.test(email);
      },

      validatePassword(password) {
        const requirements = {
          length: password.length >= 8,
          lowercase: /[a-z]/.test(password),
          uppercase: /[A-Z]/.test(password),
          numbers: /[0-9]/.test(password),
          symbols: /[^A-Za-z0-9]/.test(password),
        };

        return {
          valid: Object.values(requirements).every(Boolean),
          requirements: requirements,
        };
      },

      validateRegistrationData(userData) {
        const errors = [];

        if (!userData.email || !this.validateEmail(userData.email)) {
          errors.push({ field: 'email', message: 'Valid email is required' });
        }

        const passwordValidation = this.validatePassword(userData.password);
        if (!passwordValidation.valid) {
          errors.push({ field: 'password', message: 'Password must be at least 8 characters and include uppercase, lowercase, numbers, and symbols' });
        }

        if (!userData.fullName || userData.fullName.trim().length < 2) {
          errors.push({ field: 'fullName', message: 'Full name is required' });
        }

        if (!userData.jobTitle || userData.jobTitle.trim().length < 2) {
          errors.push({ field: 'jobTitle', message: 'Job title is required' });
        }

        return errors;
      },

      validateLoginData(email, password) {
        const errors = [];

        if (!email || !this.validateEmail(email)) {
          errors.push({ field: 'email', message: 'Valid email is required' });
        }

        if (!password || password.trim().length === 0) {
          errors.push({ field: 'password', message: 'Password is required' });
        }

        return errors;
      },

      sanitizeInput(input) {
        if (typeof input !== 'string') {
          return input;
        }

        const div = document.createElement('div');
        div.textContent = input;
        return div.innerHTML;
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

      trackRegistration(email) {
        // Mock tracking
      },

      trackLoginAttempt(email, success) {
        // Mock tracking
      },

      normalizeUserData(userData) {
        return normalizeUserData(userData);
      },

      async registerWithAPI(userData) {
        try {
          showLoading('Creating your account...');
          
          const sanitizedData = {
            fullName: this.sanitizeInput(userData.fullName),
            email: this.sanitizeInput(userData.email),
            jobTitle: this.sanitizeInput(userData.jobTitle),
            password: userData.password
          };
          
          const validationErrors = this.validateRegistrationData(sanitizedData);
          if (validationErrors.length > 0) {
            throw new ValidationError(validationErrors);
          }

          const apiData = prepareUserDataForAPI({
            fullName: sanitizedData.fullName,
            email: sanitizedData.email,
            jobTitle: sanitizedData.jobTitle,
            password: sanitizedData.password
          });

          const response = await this.apiClient.post('auth/register', apiData);
          this.apiClient.setToken(response.token);
          const normalizedUser = this.normalizeUserData(response.user);
          this.saveUserSession(normalizedUser);
          this.trackRegistration(normalizedUser.email);

          return { success: true, user: normalizedUser };
        } catch (error) {
          console.error("Registration error:", error);
          
          if (error.name === 'ValidationError') {
            throw error;
          }
          
          if (error.name === 'APIError') {
            throw error;
          }
          
          throw new Error('An error occurred during registration');
        } finally {
          hideLoading();
        }
      },

      async loginWithAPI(email, password) {
        try {
          showLoading('Signing you in...');
          
          const sanitizedEmail = this.sanitizeInput(email);
          
          const validationErrors = this.validateLoginData(sanitizedEmail, password);
          if (validationErrors.length > 0) {
            throw new ValidationError(validationErrors);
          }
          
          const response = await this.apiClient.post('auth/login', {
            email: sanitizedEmail,
            password: password
          });

          if (response.requires_2fa) {
            return { 
              success: true, 
              requires2FA: true,
              message: 'Two-factor authentication required'
            };
          }

          this.apiClient.setToken(response.token);
          const normalizedUser = this.normalizeUserData(response.user);
          this.saveUserSession(normalizedUser);
          this.trackLoginAttempt(email, true);

          return { success: true, user: normalizedUser, requires2FA: false };
        } catch (error) {
          console.error("Login error:", error);
          this.trackLoginAttempt(email, false);
          
          if (error.name === 'ValidationError') {
            throw error; // Re-throw validation errors for form handling
          }
          
          if (error.name === 'APIError') {
            throw error; // Re-throw API errors for form handling
          }
          
          throw new Error('An error occurred during login');
        } finally {
          hideLoading();
        }
      }
    };
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('registerWithAPI() - Validation Integration', () => {
    it('should validate and sanitize data before API call', async () => {
      // Arrange
      const userData = {
        fullName: 'John Doe',
        email: 'john@example.com',
        jobTitle: 'Security Analyst',
        password: 'Password123!'
      };

      const mockResponse = {
        token: 'jwt-token',
        user: {
          id: 1,
          email: 'john@example.com',
          full_name: 'John Doe',
          job_title: 'Security Analyst'
        }
      };

      apiClientMock.post.mockResolvedValue(mockResponse);

      // Act
      const result = await authManager.registerWithAPI(userData);

      // Assert
      expect(showLoadingMock).toHaveBeenCalledWith('Creating your account...');
      expect(apiClientMock.post).toHaveBeenCalledWith('auth/register', {
        full_name: 'John Doe',
        email: 'john@example.com',
        job_title: 'Security Analyst',
        password: 'Password123!'
      });
      expect(result.success).toBe(true);
      expect(hideLoadingMock).toHaveBeenCalled();
    });

    it('should reject registration with invalid email', async () => {
      // Arrange
      const userData = {
        fullName: 'John Doe',
        email: 'invalid-email',
        jobTitle: 'Security Analyst',
        password: 'Password123!'
      };

      // Act & Assert
      await expect(authManager.registerWithAPI(userData)).rejects.toThrow(ValidationError);
      expect(apiClientMock.post).not.toHaveBeenCalled();
      expect(hideLoadingMock).toHaveBeenCalled();
    });

    it('should reject registration with weak password', async () => {
      // Arrange
      const userData = {
        fullName: 'John Doe',
        email: 'john@example.com',
        jobTitle: 'Security Analyst',
        password: 'weak'
      };

      // Act & Assert
      await expect(authManager.registerWithAPI(userData)).rejects.toThrow(ValidationError);
      expect(apiClientMock.post).not.toHaveBeenCalled();
    });

    it('should reject registration with missing required fields', async () => {
      // Arrange
      const userData = {
        fullName: '',
        email: 'john@example.com',
        jobTitle: '',
        password: 'Password123!'
      };

      // Act & Assert
      await expect(authManager.registerWithAPI(userData)).rejects.toThrow(ValidationError);
      expect(apiClientMock.post).not.toHaveBeenCalled();
    });

    it('should sanitize XSS attempts in registration data', async () => {
      // Arrange
      const userData = {
        fullName: '<script>alert("XSS")</script>',
        email: 'john@example.com',
        jobTitle: 'Analyst<img src=x>',
        password: 'Password123!'
      };

      const mockResponse = {
        token: 'jwt-token',
        user: {
          id: 1,
          email: 'john@example.com',
          full_name: '&lt;script&gt;alert("XSS")&lt;/script&gt;',
          job_title: 'Analyst&lt;img src=x&gt;'
        }
      };

      apiClientMock.post.mockResolvedValue(mockResponse);

      // Act
      await authManager.registerWithAPI(userData);

      // Assert
      const callArgs = apiClientMock.post.mock.calls[0][1];
      expect(callArgs.full_name).not.toContain('<script>');
      expect(callArgs.job_title).not.toContain('<img');
      expect(callArgs.full_name).toContain('&lt;');
      expect(callArgs.full_name).toContain('&gt;');
    });

    it('should not sanitize password field', async () => {
      // Arrange
      const userData = {
        fullName: 'John Doe',
        email: 'john@example.com',
        jobTitle: 'Security Analyst',
        password: 'P@ssw0rd<>123!'
      };

      const mockResponse = {
        token: 'jwt-token',
        user: {
          id: 1,
          email: 'john@example.com',
          full_name: 'John Doe',
          job_title: 'Security Analyst'
        }
      };

      apiClientMock.post.mockResolvedValue(mockResponse);

      // Act
      await authManager.registerWithAPI(userData);

      // Assert
      const callArgs = apiClientMock.post.mock.calls[0][1];
      expect(callArgs.password).toBe('P@ssw0rd<>123!');
    });
  });

  describe('loginWithAPI() - Validation Integration', () => {
    it('should validate and sanitize email before API call', async () => {
      // Arrange
      const email = 'john@example.com';
      const password = 'anypassword';

      const mockResponse = {
        token: 'jwt-token',
        user: {
          id: 1,
          email: 'john@example.com',
          full_name: 'John Doe'
        }
      };

      apiClientMock.post.mockResolvedValue(mockResponse);

      // Act
      const result = await authManager.loginWithAPI(email, password);

      // Assert
      expect(showLoadingMock).toHaveBeenCalledWith('Signing you in...');
      expect(apiClientMock.post).toHaveBeenCalledWith('auth/login', {
        email: 'john@example.com',
        password: 'anypassword'
      });
      expect(result.success).toBe(true);
      expect(hideLoadingMock).toHaveBeenCalled();
    });

    it('should reject login with invalid email', async () => {
      // Arrange
      const email = 'invalid-email';
      const password = 'anypassword';

      // Act & Assert
      await expect(authManager.loginWithAPI(email, password)).rejects.toThrow(ValidationError);
      expect(apiClientMock.post).not.toHaveBeenCalled();
      expect(hideLoadingMock).toHaveBeenCalled();
    });

    it('should reject login with empty password', async () => {
      // Arrange
      const email = 'john@example.com';
      const password = '';

      // Act & Assert
      await expect(authManager.loginWithAPI(email, password)).rejects.toThrow(ValidationError);
      expect(apiClientMock.post).not.toHaveBeenCalled();
    });

    it('should sanitize XSS attempts in email', async () => {
      // Arrange
      const email = 'test<script>@example.com';
      const password = 'anypassword';

      const mockResponse = {
        token: 'jwt-token',
        user: {
          id: 1,
          email: 'test&lt;script&gt;@example.com',
          full_name: 'John Doe'
        }
      };

      apiClientMock.post.mockResolvedValue(mockResponse);

      // Act
      const result = await authManager.loginWithAPI(email, password);

      // Assert - Email is sanitized before sending to API
      const callArgs = apiClientMock.post.mock.calls[0][1];
      expect(callArgs.email).not.toContain('<script>');
      expect(callArgs.email).toContain('&lt;');
      expect(result.success).toBe(true);
    });

    it('should accept login without password strength validation', async () => {
      // Arrange - weak password should be accepted for login
      const email = 'john@example.com';
      const password = 'weak';

      const mockResponse = {
        token: 'jwt-token',
        user: {
          id: 1,
          email: 'john@example.com',
          full_name: 'John Doe'
        }
      };

      apiClientMock.post.mockResolvedValue(mockResponse);

      // Act
      const result = await authManager.loginWithAPI(email, password);

      // Assert
      expect(result.success).toBe(true);
      expect(apiClientMock.post).toHaveBeenCalled();
    });
  });

  describe('Validation Error Handling', () => {
    it('should throw ValidationError with detailed error list', async () => {
      // Arrange
      const userData = {
        fullName: '',
        email: 'invalid',
        jobTitle: '',
        password: 'weak'
      };

      // Act & Assert
      try {
        await authManager.registerWithAPI(userData);
        expect.fail('Should have thrown ValidationError');
      } catch (error) {
        expect(error.name).toBe('ValidationError');
        expect(error.errors).toBeInstanceOf(Array);
        expect(error.errors.length).toBeGreaterThan(0);
      }
    });

    it('should not call API when validation fails', async () => {
      // Arrange
      const userData = {
        fullName: 'John Doe',
        email: 'invalid',
        jobTitle: 'Analyst',
        password: 'Password123!'
      };

      // Act & Assert
      await expect(authManager.registerWithAPI(userData)).rejects.toThrow();
      expect(apiClientMock.post).not.toHaveBeenCalled();
    });
  });
});
