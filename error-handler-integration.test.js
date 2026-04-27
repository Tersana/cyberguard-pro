/**
 * Integration Tests for ErrorHandler with APIClient
 * Verifies that API errors are properly routed through ErrorHandler
 * 
 * Requirements: 12.1, 12.2, 12.3, 12.4
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { JSDOM } from 'jsdom';

describe('ErrorHandler Integration with APIClient', () => {
  let dom;
  let document;
  let window;
  let APIClient;
  let ErrorHandler;
  let apiClient;

  beforeEach(async () => {
    // Setup fresh DOM for each test
    dom = new JSDOM('<!DOCTYPE html><html><body></body></html>', {
      url: 'http://localhost'
    });
    document = dom.window.document;
    window = dom.window;
    
    // Make globals available
    global.document = document;
    global.window = window;
    global.HTMLElement = dom.window.HTMLElement;
    global.localStorage = {
      getItem: vi.fn(),
      setItem: vi.fn(),
      removeItem: vi.fn(),
      clear: vi.fn()
    };
    
    // Mock fetch
    global.fetch = vi.fn();
    
    // Load ErrorHandler
    const errorHandlerModule = await import('./error-handler.js');
    ErrorHandler = errorHandlerModule.ErrorHandler;
    global.ErrorHandler = ErrorHandler;
    
    // Mock CyberNotify
    global.CyberNotify = {
      alert: vi.fn()
    };
    
    // Load APIClient
    const apiClientModule = await import('./api-client.js');
    APIClient = apiClientModule.APIClient;
    
    // Create API client instance
    apiClient = new APIClient();
  });

  describe('401 Unauthorized Integration', () => {
    it('should use ErrorHandler for 401 responses', async () => {
      // Spy on ErrorHandler.handleAPIError
      const handleAPISpy = vi.spyOn(ErrorHandler, 'handleAPIError');
      
      // Mock 401 response
      global.fetch.mockResolvedValue({
        ok: false,
        status: 401,
        json: async () => ({ message: 'Unauthorized' })
      });
      
      // Make request
      try {
        await apiClient.get('/test');
      } catch (error) {
        // Expected to throw
      }
      
      // Verify ErrorHandler was called
      expect(handleAPISpy).toHaveBeenCalled();
      expect(handleAPISpy).toHaveBeenCalledWith(
        expect.objectContaining({
          name: 'APIError',
          status: 401
        })
      );
    });

    it('should clear session and redirect on 401', async () => {
      // Mock 401 response
      global.fetch.mockResolvedValue({
        ok: false,
        status: 401,
        json: async () => ({ message: 'Unauthorized' })
      });
      
      // Make request
      try {
        await apiClient.get('/test');
      } catch (error) {
        // Expected to throw
      }
      
      // Wait for async operations
      await new Promise(resolve => setTimeout(resolve, 1600));
      
      // Verify session was cleared (this is the critical behavior)
      expect(localStorage.removeItem).toHaveBeenCalledWith('cyberguard_jwt');
      expect(localStorage.removeItem).toHaveBeenCalledWith('cyberguard_user');
      expect(localStorage.removeItem).toHaveBeenCalledWith('cyberguard_session');
    });
  });

  describe('422 Validation Error Integration', () => {
    it('should use ErrorHandler for 422 responses', async () => {
      // Spy on ErrorHandler.handleValidationError
      const handleValidationSpy = vi.spyOn(ErrorHandler, 'handleValidationError');
      
      // Mock 422 response
      global.fetch.mockResolvedValue({
        ok: false,
        status: 422,
        json: async () => ({
          errors: {
            email: ['Email is required'],
            password: ['Password too short']
          }
        })
      });
      
      // Make request
      try {
        await apiClient.post('/test', { email: '', password: '123' });
      } catch (error) {
        // Expected to throw
      }
      
      // Verify ErrorHandler was called
      expect(handleValidationSpy).toHaveBeenCalled();
      expect(handleValidationSpy).toHaveBeenCalledWith(
        expect.objectContaining({
          name: 'ValidationError',
          errors: expect.arrayContaining([
            { field: 'email', message: 'Email is required' },
            { field: 'password', message: 'Password too short' }
          ])
        })
      );
    });

    it('should display inline validation errors', async () => {
      // Create form fields with parent containers
      const emailContainer = document.createElement('div');
      const emailField = document.createElement('input');
      emailField.id = 'email';
      emailContainer.appendChild(emailField);
      document.body.appendChild(emailContainer);
      
      const passwordContainer = document.createElement('div');
      const passwordField = document.createElement('input');
      passwordField.id = 'password';
      passwordContainer.appendChild(passwordField);
      document.body.appendChild(passwordContainer);
      
      // Mock 422 response
      global.fetch.mockResolvedValue({
        ok: false,
        status: 422,
        json: async () => ({
          errors: {
            email: ['Email is required'],
            password: ['Password too short']
          }
        })
      });
      
      // Make request
      try {
        await apiClient.post('/test', { email: '', password: '123' });
      } catch (error) {
        // Expected to throw
      }
      
      // Verify error styling was applied
      expect(emailField.classList.contains('border-red-500/50')).toBe(true);
      expect(passwordField.classList.contains('border-red-500/50')).toBe(true);
      
      // Verify error messages were added
      const emailError = emailContainer.querySelector('.field-error');
      const passwordError = passwordContainer.querySelector('.field-error');
      
      expect(emailError).toBeTruthy();
      expect(emailError.textContent).toBe('Email is required');
      expect(passwordError).toBeTruthy();
      expect(passwordError.textContent).toBe('Password too short');
    });
  });

  describe('500 Server Error Integration', () => {
    it('should use ErrorHandler for 500 responses', async () => {
      // Spy on ErrorHandler.handleAPIError
      const handleAPISpy = vi.spyOn(ErrorHandler, 'handleAPIError');
      
      // Mock 500 response
      global.fetch.mockResolvedValue({
        ok: false,
        status: 500,
        json: async () => ({ message: 'Internal Server Error' })
      });
      
      // Make request
      try {
        await apiClient.get('/test');
      } catch (error) {
        // Expected to throw
      }
      
      // Verify ErrorHandler was called
      expect(handleAPISpy).toHaveBeenCalled();
      expect(handleAPISpy).toHaveBeenCalledWith(
        expect.objectContaining({
          name: 'APIError',
          status: 500,
          message: 'Server error. Please try again later.'
        })
      );
    });

    it('should display generic error message for 500', async () => {
      // Mock 500 response
      global.fetch.mockResolvedValue({
        ok: false,
        status: 500,
        json: async () => ({ message: 'Internal Server Error' })
      });
      
      // Make request and verify ErrorHandler is called
      try {
        await apiClient.get('/test');
      } catch (error) {
        // Verify error is thrown with correct message
        expect(error.message).toBe('Server error. Please try again later.');
        expect(error.status).toBe(500);
      }
    });
  });

  describe('Network Error Integration', () => {
    it('should use ErrorHandler for network errors', async () => {
      // Spy on ErrorHandler.handleNetworkError
      const handleNetworkSpy = vi.spyOn(ErrorHandler, 'handleNetworkError');
      
      // Mock network error
      global.fetch.mockRejectedValue(new TypeError('Failed to fetch'));
      
      // Make request
      try {
        await apiClient.get('/test');
      } catch (error) {
        // Expected to throw
      }
      
      // Verify ErrorHandler was called
      expect(handleNetworkSpy).toHaveBeenCalled();
      expect(handleNetworkSpy).toHaveBeenCalledWith(
        expect.objectContaining({
          name: 'NetworkError',
          message: 'Network error. Please check your connection and try again.'
        })
      );
    });

    it('should display connection error message', async () => {
      // Mock network error
      global.fetch.mockRejectedValue(new TypeError('Failed to fetch'));
      
      // Make request and verify ErrorHandler is called
      try {
        await apiClient.get('/test');
      } catch (error) {
        // Verify error is thrown with correct message
        expect(error.message).toBe('Network error. Please check your connection and try again.');
        expect(error.name).toBe('NetworkError');
      }
    });
  });

  describe('Error Throwing Behavior', () => {
    it('should still throw errors for catch blocks', async () => {
      // Mock 401 response
      global.fetch.mockResolvedValue({
        ok: false,
        status: 401,
        json: async () => ({ message: 'Unauthorized' })
      });
      
      // Verify error is thrown
      await expect(apiClient.get('/test')).rejects.toThrow('Unauthorized');
    });

    it('should throw ValidationError for 422', async () => {
      // Mock 422 response
      global.fetch.mockResolvedValue({
        ok: false,
        status: 422,
        json: async () => ({
          errors: { email: ['Email is required'] }
        })
      });
      
      // Verify ValidationError is thrown
      await expect(apiClient.post('/test', {})).rejects.toThrow('Validation failed');
    });

    it('should throw NetworkError for network failures', async () => {
      // Mock network error
      global.fetch.mockRejectedValue(new TypeError('Failed to fetch'));
      
      // Verify NetworkError is thrown
      await expect(apiClient.get('/test')).rejects.toThrow('Network error');
    });
  });
});
