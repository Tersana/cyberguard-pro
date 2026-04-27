/**
 * Unit Tests for ErrorHandler Utility
 * Tests validation error handling, API error handling, and field error display
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { JSDOM } from 'jsdom';

// Import ErrorHandler
const { ErrorHandler } = await import('./error-handler.js');

// Setup DOM environment
const dom = new JSDOM(`
  <!DOCTYPE html>
  <html>
    <body>
      <form id="test-form">
        <input type="text" id="email" class="border-purple-500/30" />
        <input type="password" id="password" class="border-purple-500/30" />
        <input type="text" id="full_name" class="border-purple-500/30" />
      </form>
    </body>
  </html>
`);

global.document = dom.window.document;
global.window = dom.window;
global.HTMLElement = dom.window.HTMLElement;
global.localStorage = {
  removeItem: vi.fn(),
  getItem: vi.fn(),
  setItem: vi.fn()
};

// Mock CyberNotify
global.window.CyberNotify = {
  alert: vi.fn(),
  confirm: vi.fn()
};

describe('ErrorHandler - showFieldError', () => {
  beforeEach(() => {
    // Reset DOM
    const form = document.getElementById('test-form');
    form.innerHTML = `
      <input type="text" id="email" class="border-purple-500/30" />
      <input type="password" id="password" class="border-purple-500/30" />
      <input type="text" id="full_name" class="border-purple-500/30" />
    `;
  });

  it('should add error styling to field', () => {
    const field = document.getElementById('email');
    ErrorHandler.showFieldError(field, 'Email is required');
    
    expect(field.classList.contains('border-red-500/50')).toBe(true);
    expect(field.classList.contains('focus:border-red-500')).toBe(true);
    expect(field.classList.contains('border-purple-500/30')).toBe(false);
  });

  it('should create error message element', () => {
    const field = document.getElementById('email');
    ErrorHandler.showFieldError(field, 'Email is required');
    
    const errorEl = field.parentElement.querySelector('.field-error');
    expect(errorEl).not.toBeNull();
    expect(errorEl.textContent).toBe('Email is required');
    expect(errorEl.classList.contains('text-red-400')).toBe(true);
  });

  it('should update existing error message', () => {
    const field = document.getElementById('email');
    ErrorHandler.showFieldError(field, 'First error');
    ErrorHandler.showFieldError(field, 'Second error');
    
    const errorEls = field.parentElement.querySelectorAll('.field-error');
    expect(errorEls.length).toBe(1);
    expect(errorEls[0].textContent).toBe('Second error');
  });

  it('should handle null field gracefully', () => {
    expect(() => {
      ErrorHandler.showFieldError(null, 'Error message');
    }).not.toThrow();
  });
});

describe('ErrorHandler - clearFieldError', () => {
  beforeEach(() => {
    const form = document.getElementById('test-form');
    form.innerHTML = `
      <input type="text" id="email" class="border-purple-500/30" />
    `;
  });

  it('should remove error styling from field', () => {
    const field = document.getElementById('email');
    ErrorHandler.showFieldError(field, 'Email is required');
    ErrorHandler.clearFieldError(field);
    
    expect(field.classList.contains('border-red-500/50')).toBe(false);
    expect(field.classList.contains('focus:border-red-500')).toBe(false);
    expect(field.classList.contains('border-purple-500/30')).toBe(true);
  });

  it('should remove error message element', () => {
    const field = document.getElementById('email');
    ErrorHandler.showFieldError(field, 'Email is required');
    ErrorHandler.clearFieldError(field);
    
    const errorEl = field.parentElement.querySelector('.field-error');
    expect(errorEl).toBeNull();
  });

  it('should handle null field gracefully', () => {
    expect(() => {
      ErrorHandler.clearFieldError(null);
    }).not.toThrow();
  });
});

describe('ErrorHandler - clearAllFieldErrors', () => {
  beforeEach(() => {
    const form = document.getElementById('test-form');
    form.innerHTML = `
      <input type="text" id="email" class="border-purple-500/30" />
      <input type="password" id="password" class="border-purple-500/30" />
      <input type="text" id="full_name" class="border-purple-500/30" />
    `;
  });

  it('should clear all field errors in form', () => {
    const emailField = document.getElementById('email');
    const passwordField = document.getElementById('password');
    
    ErrorHandler.showFieldError(emailField, 'Email is required');
    ErrorHandler.showFieldError(passwordField, 'Password is required');
    
    const form = document.getElementById('test-form');
    ErrorHandler.clearAllFieldErrors(form);
    
    expect(emailField.classList.contains('border-red-500/50')).toBe(false);
    expect(passwordField.classList.contains('border-red-500/50')).toBe(false);
    
    const errorEls = form.querySelectorAll('.field-error');
    expect(errorEls.length).toBe(0);
  });

  it('should accept form selector string', () => {
    const emailField = document.getElementById('email');
    ErrorHandler.showFieldError(emailField, 'Email is required');
    
    ErrorHandler.clearAllFieldErrors('#test-form');
    
    const errorEls = document.querySelectorAll('.field-error');
    expect(errorEls.length).toBe(0);
  });
});

describe('ErrorHandler - handleValidationError', () => {
  beforeEach(() => {
    const form = document.getElementById('test-form');
    form.innerHTML = `
      <div>
        <input type="text" id="email" class="border-purple-500/30" />
      </div>
      <div>
        <input type="password" id="password" class="border-purple-500/30" />
      </div>
    `;
    vi.clearAllMocks();
  });

  it('should display inline errors for each field', () => {
    const error = {
      name: 'ValidationError',
      errors: [
        { field: 'email', message: 'Email is required' },
        { field: 'password', message: 'Password must be at least 8 characters' }
      ]
    };
    
    ErrorHandler.handleValidationError(error);
    
    const emailError = document.getElementById('email').parentElement.querySelector('.field-error');
    const passwordError = document.getElementById('password').parentElement.querySelector('.field-error');
    
    expect(emailError).not.toBeNull();
    expect(passwordError).not.toBeNull();
    expect(emailError.textContent).toBe('Email is required');
    expect(passwordError.textContent).toBe('Password must be at least 8 characters');
  });

  it('should show summary notification when showSummary option is true', () => {
    const error = {
      name: 'ValidationError',
      errors: [
        { field: 'email', message: 'Email is required' },
        { field: 'password', message: 'Password is required' }
      ]
    };
    
    ErrorHandler.handleValidationError(error, { showSummary: true });
    
    expect(window.CyberNotify.alert).toHaveBeenCalledWith(
      'Please fix 2 validation errors before continuing.',
      { type: 'warning' }
    );
  });

  it('should handle missing field elements gracefully', () => {
    const error = {
      name: 'ValidationError',
      errors: [
        { field: 'nonexistent', message: 'This field does not exist' }
      ]
    };
    
    expect(() => {
      ErrorHandler.handleValidationError(error);
    }).not.toThrow();
  });
});

describe('ErrorHandler - handleAPIError', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should handle 401 errors by clearing session', () => {
    const error = {
      name: 'APIError',
      status: 401,
      message: 'Unauthorized'
    };
    
    ErrorHandler.handleAPIError(error);
    
    expect(localStorage.removeItem).toHaveBeenCalledWith('cyberguard_jwt');
    expect(localStorage.removeItem).toHaveBeenCalledWith('cyberguard_user');
    expect(localStorage.removeItem).toHaveBeenCalledWith('cyberguard_session');
    expect(window.CyberNotify.alert).toHaveBeenCalledWith(
      'Your session has expired. Please log in again.',
      { type: 'warning' }
    );
  });

  it('should handle 500 errors with generic message', () => {
    const error = {
      name: 'APIError',
      status: 500,
      message: 'Internal Server Error'
    };
    
    ErrorHandler.handleAPIError(error);
    
    expect(window.CyberNotify.alert).toHaveBeenCalledWith(
      'Server error. Please try again later.',
      { type: 'error' }
    );
  });

  it('should use custom message for 500 errors when provided', () => {
    const error = {
      name: 'APIError',
      status: 500,
      message: 'Internal Server Error'
    };
    
    ErrorHandler.handleAPIError(error, { customMessage: 'Custom error message' });
    
    expect(window.CyberNotify.alert).toHaveBeenCalledWith(
      'Custom error message',
      { type: 'error' }
    );
  });

  it('should display error message for other API errors', () => {
    const error = {
      name: 'APIError',
      status: 404,
      message: 'Resource not found'
    };
    
    ErrorHandler.handleAPIError(error);
    
    expect(window.CyberNotify.alert).toHaveBeenCalledWith(
      'Resource not found',
      { type: 'error' }
    );
  });
});

describe('ErrorHandler - handleNetworkError', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should display network error message', () => {
    const error = {
      name: 'NetworkError',
      message: 'Network request failed'
    };
    
    ErrorHandler.handleNetworkError(error);
    
    expect(window.CyberNotify.alert).toHaveBeenCalledWith(
      'Network error. Please check your connection and try again.',
      { type: 'error' }
    );
  });

  it('should use custom message when provided', () => {
    const error = {
      name: 'NetworkError',
      message: 'Network request failed'
    };
    
    ErrorHandler.handleNetworkError(error, { customMessage: 'Connection timeout' });
    
    expect(window.CyberNotify.alert).toHaveBeenCalledWith(
      'Connection timeout',
      { type: 'error' }
    );
  });
});

describe('ErrorHandler - handle (generic handler)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    const form = document.getElementById('test-form');
    form.innerHTML = `
      <input type="text" id="email" class="border-purple-500/30" />
    `;
  });

  it('should route ValidationError to handleValidationError', () => {
    const error = {
      name: 'ValidationError',
      errors: [
        { field: 'email', message: 'Email is required' }
      ]
    };
    
    ErrorHandler.handle(error);
    
    const errorEl = document.getElementById('email').parentElement.querySelector('.field-error');
    expect(errorEl).not.toBeNull();
    expect(errorEl.textContent).toBe('Email is required');
  });

  it('should route NetworkError to handleNetworkError', () => {
    const error = {
      name: 'NetworkError',
      message: 'Network request failed'
    };
    
    ErrorHandler.handle(error);
    
    expect(window.CyberNotify.alert).toHaveBeenCalledWith(
      'Network error. Please check your connection and try again.',
      { type: 'error' }
    );
  });

  it('should route APIError to handleAPIError', () => {
    const error = {
      name: 'APIError',
      status: 404,
      message: 'Not found'
    };
    
    ErrorHandler.handle(error);
    
    expect(window.CyberNotify.alert).toHaveBeenCalledWith(
      'Not found',
      { type: 'error' }
    );
  });

  it('should handle unknown error types with generic message', () => {
    const error = {
      name: 'UnknownError',
      message: 'Something went wrong'
    };
    
    ErrorHandler.handle(error);
    
    expect(window.CyberNotify.alert).toHaveBeenCalledWith(
      'Something went wrong',
      { type: 'error' }
    );
  });
});
