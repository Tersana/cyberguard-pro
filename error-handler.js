/**
 * Global Error Handler Utility for CyberGuard API Integration
 * Provides centralized error handling for API responses and network errors
 * 
 * Requirements: 12.1, 12.2, 12.3, 12.4, 12.5, 12.7
 */

/**
 * ErrorHandler Class
 * Static methods for handling different types of API errors
 */
class ErrorHandler {
  /**
   * Handle validation errors (422 responses)
   * Displays inline error messages for form fields
   * 
   * @param {ValidationError} error - Validation error with errors array
   * @param {Object} options - Optional configuration
   * @returns {void}
   * 
   * Requirements: 12.2, 12.7
   */
  static handleValidationError(error, options = {}) {
    console.error('[ErrorHandler] Validation Error:', error);
    
    if (!error.errors || !Array.isArray(error.errors)) {
      console.warn('[ErrorHandler] Invalid validation error format');
      return;
    }
    
    // Display inline errors for each field
    error.errors.forEach(({ field, message }) => {
      const fieldEl = document.getElementById(field);
      if (fieldEl) {
        this.showFieldError(fieldEl, message);
      } else {
        console.warn(`[ErrorHandler] Field element not found: ${field}`);
      }
    });
    
    // Optionally show a summary notification
    if (options.showSummary && window.CyberNotify) {
      const errorCount = error.errors.length;
      const summaryMessage = `Please fix ${errorCount} validation error${errorCount > 1 ? 's' : ''} before continuing.`;
      window.CyberNotify.alert(summaryMessage, { type: 'warning' });
    }
  }
  
  /**
   * Handle general API errors (401, 500, etc.)
   * Displays user-friendly error messages via CyberNotify
   * 
   * @param {APIError} error - API error with status and message
   * @param {Object} options - Optional configuration
   * @returns {void}
   * 
   * Requirements: 12.1, 12.3, 12.6
   */
  static handleAPIError(error, options = {}) {
    console.error('[ErrorHandler] API Error:', error);
    
    // Handle 401 Unauthorized - clear session and redirect
    if (error.status === 401) {
      this._handle401();
      return;
    }
    
    // Handle 500+ Server Errors
    if (error.status >= 500) {
      const message = options.customMessage || 'Server error. Please try again later.';
      if (window.CyberNotify) {
        window.CyberNotify.alert(message, { type: 'error' });
      }
      return;
    }
    
    // Handle other API errors
    const message = error.message || 'An unexpected error occurred. Please try again.';
    if (window.CyberNotify) {
      window.CyberNotify.alert(message, { type: 'error' });
    }
  }
  
  /**
   * Handle network errors (connection issues, timeouts)
   * Displays connection error message via CyberNotify
   * 
   * @param {NetworkError} error - Network error
   * @param {Object} options - Optional configuration
   * @returns {void}
   * 
   * Requirements: 12.4, 12.5
   */
  static handleNetworkError(error, options = {}) {
    console.error('[ErrorHandler] Network Error:', error);
    
    const message = options.customMessage || 'Network error. Please check your connection and try again.';
    
    if (window.CyberNotify) {
      window.CyberNotify.alert(message, { type: 'error' });
    }
  }
  
  /**
   * Show inline error message for a form field
   * Adds error styling and displays error text below the field
   * 
   * @param {HTMLElement} fieldEl - The form field element
   * @param {string} message - The error message to display
   * @returns {void}
   * 
   * Requirements: 12.2, 12.7
   */
  static showFieldError(fieldEl, message) {
    if (!fieldEl) return;
    
    // Add error styling to the field
    fieldEl.classList.add('border-red-500/50', 'focus:border-red-500');
    fieldEl.classList.remove('border-purple-500/30');
    
    // Find or create error message element
    let errorEl = fieldEl.parentElement.querySelector('.field-error');
    
    if (!errorEl) {
      errorEl = document.createElement('p');
      errorEl.className = 'field-error text-xs text-red-400 mt-1';
      fieldEl.parentElement.appendChild(errorEl);
    }
    
    errorEl.textContent = message;
    
    // Add input event listener to clear error on user input
    const clearErrorHandler = () => {
      this.clearFieldError(fieldEl);
      fieldEl.removeEventListener('input', clearErrorHandler);
    };
    fieldEl.addEventListener('input', clearErrorHandler);
  }
  
  /**
   * Clear inline error message from a form field
   * Removes error styling and error message element
   * 
   * @param {HTMLElement} fieldEl - The form field element
   * @returns {void}
   * 
   * Requirements: 12.7
   */
  static clearFieldError(fieldEl) {
    if (!fieldEl) return;
    
    // Remove error styling
    fieldEl.classList.remove('border-red-500/50', 'focus:border-red-500');
    fieldEl.classList.add('border-purple-500/30');
    
    // Remove error message element
    const errorEl = fieldEl.parentElement.querySelector('.field-error');
    if (errorEl) {
      errorEl.remove();
    }
  }
  
  /**
   * Clear all field errors in a form
   * Useful for resetting form state
   * 
   * @param {HTMLElement|string} formEl - Form element or selector
   * @returns {void}
   */
  static clearAllFieldErrors(formEl) {
    const form = typeof formEl === 'string' ? document.querySelector(formEl) : formEl;
    if (!form) return;
    
    // Find all fields with error styling
    const errorFields = form.querySelectorAll('.border-red-500\\/50');
    errorFields.forEach(field => {
      this.clearFieldError(field);
    });
    
    // Remove any remaining error message elements
    const errorMessages = form.querySelectorAll('.field-error');
    errorMessages.forEach(msg => msg.remove());
  }
  
  /**
   * Handle 401 Unauthorized - clear session and redirect to login
   * Private method called by handleAPIError
   * 
   * @private
   * @returns {void}
   * 
   * Requirements: 12.1
   */
  static _handle401() {
    console.warn('[ErrorHandler] 401 Unauthorized - Clearing session and redirecting to login');
    
    // Clear all session data
    localStorage.removeItem('cyberguard_jwt');
    localStorage.removeItem('cyberguard_user');
    localStorage.removeItem('cyberguard_session');
    
    // Show notification before redirect
    if (window.CyberNotify) {
      window.CyberNotify.alert('Your session has expired. Please log in again.', { type: 'warning' });
    }
    
    // Redirect to login page after a short delay
    setTimeout(() => {
      if (window.location.pathname !== '/login') {
        window.location.href = '/login?session_expired=true';
      }
    }, 1500);
  }
  
  /**
   * Generic error handler - routes to appropriate handler based on error type
   * Use this as a catch-all for API errors
   * 
   * @param {Error} error - Any error object
   * @param {Object} context - Optional context information for debugging
   * @returns {void}
   * 
   * Requirements: 12.1, 12.2, 12.3, 12.4, 12.5, 12.6
   */
  static handle(error, context = {}) {
    console.error('[ErrorHandler] Handling error:', error, 'Context:', context);
    
    // Route to appropriate handler based on error type
    if (error.name === 'ValidationError') {
      this.handleValidationError(error, context);
    } else if (error.name === 'NetworkError') {
      this.handleNetworkError(error, context);
    } else if (error.name === 'APIError') {
      this.handleAPIError(error, context);
    } else {
      // Unknown error type - show generic error
      const message = error.message || 'An unexpected error occurred. Please try again.';
      if (window.CyberNotify) {
        window.CyberNotify.alert(message, { type: 'error' });
      }
    }
  }
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { ErrorHandler };
}
