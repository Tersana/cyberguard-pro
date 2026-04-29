/**
 * API Client for CyberGuard Backend Integration
 * Centralized HTTP client for all backend communication
 */

// Import ErrorHandler for centralized error handling
// Note: In browser context, ErrorHandler is loaded via script tag
// In Node/test context, it's imported via require/import

// API Configuration
const API_BASE_URL =
  "https://peptonelike-lelia-interdepartmentally.ngrok-free.dev/api/";
const NGROK_HEADER = { "ngrok-skip-browser-warning": "true" };
const JWT_STORAGE_KEY = "cyberguard_jwt";

/**
 * Custom Error Classes
 */
class APIError extends Error {
  constructor(message, status, data = null) {
    super(message);
    this.name = "APIError";
    this.status = status;
    this.data = data;
  }
}

class ValidationError extends Error {
  constructor(errors) {
    super("Validation failed");
    this.name = "ValidationError";
    this.errors = errors;
  }
}

class NetworkError extends Error {
  constructor(message = "Network request failed") {
    super(message);
    this.name = "NetworkError";
  }
}

/**
 * APIClient Class
 * Handles all HTTP communication with the CyberGuard backend
 */
class APIClient {
  constructor(baseURL = API_BASE_URL, options = {}) {
    this.baseURL = baseURL;
    this.options = options;
    this.requestInterceptors = [];
    this.responseInterceptors = [];
  }

  /**
   * Token Management Methods
   */
  setToken(token) {
    if (token) {
      localStorage.setItem(JWT_STORAGE_KEY, token);
    }
  }

  getToken() {
    return localStorage.getItem(JWT_STORAGE_KEY);
  }

  clearToken() {
    localStorage.removeItem(JWT_STORAGE_KEY);
  }

  /**
   * Interceptor Management
   */
  addRequestInterceptor(fn) {
    this.requestInterceptors.push(fn);
  }

  addResponseInterceptor(fn) {
    this.responseInterceptors.push(fn);
  }

  /**
   * Build request headers
   */
  _buildHeaders(customHeaders = {}) {
    const headers = {
      Accept: "application/json",
      ...NGROK_HEADER,
      ...customHeaders,
    };

    // Add JWT token if exists
    const token = this.getToken();
    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }

    return headers;
  }

  /**
   * Build full URL
   */
  _buildURL(endpoint) {
    // Remove leading slash from endpoint if present
    const cleanEndpoint = endpoint.startsWith("/")
      ? endpoint.slice(1)
      : endpoint;
    const fullURL = `${this.baseURL}${cleanEndpoint}`;

    // Ensure HTTPS is used for all API requests (Requirement 15.5)
    if (!fullURL.startsWith("https://")) {
      console.error(
        "[APIClient] Security Error: All API requests must use HTTPS",
      );
      throw new Error("Security Error: API requests must use HTTPS");
    }

    return fullURL;
  }

  /**
   * Handle 401 Unauthorized
   */
  _handle401() {
    // Clear all session data
    localStorage.removeItem(JWT_STORAGE_KEY);
    localStorage.removeItem("cyberguard_user");
    localStorage.removeItem("cyberguard_session");

    // Redirect to login if not already there
    if (window.location.pathname !== "/login.html") {
      window.location.href = "/login.html?session_expired=true";
    }
  }

  /**
   * Transform backend validation errors to frontend format
   */
  _transformValidationErrors(backendErrors) {
    const errors = [];

    // Handle different error formats
    if (Array.isArray(backendErrors)) {
      return backendErrors;
    }

    // Backend format: { email: ['Email is required'], password: ['Too short'] }
    // Frontend format: [{ field: 'email', message: 'Email is required' }]
    for (const [field, messages] of Object.entries(backendErrors)) {
      errors.push({
        field: field,
        message: Array.isArray(messages) ? messages[0] : messages,
      });
    }

    return errors;
  }

  /**
   * Handle response based on status code
   * Integrates with ErrorHandler for consistent error display
   */
  async _handleResponse(response) {
    // Handle 401 Unauthorized — read body to get the actual backend message
    if (response.status === 401) {
      const errorData = await response.json().catch(() => ({}));
      const message = errorData.message || "Unauthorized";
      const error = new APIError(message, 401, errorData);

      // Only redirect to login for session expiry, not for login failures
      const isLoginEndpoint =
        response.url && response.url.includes("auth/login");
      if (!isLoginEndpoint) {
        if (typeof ErrorHandler !== "undefined") {
          ErrorHandler.handleAPIError(error);
        } else {
          this._handle401();
        }
      }

      throw error;
    }

    // Handle 422 Validation Error
    if (response.status === 422) {
      const errorData = await response.json();
      const errors = this._transformValidationErrors(
        errorData.errors || errorData,
      );
      const error = new ValidationError(errors);
      error.data = errorData;
      error.status = 422;

      if (typeof ErrorHandler !== "undefined") {
        ErrorHandler.handleValidationError(error);
      }

      throw error;
    }

    // Handle 500+ Server Errors
    if (response.status >= 500) {
      const error = new APIError(
        "Server error. Please try again later.",
        response.status,
      );

      // Use ErrorHandler if available (browser context)
      if (typeof ErrorHandler !== "undefined") {
        ErrorHandler.handleAPIError(error);
      }

      throw error;
    }

    // Handle other error status codes
    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      const error = new APIError(
        errorData.message || `Request failed with status ${response.status}`,
        response.status,
        errorData,
      );

      // Use ErrorHandler if available (browser context)
      if (typeof ErrorHandler !== "undefined") {
        ErrorHandler.handleAPIError(error);
      }

      throw error;
    }

    // Parse successful response
    return response.json();
  }

  /**
   * Execute HTTP request
   */
  async _request(method, endpoint, data = null, options = {}) {
    try {
      // Build URL
      const url = this._buildURL(endpoint);

      // Build headers
      const headers = this._buildHeaders(options.headers || {});

      // Add Content-Type for requests with body
      if (data && ["POST", "PUT", "PATCH"].includes(method)) {
        headers["Content-Type"] = "application/json";
      }

      // Build fetch options
      const fetchOptions = {
        method,
        headers,
        ...options,
      };

      // Add body for POST/PUT/PATCH
      if (data) {
        fetchOptions.body = JSON.stringify(data);
      }

      // Apply request interceptors
      for (const interceptor of this.requestInterceptors) {
        await interceptor(fetchOptions);
      }

      // Execute fetch
      const response = await fetch(url, fetchOptions);

      // Apply response interceptors
      for (const interceptor of this.responseInterceptors) {
        await interceptor(response);
      }

      // Handle response
      return await this._handleResponse(response);
    } catch (error) {
      // Handle network errors
      if (error instanceof TypeError && error.message.includes("fetch")) {
        const networkError = new NetworkError(
          "Network error. Please check your connection and try again.",
        );

        // Use ErrorHandler if available (browser context)
        if (typeof ErrorHandler !== "undefined") {
          ErrorHandler.handleNetworkError(networkError);
        }

        throw networkError;
      }

      // Re-throw API errors (already handled by _handleResponse)
      throw error;
    }
  }

  /**
   * HTTP Methods
   */
  async get(endpoint, options = {}) {
    return this._request("GET", endpoint, null, options);
  }

  async post(endpoint, data, options = {}) {
    return this._request("POST", endpoint, data, options);
  }

  async put(endpoint, data, options = {}) {
    return this._request("PUT", endpoint, data, options);
  }

  async patch(endpoint, data, options = {}) {
    return this._request("PATCH", endpoint, data, options);
  }

  async delete(endpoint, options = {}) {
    return this._request("DELETE", endpoint, null, options);
  }
}

/**
 * Loading Indicator Utilities
 * Cyber-themed loading states for async operations
 */

/**
 * Show full-screen loading overlay
 * @param {string} message - Optional loading message to display
 */
function showLoading(message = "Loading...") {
  let overlay = document.getElementById("cyber-loading-overlay");

  // Create overlay if it doesn't exist
  if (!overlay) {
    overlay = document.createElement("div");
    overlay.id = "cyber-loading-overlay";
    overlay.className = "cyber-loading-overlay";
    overlay.innerHTML = `
      <div class="cyber-spinner-lg"></div>
      <div class="cyber-loading-text" id="cyber-loading-message">${message}</div>
    `;
    document.body.appendChild(overlay);
  } else {
    // Update message if overlay exists
    const messageEl = document.getElementById("cyber-loading-message");
    if (messageEl) {
      messageEl.textContent = message;
    }
  }

  // Trigger reflow for animation
  overlay.offsetHeight;

  // Show overlay
  overlay.classList.add("active");
}

/**
 * Hide full-screen loading overlay
 */
function hideLoading() {
  const overlay = document.getElementById("cyber-loading-overlay");
  if (overlay) {
    overlay.classList.remove("active");
  }
}

/**
 * Show inline loading indicator (for buttons, cards, etc.)
 * @param {HTMLElement} element - Element to show loading state on
 * @param {string} message - Optional loading message
 */
function showInlineLoading(element, message = "Loading") {
  if (!element) return;

  // Store original content
  element.dataset.originalContent = element.innerHTML;
  element.dataset.originalDisabled = element.disabled;

  // Disable if it's a button
  if (element.tagName === "BUTTON") {
    element.disabled = true;
  }

  // Add loading indicator
  element.innerHTML = `
    <span class="cyber-loading-inline">
      <span class="cyber-spinner-sm"></span>
      <span class="cyber-loading-dots">${message}</span>
    </span>
  `;
}

/**
 * Hide inline loading indicator and restore original content
 * @param {HTMLElement} element - Element to restore
 */
function hideInlineLoading(element) {
  if (!element) return;

  // Restore original content
  if (element.dataset.originalContent) {
    element.innerHTML = element.dataset.originalContent;
    delete element.dataset.originalContent;
  }

  // Restore disabled state
  if (element.tagName === "BUTTON") {
    element.disabled = element.dataset.originalDisabled === "true";
    delete element.dataset.originalDisabled;
  }
}

/**
 * Show loading state on a specific container
 * @param {string|HTMLElement} container - Container selector or element
 * @param {string} message - Optional loading message
 */
function showContainerLoading(container, message = "Loading...") {
  const element =
    typeof container === "string"
      ? document.querySelector(container)
      : container;

  if (!element) return;

  // Store original content
  element.dataset.originalContent = element.innerHTML;

  // Add loading state
  element.innerHTML = `
    <div class="flex flex-col items-center justify-center py-12">
      <div class="cyber-spinner"></div>
      <div class="cyber-loading-text">${message}</div>
    </div>
  `;
}

/**
 * Hide container loading and restore original content
 * @param {string|HTMLElement} container - Container selector or element
 */
function hideContainerLoading(container) {
  const element =
    typeof container === "string"
      ? document.querySelector(container)
      : container;

  if (!element || !element.dataset.originalContent) return;

  // Restore original content
  element.innerHTML = element.dataset.originalContent;
  delete element.dataset.originalContent;
}

/**
 * Wrap an async function with loading indicator
 * @param {Function} asyncFn - Async function to wrap
 * @param {Object} options - Loading options
 * @returns {Function} Wrapped function
 */
function withLoading(asyncFn, options = {}) {
  const {
    type = "overlay", // 'overlay', 'inline', 'container'
    target = null,
    message = "Loading...",
  } = options;

  return async function (...args) {
    try {
      // Show loading based on type
      if (type === "overlay") {
        showLoading(message);
      } else if (type === "inline" && target) {
        showInlineLoading(target, message);
      } else if (type === "container" && target) {
        showContainerLoading(target, message);
      }

      // Execute async function
      const result = await asyncFn.apply(this, args);

      return result;
    } finally {
      // Hide loading based on type
      if (type === "overlay") {
        hideLoading();
      } else if (type === "inline" && target) {
        hideInlineLoading(target);
      } else if (type === "container" && target) {
        hideContainerLoading(target);
      }
    }
  };
}

// Export for use in other modules
if (typeof module !== "undefined" && module.exports) {
  module.exports = {
    APIClient,
    APIError,
    ValidationError,
    NetworkError,
    showLoading,
    hideLoading,
    showInlineLoading,
    hideInlineLoading,
    showContainerLoading,
    hideContainerLoading,
    withLoading,
  };
}
