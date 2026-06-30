// Prevent default form submissions globally to bypass iframe sandboxing restrictions in preview modes
if (typeof window._globalSubmitPreventionInstalled === "undefined") {
  window._globalSubmitPreventionInstalled = true;

  // Intercept all submit events in the capturing phase to prevent native browser submission
  document.addEventListener("submit", function(e) {
    e.preventDefault();
  }, true);

  // Intercept click events on submit buttons in the capturing phase to prevent native action and dispatch JS submit
  document.addEventListener("click", function(e) {
    // Select any button that acts as a submit button: either explicitly type="submit",
    // or a button without any type attribute inside a form, or input[type="submit"]
    const btn = e.target.closest('button[type="submit"], input[type="submit"], button:not([type])');
    if (btn) {
      const form = btn.closest("form");
      if (form) {
        // Trigger native HTML5 validation UI if form is invalid
        if (typeof form.reportValidity === "function" && !form.reportValidity()) {
          e.preventDefault();
          return;
        }
        e.preventDefault();
        // Dispatch custom submit event so JS event listeners run
        const submitEvent = new Event("submit", {
          bubbles: true,
          cancelable: true
        });
        form.dispatchEvent(submitEvent);
      }
    }
  }, true);

  // Intercept Enter keypress inside form inputs to prevent native browser submission triggering sandbox warning
  document.addEventListener("keydown", function(e) {
    if (e.key === "Enter") {
      const target = e.target;
      if (target && target.tagName === "INPUT" && !["button", "submit", "reset", "checkbox", "radio", "file"].includes(target.type)) {
        const form = target.closest("form");
        if (form) {
          e.preventDefault(); // Stop native submission initiation!
          
          // Trigger the submit event programmatically, or find the submit button and click it
          const submitBtn = form.querySelector('button[type="submit"], input[type="submit"], button:not([type])');
          if (submitBtn) {
            submitBtn.click();
          } else {
            // Dispatch custom submit event directly
            const submitEvent = new Event("submit", {
              bubbles: true,
              cancelable: true
            });
            form.dispatchEvent(submitEvent);
          }
        }
      }
    }
  }, true);
}

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
  _buildHeaders(customHeaders = {}, skipAuth = false, endpoint = null) {
    const headers = {
      Accept: "application/json",
      ...NGROK_HEADER,
      ...customHeaders,
    };

    // Add JWT token if exists and auth is not skipped
    if (!skipAuth) {
      const token = this.getToken();
      if (token) {
        headers["Authorization"] = `Bearer ${token}`;
      }
    }

    // Automatically inject the active organization context if present
    if (!skipAuth && !headers["X-Organization-Id"]) {
      // Do not inject X-Organization-Id for onboarding/payment, auth, and global organization routes
      const isOnboarding = endpoint && (endpoint.includes("/payment/") || endpoint.includes("/corporate-email"));
      const isAuth = endpoint && (endpoint.includes("auth/") || endpoint.includes("/auth/"));
      const isGlobalOrgRoute = endpoint && (
        endpoint.includes("organizations/my-workspaces") ||
        endpoint.includes("organizations/initiate") ||
        endpoint.includes("organizations/invitations")
      );
      
      const shouldSkipOrgHeader = isOnboarding || isAuth || isGlobalOrgRoute;
      
      if (!shouldSkipOrgHeader) {
        let endpointOrgId = null;
        if (endpoint) {
          const match = endpoint.match(/^\/?organizations\/([^/]+)/);
          if (match && match[1]) {
            const segment = match[1];
            // Exclude static non-ID paths
            const staticRoutes = ["details", "my-workspaces", "members", "invitations", "initiate"];
            if (!staticRoutes.includes(segment)) {
              endpointOrgId = segment;
            }
          }
        }

        if (endpointOrgId) {
          headers["X-Organization-Id"] = endpointOrgId;
        } else if (window.organizationManager && typeof window.organizationManager.getActiveOrgId === "function") {
          const activeOrgId = window.organizationManager.getActiveOrgId();
          if (activeOrgId) {
            headers["X-Organization-Id"] = activeOrgId;
          }
        }
      }
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
    let fullURL = `${this.baseURL}${cleanEndpoint}`;

    // Ensure HTTPS is used for all API requests (Requirement 15.5)
    if (!fullURL.startsWith("https://")) {
      console.error(
        "[APIClient] Security Error: All API requests must use HTTPS",
      );
      throw new Error("Security Error: API requests must use HTTPS");
    }

    // Append ngrok bypass query parameter to prevent browser warning intercept on CORS preflights
    const separator = fullURL.includes("?") ? "&" : "?";
    fullURL = `${fullURL}${separator}ngrok-skip-browser-warning=true`;

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
    if (window.location.pathname !== "/login") {
      window.location.href = "/login?session_expired=true";
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
   * @param {Response} response - Fetch response
   * @param {boolean} skipAuth - If true, do not redirect on 401 (public endpoint)
   */
  async _handleResponse(response, skipAuth = false) {
    // Handle 403 Forbidden (Organization membership/access errors)
    if (response.status === 403) {
      const errorData = await response.json().catch(() => ({}));
      const message = errorData.message || "Forbidden";
      const error = new APIError(message, 403, errorData);

      const isNotMemberError =
        message.toLowerCase().includes("not a member") ||
        message.toLowerCase().includes("not member") ||
        message.toLowerCase().includes("membership");

      if (isNotMemberError && window.organizationManager && window.organizationManager.isOrgContext()) {
        console.warn("[APIClient] Received 403 Forbidden indicating not a member of organization. Clearing context.");
        window.organizationManager.clearActiveOrg();
        if (
          typeof window !== "undefined" &&
          window.location &&
          typeof window.location.reload === "function" &&
          (!window.navigator || !window.navigator.userAgent || !window.navigator.userAgent.includes("jsdom"))
        ) {
          window.location.reload();
        }
      }

      if (typeof ErrorHandler !== "undefined") {
        ErrorHandler.handleAPIError(error);
      }

      throw error;
    }

    // Handle 401 Unauthorized — read body to get the actual backend message
    if (response.status === 401) {
      const errorData = await response.json().catch(() => ({}));
      const message = errorData.message || "Unauthorized";
      const error = new APIError(message, 401, errorData);

      // Only redirect to login for session expiry, not for login failures,
      // and not for public endpoints (skipAuth === true)
      const isLoginEndpoint =
        response.url && response.url.includes("auth/login");
      if (!isLoginEndpoint && !skipAuth) {
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

      // Destructure known options so they don't leak into fetchOptions
      const { headers: customHeaders, skipAuth, ...fetchExtra } = options;

      // Build headers — skipAuth omits Authorization header for public endpoints
      const headers = this._buildHeaders(customHeaders || {}, skipAuth || false, endpoint);

      // Add Content-Type for requests with body
      if (data && ["POST", "PUT", "PATCH"].includes(method)) {
        if (!(typeof FormData !== "undefined" && data instanceof FormData)) {
          headers["Content-Type"] = "application/json";
        }
      }

      // Build fetch options — spread fetchExtra (without headers/skipAuth) to avoid overwriting
      const fetchOptions = {
        method,
        headers,
        ...fetchExtra,
      };

      // Add body for POST/PUT/PATCH
      if (data) {
        fetchOptions.body = (typeof FormData !== "undefined" && data instanceof FormData) ? data : JSON.stringify(data);
      }

      // Apply request interceptors
      for (const interceptor of this.requestInterceptors) {
        await interceptor(fetchOptions);
      }

      // Execute fetch
      console.log(`[APIClient] ${method} ${url}`, { headers: { ...headers }, body: fetchOptions.body ? "(has body)" : "(no body)" });
      const response = await fetch(url, fetchOptions);

      // Apply response interceptors
      for (const interceptor of this.responseInterceptors) {
        await interceptor(response);
      }

      // Handle response — pass skipAuth so public endpoints don't trigger login redirect
      return await this._handleResponse(response, skipAuth || false);
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

function _escapeHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

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
      <div class="cyber-loading-text" id="cyber-loading-message">${_escapeHtml(message)}</div>
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
      <span class="cyber-loading-dots">${_escapeHtml(message)}</span>
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
      <div class="cyber-loading-text">${_escapeHtml(message)}</div>
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

/* ═══════════════════════════════════════════════════════════════════════
   SCANNER API MODULE
   Centralized scanning API functions — all 9 endpoints.
   Requires: APIClient class (above), API_BASE_URL, JWT_STORAGE_KEY constants.
   Exposed on window.scannerAPI for use by scan-manager.js, scan-progress.js, etc.
═══════════════════════════════════════════════════════════════════════ */
(function () {
  "use strict";

  // Local cache/store for mock frontend scans and findings
  const mockFrontendScans = {};
  const mockFrontendFindings = {};

  /**
   * Internal helper — performs an authenticated fetch using the same
   * base URL and headers as APIClient.
   * Parses JSON and checks data.status === "success".
   * @param {string} method  HTTP method
   * @param {string} path    API path (no leading slash needed)
   * @param {Object} [body]  Request body (for POST/PATCH)
   * @returns {Promise<Object>} Parsed response data
   */
  async function _apiFetch(method, path, body) {
    const token = localStorage.getItem(JWT_STORAGE_KEY);
    const activeOrgId = localStorage.getItem("cyberguard_active_org_id");
    const headers = {
      Accept: "application/json",
      "ngrok-skip-browser-warning": "true",
    };
    if (token) headers["Authorization"] = `Bearer ${token}`;
    if (body) headers["Content-Type"] = "application/json";
    if (activeOrgId) headers["X-Organization-Id"] = activeOrgId;

    // Strip leading slash so we don't double-slash with base URL
    const cleanPath = path.replace(/^\//, "");
    const url = API_BASE_URL + cleanPath;

    let response;
    try {
      response = await fetch(url, {
        method,
        headers,
        ...(body ? { body: JSON.stringify(body) } : {}),
      });
    } catch (err) {
      throw new NetworkError(`Network request failed: ${err.message}`);
    }

    // Parse body
    let data = {};
    try {
      data = await response.json();
    } catch (_) {
      // Ignore parse errors for empty responses
    }

    if (!response.ok) {
      const msg = data.message || `Request failed (HTTP ${response.status})`;
      throw new APIError(msg, response.status, data);
    }

    return data;
  }

  /**
   * GET /api/scanners
   * Returns list of available scanners grouped ready for UI rendering.
   */
  async function getAvailableScanners() {
    const data = await _apiFetch("GET", "scanners");
    if (data.status !== "success") {
      throw new APIError(data.message || "Failed to load scanners", 0, data);
    }
    return Array.isArray(data.scanners) ? data.scanners : [];
  }

  /**
   * POST /api/scan/start
   * @param {{ target_id: string, driver_ids: string[], flags?: string[] }} params
   */
  async function startScan({ target_id, driver_ids, flags = [] }) {
    if (!target_id) throw new Error("target_id is required");
    if (!Array.isArray(driver_ids) || driver_ids.length === 0) {
      throw new Error("At least one driver_id is required");
    }
    const data = await _apiFetch("POST", "scan/start", {
      target_id,
      driver_ids,
      flags,
    });
    if (data.status !== "success") {
      throw new APIError(data.message || "Failed to start scan", 0, data);
    }
    return data.scan_job;
  }

  /**
   * GET /api/scan/{scanJobId}/status
   * @param {string} scanJobId
   */
  async function getScanStatus(scanJobId) {
    if (!scanJobId) throw new Error("scanJobId is required");
    if (typeof scanJobId === "string" && scanJobId.startsWith("frontend_")) {
      // Always read fresh from localStorage so that fields written by other
      // functions (acquireProgressPageLock, addCompletedFrontendTool, etc.)
      // on the same page are immediately visible — no stale in-memory cache.
      let storedScan = null;
      try {
        const storedScansRaw = localStorage.getItem("cg_frontend_scans");
        if (storedScansRaw) {
          const storedScans = JSON.parse(storedScansRaw);
          storedScan = storedScans.find(s => s.id === scanJobId);
        }
      } catch (_) {}

      if (storedScan) {
        // Keep in-memory cache in sync for callers that reference it directly
        mockFrontendScans[scanJobId] = storedScan;
        return storedScan;
      }

      // Not in localStorage yet — fall back to in-memory or create a stub
      if (!mockFrontendScans[scanJobId]) {
        let targetValue = "Local Target";
        let targetId = "mock-target-id";
        try {
          const pendingRaw = sessionStorage.getItem("cg_pending_scan");
          if (pendingRaw) {
            const pending = JSON.parse(pendingRaw);
            if (pending.sessionId === scanJobId) {
              targetValue = pending.targetValue || targetValue;
              targetId = pending.targetId || targetId;
            }
          }
        } catch (_) {}

        mockFrontendScans[scanJobId] = {
          id: scanJobId,
          status: "running",
          target: {
            id: targetId,
            value: targetValue
          },
          driver_id: ["NETWORK_ANALYSIS"],
          selected_frontend_tools: [],
          completed_frontend_tools: [],
          created_at: new Date().toISOString(),
          finished_at: null
        };
      }
      return mockFrontendScans[scanJobId];
    }
    const data = await _apiFetch("GET", `scan/${scanJobId}/status`);
    if (data.status !== "success") {
      throw new APIError(data.message || "Failed to get scan status", 0, data);
    }
    return data.scan_session;
  }

  /**
   * GET /api/scan/{scanJobId}/findings
   * @param {string} scanJobId
   */
  async function getScanFindings(scanJobId) {
    if (!scanJobId) throw new Error("scanJobId is required");
    if (typeof scanJobId === "string" && scanJobId.startsWith("frontend_")) {
      if (!mockFrontendFindings[scanJobId]) {
        // Try to load from localStorage scan record
        let localFindings = [];
        try {
          const storedScansRaw = localStorage.getItem("cg_frontend_scans");
          if (storedScansRaw) {
            const storedScans = JSON.parse(storedScansRaw);
            const scan = storedScans.find(s => s.id === scanJobId);
            if (scan && Array.isArray(scan.findings)) {
              localFindings = scan.findings;
            }
          }
        } catch (_) {}
        mockFrontendFindings[scanJobId] = localFindings;
      }
      return mockFrontendFindings[scanJobId];
    }
    const data = await _apiFetch("GET", `scan/${scanJobId}/findings`);
    if (data.status !== "success") {
      throw new APIError(data.message || "Failed to get scan findings", 0, data);
    }
    return Array.isArray(data.findings) ? data.findings : [];
  }

  /**
   * GET /api/projects/{projectId}/scans
   * @param {string} projectId
   */
  async function getProjectScans(projectId) {
    if (!projectId) throw new Error("projectId is required");
    const data = await _apiFetch("GET", `projects/${projectId}/scans`);
    if (data.status !== "success") {
      throw new APIError(data.message || "Failed to get project scans", 0, data);
    }
    const apiScans = Array.isArray(data.scans) ? data.scans : [];

    // Fetch and merge local frontend scans for this project
    let localScans = [];
    try {
      const storedScansRaw = localStorage.getItem("cg_frontend_scans");
      if (storedScansRaw) {
        localScans = JSON.parse(storedScansRaw).filter(s => s.project_id === projectId);
      }
    } catch (_) {}

    return [...localScans, ...apiScans];
  }

  /**
   * GET /api/targets/{targetId}/scans
   * @param {string} targetId
   */
  async function getTargetScans(targetId) {
    if (!targetId) throw new Error("targetId is required");
    const data = await _apiFetch("GET", `targets/${targetId}/scans`);
    if (data.status !== "success") {
      throw new APIError(data.message || "Failed to get target scans", 0, data);
    }
    const apiScans = Array.isArray(data.scans) ? data.scans : [];

    // Fetch and merge local frontend scans for this target
    let localScans = [];
    try {
      const storedScansRaw = localStorage.getItem("cg_frontend_scans");
      if (storedScansRaw) {
        localScans = JSON.parse(storedScansRaw).filter(s => s.target_id === targetId);
      }
    } catch (_) {}

    return [...localScans, ...apiScans];
  }

  // Local helper to update status and timestamps in localStorage persistence
  function updateFrontendScanInLocalStorage(scanJobId, status, finishedAt = null, progress = null) {
    try {
      const storedScansRaw = localStorage.getItem("cg_frontend_scans");
      if (storedScansRaw) {
        const storedScans = JSON.parse(storedScansRaw);
        const scan = storedScans.find(s => s.id === scanJobId);
        if (scan) {
          if (status) scan.status = status;
          if (finishedAt) {
            scan.finished_at = finishedAt;
          }
          if (progress !== null) {
            scan.progress = progress;
          }
          localStorage.setItem("cg_frontend_scans", JSON.stringify(storedScans));
        }
      }
    } catch (e) {
      console.error("[APIClient] Failed to update frontend scan in localStorage:", e);
    }
  }

  /**
   * POST /api/scan/{scanJobId}/pause
   * @param {string} scanJobId
   */
  async function pauseScan(scanJobId) {
    if (!scanJobId) throw new Error("scanJobId is required");
    if (typeof scanJobId === "string" && scanJobId.startsWith("frontend_")) {
      if (mockFrontendScans[scanJobId]) {
        mockFrontendScans[scanJobId].status = "pending";
        updateFrontendScanInLocalStorage(scanJobId, "pending");
      }
      return mockFrontendScans[scanJobId];
    }
    const data = await _apiFetch("POST", `scan/${scanJobId}/pause`);
    if (data.status !== "success") {
      throw new APIError(data.message || "Failed to pause scan", 0, data);
    }
    return data; // { status, message, scan_job_status }
  }

  /**
   * POST /api/scan/{scanJobId}/continue
   * @param {string} scanJobId
   */
  async function continueScan(scanJobId) {
    if (!scanJobId) throw new Error("scanJobId is required");
    if (typeof scanJobId === "string" && scanJobId.startsWith("frontend_")) {
      if (mockFrontendScans[scanJobId]) {
        mockFrontendScans[scanJobId].status = "running";
        updateFrontendScanInLocalStorage(scanJobId, "running");
      }
      return mockFrontendScans[scanJobId];
    }
    const data = await _apiFetch("POST", `scan/${scanJobId}/continue`);
    if (data.status !== "success") {
      throw new APIError(data.message || "Failed to resume scan", 0, data);
    }
    return data.scan_job;
  }

  /**
   * POST /api/scan/{scanJobId}/cancel
   * @param {string} scanJobId
   */
  async function cancelScan(scanJobId) {
    if (!scanJobId) throw new Error("scanJobId is required");
    if (typeof scanJobId === "string" && scanJobId.startsWith("frontend_")) {
      if (mockFrontendScans[scanJobId]) {
        mockFrontendScans[scanJobId].status = "cancelled";
        mockFrontendScans[scanJobId].finished_at = new Date().toISOString();
        updateFrontendScanInLocalStorage(scanJobId, "cancelled", mockFrontendScans[scanJobId].finished_at);
      }
      return mockFrontendScans[scanJobId];
    }
    const data = await _apiFetch("POST", `scan/${scanJobId}/cancel`);
    if (data.status !== "success") {
      throw new APIError(data.message || "Failed to cancel scan", 0, data);
    }
    return data.scan_job;
  }

  function completeFrontendScan(scanJobId) {
    if (!mockFrontendScans[scanJobId]) {
      // Try to load it first
      let storedScan = null;
      try {
        const storedScansRaw = localStorage.getItem("cg_frontend_scans");
        if (storedScansRaw) {
          const storedScans = JSON.parse(storedScansRaw);
          storedScan = storedScans.find(s => s.id === scanJobId);
        }
      } catch (_) {}

      mockFrontendScans[scanJobId] = storedScan || {
        id: scanJobId,
        status: "completed",
        driver_id: ["NETWORK_ANALYSIS"],
        created_at: new Date().toISOString(),
      };
    }
    mockFrontendScans[scanJobId].status = "completed";
    mockFrontendScans[scanJobId].finished_at = new Date().toISOString();
    updateFrontendScanInLocalStorage(scanJobId, "completed", mockFrontendScans[scanJobId].finished_at);
  }

  function updateFrontendScanProgress(scanJobId, progress) {
    if (!mockFrontendScans[scanJobId]) {
      // Try to load it first
      let storedScan = null;
      try {
        const storedScansRaw = localStorage.getItem("cg_frontend_scans");
        if (storedScansRaw) {
          const storedScans = JSON.parse(storedScansRaw);
          storedScan = storedScans.find(s => s.id === scanJobId);
        }
      } catch (_) {}

      mockFrontendScans[scanJobId] = storedScan || {
        id: scanJobId,
        status: "running",
        driver_id: ["NETWORK_ANALYSIS"],
        created_at: new Date().toISOString(),
      };
    }
    mockFrontendScans[scanJobId].progress = progress;
    updateFrontendScanInLocalStorage(scanJobId, null, null, progress);
  }

  function addFrontendFinding(scanJobId, finding) {
    if (!mockFrontendFindings[scanJobId]) {
      // Try to load from localStorage first
      let localFindings = [];
      try {
        const storedScansRaw = localStorage.getItem("cg_frontend_scans");
        if (storedScansRaw) {
          const storedScans = JSON.parse(storedScansRaw);
          const scan = storedScans.find(s => s.id === scanJobId);
          if (scan && Array.isArray(scan.findings)) {
            localFindings = scan.findings;
          }
        }
      } catch (_) {}
      mockFrontendFindings[scanJobId] = localFindings;
    }

    if (!mockFrontendFindings[scanJobId].some(f => f.id === finding.id)) {
      mockFrontendFindings[scanJobId].push(finding);
    }

    try {
      const storedScansRaw = localStorage.getItem("cg_frontend_scans");
      if (storedScansRaw) {
        const storedScans = JSON.parse(storedScansRaw);
        const scan = storedScans.find(s => s.id === scanJobId);
        if (scan) {
          if (!scan.findings) scan.findings = [];
          if (!scan.findings.some(f => f.id === finding.id)) {
            scan.findings.push(finding);
          }
          localStorage.setItem("cg_frontend_scans", JSON.stringify(storedScans));
        }
      }
    } catch (e) {
      console.error("[APIClient] Failed to save frontend finding to localStorage:", e);
    }
  }

  function addFrontendLog(scanJobId, line) {
    if (mockFrontendScans[scanJobId]) {
      if (!mockFrontendScans[scanJobId].logs) mockFrontendScans[scanJobId].logs = [];
      mockFrontendScans[scanJobId].logs.push(line);
    }
    try {
      const storedScansRaw = localStorage.getItem("cg_frontend_scans");
      if (storedScansRaw) {
        const storedScans = JSON.parse(storedScansRaw);
        const scan = storedScans.find(s => s.id === scanJobId);
        if (scan) {
          if (!scan.logs) scan.logs = [];
          scan.logs.push(line);
          localStorage.setItem("cg_frontend_scans", JSON.stringify(storedScans));
        }
      }
    } catch (e) {
      console.error("[APIClient] Failed to save frontend log to localStorage:", e);
    }
  }

  function addCompletedFrontendTool(scanJobId, toolId) {
    if (!mockFrontendScans[scanJobId]) {
      let storedScan = null;
      try {
        const storedScansRaw = localStorage.getItem("cg_frontend_scans");
        if (storedScansRaw) {
          const storedScans = JSON.parse(storedScansRaw);
          storedScan = storedScans.find(s => s.id === scanJobId);
        }
      } catch (_) {}

      mockFrontendScans[scanJobId] = storedScan || {
        id: scanJobId,
        status: "running",
        driver_id: ["NETWORK_ANALYSIS"],
        created_at: new Date().toISOString(),
      };
    }
    if (!mockFrontendScans[scanJobId].completed_frontend_tools) {
      mockFrontendScans[scanJobId].completed_frontend_tools = [];
    }
    if (!mockFrontendScans[scanJobId].completed_frontend_tools.includes(toolId)) {
      mockFrontendScans[scanJobId].completed_frontend_tools.push(toolId);
    }

    try {
      const storedScansRaw = localStorage.getItem("cg_frontend_scans");
      if (storedScansRaw) {
        const storedScans = JSON.parse(storedScansRaw);
        const scan = storedScans.find(s => s.id === scanJobId);
        if (scan) {
          if (!scan.completed_frontend_tools) scan.completed_frontend_tools = [];
          if (!scan.completed_frontend_tools.includes(toolId)) {
            scan.completed_frontend_tools.push(toolId);
          }
          localStorage.setItem("cg_frontend_scans", JSON.stringify(storedScans));
        }
      }
    } catch (e) {
      console.error("[APIClient] Failed to save completed frontend tool to localStorage:", e);
    }
  }

  // ── Background Scan Execution & Tab Coordination ───────────────────────
  const tabId = "tab_" + Math.random().toString(36).substring(2, 11);
  let backgroundScanInterval = null;
  let backgroundHeartbeatInterval = null;
  let activeBackgroundScanId = null;

  function initBackgroundScanner() {
    if (typeof window === "undefined" || !window.location) return;
    if (window.location.pathname.includes("/scan/")) {
      return; // Handled by scan-progress.js directly
    }

    // Check every 3 seconds for active running scans
    backgroundScanInterval = setInterval(checkAndRunBackgroundScans, 3000);
    checkAndRunBackgroundScans();
  }

  async function checkAndRunBackgroundScans() {
    if (activeBackgroundScanId) return;

    try {
      const storedScansRaw = localStorage.getItem("cg_frontend_scans");
      if (!storedScansRaw) return;

      const storedScans = JSON.parse(storedScansRaw);
      const runningScan = storedScans.find(s => s.status === "running");
      if (!runningScan) return;

      const scanJobId = runningScan.id;
      const now = Date.now();
      const lockAcquired = acquireScanLock(runningScan, now);
      if (!lockAcquired) return;

      activeBackgroundScanId = scanJobId;
      startHeartbeat(scanJobId);

      await runBackgroundScan(runningScan);
    } catch (e) {
      console.error("[APIClient] Error in checkAndRunBackgroundScans:", e);
      cleanupBackgroundScanState();
    }
  }

  function acquireScanLock(scan, now) {
    const activeTab = scan.active_tab_id;
    const lastHb = scan.last_heartbeat || 0;

    if (!activeTab || activeTab === tabId || (now - lastHb) > 6000) {
      scan.active_tab_id = tabId;
      scan.last_heartbeat = now;

      try {
        const storedScansRaw = localStorage.getItem("cg_frontend_scans");
        if (storedScansRaw) {
          const storedScans = JSON.parse(storedScansRaw);
          const idx = storedScans.findIndex(s => s.id === scan.id);
          if (idx !== -1) {
            storedScans[idx].active_tab_id = tabId;
            storedScans[idx].last_heartbeat = now;
            localStorage.setItem("cg_frontend_scans", JSON.stringify(storedScans));
            return true;
          }
        }
      } catch (_) {}
    }
    return false;
  }

  function startHeartbeat(scanJobId) {
    stopHeartbeat();
    backgroundHeartbeatInterval = setInterval(() => {
      try {
        const storedScansRaw = localStorage.getItem("cg_frontend_scans");
        if (!storedScansRaw) return;
        const storedScans = JSON.parse(storedScansRaw);
        const scan = storedScans.find(s => s.id === scanJobId);

        if (!scan || scan.status !== "running" || scan.active_tab_id !== tabId) {
          stopHeartbeat();
          cleanupBackgroundScanState();
          return;
        }

        scan.last_heartbeat = Date.now();
        localStorage.setItem("cg_frontend_scans", JSON.stringify(storedScans));
      } catch (_) {}
    }, 2000);
  }

  function stopHeartbeat() {
    if (backgroundHeartbeatInterval) {
      clearInterval(backgroundHeartbeatInterval);
      backgroundHeartbeatInterval = null;
    }
  }

  function cleanupBackgroundScanState() {
    activeBackgroundScanId = null;
    stopHeartbeat();
  }

  async function runBackgroundScan(scan) {
    const scanJobId = scan.id;
    const targetValue = scan.target?.value || "unknown";
    const selectedTools = scan.selected_frontend_tools || [];
    const completedTools = scan.completed_frontend_tools || [];
    const remainingTools = selectedTools.filter(t => !completedTools.includes(t));

    if (remainingTools.length === 0) {
      completeFrontendScan(scanJobId);
      cleanupBackgroundScanState();
      return;
    }

    try {
      await ensureNetworkToolsLoaded();
    } catch (e) {
      console.error("[APIClient] Failed to load network analysis tools for background scan:", e);
      cleanupBackgroundScanState();
      return;
    }

    window.onFrontendToolLog = function (msg, scanner) {
      addFrontendLog(scanJobId, `[INFO] [${scanner}] ${msg}`);
    };

    window.onFrontendToolStatus = function (statusText) {
      addFrontendLog(scanJobId, `[SYS] ${statusText}`);
    };

    window.onFrontendToolResult = function ({ timestamp, feature, message, status, details }) {
      let badge = "[INFO]";
      if (status === "danger" || status === "threat") badge = "[ERROR]";
      else if (status === "warning") badge = "[WARN]";
      else if (status === "success" || status === "safe") badge = "[LIVE]";

      const logLine = `${badge} [${feature}] ${message}`;
      addFrontendLog(scanJobId, logLine);

      if (status === "danger" || status === "threat" || status === "success" || status === "safe" || message.includes("COMPLETE") || message.includes("Detailed")) {
        const severity = (status === "danger" || status === "threat") ? "high" : (status === "warning" ? "medium" : "info");
        const finding = {
          id: `net-${feature.toLowerCase().replace(/\s+/g, "-")}-${Date.now()}`,
          title: `${feature}: Analysis Complete`,
          severity: severity,
          status: "open",
          driver_id: feature.toUpperCase().replace(/\s+/g, "_"),
          description: message,
          created_at: new Date().toISOString()
        };
        addFrontendFinding(scanJobId, finding);
      }
    };

    addFrontendLog(scanJobId, `[SYS] Resuming scan in background. Remaining tools: ${remainingTools.length}`);

    const originalSelectedTools = scan.selected_frontend_tools || remainingTools;

    for (let i = 0; i < remainingTools.length; i++) {
      const currentScanState = await getScanStatus(scanJobId);
      if (currentScanState.status !== "running" || currentScanState.active_tab_id !== tabId) {
        break;
      }

      const toolId = remainingTools[i];
      const completedCount = originalSelectedTools.length - remainingTools.length;
      const progressPercent = Math.round(((completedCount + i) / originalSelectedTools.length) * 100);
      updateFrontendScanProgress(scanJobId, progressPercent);

      addFrontendLog(scanJobId, `[SYS] Initialising ${toolId.replace("net-", "").replace("frontend-", "").toUpperCase().replace("-", " ")}…`);

      try {
        if (toolId === "net-port-scanner" || toolId === "frontend-port-scanner") {
          await window.portScan(targetValue);
        } else if (toolId === "net-tcp-connectivity" || toolId === "frontend-tcp-connectivity") {
          await window.realTcpPortScan(targetValue);
        } else if (toolId === "net-udp-services" || toolId === "frontend-udp-services") {
          await window.realUdpConnectivityTest(targetValue);
        } else if (toolId === "net-ip-geolocation" || toolId === "frontend-ip-geolocation") {
          await window.ipGeolocation(targetValue);
        } else if (toolId === "net-reverse-dns" || toolId === "frontend-reverse-dns") {
          await window.reverseDns(targetValue);
        } else if (toolId === "net-whois-lookup" || toolId === "frontend-whois-lookup") {
          await window.whoisLookup(targetValue);
        }
      } catch (err) {
        console.error(`[Background Tool Error] ${toolId}:`, err);
        addFrontendLog(scanJobId, `[ERROR] [${toolId}] Execution failed: ${err.message}`);
      }

      addCompletedFrontendTool(scanJobId, toolId);
    }

    const finalScanState = await getScanStatus(scanJobId);
    if (finalScanState.status === "running" && finalScanState.active_tab_id === tabId) {
      const updatedCompleted = finalScanState.completed_frontend_tools || [];
      const stillRemaining = originalSelectedTools.filter(t => !updatedCompleted.includes(t));
      if (stillRemaining.length === 0) {
        updateFrontendScanProgress(scanJobId, 100);
        addFrontendLog(scanJobId, "[SYS] All selected network analysis tools completed.");
        completeFrontendScan(scanJobId);
      }
    }

    cleanupBackgroundScanState();
  }

  function ensureNetworkToolsLoaded() {
    if (window.portScan && window.whoisLookup && window.ipGeolocation) {
      return Promise.resolve();
    }
    return new Promise((resolve, reject) => {
      let script = document.querySelector('script[src*="network-analysis-tools.js"]');
      if (!script) {
        script = document.createElement("script");
        script.src = "/js/network-analysis-tools.js";
        document.head.appendChild(script);
      }
      script.addEventListener("load", () => resolve());
      script.addEventListener("error", (e) => reject(e));
    });
  }

  /* ── Expose on window ─────────────────────────────────────────────────── */
  window.scannerAPI = {
    getAvailableScanners,
    startScan,
    getScanStatus,
    getScanFindings,
    getProjectScans,
    getTargetScans,
    pauseScan,
    continueScan,
    cancelScan,
    completeFrontendScan,
    updateFrontendScanProgress,
    addFrontendFinding,
    addFrontendLog,
    addCompletedFrontendTool,
    tabId,
  };

  // Start background scanner after DOM and scripts have initialized
  setTimeout(initBackgroundScanner, 1000);
})();

// Transient in-memory storage for user API keys
window.userApiKeys = {};

// Retrieve an API key from transient memory
window.getApiKey = function (serviceName) {
  if (!serviceName) return "";
  let name = serviceName.toLowerCase().replace(/[^a-z0-9_]/g, "");
  // Map legacy names to service names in backend response
  if (name === "vtapikey") name = "virustotal";
  if (name === "whoisapikey") name = "whoisxml";
  if (name === "shodanapikey") name = "shodan";
  if (name === "urlscanapikey") name = "urlscan";
  if (name === "abuseipdbapikey") name = "abuseipdb";

  const serviceData = window.userApiKeys[name];
  if (serviceData && serviceData.has_key) {
    return serviceData.key || "";
  }
  return "";
};

// Fetch API keys from the backend API and update transient cache
window.fetchUserApiKeys = async function () {
  // Clean up any legacy localStorage keys left from the frontend side for security
  const legacyKeys = ["vtApiKey", "whoisApiKey", "shodanApiKey", "urlscanApiKey", "abuseipdbApiKey", "abuseipdb_api_key", "abuseipdb_key"];
  legacyKeys.forEach(k => localStorage.removeItem(k));

  // If there is no auth token, we skip fetching
  const client = new APIClient();
  if (!client.getToken()) {
    window.userApiKeys = {};
    return {};
  }

  try {
    const data = await client.get("apiKeys");
    if (data) {
      window.userApiKeys = data;
      document.dispatchEvent(new CustomEvent("cyberguard:apiKeysLoaded"));
      return data;
    }
  } catch (e) {
    console.error("[APIClient] Failed to fetch user API keys:", e);
  }
  return {};
};

if (typeof window !== "undefined") {
  window.APIClient = APIClient;
  window.APIError = APIError;
  window.ValidationError = ValidationError;
  window.NetworkError = NetworkError;
  
  if (typeof window.apiClient === "undefined") {
    window.apiClient = new APIClient();
  }
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
