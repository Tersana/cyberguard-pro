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
  const RECENT_SCAN_KEY = "cg_recent_scan_sessions";
  const RECENT_FINDINGS_KEY = "cg_recent_scan_findings";
  const RECENT_SCAN_LIMIT = 100;
  const RECENT_FINDINGS_PER_SCAN_LIMIT = 500;

  // Findings produced by discovery-style scanners (web endpoint fuzzer / classifier /
  // wayback / url-fuzz) are inventory, not vulnerabilities. Matched against a finding's
  // driver_id / tool / title.
  const DISCOVERY_RE = /endpoint[-_\s]?fuzzer|web_endpoint_fuzzer|waybackurls|classifier|url[-_\s]?fuzz|high risk endpoint/;
  // User preference: fold discovery findings back into vuln counts/cards/risk.
  const INCLUDE_DISCOVERY_KEY = "cyberguard_include_discovery";
  // Promotion (discovery endpoint -> real finding) depends on a backend endpoint that is
  // not live yet. Keep the UI + wiring off until it ships, then flip to true.
  const PROMOTE_ENABLED = false;

  function safeJsonParse(raw, fallback) {
    if (!raw) return fallback;
    try {
      return JSON.parse(raw);
    } catch (_) {
      return fallback;
    }
  }

  function sameId(a, b) {
    return a !== undefined && a !== null && b !== undefined && b !== null && String(a) === String(b);
  }

  function firstValue(...values) {
    for (const value of values) {
      if (value !== undefined && value !== null && value !== "") return value;
    }
    return null;
  }

  function asArray(value) {
    if (Array.isArray(value)) return value;
    if (value === undefined || value === null || value === "") return [];
    return [value];
  }

  function getRawScan(item) {
    if (!item || typeof item !== "object") return {};
    return item.scan_session || item.scan_job || item.scan || item.session || item;
  }

  function normalizeDriverIds(raw, metadata = {}) {
    const candidates = [
      raw.driver_ids,
      raw.driver_id,
      raw.scanner_ids,
      raw.scanner_id,
      raw.tool,
      raw.tool_id,
      raw.type,
      raw.name,
      metadata.driver_id,
      metadata.driver_ids,
      metadata.scanner,
      metadata.scanner_name,
      metadata.tool,
    ];
    const flattened = [];
    candidates.forEach(value => {
      asArray(value).forEach(item => {
        if (item && typeof item === "object") {
          flattened.push(item.id || item.name || item.slug || item.driver_id || "");
        } else {
          flattened.push(item);
        }
      });
    });
    return Array.from(new Set(flattened.map(v => String(v || "").trim()).filter(Boolean)));
  }

  function normalizeScanRecord(item, fallback = {}) {
    const raw = getRawScan(item);
    const rawMetadata = raw.metadata && typeof raw.metadata === "object" ? raw.metadata : {};
    const itemMetadata = item && item.metadata && typeof item.metadata === "object" ? item.metadata : {};
    const fallbackMetadata = fallback.metadata && typeof fallback.metadata === "object" ? fallback.metadata : {};
    const metadata = { ...itemMetadata, ...rawMetadata, ...fallbackMetadata };

    const id = firstValue(
      raw.id,
      raw.scan_id,
      raw.scan_job_id,
      raw.scan_session_id,
      raw.job_id,
      fallback.id,
      fallback.scanJobId,
    );
    if (!id) return null;

    const targetObj = raw.target && typeof raw.target === "object" ? raw.target : {};
    const projectObj = raw.project && typeof raw.project === "object" ? raw.project : {};
    const targetId = firstValue(
      raw.target_id,
      targetObj.id,
      targetObj.target_id,
      metadata.target_id,
      fallback.target_id,
      fallback.targetId,
    );
    const projectId = firstValue(
      raw.project_id,
      projectObj.id,
      targetObj.project_id,
      metadata.project_id,
      fallback.project_id,
      fallback.projectId,
    );
    const targetValue = firstValue(
      targetObj.value,
      targetObj.url,
      targetObj.host,
      targetObj.name,
      raw.target_value,
      raw.target_name,
      metadata.target_name,
      metadata.target_value,
      fallback.target_value,
      fallback.targetValue,
    );
    const triggerUser = firstValue(
      raw.triggered_by,
      raw.user && (raw.user.name || raw.user.full_name || raw.user.email),
      metadata.triggered_by,
      fallback.triggered_by,
      fallback.triggeredBy,
    );
    const startedAt = firstValue(raw.started_at, raw.created_at, raw.timestamp, fallback.started_at, fallback.startedAt);
    const createdAt = firstValue(raw.created_at, startedAt, fallback.created_at, fallback.startedAt);
    const finishedAt = firstValue(raw.finished_at, raw.completed_at, raw.ended_at, fallback.finished_at, fallback.finishedAt);
    const normalizedMetadata = {
      ...metadata,
      ...(targetValue && !metadata.target_name ? { target_name: targetValue } : {}),
      ...(triggerUser && !metadata.triggered_by ? { triggered_by: triggerUser } : {}),
      ...(projectId && !metadata.project_id ? { project_id: projectId } : {}),
      ...(targetId && !metadata.target_id ? { target_id: targetId } : {}),
    };

    return {
      ...raw,
      id: String(id),
      scan_job_id: String(id),
      status: String(firstValue(raw.status, fallback.status, "unknown")).toLowerCase(),
      project_id: projectId !== null ? String(projectId) : null,
      target_id: targetId !== null ? String(targetId) : null,
      target: {
        ...targetObj,
        ...(targetId !== null ? { id: String(targetId) } : {}),
        ...(targetValue ? { value: targetValue, name: targetObj.name || targetValue } : {}),
      },
      project: {
        ...projectObj,
        ...(projectId !== null ? { id: String(projectId) } : {}),
      },
      driver_id: normalizeDriverIds(raw, normalizedMetadata),
      metadata: normalizedMetadata,
      started_at: startedAt || null,
      created_at: createdAt || null,
      finished_at: finishedAt || null,
      completed_at: raw.completed_at || finishedAt || null,
      progress: raw.progress ?? fallback.progress ?? null,
      source: fallback.source || raw.source || (String(id).startsWith("frontend_") ? "frontend" : "api"),
      remembered_at: raw.remembered_at || new Date().toISOString(),
    };
  }

  function normalizeFindingRecord(item, scanContext = {}) {
    const raw = item && (item.finding || item.vulnerability || item) || {};
    const scan = normalizeScanRecord(scanContext, {}) || scanContext || {};
    const metadata = raw.metadata && typeof raw.metadata === "object" ? raw.metadata : {};
    const scanId = firstValue(raw.scan_job_id, raw.scan_id, raw.scan_session_id, raw.scanJobId, scan.id, scan.scan_job_id);
    const projectId = firstValue(raw.project_id, metadata.project_id, scan.project_id);
    const targetId = firstValue(raw.target_id, raw.target && raw.target.id, metadata.target_id, scan.target_id);
    const title = firstValue(raw.title, raw.name, raw.path, raw.url, raw.affected_url, raw.endpoint, "Finding");
    const affectedUrl = firstValue(raw.affected_url, raw.url, raw.endpoint, raw.path, metadata.affected_url);
    const id = firstValue(raw.id, raw.finding_id, raw.uuid, scanId ? `${scanId}:${title}:${affectedUrl || ""}:${raw.severity || ""}` : null);

    return {
      ...raw,
      id: String(id || `${title}:${Date.now()}`),
      scan_job_id: scanId ? String(scanId) : null,
      project_id: projectId !== null ? String(projectId) : null,
      target_id: targetId !== null ? String(targetId) : null,
      title,
      severity: String(firstValue(raw.severity, metadata.severity, "info")).toLowerCase(),
      status: String(firstValue(raw.status, metadata.status, "open")).toLowerCase(),
      driver_id: firstValue(raw.driver_id, raw.tool, raw.scanner_id, raw.scanner, scan.driver_id && scan.driver_id[0], null),
      affected_url: affectedUrl || null,
      target: raw.target || scan.target || null,
      target_name: firstValue(raw.target_name, raw.target && (raw.target.value || raw.target.name), scan.metadata && scan.metadata.target_name),
      project_name: firstValue(raw.project_name, scan.project && scan.project.name, null),
      created_at: firstValue(raw.created_at, raw.timestamp, new Date().toISOString()),
      metadata,
    };
  }

  function getStoredFrontendScans() {
    const stored = safeJsonParse(localStorage.getItem("cg_frontend_scans"), []);
    return Array.isArray(stored) ? stored : [];
  }

  function readRecentScans() {
    const stored = safeJsonParse(localStorage.getItem(RECENT_SCAN_KEY), []);
    return (Array.isArray(stored) ? stored : []).map(scan => normalizeScanRecord(scan)).filter(Boolean);
  }

  function writeRecentScans(scans) {
    try {
      localStorage.setItem(RECENT_SCAN_KEY, JSON.stringify(scans.slice(0, RECENT_SCAN_LIMIT)));
    } catch (err) {
      console.warn("[ScannerAPI] Failed to write recent scan cache:", err);
    }
  }

  function readRecentFindingsMap() {
    const stored = safeJsonParse(localStorage.getItem(RECENT_FINDINGS_KEY), {});
    return stored && typeof stored === "object" && !Array.isArray(stored) ? stored : {};
  }

  function writeRecentFindingsMap(map) {
    try {
      localStorage.setItem(RECENT_FINDINGS_KEY, JSON.stringify(map));
    } catch (err) {
      console.warn("[ScannerAPI] Failed to write recent finding cache:", err);
    }
  }

  function getScanSortTime(scan) {
    const t = Date.parse(scan.started_at || scan.created_at || scan.finished_at || scan.remembered_at || 0);
    return Number.isNaN(t) ? 0 : t;
  }

  function dedupeScans(scans) {
    const map = new Map();
    scans.filter(Boolean).forEach(scan => {
      const normalized = normalizeScanRecord(scan);
      if (!normalized) return;
      const prev = map.get(normalized.id);
      map.set(normalized.id, prev ? { ...prev, ...normalized, metadata: { ...(prev.metadata || {}), ...(normalized.metadata || {}) } } : normalized);
    });
    return Array.from(map.values()).sort((a, b) => getScanSortTime(b) - getScanSortTime(a));
  }

  function dedupeFindings(findings) {
    const map = new Map();
    findings.filter(Boolean).forEach(finding => {
      const key = String(finding.id || `${finding.scan_job_id || ""}:${finding.title || ""}:${finding.affected_url || ""}`);
      if (!map.has(key)) map.set(key, finding);
    });
    return Array.from(map.values()).sort((a, b) => {
      const bTime = Date.parse(b.created_at || b.timestamp || 0);
      const aTime = Date.parse(a.created_at || a.timestamp || 0);
      return (Number.isNaN(bTime) ? 0 : bTime) - (Number.isNaN(aTime) ? 0 : aTime);
    });
  }

  function rememberScanSession(session, context = {}) {
    const normalized = normalizeScanRecord(session, context);
    if (!normalized) return null;
    const scans = dedupeScans([normalized, ...readRecentScans()]).slice(0, RECENT_SCAN_LIMIT);
    writeRecentScans(scans);
    return normalized;
  }

  function findCachedScan(scanJobId) {
    const id = String(scanJobId || "");
    return readRecentScans().find(scan => scan.id === id || scan.scan_job_id === id) || null;
  }

  function rememberScanFindings(scanJobId, findings, scanContext = {}) {
    let resolvedScanJobId = scanJobId;
    let resolvedFindings = findings;
    let resolvedContext = scanContext;
    if (Array.isArray(scanJobId)) {
      resolvedFindings = scanJobId;
      resolvedContext = findings || {};
      resolvedScanJobId = resolvedContext.id || resolvedContext.scan_job_id;
    }
    const cachedScan = findCachedScan(resolvedScanJobId) || normalizeScanRecord(resolvedContext, { id: resolvedScanJobId });
    const scanId = String(resolvedScanJobId || cachedScan?.id || "");
    if (!scanId || !Array.isArray(resolvedFindings)) return [];

    const normalizedFindings = dedupeFindings(
      resolvedFindings.map(f => normalizeFindingRecord(f, cachedScan || { id: scanId })),
    ).slice(0, RECENT_FINDINGS_PER_SCAN_LIMIT);

    const map = readRecentFindingsMap();
    map[scanId] = { updated_at: new Date().toISOString(), scan: cachedScan || { id: scanId }, findings: normalizedFindings };
    writeRecentFindingsMap(map);
    return normalizedFindings;
  }

  function getRecentFindingsForProject(projectId) {
    const map = readRecentFindingsMap();
    const scansById = new Map(readRecentScans().map(scan => [scan.id, scan]));
    const findings = [];
    Object.entries(map).forEach(([scanId, entry]) => {
      const scan = normalizeScanRecord(entry.scan || scansById.get(scanId) || { id: scanId });
      if (!scan || !sameId(scan.project_id, projectId)) return;
      asArray(entry.findings).forEach(f => findings.push(normalizeFindingRecord(f, scan)));
    });
    return dedupeFindings(findings);
  }

  function getRecentFindingsForTarget(targetId) {
    const map = readRecentFindingsMap();
    const scansById = new Map(readRecentScans().map(scan => [scan.id, scan]));
    const findings = [];
    Object.entries(map).forEach(([scanId, entry]) => {
      const scan = normalizeScanRecord(entry.scan || scansById.get(scanId) || { id: scanId });
      if (!scan || !sameId(scan.target_id, targetId)) return;
      asArray(entry.findings).forEach(f => findings.push(normalizeFindingRecord(f, scan)));
    });
    return dedupeFindings(findings);
  }

  function getRecentScansForProject(projectId) {
    return readRecentScans().filter(scan => sameId(scan.project_id, projectId));
  }

  function getRecentScansForTarget(targetId) {
    return readRecentScans().filter(scan => sameId(scan.target_id, targetId));
  }

  function isFuzzerScan(scan) {
    const normalized = normalizeScanRecord(scan) || {};
    const haystack = [
      normalized.id,
      normalized.driver_id,
      normalized.selected_frontend_tools,
      normalized.metadata && Object.values(normalized.metadata),
      normalized.logs,
    ].flat(3).map(v => String(v || "").toLowerCase()).join(" ");
    return DISCOVERY_RE.test(haystack);
  }

  /**
   * True when a finding is discovery/inventory output (e.g. web endpoint fuzzer) rather
   * than a real vulnerability. An explicit backend flag wins over the heuristic so that a
   * promoted finding, or a backend that tags discovery findings, is always honored.
   */
  function isDiscoveryFinding(finding) {
    if (!finding || typeof finding !== "object") return false;
    if (finding.promoted === true || finding.is_discovery === false) return false;
    if (finding.is_discovery === true || finding.category === "discovery") return true;
    const haystack = [finding.driver_id, finding.tool, finding.title]
      .map(v => String(v || "").toLowerCase()).join(" ");
    return DISCOVERY_RE.test(haystack);
  }

  /**
   * Normalize a URL/path for grouping duplicate discovered endpoints. Drops scheme, lowercases
   * the host, and collapses a trailing slash. Falls back to the raw lowercased string when the
   * value is not a parseable URL (e.g. a bare path).
   */
  function normalizeEndpointUrl(url) {
    const raw = String(url || "").trim();
    if (!raw) return "";
    // Bare path (no scheme, starts with "/"): normalize without URL parsing.
    if (!raw.includes("://") && raw.startsWith("/")) {
      return raw.toLowerCase().replace(/\/+$/, "") || "/";
    }
    try {
      const u = new URL(raw.includes("://") ? raw : `http://${raw}`);
      const path = u.pathname.replace(/\/+$/, "") || "/";
      return `${u.host.toLowerCase()}${path}${u.search}`;
    } catch (_) {
      return raw.toLowerCase().replace(/\/+$/, "");
    }
  }

  /** Split findings into { vulnerabilities, discovery } using isDiscoveryFinding. */
  function partitionFindings(findings) {
    const vulnerabilities = [];
    const discovery = [];
    (Array.isArray(findings) ? findings : []).forEach(f => {
      (isDiscoveryFinding(f) ? discovery : vulnerabilities).push(f);
    });
    return { vulnerabilities, discovery };
  }

  /** Whether discovery findings should be folded back into vuln counts/cards/risk. */
  function getIncludeDiscovery() {
    return localStorage.getItem(INCLUDE_DISCOVERY_KEY) === "true";
  }

  function setIncludeDiscovery(value) {
    try {
      localStorage.setItem(INCLUDE_DISCOVERY_KEY, value ? "true" : "false");
    } catch (err) {
      console.warn("[ScannerAPI] Failed to persist include-discovery preference:", err);
    }
  }

  /** Feature flag: is the promote-to-finding flow wired to a live backend endpoint? */
  function isPromoteEnabled() {
    return PROMOTE_ENABLED;
  }

  /**
   * PATCH /api/findings/{id}/promote — reclassify a discovery finding as a real vulnerability.
   * Backend dependency: endpoint returns the updated finding (with promoted: true /
   * is_discovery: false). Gated by PROMOTE_ENABLED until the backend ships it.
   */
  async function promoteFinding(findingId) {
    if (!findingId) throw new Error("findingId is required");
    const data = await _apiFetch("PATCH", `findings/${findingId}/promote`);
    return data.finding || data;
  }

  function getScanDisplayPrefix(scan) {
    const normalized = normalizeScanRecord(scan) || {};
    if (isFuzzerScan(normalized)) return "FUZZ";
    const tools = normalized.selected_frontend_tools || [];
    const drivers = normalizeDriverIds(normalized, normalized.metadata || {});
    const values = [...tools, ...drivers].map(v => String(v || "").toLowerCase());
    if (values.some(v => v.includes("port-scanner") || v.includes("port scanner"))) return "PORT";
    if (values.some(v => v.includes("tcp-connectivity") || v.includes("tcp connectivity"))) return "TCP";
    if (values.some(v => v.includes("udp-services") || v.includes("udp services"))) return "UDP";
    if (values.some(v => v.includes("ip-geolocation") || v.includes("ip geolocation"))) return "GEO";
    if (values.some(v => v.includes("reverse-dns") || v.includes("reverse dns"))) return "RDNS";
    if (values.some(v => v.includes("whois-lookup") || v.includes("whois lookup") || v.includes("whois"))) return "WHOIS";
    if (values.some(v => v.includes("network_analysis"))) return "NET";
    return "SCAN";
  }

  function formatScanShortId(scan) {
    const normalized = normalizeScanRecord(scan) || {};
    const scanId = String(normalized.id || "");
    const prefix = getScanDisplayPrefix(normalized);
    if (!scanId) return "SCAN";
    if (scanId.startsWith("frontend_")) return `${prefix}-${scanId.replace("frontend_", "").substring(0, 6).toUpperCase()}`;
    if (prefix !== "SCAN") return `${prefix}-${scanId.substring(0, 6).toUpperCase()}`;
    return scanId.substring(0, 8).toUpperCase();
  }

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
    const scanJob = data.scan_job || data.scan_session || { id: data.scan_session_id || data.session_id || data.id };
    return rememberScanSession(scanJob, {
      target_id,
      driver_ids,
      status: "running",
      source: "api",
      started_at: new Date().toISOString(),
    }) || scanJob;
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
        return rememberScanSession(storedScan, { source: "frontend" }) || storedScan;
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
      return rememberScanSession(mockFrontendScans[scanJobId], { source: "frontend" }) || mockFrontendScans[scanJobId];
    }
    const data = await _apiFetch("GET", `scan/${scanJobId}/status`);
    if (data.status !== "success") {
      throw new APIError(data.message || "Failed to get scan status", 0, data);
    }
    const session = data.scan_session || data.scan_job || { id: scanJobId };
    return rememberScanSession(session, { id: scanJobId, source: "api" }) || session;
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
      return rememberScanFindings(scanJobId, mockFrontendFindings[scanJobId], findCachedScan(scanJobId) || { id: scanJobId, source: "frontend" });
    }
    const data = await _apiFetch("GET", `scan/${scanJobId}/findings`);
    if (data.status !== "success") {
      throw new APIError(data.message || "Failed to get scan findings", 0, data);
    }
    const findings = Array.isArray(data.findings) ? data.findings : [];
    return rememberScanFindings(scanJobId, findings, findCachedScan(scanJobId) || { id: scanJobId, source: "api" });
  }

  /**
   * GET /api/projects/{projectId}/scans
   * @param {string} projectId
   */
  async function getProjectScans(projectId) {
    if (!projectId) throw new Error("projectId is required");
    let apiScans = [];
    let apiError = null;

    try {
      const data = await _apiFetch("GET", `projects/${projectId}/scans`);
      if (data.status !== "success") {
        throw new APIError(data.message || "Failed to get project scans", 0, data);
      }
      apiScans = Array.isArray(data.scans) ? data.scans : [];
      apiScans.forEach(scan => rememberScanSession(scan, { project_id: projectId, source: "api" }));
    } catch (err) {
      apiError = err;
      console.warn("[ScannerAPI] Project scans API unavailable; using recent cache fallback:", err.message || err);
    }

    const localScans = getStoredFrontendScans().filter(scan => sameId(scan.project_id, projectId));
    const recentScans = getRecentScansForProject(projectId);
    const merged = dedupeScans([...localScans, ...recentScans, ...apiScans]);
    if (merged.length === 0 && apiError) throw apiError;
    return merged;
  }

  /**
   * GET /api/targets/{targetId}/scans
   * @param {string} targetId
   */
  async function getTargetScans(targetId) {
    if (!targetId) throw new Error("targetId is required");
    let apiScans = [];
    let apiError = null;

    try {
      const data = await _apiFetch("GET", `targets/${targetId}/scans`);
      if (data.status !== "success") {
        throw new APIError(data.message || "Failed to get target scans", 0, data);
      }
      apiScans = Array.isArray(data.scans) ? data.scans : [];
      apiScans.forEach(scan => rememberScanSession(scan, { target_id: targetId, source: "api" }));
    } catch (err) {
      apiError = err;
      console.warn("[ScannerAPI] Target scans API unavailable; using recent cache fallback:", err.message || err);
    }

    const localScans = getStoredFrontendScans().filter(scan => sameId(scan.target_id, targetId));
    const recentScans = getRecentScansForTarget(targetId);
    const merged = dedupeScans([...localScans, ...recentScans, ...apiScans]);
    if (merged.length === 0 && apiError) throw apiError;
    return merged;
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
      return rememberScanSession(mockFrontendScans[scanJobId], { source: "frontend" }) || mockFrontendScans[scanJobId];
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
      return rememberScanSession(mockFrontendScans[scanJobId], { source: "frontend" }) || mockFrontendScans[scanJobId];
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
      return rememberScanSession(mockFrontendScans[scanJobId], { source: "frontend" }) || mockFrontendScans[scanJobId];
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
      if (status === "danger" || status === "threat") {
        badge = message.includes("[SCAN COMPLETE]") ? "[LIVE]" : "[ERROR]";
      }
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
    rememberScanSession,
    rememberScanFindings,
    getRecentScansForProject,
    getRecentScansForTarget,
    getRecentFindingsForProject,
    getRecentFindingsForTarget,
    normalizeScanRecord,
    normalizeFindingRecord,
    formatScanShortId,
    getScanDisplayPrefix,
    isFuzzerScan,
    isDiscoveryFinding,
    normalizeEndpointUrl,
    partitionFindings,
    getIncludeDiscovery,
    setIncludeDiscovery,
    isPromoteEnabled,
    promoteFinding,
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
