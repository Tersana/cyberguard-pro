/**
 * Threat Intel Hub Module
 * Universal threat intelligence aggregation from multiple security APIs
 * Integrates with VirusTotal, AbuseIPDB, and URLScan.io
 */

// API Configuration
const VT_BASE_URL = 'https://www.virustotal.com/api/v3';
const ABUSE_BASE_URL = 'https://api.abuseipdb.com/api/v2';
const URLSCAN_BASE_URL = 'https://urlscan.io/api/v1';
// CORS proxy fallback chain — tried in order until one succeeds.
// corsproxy.io is first because it transparently forwards custom auth headers
// (API-Key, x-apikey etc.); allorigins and cors.lol do NOT forward custom
// headers so they only work for unauthenticated / public GET requests.
const CORS_PROXIES = [
  { url: 'https://corsproxy.io/?',          encode: true },
  { url: 'https://api.allorigins.win/raw?url=', encode: true },
  { url: 'https://cors.lol/?url=',              encode: true },
];

/**
 * Fetch through the CORS proxy fallback chain.
 * Tries each proxy in order; returns the first successful Response.
 * @param {string} targetUrl - The actual API endpoint URL
 * @param {Object} fetchOptions - Standard fetch() options (method, headers, body …)
 * @returns {Promise<Response>} The fetch Response from the first proxy that works
 */
async function fetchWithProxy(targetUrl, fetchOptions = {}) {
  let lastError = null;

  // 1. Try local proxy first for GET requests (highly reliable, bypasses CORS completely)
  const method = fetchOptions.method || 'GET';
  if (method.toUpperCase() === 'GET') {
    try {
      const localProxyUrl = `/api/proxy?url=${encodeURIComponent(targetUrl)}`;
      const response = await fetch(localProxyUrl, fetchOptions);
      if (response.ok) {
        const data = await response.json();
        const targetStatus = data.status?.http_code || 200;
        if (targetStatus >= 200 && targetStatus < 300) {
          return new Response(data.contents, {
            status: targetStatus,
            headers: new Headers(data.headers || {})
          });
        }
        // For non-2xx from upstream, still return the body so callers can parse error details
        if (targetStatus >= 400) {
          return new Response(data.contents, {
            status: targetStatus,
            headers: new Headers(data.headers || {})
          });
        }
        console.warn(`Local proxy target returned non-success status ${targetStatus}. Trying public CORS proxies...`);
      }
      console.warn(`Local proxy returned status ${response.status}. Trying public CORS proxies...`);
    } catch (err) {
      if (err.name === 'AbortError') {
        throw err;
      }
      console.warn('Local proxy failed, falling back to public CORS proxies:', err);
    }
  }

  // 2. Fallback to public CORS proxy chain
  for (const proxy of CORS_PROXIES) {
    try {
      const proxiedUrl = proxy.encode
        ? `${proxy.url}${encodeURIComponent(targetUrl)}`
        : `${proxy.url}${targetUrl}`;

      const response = await fetch(proxiedUrl, fetchOptions);
      if (response.ok) {
        return response;
      }

      if (response.status === 404) {
        console.warn(`Proxy ${proxy.url} returned 404. Trying next proxy instead of treating it as an upstream API response...`);
        lastError = new Error('Proxy returned 404 for proxied request');
        continue;
      }

      if (response.status === 401 || response.status === 403) {
        const hasAuthHeader = fetchOptions.headers && Object.keys(fetchOptions.headers).some(h => {
          const lower = h.toLowerCase();
          return lower === 'x-apikey' || lower === 'key' || lower === 'api-key' || lower === 'authorization';
        });

        if (hasAuthHeader) {
          const contentType = response.headers.get('content-type') || '';
          if (contentType.includes('json')) {
            return response;
          }
        }

        console.warn(`Proxy ${proxy.url} returned status ${response.status} (likely proxy block). Trying next proxy...`);
        lastError = new Error(`Proxy blocked request (status ${response.status})`);
        continue;
      }

      console.warn(`Proxy ${proxy.url} failed with status ${response.status}. Trying next proxy...`);
      lastError = new Error(`Proxy status: ${response.status}`);
    } catch (err) {
      console.warn(`CORS proxy failed (${proxy.url}):`, err.message);
      lastError = err;
      // Continue to next proxy
    }
  }

  // All proxies exhausted
  throw lastError || new Error('All CORS proxies failed');
}

// Encryption key for API key storage (matches main.js)
const ENCRYPTION_KEY = 'CyberGuard2024!@#';

/**
 * Encrypt API key using XOR encryption
 * @param {string} key - Plain text API key
 * @returns {string} Encrypted and base64 encoded key
 */
function encryptApiKey(key) {
  if (!key) return '';
  try {
    let encrypted = '';
    for (let i = 0; i < key.length; i++) {
      encrypted += String.fromCharCode(
        key.charCodeAt(i) ^ ENCRYPTION_KEY.charCodeAt(i % ENCRYPTION_KEY.length)
      );
    }
    return btoa(encrypted);
  } catch (e) {
    console.error('Encryption failed:', e);
    return key;
  }
}

/**
 * Decrypt API key using XOR decryption
 * @param {string} encryptedKey - Encrypted and base64 encoded key
 * @returns {string} Plain text API key
 */
function decryptApiKey(encryptedKey) {
  if (!encryptedKey) return '';
  try {
    const decoded = atob(encryptedKey);
    let decrypted = '';
    for (let i = 0; i < decoded.length; i++) {
      decrypted += String.fromCharCode(
        decoded.charCodeAt(i) ^ ENCRYPTION_KEY.charCodeAt(i % ENCRYPTION_KEY.length)
      );
    }
    return decrypted;
  } catch (e) {
    console.error('Decryption failed:', e);
    return encryptedKey;
  }
}

/**
 * ThreatIntelState - State management object
 * Tracks current search, API responses, verdict, and search history
 */
const ThreatIntelState = {
  // Current search
  currentSearch: {
    input: '',
    inputType: '', // 'ip', 'domain', 'hash', 'url'
    timestamp: null
  },
  
  // API responses
  sources: {
    virustotal: {
      loading: false,
      data: null,
      error: null,
      threatFlag: false
    },
    abuseipdb: {
      loading: false,
      data: null,
      error: null,
      threatFlag: false
    },
    urlscan: {
      loading: false,
      data: null,
      error: null,
      threatFlag: false
    }
  },
  
  // Aggregated verdict
  verdict: {
    status: '', // 'MALICIOUS' or 'CLEAR/UNVERIFIED'
    threatCount: 0,
    timestamp: null
  },
  
  // Search history (persisted to localStorage)
  searchHistory: []
};

/**
 * InputValidator - Input validation and type detection module
 * Validates and sanitizes user input for threat intelligence lookups
 */
const InputValidator = {
  // Regex patterns for input validation
  patterns: {
    ipv4: /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/,
    domain: /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/,
    md5: /^[a-fA-F0-9]{32}$/,
    sha1: /^[a-fA-F0-9]{40}$/,
    sha256: /^[a-fA-F0-9]{64}$/,
    // Matches URLs with protocol, or domain-like strings with paths/trailing slashes
    url: /^(?:https?:\/\/)?(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}(?::\d{1,5})?(?:\/[^\s]*)?$/
  },
  
  /**
   * Validate user input
   * @param {string} input - Raw user input
   * @returns {Object} { valid: boolean, error: string }
   */
  validate(input) {
    // Sanitize input first
    const sanitized = this.sanitize(input);
    
    // Check if empty
    if (!sanitized || sanitized.length === 0) {
      return {
        valid: false,
        error: 'Please enter an IP address, domain, URL, or file hash'
      };
    }
    
    // Check if matches any pattern
    const type = this.detectType(sanitized);
    
    if (!type) {
      return {
        valid: false,
        error: 'Invalid format. Please enter a valid IP, domain, URL, or hash'
      };
    }
    
    return {
      valid: true,
      error: ''
    };
  },
  
  /**
   * Detect input type
   * @param {string} input - Sanitized input
   * @returns {string|null} 'ip', 'domain', 'hash', 'url', or null
   */
  detectType(input) {
    const sanitized = this.sanitize(input);
    
    // Test IPv4
    if (this.patterns.ipv4.test(sanitized)) {
      return 'ip';
    }
    
    // Test hashes (MD5, SHA-1, SHA-256) — before domain/url to avoid
    // false positives on hex strings
    if (this.patterns.md5.test(sanitized) || 
        this.patterns.sha1.test(sanitized) || 
        this.patterns.sha256.test(sanitized)) {
      return 'hash';
    }
    
    // Test bare domain (no path, no protocol, no trailing slash)
    if (this.patterns.domain.test(sanitized)) {
      return 'domain';
    }
    
    // Test URL (has protocol, path, trailing slash, port, etc.)
    if (this.patterns.url.test(sanitized)) {
      return 'url';
    }
    
    return null;
  },
  
  /**
   * Extract the hostname from a URL or domain-like input
   * @param {string} input - URL or domain string
   * @returns {string} The hostname portion
   */
  extractHostname(input) {
    try {
      // Add protocol if missing so URL constructor works
      const withProtocol = input.includes('://') ? input : `http://${input}`;
      return new URL(withProtocol).hostname;
    } catch {
      // Fallback: strip protocol and path manually
      return input.replace(/^https?:\/\//, '').split('/')[0].split(':')[0];
    }
  },

  /**
   * Normalise input into a full URL for URLScan submission.
   * Ensures a protocol is present.
   * @param {string} input - Raw or sanitized input
   * @returns {string} URL with protocol
   */
  toFullURL(input) {
    if (/^https?:\/\//i.test(input)) return input;
    return `http://${input}`;
  },
  
  /**
   * Sanitize input
   * @param {string} input - Raw input
   * @returns {string} Sanitized input
   */
  sanitize(input) {
    if (typeof input !== 'string') {
      return '';
    }
    
    // Trim whitespace
    let sanitized = input.trim();
    
    // Normalize case for hashes (lowercase)
    // Check if it looks like a hash (only hex characters)
    if (/^[a-fA-F0-9]+$/.test(sanitized)) {
      sanitized = sanitized.toLowerCase();
    }
    
    return sanitized;
  }
};

/**
 * APIOrchestrator - API orchestration module
 * Manages parallel API calls and response handling
 */
const APIOrchestrator = {
  /**
   * Fetch threat intelligence from all applicable sources
   * @param {string} input - Sanitized input (IP, domain, or hash)
   * @param {string} inputType - Type of input ('ip', 'domain', 'hash')
   * @returns {Promise<Object>} Results from all sources
   */
  async fetchAll(input, inputType) {
    const promises = [];
    
    // Determine which APIs to call based on input type
    if (inputType === 'ip') {
      // IP addresses: VirusTotal + AbuseIPDB
      promises.push(
        this.fetchVirusTotal(input, 'ip').then(result => ({ source: 'virustotal', result }))
      );
      promises.push(
        this.fetchAbuseIPDB(input).then(result => ({ source: 'abuseipdb', result }))
      );
    } else if (inputType === 'domain') {
      // Domains: VirusTotal (domain lookup) + URLScan
      promises.push(
        this.fetchVirusTotal(input, 'domain').then(result => ({ source: 'virustotal', result }))
      );
      promises.push(
        this.fetchURLScan(InputValidator.toFullURL(input)).then(result => ({ source: 'urlscan', result }))
      );
    } else if (inputType === 'url') {
      // Full URLs: VirusTotal (domain lookup on hostname) + URLScan (full URL)
      const hostname = InputValidator.extractHostname(input);
      promises.push(
        this.fetchVirusTotal(hostname, 'domain').then(result => ({ source: 'virustotal', result }))
      );
      promises.push(
        this.fetchURLScan(InputValidator.toFullURL(input)).then(result => ({ source: 'urlscan', result }))
      );
    } else if (inputType === 'hash') {
      // Hashes: VirusTotal only
      promises.push(
        this.fetchVirusTotal(input, 'file').then(result => ({ source: 'virustotal', result }))
      );
    }
    
    // Execute all promises with individual error handling
    const results = await Promise.allSettled(promises);
    
    return this.processResults(results, inputType);
  },
  
  /**
   * Fetch data from VirusTotal API
   * @param {string} input - IP, domain, or hash
   * @param {string} type - 'ip', 'domain', or 'file'
   * @returns {Promise<Object>} VirusTotal response
   */
  async fetchVirusTotal(input, type) {
    try {
      // Get API key from memory cache
      let apiKey = "";
      if (typeof window.getApiKey === "function") {
        apiKey = window.getApiKey('virustotal');
      }
      if (!apiKey) {
        throw new Error('VirusTotal API key not configured');
      }
      
      // Build endpoint based on type
      let endpoint = '';
      if (type === 'ip') {
        endpoint = `${VT_BASE_URL}/ip_addresses/${input}`;
      } else if (type === 'domain') {
        endpoint = `${VT_BASE_URL}/domains/${input}`;
      } else if (type === 'file') {
        endpoint = `${VT_BASE_URL}/files/${input}`;
      } else {
        throw new Error(`Invalid type: ${type}`);
      }
      
      // Fetch through CORS proxy fallback chain
      const response = await fetchWithProxy(endpoint, {
        method: 'GET',
        headers: {
          'x-apikey': apiKey
        }
      });
      
      // Handle response
      if (!response.ok) {
        if (response.status === 401 || response.status === 403) {
          throw new Error('VirusTotal: Invalid API key');
        } else if (response.status === 429) {
          throw new Error('VirusTotal: Rate limit exceeded');
        } else if (response.status === 404) {
          throw new Error('VirusTotal: Resource not found');
        } else {
          throw new Error(`VirusTotal: Request failed with status ${response.status}`);
        }
      }
      
      // Parse and return response
      const data = await response.json();
      return data;
      
    } catch (error) {
      // Re-throw with VirusTotal prefix for error handling
      if (error.message.includes('VirusTotal')) {
        throw error;
      } else if (error.name === 'TypeError' && error.message.includes('fetch')) {
        throw new Error('VirusTotal: Network failure');
      } else {
        throw new Error(`VirusTotal: ${error.message}`);
      }
    }
  },
  
  /**
   * Fetch data from AbuseIPDB API
   * @param {string} ip - IP address
   * @returns {Promise<Object>} AbuseIPDB response
   */
  async fetchAbuseIPDB(ip) {
    try {
      // Get API key from memory cache
      let apiKey = "";
      if (typeof window.getApiKey === "function") {
        apiKey = window.getApiKey('abuseipdb');
      }
      if (!apiKey) {
        throw new Error('AbuseIPDB API key not configured');
      }
      
      // Use dedicated server-side AbuseIPDB endpoint.
      // This avoids all CORS/proxy header-forwarding issues — the server
      // makes the call directly to api.abuseipdb.com with the correct headers.
      const params = new URLSearchParams({
        ip: ip,
        key: apiKey,
        maxAge: '90'
      });
      
      const response = await fetch(`/api/abuseipdb?${params.toString()}`);
      
      // Parse the response body
      let data;
      const text = await response.text();
      try {
        data = JSON.parse(text);
      } catch (_) {
        throw new Error('AbuseIPDB: Invalid JSON response from API');
      }
      
      // Handle error status codes with real error detail from AbuseIPDB
      if (!response.ok) {
        const detail = data?.errors?.[0]?.detail || '';
        if (response.status === 401 || response.status === 403) {
          throw new Error(`AbuseIPDB: ${detail || 'Invalid API key'}`);
        } else if (response.status === 422) {
          throw new Error(`AbuseIPDB: ${detail || 'Unprocessable request'}`);
        } else if (response.status === 429) {
          throw new Error('AbuseIPDB: Rate limit exceeded');
        } else {
          throw new Error(`AbuseIPDB: ${detail || 'Request failed with status ' + response.status}`);
        }
      }
      
      return data;
      
    } catch (error) {
      // Re-throw with AbuseIPDB prefix for error handling
      if (error.message.includes('AbuseIPDB')) {
        throw error;
      } else if (error.name === 'TypeError' && error.message.includes('fetch')) {
        throw new Error('AbuseIPDB: Network failure');
      } else {
        throw new Error(`AbuseIPDB: ${error.message}`);
      }
    }
  },
  
  /**
   * Fetch data from URLScan.io API.
   * Strategy (per URLScan best-practices):
   *   1. Search for existing results first (compact JSON, avoids 413).
   *   2. If no results found, submit a new scan and poll for completion.
   * @param {string} url - Full URL to scan (must include protocol)
   * @returns {Promise<Object>} URLScan response (search or scan result)
   */
  async fetchURLScan(url) {
    try {
      // Get API key from memory cache
      let apiKey = "";
      if (typeof window.getApiKey === "function") {
        apiKey = window.getApiKey('urlscan');
      }
      if (!apiKey) {
        throw new Error('URLScan API key not configured');
      }

      // --- Step 1: Search for existing results (recommended by docs) ---
      // Extract hostname for the search query
      let hostname;
      try {
        hostname = new URL(url).hostname;
      } catch (_) {
        hostname = url.replace(/^https?:\/\//, '').split('/')[0];
      }

      const searchQuery = encodeURIComponent(`domain:${hostname}`);
      const searchEndpoint = `${URLSCAN_BASE_URL}/search/?q=${searchQuery}&size=1`;

      console.log('URLScan: Searching existing results for', hostname);

      try {
        const searchResponse = await fetchWithProxy(searchEndpoint, {
          method: 'GET',
          headers: { 'API-Key': apiKey }
        });

        if (searchResponse.ok) {
          const searchData = await searchResponse.json();

          if (searchData.results && searchData.results.length > 0) {
            console.log('URLScan: Found existing result via Search API');
            // Return first result in a normalised wrapper so DataExtractor
            // can handle both search and full-result formats.
            const hit = searchData.results[0];
            return {
              _source: 'search',
              verdicts: hit.verdicts || { overall: { malicious: false, score: 0 } },
              page: hit.page || {},
              task: hit.task || {},
              stats: hit.stats || {},
              lists: hit.lists || {},
              result: hit.result || null
            };
          }
          console.log('URLScan: No existing results, will submit a new scan');
        } else {
          console.warn('URLScan: Search API returned', searchResponse.status, '- falling back to scan submission');
        }
      } catch (searchErr) {
        console.warn('URLScan: Search API failed, falling back to scan submission:', searchErr.message);
      }

      // --- Step 2: Submit a new scan ---
      const submitEndpoint = `${URLSCAN_BASE_URL}/scan/`;

      const submitResponse = await fetchWithProxy(submitEndpoint, {
        method: 'POST',
        headers: {
          'API-Key': apiKey,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          url: url,
          visibility: 'public'
        })
      });

      if (!submitResponse.ok) {
        if (submitResponse.status === 401 || submitResponse.status === 403) {
          throw new Error('URLScan: Invalid API key');
        } else if (submitResponse.status === 429) {
          throw new Error('URLScan: Rate limit exceeded. Please wait before trying again');
        } else {
          let detail = '';
          try {
            const errBody = await submitResponse.json();
            detail = errBody.message || errBody.description || '';
          } catch (_) { /* ignore */ }
          throw new Error(`URLScan: Scan submission failed (${submitResponse.status})${detail ? ' - ' + detail : ''}`);
        }
      }

      const submitData = await submitResponse.json();
      const uuid = submitData.uuid;

      if (!uuid) {
        throw new Error('URLScan: No UUID returned from scan submission');
      }

      console.log('URLScan: Scan submitted, UUID:', uuid);

      // --- Step 3: Poll for scan results ---
      const resultData = await this.pollURLScanResult(uuid, apiKey);
      return resultData;

    } catch (error) {
      if (error.message.includes('URLScan')) {
        throw error;
      } else if (error.name === 'TypeError' && error.message.includes('fetch')) {
        throw new Error('URLScan: Network failure');
      } else {
        throw new Error(`URLScan: ${error.message}`);
      }
    }
  },

  /**
   * Poll URLScan.io result endpoint until scan completes.
   * Per URLScan docs: scans take at least 30 seconds.
   * @param {string} uuid - Scan UUID from submission
   * @param {string} apiKey - URLScan API key
   * @returns {Promise<Object>} URLScan result data
   */
  async pollURLScanResult(uuid, apiKey) {
    const initialWait = 15000;
    const pollInterval = 5000;
    const maxAttempts = 15; // 15s initial + 15×5s = 90s total

    console.log('URLScan: Waiting 15s before first poll...');
    await new Promise(resolve => setTimeout(resolve, initialWait));

    for (let attempt = 0; attempt < maxAttempts; attempt++) {
      try {
        const resultEndpoint = `${URLSCAN_BASE_URL}/result/${uuid}/`;

        const resultResponse = await fetchWithProxy(resultEndpoint, {
          method: 'GET',
          headers: { 'API-Key': apiKey }
        });

        if (resultResponse.status === 200) {
          const resultData = await resultResponse.json();
          console.log('URLScan: Scan complete after', attempt + 1, 'polls');
          return resultData;
        } else if (resultResponse.status === 404) {
          console.log(`URLScan: Still processing, poll ${attempt + 1}/${maxAttempts}`);
          await new Promise(resolve => setTimeout(resolve, pollInterval));
          continue;
        } else if (resultResponse.status === 410) {
          throw new Error('URLScan: Scan result was deleted (HTTP 410)');
        } else if (resultResponse.status === 413) {
          // Proxy payload too large — try search API as fallback
          console.warn('URLScan: 413 from proxy (result too large), trying Search API fallback...');
          return await this.searchFallbackByUuid(uuid, apiKey);
        } else {
          throw new Error(`URLScan: Unexpected status ${resultResponse.status} while polling`);
        }

      } catch (error) {
        if (error.message.includes('URLScan:')) throw error;
        if (attempt === maxAttempts - 1) {
          throw new Error('URLScan: Scan did not complete within 90 seconds');
        }
        if (error.name === 'TypeError' && error.message.includes('fetch')) {
          console.warn('URLScan: Network error during polling, retrying...');
          await new Promise(resolve => setTimeout(resolve, pollInterval));
          continue;
        }
        throw error;
      }
    }

    throw new Error('URLScan: Scan did not complete within 90 seconds');
  },

  /**
   * Fallback: use Search API to retrieve a compact summary when the full
   * result payload is too large for the CORS proxy (413).
   * @param {string} uuid - Scan UUID
   * @param {string} apiKey - URLScan API key
   * @returns {Promise<Object>} Normalised result
   */
  async searchFallbackByUuid(uuid, apiKey) {
    const q = encodeURIComponent(`scan:${uuid}`);
    const endpoint = `${URLSCAN_BASE_URL}/search/?q=${q}&size=1`;

    const resp = await fetchWithProxy(endpoint, {
      method: 'GET',
      headers: { 'API-Key': apiKey }
    });

    if (!resp.ok) throw new Error(`URLScan: Search fallback failed (${resp.status})`);

    const data = await resp.json();
    if (!data.results || data.results.length === 0) {
      throw new Error('URLScan: Scan completed but could not retrieve results');
    }

    const hit = data.results[0];
    return {
      _source: 'search',
      verdicts: hit.verdicts || { overall: { malicious: false, score: 0 } },
      page: hit.page || {},
      task: hit.task || {},
      stats: hit.stats || {},
      lists: hit.lists || {},
      result: hit.result || null
    };
  },
  
  /**
   * Process Promise.allSettled results
   * @param {Array} results - Promise.allSettled results
   * @param {string} inputType - Type of input for N/A handling
   * @returns {Object} Structured results object
   */
  processResults(results, inputType) {
    const processedResults = {
      virustotal: null,
      abuseipdb: null,
      urlscan: null
    };
    
    // Process each result
    results.forEach(result => {
      if (result.status === 'fulfilled') {
        const { source, result: data } = result.value;
        processedResults[source] = {
          success: true,
          data: data,
          error: null
        };
      } else {
        // Extract source from error or promise
        const errorMessage = result.reason?.message || 'Unknown error';
        
        // Try to determine which source failed
        let source = null;
        if (errorMessage.includes('VirusTotal')) {
          source = 'virustotal';
        } else if (errorMessage.includes('AbuseIPDB')) {
          source = 'abuseipdb';
        } else if (errorMessage.includes('URLScan')) {
          source = 'urlscan';
        }
        
        if (source) {
          processedResults[source] = {
            success: false,
            data: null,
            error: errorMessage
          };
        }
      }
    });
    
    // Handle N/A cases based on input type
    if (inputType === 'ip') {
      // URLScan not applicable for IPs
      processedResults.urlscan = {
        success: true,
        data: null,
        error: null,
        notApplicable: true,
        reason: 'N/A - URL/Domain only'
      };
    } else if (inputType === 'domain' || inputType === 'url') {
      // AbuseIPDB not applicable for domains/URLs
      processedResults.abuseipdb = {
        success: true,
        data: null,
        error: null,
        notApplicable: true,
        reason: 'N/A - IP only'
      };
    } else if (inputType === 'hash') {
      // Only VirusTotal applicable for hashes
      processedResults.abuseipdb = {
        success: true,
        data: null,
        error: null,
        notApplicable: true,
        reason: 'N/A - IP only'
      };
      processedResults.urlscan = {
        success: true,
        data: null,
        error: null,
        notApplicable: true,
        reason: 'N/A - URL/Domain only'
      };
    }
    
    return processedResults;
  }
};

/**
 * DataExtractor - Data extraction module
 * Extracts threat indicators from API responses
 */
const DataExtractor = {
  /**
   * Extract threat indicators from VirusTotal response
   * @param {Object} response - VirusTotal API response
   * @returns {Object} { threatFlag, maliciousCount, totalEngines, displayText, rawData }
   */
  extractVirusTotal(response) {
    try {
      // Handle N/A case (null response)
      if (!response || response.notApplicable) {
        return {
          threatFlag: false,
          maliciousCount: 0,
          totalEngines: 0,
          displayText: response?.reason || 'N/A',
          rawData: null
        };
      }
      
      // Extract last_analysis_stats from response
      const stats = response.data?.attributes?.last_analysis_stats;
      
      if (!stats) {
        throw new Error('Invalid VirusTotal response structure');
      }
      
      // Count malicious detections
      const maliciousCount = stats.malicious || 0;
      
      // Calculate total engines (sum of all detection categories)
      const totalEngines = (stats.malicious || 0) + 
                          (stats.suspicious || 0) + 
                          (stats.undetected || 0) + 
                          (stats.harmless || 0) + 
                          (stats.timeout || 0);
      
      // Calculate threat flag (malicious > 0)
      const threatFlag = maliciousCount > 0;
      
      // Format display string
      const displayText = `${maliciousCount}/${totalEngines} engines flagged`;
      
      return {
        threatFlag,
        maliciousCount,
        totalEngines,
        displayText,
        rawData: response
      };
      
    } catch (error) {
      console.error('DataExtractor: Error extracting VirusTotal data:', error);
      throw error;
    }
  },
  
  /**
   * Extract threat indicators from AbuseIPDB response
   * @param {Object} response - AbuseIPDB API response
   * @returns {Object} { threatFlag, confidenceScore, displayText, rawData }
   */
  extractAbuseIPDB(response) {
    try {
      // Handle N/A case (null response)
      if (!response || response.notApplicable) {
        return {
          threatFlag: false,
          confidenceScore: 0,
          displayText: response?.reason || 'N/A',
          rawData: null
        };
      }
      
      // Extract abuseConfidenceScore from response
      const confidenceScore = response.data?.abuseConfidenceScore;
      
      if (confidenceScore === undefined || confidenceScore === null) {
        throw new Error('Invalid AbuseIPDB response structure');
      }
      
      // Calculate threat flag (score > 50)
      const threatFlag = confidenceScore > 50;
      
      // Format display string
      const displayText = `Confidence: ${confidenceScore}%`;
      
      return {
        threatFlag,
        confidenceScore,
        displayText,
        rawData: response
      };
      
    } catch (error) {
      console.error('DataExtractor: Error extracting AbuseIPDB data:', error);
      throw error;
    }
  },
  
  /**
   * Extract threat indicators from URLScan response
   * @param {Object} response - URLScan API response
   * @returns {Object} { threatFlag, verdict, displayText, rawData }
   */
  extractURLScan(response) {
    try {
      // Handle N/A case (null response)
      if (!response || response.notApplicable) {
        return {
          threatFlag: false,
          verdict: 'N/A',
          displayText: response?.reason || 'N/A',
          rawData: null
        };
      }

      // Supports both full-result and Search-API responses.
      // Full result:  response.verdicts.overall.malicious  (boolean)
      // Search API:   response.verdicts.overall.malicious  (boolean)
      //               response.verdicts.overall.score      (number)
      const verdicts = response.verdicts?.overall;

      // If verdicts are present, use them
      if (verdicts && typeof verdicts.malicious === 'boolean') {
        const threatFlag = verdicts.malicious === true;
        const score = verdicts.score ?? 0;
        const verdict = threatFlag ? 'Malicious' : 'Clean';
        const displayText = threatFlag
          ? `Verdict: ${verdict} (score ${score})`
          : `Verdict: ${verdict}`;

        return { threatFlag, verdict, displayText, rawData: response };
      }

      // Fallback: if verdicts block is missing but we have page info
      // (e.g. from a search result without verdict data), still succeed.
      if (response.page) {
        return {
          threatFlag: false,
          verdict: 'Unknown',
          displayText: 'Verdict: No verdict data available',
          rawData: response
        };
      }

      throw new Error('Invalid URLScan response structure');

    } catch (error) {
      console.error('DataExtractor: Error extracting URLScan data:', error);
      throw error;
    }
  }
};

/**
 * VerdictCalculator - Verdict calculation module
 * Calculates aggregated threat verdict based on multiple sources
 * 
 * **Validates: Requirements 10.1, 10.2, 10.3, 10.4, 10.5**
 */
const VerdictCalculator = {
  /**
   * Calculate aggregated threat verdict
   * @param {Object} sourcesData - Object containing extracted data from all sources
   * @returns {Object} { status, threatCount, timestamp, sources }
   */
  calculate(sourcesData) {
    // Count sources with threatFlag = true
    const sources = {
      virustotal: false,
      abuseipdb: false,
      urlscan: false
    };
    
    let threatCount = 0;
    
    // Check each source for threat flag
    if (sourcesData.virustotal && sourcesData.virustotal.threatFlag === true) {
      sources.virustotal = true;
      threatCount++;
    }
    
    if (sourcesData.abuseipdb && sourcesData.abuseipdb.threatFlag === true) {
      sources.abuseipdb = true;
      threatCount++;
    }
    
    if (sourcesData.urlscan && sourcesData.urlscan.threatFlag === true) {
      sources.urlscan = true;
      threatCount++;
    }
    
    // Apply threshold (2+ sources = malicious)
    const status = threatCount >= 2 ? 'MALICIOUS' : 'CLEAR/UNVERIFIED';
    
    return {
      status,
      threatCount,
      timestamp: new Date().toISOString(),
      sources
    };
  }
};

/**
 * ThreatIntelHub - Main module object
 * Orchestrates threat intelligence lookups and UI updates
 */
const ThreatIntelHub = {
  /**
   * Initialize the Threat Intel Hub
   * Binds event listeners and loads search history
   */
  init() {
    // === AUTHENTICATION CHECK ===
    if (typeof window.runAuthGuard === 'function' && !window.runAuthGuard()) {
      return; // Stop initialization if not authenticated
    }

    console.log('ThreatIntelHub: Initializing...');
    
    try {
      this.bindEventListeners();
      this.loadSearchHistory();
      this.checkAPIKeys();
      
      // Ensure idle state is shown for all source cards on initialization
      UIRenderer.renderIdleState('virustotal');
      UIRenderer.renderIdleState('abuseipdb');
      UIRenderer.renderIdleState('urlscan');
      
      console.log('ThreatIntelHub: Initialization complete');
    } catch (error) {
      console.error('ThreatIntelHub: Initialization error:', error);
    }
  },
  
  /**
   * Bind event listeners for user interactions
   * Uses event delegation for dynamically created elements
   * Binds listeners only once during initialization
   */
  bindEventListeners() {
    // Get DOM elements
    const searchInput = document.getElementById('threat-intel-search-input');
    const searchBtn = document.getElementById('threat-intel-search-btn');
    const clearHistoryBtn = document.getElementById('threat-intel-clear-history-btn');
    
    if (!searchInput || !searchBtn) {
      console.error('ThreatIntelHub: Search input or button not found');
      return;
    }
    
    // Search button click handler - bound once
    searchBtn.addEventListener('click', () => {
      const input = searchInput.value;
      this.performSearch(input);
    });
    
    // Enter key handler on input - bound once
    searchInput.addEventListener('keypress', (event) => {
      if (event.key === 'Enter') {
        const input = searchInput.value;
        this.performSearch(input);
      }
    });
    
    // Clear history button handler - bound once
    if (clearHistoryBtn) {
      clearHistoryBtn.addEventListener('click', () => {
        this.clearHistory();
      });
    }
    
    // Event delegation for dynamically created history items
    const historyList = document.getElementById('threat-intel-history-list');
    if (historyList) {
      historyList.addEventListener('click', (event) => {
        const historyItem = event.target.closest('.recent-search-item');
        if (historyItem) {
          const index = parseInt(historyItem.dataset.index, 10);
          if (!isNaN(index) && ThreatIntelState.searchHistory[index]) {
            const item = ThreatIntelState.searchHistory[index];
            searchInput.value = item.input;
            
            // If the item has saved scan results, display them directly instead of performing a new scan
            if (item.sources && item.verdictDetails) {
              this.showSavedResults(item);
            } else {
              this.performSearch(item.input);
            }
          }
        }
      });
    }
    
    // Event delegation for dynamically created "View Details" buttons and Tabs
    const sourceCardsContainer = document.getElementById('threat-intel-source-cards');
    if (sourceCardsContainer) {
      sourceCardsContainer.addEventListener('click', (event) => {
        const detailsBtn = event.target.closest('.view-details-btn');
        if (detailsBtn) {
          const sourceName = detailsBtn.dataset.source;
          if (sourceName) {
            UIRenderer.toggleDetails(sourceName);
          }
          return;
        }
        
        const tabBtn = event.target.closest('.details-tab-btn');
        if (tabBtn) {
          const sourceName = tabBtn.dataset.source;
          const tabName = tabBtn.dataset.tab;
          if (sourceName && tabName) {
            UIRenderer.switchTab(tabBtn, sourceName, tabName);
          }
        }
      });
    }
    
    console.log('ThreatIntelHub: Event listeners bound (with delegation)');
  },
  
  /**
   * Load search history from localStorage
   */
  loadSearchHistory() {
    try {
      const stored = localStorage.getItem('threat-intel-history');
      if (stored) {
        ThreatIntelState.searchHistory = JSON.parse(stored);
        console.log(`ThreatIntelHub: Loaded ${ThreatIntelState.searchHistory.length} history items`);
        
        // Render history UI
        UIRenderer.renderSearchHistory(ThreatIntelState.searchHistory);
      } else {
        ThreatIntelState.searchHistory = [];
        console.log('ThreatIntelHub: No search history found');
        UIRenderer.renderSearchHistory([]);
      }
    } catch (error) {
      console.error('ThreatIntelHub: Error loading search history:', error);
      ThreatIntelState.searchHistory = [];
      UIRenderer.renderSearchHistory([]);
    }
  },
  
  /**
   * Check for required API keys
   * Validates URLScan, VirusTotal, and AbuseIPDB API keys
   */
  checkAPIKeys() {
    let urlscanKey = "";
    if (typeof window.getApiKey === "function") {
      urlscanKey = window.getApiKey('urlscan');
    }
    
    // Check for URLScan API key and show warning if missing
    if (!urlscanKey && typeof CyberNotify !== 'undefined') {
      CyberNotify.alert('URLScan API key not configured. Add it in Settings to enable URL/domain scanning.', { type: 'warning' });
    }
    
    console.log('ThreatIntelHub: API key validation complete');
  },
  
  /**
   * Perform threat intelligence search
   * @param {string} input - User input (IP, domain, or hash)
   */
  async performSearch(input) {
    console.log('ThreatIntelHub: performSearch called with:', input);
    
    // Get DOM elements
    const searchBtn = document.getElementById('threat-intel-search-btn');
    const searchInput = document.getElementById('threat-intel-search-input');
    
    if (!searchBtn) {
      console.error('ThreatIntelHub: Search button not found');
      return;
    }
    
    // 1. Validate input
    const validation = InputValidator.validate(input);
    if (!validation.valid) {
      // Show error notification
      if (typeof CyberNotify !== 'undefined') {
        CyberNotify.alert(validation.error, { type: 'warning' });
      } else {
        console.warn('ThreatIntelHub:', validation.error);
      }
      return;
    }
    
    // 2. Detect input type
    const inputType = InputValidator.detectType(input);
    const sanitizedInput = InputValidator.sanitize(input);
    
    console.log('ThreatIntelHub: Input type detected:', inputType);
    
    // Update state
    ThreatIntelState.currentSearch = {
      input: sanitizedInput,
      inputType: inputType,
      timestamp: new Date().toISOString()
    };
    
    // 3. Show loading states - Disable button and change text
    const originalButtonText = searchBtn.textContent;
    searchBtn.disabled = true;
    searchBtn.style.opacity = '0.5';
    searchBtn.style.cursor = 'not-allowed';
    searchBtn.textContent = 'Searching...';
    
    // Disable input during search
    if (searchInput) {
      searchInput.disabled = true;
    }
    
    // Show loading spinners for applicable sources
    if (inputType === 'ip') {
      UIRenderer.showLoadingState('virustotal');
      UIRenderer.showLoadingState('abuseipdb');
      // URLScan N/A for IPs
      UIRenderer.renderSourceCard('urlscan', {
        threatFlag: false,
        displayText: 'N/A - URL/Domain only',
        rawData: null
      });
    } else if (inputType === 'domain' || inputType === 'url') {
      UIRenderer.showLoadingState('virustotal');
      UIRenderer.showLoadingState('urlscan');
      // AbuseIPDB N/A for domains/URLs
      UIRenderer.renderSourceCard('abuseipdb', {
        threatFlag: false,
        displayText: 'N/A - IP only',
        rawData: null
      });
    } else if (inputType === 'hash') {
      UIRenderer.showLoadingState('virustotal');
      // Both AbuseIPDB and URLScan N/A for hashes
      UIRenderer.renderSourceCard('abuseipdb', {
        threatFlag: false,
        displayText: 'N/A - IP only',
        rawData: null
      });
      UIRenderer.renderSourceCard('urlscan', {
        threatFlag: false,
        displayText: 'N/A - URL/Domain only',
        rawData: null
      });
    }
    
    try {
      // 4. Call appropriate APIs in parallel
      const apiResults = await APIOrchestrator.fetchAll(sanitizedInput, inputType);
      
      console.log('ThreatIntelHub: API results received:', apiResults);
      
      // 5. Process responses with DataExtractor
      const extractedData = {
        virustotal: null,
        abuseipdb: null,
        urlscan: null
      };
      
      // Extract VirusTotal data
      if (apiResults.virustotal) {
        if (apiResults.virustotal.success) {
          try {
            extractedData.virustotal = DataExtractor.extractVirusTotal(apiResults.virustotal.data);
            UIRenderer.renderSourceCard('virustotal', extractedData.virustotal);
          } catch (error) {
            console.error('ThreatIntelHub: Error extracting VirusTotal data:', error);
            UIRenderer.renderError('virustotal', 'Error: Failed to parse response');
          }
        } else if (apiResults.virustotal.notApplicable) {
          extractedData.virustotal = DataExtractor.extractVirusTotal(apiResults.virustotal);
          UIRenderer.renderSourceCard('virustotal', extractedData.virustotal);
        } else {
          UIRenderer.renderError('virustotal', apiResults.virustotal.error || 'Unknown error');
        }
      }
      
      // Extract AbuseIPDB data
      if (apiResults.abuseipdb) {
        if (apiResults.abuseipdb.success) {
          try {
            extractedData.abuseipdb = DataExtractor.extractAbuseIPDB(apiResults.abuseipdb.data);
            UIRenderer.renderSourceCard('abuseipdb', extractedData.abuseipdb);
          } catch (error) {
            console.error('ThreatIntelHub: Error extracting AbuseIPDB data:', error);
            UIRenderer.renderError('abuseipdb', 'Error: Failed to parse response');
          }
        } else if (apiResults.abuseipdb.notApplicable) {
          extractedData.abuseipdb = DataExtractor.extractAbuseIPDB(apiResults.abuseipdb);
          UIRenderer.renderSourceCard('abuseipdb', extractedData.abuseipdb);
        } else {
          UIRenderer.renderError('abuseipdb', apiResults.abuseipdb.error || 'Unknown error');
        }
      }
      
      // Extract URLScan data
      if (apiResults.urlscan) {
        if (apiResults.urlscan.success) {
          try {
            extractedData.urlscan = DataExtractor.extractURLScan(apiResults.urlscan.data);
            UIRenderer.renderSourceCard('urlscan', extractedData.urlscan);
          } catch (error) {
            console.error('ThreatIntelHub: Error extracting URLScan data:', error);
            UIRenderer.renderError('urlscan', 'Error: Failed to parse response');
          }
        } else if (apiResults.urlscan.notApplicable) {
          extractedData.urlscan = DataExtractor.extractURLScan(apiResults.urlscan);
          UIRenderer.renderSourceCard('urlscan', extractedData.urlscan);
        } else {
          UIRenderer.renderError('urlscan', apiResults.urlscan.error || 'Unknown error');
        }
      }
      
      // 6. Calculate verdict
      const verdict = VerdictCalculator.calculate(extractedData);
      
      console.log('ThreatIntelHub: Verdict calculated:', verdict);
      
      // Update state
      ThreatIntelState.verdict = verdict;
      ThreatIntelState.sources = {
        virustotal: extractedData.virustotal || { threatFlag: false },
        abuseipdb: extractedData.abuseipdb || { threatFlag: false },
        urlscan: extractedData.urlscan || { threatFlag: false }
      };
      
      // 7. Update UI with verdict
      UIRenderer.renderVerdictCard(verdict);
      
      // 8. Save to history
      this.saveToHistory({
        input: sanitizedInput,
        inputType: inputType,
        verdict: verdict.status,
        verdictDetails: verdict,
        sources: ThreatIntelState.sources,
        timestamp: verdict.timestamp
      });
      
      console.log('ThreatIntelHub: Search completed successfully');
      
      // Show success notification
      if (typeof CyberNotify !== 'undefined') {
        CyberNotify.alert('Threat intelligence search completed', { type: 'success' });
      }
      
    } catch (error) {
      console.error('ThreatIntelHub: Search error:', error);
      if (typeof CyberNotify !== 'undefined') {
        CyberNotify.alert('Search failed: ' + error.message, { type: 'error' });
      }
    } finally {
      // Restore button state
      searchBtn.disabled = false;
      searchBtn.style.opacity = '';
      searchBtn.style.cursor = '';
      searchBtn.textContent = originalButtonText;
      
      // Re-enable input
      if (searchInput) {
        searchInput.disabled = false;
      }
    }
  },
  
  /**
   * Save search to history
   * @param {Object} searchData - Search data to save
   */
  saveToHistory(searchData) {
    try {
      // Add to beginning of history
      ThreatIntelState.searchHistory.unshift(searchData);
      
      // Keep only last 10 items
      if (ThreatIntelState.searchHistory.length > 10) {
        ThreatIntelState.searchHistory = ThreatIntelState.searchHistory.slice(0, 10);
      }
      
      // Save to localStorage
      localStorage.setItem('threat-intel-history', JSON.stringify(ThreatIntelState.searchHistory));
      
      // Update UI
      UIRenderer.renderSearchHistory(ThreatIntelState.searchHistory);
      
      console.log('ThreatIntelHub: Search saved to history');
    } catch (error) {
      console.error('ThreatIntelHub: Error saving to history:', error);
    }
  },
  
  /**
   * Clear search history
   * Shows confirmation prompt before clearing
   */
  clearHistory() {
    // Check if CyberNotify.confirm is available
    if (typeof CyberNotify !== 'undefined' && typeof CyberNotify.confirm === 'function') {
      // Use CyberNotify confirm dialog
      CyberNotify.confirm(
        'Are you sure you want to clear all search history? This action cannot be undone.',
        (confirmed) => {
          if (confirmed) {
            try {
              ThreatIntelState.searchHistory = [];
              localStorage.removeItem('threat-intel-history');
              console.log('ThreatIntelHub: Search history cleared');
              
              // Update UI
              UIRenderer.renderSearchHistory([]);
              
              // Show success notification
              CyberNotify.alert('Search history cleared successfully', { type: 'success' });
            } catch (error) {
              console.error('ThreatIntelHub: Error clearing history:', error);
              CyberNotify.alert('Failed to clear search history', { type: 'error' });
            }
          }
        }
      );
    } else {
      // Fallback to native confirm
      const confirmed = confirm('Are you sure you want to clear all search history? This action cannot be undone.');
      
      if (confirmed) {
        try {
          ThreatIntelState.searchHistory = [];
          localStorage.removeItem('threat-intel-history');
          console.log('ThreatIntelHub: Search history cleared');
          
          // Update UI
          UIRenderer.renderSearchHistory([]);
        } catch (error) {
          console.error('ThreatIntelHub: Error clearing history:', error);
        }
      }
    }
  },

  /**
   * Display saved scan results from history directly in the UI.
   * Prevents performing a new redundant API scan.
   * @param {Object} item - Saved search history item containing results
   */
  showSavedResults(item) {
    try {
      console.log('ThreatIntelHub: Showing saved results for:', item.input);
      
      // Update ThreatIntelState
      ThreatIntelState.currentSearch = {
        input: item.input,
        inputType: item.inputType
      };
      ThreatIntelState.verdict = item.verdictDetails;
      ThreatIntelState.sources = item.sources;
      
      // Update UI - Verdict Card
      UIRenderer.renderVerdictCard(item.verdictDetails);
      
      // Update UI - Source Cards
      if (item.sources.virustotal) {
        UIRenderer.renderSourceCard('virustotal', item.sources.virustotal);
      } else {
        UIRenderer.renderIdleState('virustotal');
      }
      
      if (item.sources.abuseipdb) {
        UIRenderer.renderSourceCard('abuseipdb', item.sources.abuseipdb);
      } else {
        UIRenderer.renderIdleState('abuseipdb');
      }
      
      if (item.sources.urlscan) {
        UIRenderer.renderSourceCard('urlscan', item.sources.urlscan);
      } else {
        UIRenderer.renderIdleState('urlscan');
      }
      
      // Show success notification
      if (typeof CyberNotify !== 'undefined') {
        CyberNotify.alert('Loaded saved scan results', { type: 'success' });
      }
    } catch (error) {
      console.error('ThreatIntelHub: Error displaying saved results:', error);
      if (typeof CyberNotify !== 'undefined') {
        CyberNotify.alert('Failed to load saved scan results', { type: 'error' });
      }
    }
  }
};

/**
 * UIRenderer - UI rendering module
 * Handles all UI updates and rendering for the Threat Intel Hub
 */
const UIRenderer = {
  /**
   * Render verdict card with status and styling
   * @param {Object} verdict - Verdict object from VerdictCalculator
   */
  renderVerdictCard(verdict) {
    const verdictCard = document.getElementById('threat-intel-verdict-card');
    const verdictText = document.getElementById('threat-intel-verdict-text');
    const verdictDetails = document.getElementById('threat-intel-verdict-details');
    const verdictIconClear = document.getElementById('verdict-icon-clear');
    const verdictIconMalicious = document.getElementById('verdict-icon-malicious');
    
    if (!verdictCard || !verdictText || !verdictDetails) {
      console.error('UIRenderer: Verdict card elements not found');
      return;
    }
    
    // Show verdict card
    verdictCard.classList.remove('hidden');
    
    // Update verdict text and styling
    if (verdict.status === 'MALICIOUS') {
      verdictText.textContent = 'VERDICT: MALICIOUS';
      verdictText.className = 'text-3xl font-bold tracking-wider text-red-500';
      verdictText.style.textShadow = '0 0 20px rgba(239, 68, 68, 0.5)';
      verdictCard.style.boxShadow = '0 0 20px rgba(239, 68, 68, 0.5), 0 0 40px rgba(239, 68, 68, 0.2)';
      
      // Show malicious icon, hide clear icon
      if (verdictIconMalicious) {
        verdictIconMalicious.classList.remove('hidden');
        verdictIconMalicious.classList.add('text-red-500');
      }
      if (verdictIconClear) {
        verdictIconClear.classList.add('hidden');
      }
    } else {
      verdictText.textContent = 'VERDICT: CLEAR/UNVERIFIED';
      verdictText.className = 'text-3xl font-bold tracking-wider text-cyan-400';
      verdictText.style.textShadow = 'none';
      verdictCard.style.boxShadow = '0 4px 16px rgba(0, 0, 0, 0.4)';
      
      // Show clear icon, hide malicious icon
      if (verdictIconClear) {
        verdictIconClear.classList.remove('hidden');
        verdictIconClear.classList.add('text-cyan-400');
      }
      if (verdictIconMalicious) {
        verdictIconMalicious.classList.add('hidden');
      }
    }
    
    // Update verdict details
    verdictDetails.textContent = `${verdict.threatCount} of 3 sources flagged as threat`;
  },
  
  /**
   * Render source card with results
   * @param {string} sourceName - 'virustotal', 'abuseipdb', or 'urlscan'
   * @param {Object} sourceData - Extracted data from DataExtractor
   */
  renderSourceCard(sourceName, sourceData) {
    const loadingEl = document.getElementById(`${sourceName}-loading`);
    const resultsEl = document.getElementById(`${sourceName}-results`);
    const statusEl = document.getElementById(`${sourceName}-status`);
    
    if (!loadingEl || !resultsEl || !statusEl) {
      console.error(`UIRenderer: Source card elements not found for ${sourceName}`);
      return;
    }
    
    // Hide loading spinner
    loadingEl.classList.add('hidden');
    
    // Show results section
    resultsEl.classList.remove('hidden');
    
    // Render status indicator and results
    if (sourceData.threatFlag) {
      // Threat detected
      statusEl.innerHTML = `
        <div class="flex items-center gap-2 text-red-400">
          <svg class="w-5 h-5" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126ZM12 15.75h.007v.008H12v-.008Z" />
          </svg>
          <span class="font-semibold">Threat</span>
        </div>
      `;
      
      resultsEl.innerHTML = `
        <div class="space-y-3">
          <div class="text-red-400 font-semibold text-lg">${this.escapeHtml(sourceData.displayText)}</div>
          <button class="view-details-btn cyber-btn-ghost text-xs px-3 py-2 rounded-lg w-full flex items-center justify-center gap-2" data-source="${this.escapeHtml(sourceName)}">
            <span>View Details</span>
            <svg class="chevron-icon w-4 h-4 transition-transform" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor">
              <path stroke-linecap="round" stroke-linejoin="round" d="m19.5 8.25-7.5 7.5-7.5-7.5" />
            </svg>
          </button>
          
          <div class="source-details hidden bg-slate-950/40 border border-white/10 rounded-lg p-4 mt-3 overflow-y-auto" style="max-height: 500px;">
            <!-- Tab Headers -->
            <div class="flex border-b border-white/10 pb-2 mb-4 text-xs">
              <button class="details-tab-btn border-b-2 border-cyan-500 text-cyan-400 font-semibold px-3 py-1 mr-2 focus:outline-none" data-source="${this.escapeHtml(sourceName)}" data-tab="visual">Visual Details</button>
              <button class="details-tab-btn border-b-2 border-transparent text-slate-400 font-semibold px-3 py-1 hover:text-slate-200 focus:outline-none" data-source="${this.escapeHtml(sourceName)}" data-tab="raw">Raw JSON</button>
            </div>
            
            <!-- Visual Content -->
            <div class="tab-content-visual text-sm text-slate-300 space-y-4">
              ${this.renderVisualDetails(sourceName, sourceData.rawData)}
            </div>
            
            <!-- Raw JSON Content -->
            <div class="tab-content-raw hidden">
              <pre class="text-xs font-mono text-slate-300 whitespace-pre-wrap">${this.escapeHtml(JSON.stringify(sourceData.rawData, null, 2))}</pre>
            </div>
          </div>
        </div>
      `;
    } else {
      // Clean / No threat
      statusEl.innerHTML = `
        <div class="flex items-center gap-2 text-green-400">
          <svg class="w-5 h-5" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" d="M9 12.75 11.25 15 15 9.75M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0Z" />
          </svg>
          <span class="font-semibold">Clean</span>
        </div>
      `;
      
      resultsEl.innerHTML = `
        <div class="space-y-3">
          <div class="text-green-400 font-semibold text-lg">${this.escapeHtml(sourceData.displayText)}</div>
          ${sourceData.rawData ? `
            <button class="view-details-btn cyber-btn-ghost text-xs px-3 py-2 rounded-lg w-full flex items-center justify-center gap-2" data-source="${this.escapeHtml(sourceName)}">
              <span>View Details</span>
              <svg class="chevron-icon w-4 h-4 transition-transform" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" d="m19.5 8.25-7.5 7.5-7.5-7.5" />
              </svg>
            </button>
            
            <div class="source-details hidden bg-slate-950/40 border border-white/10 rounded-lg p-4 mt-3 overflow-y-auto" style="max-height: 500px;">
              <!-- Tab Headers -->
              <div class="flex border-b border-white/10 pb-2 mb-4 text-xs">
                <button class="details-tab-btn border-b-2 border-cyan-500 text-cyan-400 font-semibold px-3 py-1 mr-2 focus:outline-none" data-source="${this.escapeHtml(sourceName)}" data-tab="visual">Visual Details</button>
                <button class="details-tab-btn border-b-2 border-transparent text-slate-400 font-semibold px-3 py-1 hover:text-slate-200 focus:outline-none" data-source="${this.escapeHtml(sourceName)}" data-tab="raw">Raw JSON</button>
              </div>
              
              <!-- Visual Content -->
              <div class="tab-content-visual text-sm text-slate-300 space-y-4">
                ${this.renderVisualDetails(sourceName, sourceData.rawData)}
              </div>
              
              <!-- Raw JSON Content -->
              <div class="tab-content-raw hidden">
                <pre class="text-xs font-mono text-slate-300 whitespace-pre-wrap">${this.escapeHtml(JSON.stringify(sourceData.rawData, null, 2))}</pre>
              </div>
            </div>
          ` : ''}
        </div>
      `;
    }
  },

  /**
   * Switch active tab in details panel
   */
  switchTab(btn, sourceName, tabName) {
    const parent = btn.closest('.source-details');
    if (!parent) return;
    
    // Update button states
    const tabs = parent.querySelectorAll('.details-tab-btn');
    tabs.forEach(t => {
      if (t === btn) {
        t.classList.add('border-cyan-500', 'text-cyan-400');
        t.classList.remove('border-transparent', 'text-slate-400');
      } else {
        t.classList.remove('border-cyan-500', 'text-cyan-400');
        t.classList.add('border-transparent', 'text-slate-400');
      }
    });
    
    // Update contents
    const visualContent = parent.querySelector('.tab-content-visual');
    const rawContent = parent.querySelector('.tab-content-raw');
    
    if (tabName === 'visual') {
      visualContent?.classList.remove('hidden');
      rawContent?.classList.add('hidden');
    } else {
      visualContent?.classList.add('hidden');
      rawContent?.classList.remove('hidden');
    }
  },

  /**
   * Render custom visual HTML for different scan sources
   */
  renderVisualDetails(sourceName, rawData) {
    if (!rawData) return '<div class="text-slate-400 text-xs">No details available.</div>';
    
    if (sourceName === 'virustotal') {
      const attrs = rawData.data?.attributes || {};
      const stats = attrs.last_analysis_stats || {};
      const total = Object.values(stats).reduce((a, b) => a + b, 0) || 1;
      const maliciousPercent = Math.round((stats.malicious || 0) / total * 100);
      
      const engines = attrs.last_analysis_results || {};
      const maliciousEngines = Object.keys(engines).filter(eng => engines[eng]?.category === 'malicious');
      
      return `
        <div class="space-y-4">
          <!-- Detection Bar -->
          <div class="space-y-1">
            <div class="flex justify-between text-xs">
              <span class="text-slate-400">Threat Detection Rate</span>
              <span class="font-mono text-red-400 font-bold">${stats.malicious || 0}/${total} Scanners Flagged</span>
            </div>
            <div class="w-full bg-slate-800 rounded-full h-2 overflow-hidden flex">
              <div class="bg-red-500" style="width: ${maliciousPercent}%"></div>
              <div class="bg-slate-700" style="width: ${100 - maliciousPercent}%"></div>
            </div>
          </div>

          <!-- Attributes Grid -->
          <div class="grid grid-cols-2 gap-3 text-xs bg-slate-900/40 p-3 rounded-lg border border-white/5">
            <div>
              <span class="text-slate-500 block">ISP / ASN Owner</span>
              <span class="text-slate-200 font-semibold truncate block" title="${this.escapeHtml(attrs.as_owner || 'N/A')}">${this.escapeHtml(attrs.as_owner || 'N/A')}</span>
            </div>
            <div>
              <span class="text-slate-500 block">ASN</span>
              <span class="text-slate-200 font-semibold font-mono block">${this.escapeHtml(attrs.asn || 'N/A')}</span>
            </div>
            <div>
              <span class="text-slate-500 block">Network</span>
              <span class="text-slate-200 font-semibold font-mono block">${this.escapeHtml(attrs.network || 'N/A')}</span>
            </div>
            <div>
              <span class="text-slate-500 block">Reputation</span>
              <span class="font-semibold block ${attrs.reputation < 0 ? 'text-red-400' : 'text-green-400'}">${attrs.reputation ?? 0}</span>
            </div>
            <div>
              <span class="text-slate-500 block">Country</span>
              <span class="text-slate-200 font-semibold block">${this.escapeHtml(attrs.country || 'N/A')}</span>
            </div>
            <div>
              <span class="text-slate-500 block">Stats</span>
              <span class="text-slate-400 block font-mono text-[10px]">
                Harmless: ${stats.harmless ?? 0} | Suspicious: ${stats.suspicious ?? 0}
              </span>
            </div>
          </div>

          <!-- Detections List -->
          ${maliciousEngines.length > 0 ? `
            <div class="space-y-1">
              <span class="text-xs text-slate-400">Flagging Engines:</span>
              <div class="flex flex-wrap gap-1">
                ${maliciousEngines.map(eng => `<span class="bg-red-950/50 border border-red-500/30 text-red-400 text-[10px] px-2 py-0.5 rounded font-mono">${this.escapeHtml(eng)}</span>`).join('')}
              </div>
            </div>
          ` : `
            <div class="text-xs text-green-400 flex items-center gap-1">
              <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" /></svg>
              No engines flagged this resource as malicious.
            </div>
          `}
        </div>
      `;
    }
    
    if (sourceName === 'abuseipdb') {
      const data = rawData.data || {};
      const score = data.abuseConfidenceScore ?? 0;
      
      let scoreColor = 'text-green-400';
      let scoreBg = 'bg-green-500';
      if (score > 70) { scoreColor = 'text-red-500'; scoreBg = 'bg-red-500'; }
      else if (score > 30) { scoreColor = 'text-orange-400'; scoreBg = 'bg-orange-500'; }
      else if (score > 10) { scoreColor = 'text-yellow-400'; scoreBg = 'bg-yellow-500'; }

      const categoriesMap = {
        1: 'DNS Compromise', 2: 'DNS Poisoning', 3: 'Fraud Web', 4: 'DDoS Attack',
        5: 'FTP Bruteforce', 6: 'Ping of Death', 7: 'Phishing', 8: 'Fraud VoIP',
        9: 'Open Proxy', 10: 'Web Spam', 11: 'Email Spam', 12: 'Blog Spam',
        13: 'VPN IP', 14: 'Port Scan', 15: 'Hacking', 16: 'SQL Injection',
        17: 'Spoofing', 18: 'Brute-Force', 19: 'Bad Web Bot', 20: 'Exploited Host',
        21: 'Web App Attack', 22: 'SSH', 23: 'IoT Targeting'
      };

      const reports = data.reports || [];

      return `
        <div class="space-y-4">
          <!-- Reputation Score Bar -->
          <div class="space-y-1">
            <div class="flex justify-between text-xs">
              <span class="text-slate-400">Abuse Confidence Score</span>
              <span class="font-mono font-bold ${scoreColor}">${score}%</span>
            </div>
            <div class="w-full bg-slate-800 rounded-full h-2 overflow-hidden">
              <div class="${scoreBg} h-2" style="width: ${score}%"></div>
            </div>
          </div>

          <!-- Stats Grid -->
          <div class="grid grid-cols-2 gap-3 text-xs bg-slate-900/40 p-3 rounded-lg border border-white/5">
            <div>
              <span class="text-slate-500 block">ISP</span>
              <span class="text-slate-200 font-semibold truncate block" title="${this.escapeHtml(data.isp || 'N/A')}">${this.escapeHtml(data.isp || 'N/A')}</span>
            </div>
            <div>
              <span class="text-slate-500 block">Domain</span>
              <span class="text-slate-200 font-semibold font-mono truncate block" title="${this.escapeHtml(data.domain || 'N/A')}">${this.escapeHtml(data.domain || 'N/A')}</span>
            </div>
            <div>
              <span class="text-slate-500 block">Usage Type</span>
              <span class="text-slate-200 font-semibold truncate block" title="${this.escapeHtml(data.usageType || 'N/A')}">${this.escapeHtml(data.usageType || 'N/A')}</span>
            </div>
            <div>
              <span class="text-slate-500 block">Location</span>
              <span class="text-slate-200 font-semibold block">${this.escapeHtml(data.countryName || 'N/A')} (${this.escapeHtml(data.countryCode || 'N/A')})</span>
            </div>
            <div>
              <span class="text-slate-500 block">Total Reports</span>
              <span class="text-slate-200 font-semibold block">${data.totalReports ?? 0} (from ${data.numDistinctUsers ?? 0} users)</span>
            </div>
            <div>
              <span class="text-slate-500 block">Tor Exit Node</span>
              <span class="block font-semibold ${data.isTor ? 'text-orange-400' : 'text-slate-400'}">${data.isTor ? 'Yes' : 'No'}</span>
            </div>
          </div>

          <!-- Reports Comments -->
          <div class="space-y-2">
            <span class="text-xs text-slate-400 font-semibold block">Recent Abuse Reports (${reports.length}):</span>
            ${reports.length > 0 ? `
              <div class="space-y-2 max-h-48 overflow-y-auto pr-1 select-text">
                ${reports.map(rep => {
                  const date = new Date(rep.reportedAt).toLocaleDateString(undefined, {month:'short', day:'numeric', hour:'2-digit', minute:'2-digit'});
                  const catBadges = (rep.categories || []).map(catId => {
                    const name = categoriesMap[catId] || `Cat ${catId}`;
                    return `<span class="bg-slate-800 text-slate-300 text-[9px] px-1 py-0.5 rounded mr-1 font-mono">${this.escapeHtml(name)}</span>`;
                  }).join('');
                  
                  return `
                    <div class="bg-black/20 p-2.5 rounded border border-white/5 space-y-1.5">
                      <div class="flex justify-between items-center text-[10px]">
                        <span class="text-slate-400 font-mono">${date}</span>
                        <div class="flex flex-wrap">${catBadges}</div>
                      </div>
                      <p class="text-xs text-slate-300 font-sans italic whitespace-pre-wrap break-all">${this.escapeHtml(rep.comment || '(No comment)')}</p>
                    </div>
                  `;
                }).join('')}
              </div>
            ` : `
              <div class="text-xs text-green-400">No recent reports found in AbuseIPDB.</div>
            `}
          </div>
        </div>
      `;
    }
    
    if (sourceName === 'urlscan') {
      const page = rawData.page || {};
      const stats = rawData.stats || {};
      const task = rawData.task || {};
      const verdicts = rawData.verdicts?.overall || {};
      
      const screenshot = rawData.screenshot || task.screenshotURL || '';
      
      return `
        <div class="space-y-4">
          <!-- Verdict info -->
          <div class="flex items-center justify-between">
            <div class="flex items-center gap-1.5">
              <span class="text-xs text-slate-400">Status:</span>
              <span class="text-xs font-bold px-2 py-0.5 rounded ${verdicts.malicious ? 'bg-red-950 text-red-400 border border-red-500/30' : 'bg-green-950 text-green-400 border border-green-500/30'}">
                ${verdicts.malicious ? 'Malicious' : 'Clean'}
              </span>
            </div>
            ${verdicts.score !== undefined ? `
              <div class="text-xs">
                <span class="text-slate-400">Risk Score:</span>
                <span class="font-mono font-bold ${verdicts.score > 50 ? 'text-red-400' : 'text-green-400'}">${verdicts.score}/100</span>
              </div>
            ` : ''}
          </div>

          <!-- Page Details Grid -->
          <div class="grid grid-cols-2 gap-3 text-xs bg-slate-900/40 p-3 rounded-lg border border-white/5">
            <div class="col-span-2">
              <span class="text-slate-500 block">Scan URL</span>
              <span class="text-slate-200 font-semibold font-mono truncate block select-all" title="${this.escapeHtml(task.url || 'N/A')}">${this.escapeHtml(task.url || 'N/A')}</span>
            </div>
            <div>
              <span class="text-slate-500 block">Domain</span>
              <span class="text-slate-200 font-semibold truncate block" title="${this.escapeHtml(page.domain || 'N/A')}">${this.escapeHtml(page.domain || 'N/A')}</span>
            </div>
            <div>
              <span class="text-slate-500 block">Server IP</span>
              <span class="text-slate-200 font-semibold font-mono block">${this.escapeHtml(page.ip || 'N/A')}</span>
            </div>
            <div>
              <span class="text-slate-500 block">ASN Name</span>
              <span class="text-slate-200 font-semibold truncate block" title="${this.escapeHtml(page.asnname || 'N/A')}">${this.escapeHtml(page.asnname || 'N/A')}</span>
            </div>
            <div>
              <span class="text-slate-500 block">Location</span>
              <span class="text-slate-200 font-semibold block">${this.escapeHtml(page.country || 'N/A')} (${this.escapeHtml(page.city || 'N/A')})</span>
            </div>
            <div>
              <span class="text-slate-500 block">Unique IPs</span>
              <span class="text-slate-200 font-semibold block">${stats.uniqIPs ?? 0} IPs</span>
            </div>
            <div>
              <span class="text-slate-500 block">Console Warnings</span>
              <span class="text-slate-200 font-semibold block">${stats.consoleMsgs ?? 0} / ${stats.securityWarnings ?? 0}</span>
            </div>
          </div>

          <!-- Screenshot preview if available -->
          ${screenshot ? `
            <div class="space-y-1">
              <span class="text-xs text-slate-400 block">Site Screenshot:</span>
              <div class="rounded-lg overflow-hidden border border-white/10 shadow-lg bg-black/40">
                <img src="${this.escapeHtml(screenshot)}" alt="Scan screenshot" class="w-full h-auto object-cover max-h-48 cursor-zoom-in" onclick="window.open('${this.escapeHtml(screenshot)}', '_blank')"/>
              </div>
            </div>
          ` : ''}
        </div>
      `;
    }

    return '<div class="text-slate-400 text-xs">Unknown source type.</div>';
  },

  /**
   * Show loading state for a source
   * @param {string} sourceName - 'virustotal', 'abuseipdb', or 'urlscan'
   */
  showLoadingState(sourceName) {
    const loadingEl = document.getElementById(`${sourceName}-loading`);
    const resultsEl = document.getElementById(`${sourceName}-results`);
    const statusEl = document.getElementById(`${sourceName}-status`);
    
    if (!loadingEl || !resultsEl || !statusEl) {
      console.error(`UIRenderer: Source card elements not found for ${sourceName}`);
      return;
    }
    
    // Show loading spinner
    loadingEl.classList.remove('hidden');
    
    // Hide results
    resultsEl.classList.add('hidden');
    
    // Clear status
    statusEl.innerHTML = '';
  },
  
  /**
   * Render error in source card
   * @param {string} sourceName - 'virustotal', 'abuseipdb', or 'urlscan'
   * @param {string} error - Error message
   */
  renderError(sourceName, error) {
    const loadingEl = document.getElementById(`${sourceName}-loading`);
    const resultsEl = document.getElementById(`${sourceName}-results`);
    const statusEl = document.getElementById(`${sourceName}-status`);
    
    if (!loadingEl || !resultsEl || !statusEl) {
      console.error(`UIRenderer: Source card elements not found for ${sourceName}`);
      return;
    }
    
    // Hide loading spinner
    loadingEl.classList.add('hidden');
    
    // Show results section
    resultsEl.classList.remove('hidden');
    
    // Render error
    statusEl.innerHTML = `
      <div class="flex items-center gap-2 text-red-400">
        <svg class="w-5 h-5" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor">
          <path stroke-linecap="round" stroke-linejoin="round" d="M12 9v3.75m9-.75a9 9 0 1 1-18 0 9 9 0 0 1 18 0Zm-9 3.75h.008v.008H12v-.008Z" />
        </svg>
        <span class="font-semibold">Error</span>
      </div>
    `;
    
    resultsEl.innerHTML = `
      <div class="text-red-400 text-sm">${this.escapeHtml(error)}</div>
    `;
  },
  
  /**
   * Toggle details expansion for a source
   * @param {string} sourceName - 'virustotal', 'abuseipdb', or 'urlscan'
   */
  toggleDetails(sourceName) {
    const resultsEl = document.getElementById(`${sourceName}-results`);
    if (!resultsEl) return;
    
    const detailsEl = resultsEl.querySelector('.source-details');
    const chevronIcon = resultsEl.querySelector('.chevron-icon');
    
    if (detailsEl && chevronIcon) {
      detailsEl.classList.toggle('hidden');
      
      // Rotate chevron
      if (detailsEl.classList.contains('hidden')) {
        chevronIcon.style.transform = 'rotate(0deg)';
      } else {
        chevronIcon.style.transform = 'rotate(180deg)';
      }
    }
  },
  
  /**
   * Render search history
   * @param {Array} history - Array of search history items
   */
  renderSearchHistory(history) {
    const historyList = document.getElementById('threat-intel-history-list');
    
    if (!historyList) {
      console.error('UIRenderer: History list element not found');
      return;
    }
    
    // Clear existing content
    historyList.innerHTML = '';
    
    // If no history, show empty state
    if (!history || history.length === 0) {
      historyList.innerHTML = `
        <div class="text-sm text-slate-400 text-center py-4">
          No recent searches
        </div>
      `;
      return;
    }
    
    // Render each history item
    history.forEach((item, index) => {
      const historyItem = document.createElement('div');
      historyItem.className = 'recent-search-item cyber-card p-3 cursor-pointer transition-all duration-200 hover:bg-blue-500/10 hover:border-blue-500/30 flex items-center justify-between';
      historyItem.dataset.index = index;
      
      // Format timestamp to relative time
      const relativeTime = this.formatRelativeTime(item.timestamp);
      
      // Determine verdict color
      const verdictColor = item.verdict === 'MALICIOUS' ? 'text-red-400' : 'text-cyan-400';
      
      historyItem.innerHTML = `
        <div class="flex-1 min-w-0">
          <div class="font-mono text-sm text-slate-200 truncate">${this.escapeHtml(item.input)}</div>
          <div class="flex items-center gap-2 mt-1">
            <span class="text-xs text-slate-500">${relativeTime}</span>
            <span class="text-xs ${verdictColor} font-semibold">${item.verdict}</span>
          </div>
        </div>
        <svg class="w-5 h-5 text-slate-400 flex-shrink-0 ml-2" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor">
          <path stroke-linecap="round" stroke-linejoin="round" d="m21 21-5.197-5.197m0 0A7.5 7.5 0 1 0 5.196 5.196a7.5 7.5 0 0 0 10.607 10.607Z" />
        </svg>
      `;
      
      // Event listener is handled by event delegation in bindEventListeners()
      // No need to bind individual listeners here
      
      historyList.appendChild(historyItem);
    });
    
    console.log(`UIRenderer: Rendered ${history.length} history items`);
  },
  
  /**
   * Format timestamp to relative time
   * @param {string} timestamp - ISO 8601 timestamp
   * @returns {string} Relative time string (e.g., "2 hours ago")
   */
  formatRelativeTime(timestamp) {
    try {
      const now = new Date();
      const then = new Date(timestamp);
      const diffMs = now - then;
      const diffSecs = Math.floor(diffMs / 1000);
      const diffMins = Math.floor(diffSecs / 60);
      const diffHours = Math.floor(diffMins / 60);
      const diffDays = Math.floor(diffHours / 24);
      
      if (diffSecs < 60) {
        return 'Just now';
      } else if (diffMins < 60) {
        return `${diffMins} ${diffMins === 1 ? 'minute' : 'minutes'} ago`;
      } else if (diffHours < 24) {
        return `${diffHours} ${diffHours === 1 ? 'hour' : 'hours'} ago`;
      } else if (diffDays < 7) {
        return `${diffDays} ${diffDays === 1 ? 'day' : 'days'} ago`;
      } else {
        return then.toLocaleDateString();
      }
    } catch (error) {
      console.error('UIRenderer: Error formatting relative time:', error);
      return 'Unknown';
    }
  },
  
  /**
   * Escape HTML to prevent XSS
   * @param {string} text - Text to escape
   * @returns {string} Escaped text
   */
  escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  },
  
  /**
   * Render idle state for a source card
   * Displays "Awaiting search" placeholder and hides loading spinners
   * @param {string} sourceName - 'virustotal', 'abuseipdb', or 'urlscan'
   */
  renderIdleState(sourceName) {
    const loadingEl = document.getElementById(`${sourceName}-loading`);
    const resultsEl = document.getElementById(`${sourceName}-results`);
    const statusEl = document.getElementById(`${sourceName}-status`);
    
    if (!loadingEl || !resultsEl || !statusEl) {
      console.error(`UIRenderer: Source card elements not found for ${sourceName}`);
      return;
    }
    
    // Hide loading spinner
    loadingEl.classList.add('hidden');
    
    // Hide results section (idle state)
    resultsEl.classList.add('hidden');
    
    // Show idle state message in status element
    statusEl.innerHTML = `
      <div class="text-center py-8 text-slate-400 text-sm">
        Awaiting search
      </div>
    `;
  }
};

// Export for use in other scripts
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { ThreatIntelHub, ThreatIntelState, InputValidator, APIOrchestrator, DataExtractor, VerdictCalculator, UIRenderer };
}
