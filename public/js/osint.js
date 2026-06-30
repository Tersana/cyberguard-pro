/**
 * CyberGuard OSINT Passive Reconnaissance Module
 * Version: 1.0.0
 * Provides 8 passive target intelligence tools:
 * 1. Subdomain Finder (crt.sh)
 * 2. Email Breach Checker (HaveIBeenPwned)
 * 3. DNS Record Lookup (Cloudflare DoH)
 * 4. IP Intelligence (ip-api & AbuseIPDB)
 * 5. Wayback Machine History (CDX API)
 * 6. Username Profile Search (Sherlock Profiles check)
 * 7. Email Format Guesser (Pattern permutation engine)
 * 8. Aggregated PDF Report (jsPDF builder)
 */

(() => {
const ENCRYPTION_KEY = 'CyberGuard2024!@#';

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// CORS Proxy Fallback Chain
const CORS_PROXIES = [
  { url: 'https://corsproxy.io/?url=',          encode: true },
  { url: 'https://api.allorigins.win/raw?url=', encode: true },
  { url: 'https://cors.lol/?url=',              encode: true },
];

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
 * Fetch through the CORS proxy fallback chain.
 * Tries each proxy in order until success.
 * @param {string} targetUrl - The actual API endpoint URL
 * @param {Object} fetchOptions - Standard fetch() options
 * @returns {Promise<Response>} The fetch Response
 */
async function fetchWithProxy(targetUrl, fetchOptions = {}) {
  // Inject AbortController signal if active in OSINT module
  if (typeof OSINT !== 'undefined' && OSINT.activeAbortController && !fetchOptions.signal) {
    fetchOptions.signal = OSINT.activeAbortController.signal;
  }
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
        if ((targetStatus >= 200 && targetStatus < 300) || targetStatus === 404) {
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
        return response;
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
      if (err.name === 'AbortError') {
        throw err;
      }
      console.warn(`CORS proxy failed (${proxy.url}):`, err.message);
      lastError = err;
    }
  }

  throw lastError || new Error('All CORS proxies failed');
}

/**
 * OSINT Module Controller
 */
const OSINT = {
  // Storage of results for PDF report generation
  results: {
    subdomains: null,
    dns: null,
    ip: null,
    wayback: null,
    username: null,
    emailformat: null
  },

  // Active status tracker
  isRunningAll: false,
  activeTool: 'subdomain',
  activeAbortController: null,

  // Scan history (persisted in localStorage)
  scanHistory: [],

  /**
   * Initialize module listeners and target auto-fills
   */
  init() {
    console.log('OSINT Module: Initializing...');

    // Bind Global Input Events
    const globalInput = document.getElementById('osint-global-target');
    if (globalInput) {
      globalInput.addEventListener('input', (e) => this.handleGlobalInput(e.target.value));
    }

    // Bind Action Buttons
    const runAllBtn = document.getElementById('osint-run-all-btn');
    if (runAllBtn) {
      runAllBtn.addEventListener('click', () => this.runAllTools());
    }

    const stopBtn = document.getElementById('osint-stop-btn');
    if (stopBtn) {
      stopBtn.addEventListener('click', () => this.stopAllTools());
    }

    const clearAllBtn = document.getElementById('osint-clear-all-btn');
    if (clearAllBtn) {
      clearAllBtn.addEventListener('click', () => {
        try {
          CyberNotify.confirm(
            'This will erase all target inputs, scan results, and terminal logs. Are you sure?',
            (confirmed) => {
              if (confirmed) this.clearAll();
            },
            { type: 'warning' }
          );
        } catch (e) {
          // Fallback if CyberNotify is unavailable
          if (window.confirm('Clear all inputs and results?')) this.clearAll();
        }
      });
    }

    const reportBtn = document.getElementById('osint-generate-report-btn');
    if (reportBtn) {
      reportBtn.addEventListener('click', () => this.generateFullReport());
    }

    // Bind Clear History button
    const clearHistoryBtn = document.getElementById('osint-clear-history-btn');
    if (clearHistoryBtn) {
      clearHistoryBtn.addEventListener('click', () => this.clearScanHistory());
    }

    // Load scan history from localStorage
    try {
      const stored = localStorage.getItem('osint_scan_history');
      if (stored) {
        this.scanHistory = JSON.parse(stored);
      } else {
        this.scanHistory = [];
      }
    } catch (e) {
      this.scanHistory = [];
    }
    this.renderScanHistoryList();

    this.selectTool('subdomain');
    this.updateReportButtonState();
    console.log('OSINT Module: Initialization complete');
  },

  /**
   * Toggle visual state of the scanning buttons
   */
  setScanningState(isScanning) {
    const runBtn = document.getElementById('osint-run-all-btn');
    const stopBtn = document.getElementById('osint-stop-btn');
    if (runBtn && stopBtn) {
      if (isScanning) {
        runBtn.classList.add('hidden');
        stopBtn.classList.remove('hidden');
      } else {
        runBtn.classList.remove('hidden');
        stopBtn.classList.add('hidden');
      }
    }
  },

  /**
   * Stop all active recon tools immediately
   */
  stopAllTools() {
    this.log('Passive reconnaissance scan stopped by user.', 'info');
    if (this.activeAbortController) {
      this.activeAbortController.abort();
      this.activeAbortController = null;
    }
    this.isRunningAll = false;
    this.setScanningState(false);

    // Set all currently scanning or idle tools to stopped state
    const tools = ['subdomain', 'dns', 'ip', 'wayback', 'username', 'emailformat'];
    tools.forEach(toolId => {
      const dot = document.getElementById(`osint-status-dot-${toolId}`);
      if (dot && (dot.classList.contains('scanning') || dot.classList.contains('idle'))) {
        this.setStatus(toolId, 'idle');
        const resultsContainer = document.getElementById(`osint-${toolId}-results`);
        if (resultsContainer && (resultsContainer.innerHTML.includes('cyber-spinner') || resultsContainer.innerHTML.includes('osint-loading'))) {
          this.setErrorState(
            `osint-${toolId}-results`,
            'Scan was stopped by the user.'
          );
        }
      }
    });
  },

  /**
   * Focus a specific tool visualizer panel
   */
  selectTool(toolId) {
    this.activeTool = toolId;

    // 1. Switch active class on tool list items
    const items = document.querySelectorAll('.osint-console-tool-item');
    items.forEach(item => {
      if (item.getAttribute('data-tool') === toolId) {
        item.classList.add('active');
      } else {
        item.classList.remove('active');
      }
    });

    // 2. Switch active class on results wrappers
    const wrappers = document.querySelectorAll('.osint-results-wrapper');
    wrappers.forEach(wrap => {
      if (wrap.id === `osint-${toolId}-wrapper`) {
        wrap.classList.add('active');
      } else {
        wrap.classList.remove('active');
      }
    });

    // 3. Update active tool title
    const titleEl = document.getElementById('osint-active-tool-title');
    if (titleEl) {
      const toolNames = {
        subdomain: 'Subdomain Finder',
        dns: 'DNS Record Lookup',
        wayback: 'Wayback Machine',
        username: 'Username OSINT',
        emailformat: 'Email Format Guesser',
        ip: 'IP Intelligence'
      };
      titleEl.textContent = `Active Module: ${toolNames[toolId] || toolId}`;
    }
  },

  /**
   * Append log entry to console terminal
   */
  log(message, type = 'info') {
    const logEl = document.getElementById('osint-terminal-log');
    if (!logEl) return;

    const timeStr = new Date().toTimeString().split(' ')[0];
    const lineEl = document.createElement('div');
    lineEl.className = `terminal-line terminal-${type}`;
    
    lineEl.innerHTML = `
      <span class="terminal-timestamp">[${timeStr}]</span>
      <span class="terminal-prefix">[${type.toUpperCase()}]</span>
      <span class="terminal-content">${escapeHtml(message)}</span>
    `; // security-audit-ignore

    logEl.appendChild(lineEl);
    logEl.scrollTop = logEl.scrollHeight;
  },

  /**
   * Set status dot indicator
   */
  setStatus(toolId, status) {
    const dot = document.getElementById(`osint-status-dot-${toolId}`);
    if (!dot) return;
    
    dot.className = `osint-tool-status-dot ${status}`;
  },

  /**
   * Helper to copy data to clipboard with notification
   */
  copyToClipboard(text) {
    if (!text) return;
    navigator.clipboard.writeText(text).then(() => {
      try {
        CyberNotify.alert('Copied to clipboard!', { type: 'success' });
      } catch (e) {
        // CyberNotify unavailable
      }
    }).catch(err => {
      console.error('Clipboard copy failed:', err);
      // Fallback
      const textarea = document.createElement('textarea');
      textarea.value = text;
      document.body.appendChild(textarea);
      textarea.select();
      try {
        document.execCommand('copy');
        try {
          CyberNotify.alert('Copied to clipboard!', { type: 'success' });
        } catch (e) { /* unavailable */ }
      } catch (e) {
        console.error('Fallback copy failed:', e);
      }
      document.body.removeChild(textarea);
    });
  },

  /**
   * Dynamic input type detection
   * @param {string} input 
   * @returns {string|null} - 'email', 'ip', 'domain', 'username'
   */
  detectInputType(input) {
    input = input.trim();
    if (!input) return null;

    // Email check
    if (input.includes('@') && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(input)) {
      return 'email';
    }

    // IPv4 check
    const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    if (ipRegex.test(input)) {
      return 'ip';
    }

    // Domain check
    const domainRegex = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,18}$/i;
    if (domainRegex.test(input)) {
      return 'domain';
    }

    // Default to username if alphanumeric and correct size
    if (/^[a-zA-Z0-9_\-\.]{3,30}$/.test(input)) {
      return 'username';
    }

    return null;
  },

  /**
   * Auto-fill specific tool input fields on global input changes
   */
  handleGlobalInput(value) {
    const type = this.detectInputType(value);
    if (!type) return;

    const trimmed = value.trim();

    // Fill corresponding inputs based on type
    if (type === 'domain') {
      this.setInputVal('osint-subdomain-input', trimmed);
      this.setInputVal('osint-dns-input', trimmed);
      this.setInputVal('osint-wayback-input', trimmed);
      this.setInputVal('osint-emailformat-domain', trimmed);
    } else if (type === 'ip') {
      this.setInputVal('osint-ip-input', trimmed);
    } else if (type === 'email') {
      // Parse email structure for permutations
      const parts = trimmed.split('@');
      if (parts.length === 2) {
        const usernamePart = parts[0];
        const domainPart = parts[1];
        this.setInputVal('osint-emailformat-domain', domainPart);
        
        // Try parsing first/last names from dot notation
        const nameParts = usernamePart.split('.');
        if (nameParts.length >= 2) {
          this.setInputVal('osint-emailformat-firstname', nameParts[0]);
          this.setInputVal('osint-emailformat-lastname', nameParts[1]);
        } else {
          this.setInputVal('osint-emailformat-firstname', usernamePart);
          this.setInputVal('osint-emailformat-lastname', '');
        }
      }
    } else if (type === 'username') {
      this.setInputVal('osint-username-input', trimmed);
    }
  },

  setInputVal(id, value) {
    const el = document.getElementById(id);
    if (el) {
      el.value = value;
    }
  },

  /**
   * Verify if any result is available and toggle PDF report button state
   */
  updateReportButtonState() {
    const reportBtn = document.getElementById('osint-generate-report-btn');
    if (!reportBtn) return;

    const hasData = Object.values(this.results).some(res => res !== null);
    reportBtn.disabled = !hasData;
  },

  /**
   * Clear all fields and results
   */
  clearAll() {
    // Clear state
    for (const key in this.results) {
      this.results[key] = null;
    }
    
    // Clear inputs
    const inputs = [
      'osint-global-target',
      'osint-subdomain-input',
      'osint-dns-input',
      'osint-ip-input',
      'osint-wayback-input',
      'osint-username-input',
      'osint-emailformat-firstname',
      'osint-emailformat-lastname',
      'osint-emailformat-domain'
    ];
    inputs.forEach(id => {
      const el = document.getElementById(id);
      if (el) el.value = '';
    });

    // Reset results containers to empty states
    const tools = [
      { id: 'subdomain', text: 'Enter a target and click Run' },
      { id: 'dns', text: 'Enter a target and click Run' },
      { id: 'ip', text: 'Enter a target and click Run' },
      { id: 'wayback', text: 'Enter a target and click Run' },
      { id: 'username', text: 'Enter a target and click Run' },
      { id: 'emailformat', text: 'Enter details and click Run' }
    ];

    tools.forEach(tool => {
      const container = document.getElementById(`osint-${tool.id}-results`);
      if (container) {
        container.innerHTML = `
          <div class="osint-empty-state">
            <span>${escapeHtml(tool.text)}</span>
          </div>
        `; // security-audit-ignore
      }
      this.setStatus(tool.id, 'idle');
    });

    // Reset terminal logs
    const logEl = document.getElementById('osint-terminal-log');
    if (logEl) {
      logEl.innerHTML = `
        <div class="terminal-line system-welcome">[SYSTEM] CyberGuard Passive Reconnaissance Console v1.0.0</div>
        <div class="terminal-line system-ready">[SYSTEM] All modules loaded. Ready for target input.</div>
      `;
    }

    // Uncheck all module checkboxes and deactivate all rows
    const toggleIds = ['subdomain','dns','wayback','username','emailformat','ip'];
    toggleIds.forEach(id => {
      const cb = document.getElementById(`osint-toggle-${id}`);
      if (cb) cb.checked = false;
    });
    document.querySelectorAll('.osint-console-tool-item').forEach(el => el.classList.remove('active'));
    this.activeTool = null;

    this.updateReportButtonState();
    
    try {
        CyberNotify.alert('All target inputs and results have been cleared.', { type: 'info' });
    } catch (e) { /* CyberNotify unavailable */ }
  },

  /**
   * Helper to set loading container HTML
   */
  setLoadingState(containerId, message = 'Analyzing target...') {
    const el = document.getElementById(containerId);
    if (!el) return;
    el.innerHTML = `
      <div class="osint-loading">
        <div class="osint-loading-spinner"></div>
        <span>${escapeHtml(message)}</span>
      </div>
    `; // security-audit-ignore
  },

  /**
   * Helper to set error container HTML
   */
  setErrorState(containerId, errorMessage) {
    const el = document.getElementById(containerId);
    if (!el) return;
    el.innerHTML = `
      <div class="osint-error-state">
        <span class="osint-error-icon">
          <svg class="w-6 h-6 text-red-500" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2" style="width: 1.5rem; height: 1.5rem; display: inline-block; vertical-align: middle;">
            <path stroke-linecap="round" stroke-linejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
          </svg>
        </span>
        <span>Error: ${escapeHtml(errorMessage)}</span>
      </div>
    `; // security-audit-ignore
  },

  /**
   * Run all tools sequentially based on inputs
   */
  async runAllTools() {
    const globalVal = document.getElementById('osint-global-target')?.value || '';
    if (!globalVal.trim()) {
      try {
        CyberNotify.alert('Please enter a target in the global input field to run all tools.', { type: 'warning' });
      } catch (e) {
        alert('Please enter a target.');
      }
      return;
    }

    this.isRunningAll = true;
    this.setScanningState(true);
    this.activeAbortController = new AbortController();
    
    // Auto-fill fields if not done
    this.handleGlobalInput(globalVal);

    const promises = [];

    // Find the first checked tool and focus it
    const checkedTools = [];
    if (document.getElementById('osint-toggle-subdomain')?.checked) checkedTools.push('subdomain');
    if (document.getElementById('osint-toggle-dns')?.checked) checkedTools.push('dns');
    if (document.getElementById('osint-toggle-wayback')?.checked) checkedTools.push('wayback');
    if (document.getElementById('osint-toggle-username')?.checked) checkedTools.push('username');
    if (document.getElementById('osint-toggle-emailformat')?.checked) checkedTools.push('emailformat');
    if (document.getElementById('osint-toggle-ip')?.checked) checkedTools.push('ip');

    if (checkedTools.length > 0) {
      this.selectTool(checkedTools[0]);
    }

    this.log(`Initiating multi-module passive reconnaissance scan for target: ${globalVal}`, 'info');

    // Check subdomain finder input and checkbox
    const subInput = document.getElementById('osint-subdomain-input')?.value;
    const subChecked = document.getElementById('osint-toggle-subdomain')?.checked;
    if (subInput && subChecked) promises.push(this.runSubdomainFinder());

    // Check DNS input and checkbox
    const dnsInput = document.getElementById('osint-dns-input')?.value;
    const dnsChecked = document.getElementById('osint-toggle-dns')?.checked;
    if (dnsInput && dnsChecked) promises.push(this.runDNSLookup());

    // Check IP input and checkbox
    const ipInput = document.getElementById('osint-ip-input')?.value;
    const ipChecked = document.getElementById('osint-toggle-ip')?.checked;
    if (ipInput && ipChecked) promises.push(this.runIPIntelligence());

    // Check Wayback input and checkbox
    const wbInput = document.getElementById('osint-wayback-input')?.value;
    const wbChecked = document.getElementById('osint-toggle-wayback')?.checked;
    if (wbInput && wbChecked) promises.push(this.runWaybackMachine());

    // Check Username input and checkbox
    const usernameInput = document.getElementById('osint-username-input')?.value;
    const usernameChecked = document.getElementById('osint-toggle-username')?.checked;
    if (usernameInput && usernameChecked) promises.push(this.runUsernameOSINT());

    // Check Email Format Guesser input and checkbox
    const fn = document.getElementById('osint-emailformat-firstname')?.value;
    const ln = document.getElementById('osint-emailformat-lastname')?.value;
    const dom = document.getElementById('osint-emailformat-domain')?.value;
    const emailformatChecked = document.getElementById('osint-toggle-emailformat')?.checked;
    if ((fn || ln || dom) && emailformatChecked) promises.push(this.runEmailFormatGuesser());

    if (promises.length === 0) {
      try {
        CyberNotify.alert('No enabled modules with valid inputs found. Verify target format and checkboxes.', { type: 'warning' });
      } catch (e) { /* CyberNotify unavailable */ }
      this.isRunningAll = false;
      this.setScanningState(false);
      this.activeAbortController = null;
      return;
    }

    try {
      await Promise.all(promises);
      this.isRunningAll = false;
      this.setScanningState(false);
      this.activeAbortController = null;

      this.log(`Multi-module scan completed for target: ${globalVal}`, 'success');

      // Save this multi-module scan to history
      this.saveCurrentScanToHistory(globalVal, 'Multi-module scan');

      try {
          CyberNotify.alert('All reconnaissance processes completed.', { type: 'success' });
      } catch (e) { /* CyberNotify unavailable */ }
    } catch (err) {
      this.isRunningAll = false;
      this.setScanningState(false);
      this.activeAbortController = null;

      if (err.name === 'AbortError') {
        this.log('Multi-module passive reconnaissance scan was stopped by user.', 'warning');
        try {
            CyberNotify.alert('Scan stopped by user.', { type: 'info' });
        } catch (e) { /* CyberNotify unavailable */ }
      } else {
        this.log(`Multi-module scan failed: ${err.message}`, 'error');
        try {
            CyberNotify.alert(`Scan failed: ${err.message}`, { type: 'error' });
        } catch (e) { /* CyberNotify unavailable */ }
      }
    }
  },

  // =========================================================================
  // TOOL 1: SUBDOMAIN FINDER (crt.sh)
  // =========================================================================
  async runSubdomainFinder() {
    const inputEl = document.getElementById('osint-subdomain-input');
    const containerId = 'osint-subdomain-results';
    
    if (!inputEl) return;
    const domain = inputEl.value.trim().toLowerCase();
    
    if (!domain) {
      try {
        CyberNotify.alert('Please enter a target domain name.', { type: 'warning' });
      } catch (e) { /* CyberNotify unavailable */ }
      inputEl.focus();
      return;
    }

    if (!this.isRunningAll) {
      this.selectTool('subdomain');
      this.setScanningState(true);
      this.activeAbortController = new AbortController();
    }
    this.setStatus('subdomain', 'scanning');
    this.log(`Starting subdomain reconnaissance for: ${domain}`, 'scanning');

    this.setLoadingState(containerId, 'Querying Certificate Transparency logs...');

    try {
      let subdomainsSet = new Set();
      let querySuccessful = false;

      // Phase 1: Try crt.sh
      try {
        const url = `https://crt.sh/?q=%.${domain}&output=json`;
        const response = await fetchWithProxy(url);
        if (!response.ok) {
          throw new Error(`Status ${response.status}`);
        }

        const text = await response.text();
        const trimmedText = text.trim();
        if (trimmedText.startsWith('<') || !trimmedText.startsWith('[')) {
          throw new Error('Invalid JSON format (HTML/Error message received)');
        }

        const rawData = JSON.parse(trimmedText);
        if (!Array.isArray(rawData)) {
          throw new Error('Response payload is not an array');
        }

        // Extract unique domain names
        rawData.forEach(item => {
          if (item.name_value) {
            const names = item.name_value.split('\n');
            names.forEach(name => {
              const cleanName = name.trim().toLowerCase();
              if (cleanName && cleanName.endsWith(domain)) {
                const formattedName = cleanName.replace(/^\*\./, '');
                subdomainsSet.add(formattedName);
              }
            });
          }
        });
        
        querySuccessful = true;
      } catch (crtErr) {
        if (crtErr.name === 'AbortError') throw crtErr;
        console.warn('Subdomain finder: crt.sh query failed, attempting HackerTarget fallback...', crtErr);
        this.log(`crt.sh query failed/blocked. Attempting HackerTarget fallback...`, 'warning');
      }

      // Phase 2: If crt.sh failed, try HackerTarget fallback
      if (!querySuccessful) {
        try {
          this.setLoadingState(containerId, 'crt.sh overloaded. Querying HackerTarget DNS cache...');
          const url = `https://api.hackertarget.com/hostsearch/?q=${domain}`;
          const response = await fetchWithProxy(url);
          if (!response.ok) {
            throw new Error(`Status ${response.status}`);
          }

          const text = await response.text();
          const trimmed = text.trim();
          if (trimmed.startsWith('<') || trimmed.includes('error') || trimmed.includes('API count exceeded')) {
            throw new Error('API limit reached or invalid response');
          }

          const lines = trimmed.split('\n');
          lines.forEach(line => {
            const parts = line.split(',');
            if (parts[0]) {
              const cleanSub = parts[0].trim().toLowerCase();
              if (cleanSub && cleanSub.endsWith(domain)) {
                subdomainsSet.add(cleanSub);
              }
            }
          });

          querySuccessful = true;
        } catch (fallbackErr) {
          if (fallbackErr.name === 'AbortError') throw fallbackErr;
          console.error('Subdomain finder: Fallback query failed as well:', fallbackErr);
        }
      }

      // Phase 3: Handle outcomes
      if (!querySuccessful) {
        this.setStatus('subdomain', 'failed');
        this.log(`Subdomain discovery failed for ${domain}. Upstream services are unresponsive.`, 'error');
        this.setErrorState(
          containerId, 
          'Unable to retrieve subdomain logs. Upstream services (crt.sh and HackerTarget) are currently unresponsive or rate-limiting queries. Please try again later.'
        );
        if (!this.isRunningAll) {
          this.setScanningState(false);
          this.activeAbortController = null;
        }
        return;
      }

      const sortedSubdomains = Array.from(subdomainsSet).sort();

      // Store state
      this.results.subdomains = {
        target: domain,
        data: sortedSubdomains
      };

      this.updateReportButtonState();
      this.setStatus('subdomain', 'success');
      this.log(`Subdomain discovery completed. Found ${sortedSubdomains.length} unique subdomains for ${domain}`, 'success');

      // Render layout
      const resultsContainer = document.getElementById(containerId);
      if (!resultsContainer) return;

      if (sortedSubdomains.length === 0) {
        resultsContainer.innerHTML = `
          <div class="osint-empty-state">
            <span>No subdomains found for ${escapeHtml(domain)}</span>
          </div>
        `; // security-audit-ignore
        if (!this.isRunningAll) {
          this.setScanningState(false);
          this.activeAbortController = null;
        }
        return;
      }

      let listHtml = '';
      sortedSubdomains.forEach(sub => {
        listHtml += `
          <div class="osint-subdomain-item">
            <span class="osint-subdomain-icon inline-block mr-1.5"><svg class="w-3.5 h-3.5 text-blue-400 inline-block align-middle" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2" style="width: 0.875rem; height: 0.875rem;"><path stroke-linecap="round" stroke-linejoin="round" d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9" /></svg></span>
            <span class="osint-subdomain-name">${escapeHtml(sub)}</span>
            <button class="osint-item-copy" onclick="OSINT.copyToClipboard('${escapeHtml(sub)}')" title="Copy Subdomain">
              <span class="material-symbols-outlined" style="font-size: 1rem;">content_copy</span>
            </button>
          </div>
        `;
      });

      resultsContainer.innerHTML = `
        <div class="osint-results-header">
          <span class="osint-results-count">Discovered: <strong>${sortedSubdomains.length}</strong> unique domains</span>
        </div>
        <div class="osint-subdomain-list">
          ${listHtml}
        </div>
      `; // security-audit-ignore

      if (!this.isRunningAll) {
        this.saveCurrentScanToHistory(domain, `Subdomain: ${domain}`);
        this.setScanningState(false);
        this.activeAbortController = null;
      }
    } catch (err) {
      if (err.name === 'AbortError') {
        this.setStatus('subdomain', 'idle');
        this.setErrorState(containerId, 'Scan was stopped by the user.');
      } else {
        this.setStatus('subdomain', 'failed');
        this.setErrorState(containerId, `Error: ${err.message}`);
      }
      if (!this.isRunningAll) {
        this.setScanningState(false);
        this.activeAbortController = null;
      }
    }
  },

  // =========================================================================
  // TOOL 3: DNS RECORD LOOKUP (Cloudflare DoH)
  // =========================================================================
  async runDNSLookup() {
    const inputEl = document.getElementById('osint-dns-input');
    const containerId = 'osint-dns-results';

    if (!inputEl) return;
    const domain = inputEl.value.trim().toLowerCase();

    if (!domain) {
      try {
        CyberNotify.alert('Please enter a target domain name.', { type: 'warning' });
      } catch (e) { /* CyberNotify unavailable */ }
      inputEl.focus();
      return;
    }

    if (!this.isRunningAll) {
      this.selectTool('dns');
      this.setScanningState(true);
      this.activeAbortController = new AbortController();
    }
    this.setStatus('dns', 'scanning');
    this.log(`Querying DNS records via Cloudflare DoH for: ${domain}`, 'scanning');

    this.setLoadingState(containerId, 'Resolving records via Cloudflare DoH...');

    try {
      const recordTypes = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA'];
      const results = {};

      const fetchPromises = recordTypes.map(async (type) => {
        try {
          const response = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=${type}`, {
            headers: {
              'Accept': 'application/dns-json'
            },
            ...(OSINT.activeAbortController ? { signal: OSINT.activeAbortController.signal } : {})
          });
          if (response.ok) {
            const data = await response.json();
            if (data.Answer && Array.isArray(data.Answer)) {
              results[type] = data.Answer;
            } else {
              results[type] = [];
            }
          } else {
            results[type] = [];
          }
        } catch (e) {
          if (e.name === 'AbortError') throw e;
          console.warn(`DNS lookup failed for type ${type}:`, e);
          results[type] = [];
        }
      });

      await Promise.all(fetchPromises);

      // Store state
      this.results.dns = {
        target: domain,
        data: results
      };
      this.updateReportButtonState();

      const resultsContainer = document.getElementById(containerId);
      if (!resultsContainer) return;

      const hasAnyRecords = Object.values(results).some(arr => arr.length > 0);
      if (!hasAnyRecords) {
        this.setStatus('dns', 'success');
        this.log(`DNS resolution completed. No records returned for ${domain}`, 'info');

        resultsContainer.innerHTML = `
          <div class="osint-empty-state">
            <span>No DNS records returned for ${escapeHtml(domain)}</span>
          </div>
        `; // security-audit-ignore
        if (!this.isRunningAll) {
          this.setScanningState(false);
          this.activeAbortController = null;
        }
        return;
      }

      let totalRecords = 0;
      Object.values(results).forEach(arr => totalRecords += arr.length);
      this.setStatus('dns', 'success');
      this.log(`DNS resolution completed. Found ${totalRecords} records across requested types for ${domain}`, 'success');

      let dnsHtml = '';
      recordTypes.forEach(type => {
        const records = results[type] || [];
        if (records.length === 0) return;

        let recordRows = '';
        records.forEach(r => {
          // Clean up quotes around text in TXT records
          const val = r.data.replace(/^"|"$/g, '');
          recordRows += `
            <div class="osint-dns-record">
              <span class="osint-dns-value">${escapeHtml(val)}</span>
              <span class="osint-dns-ttl">TTL: ${escapeHtml(r.TTL)}</span>
            </div>
          `;
        });

        dnsHtml += `
          <div class="osint-dns-section">
            <div class="osint-dns-type-label">
              <span>${escapeHtml(type)} Records</span>
              <span class="osint-dns-count">${records.length}</span>
            </div>
            ${recordRows}
          </div>
        `;
      });

      resultsContainer.innerHTML = `
        <div class="osint-dns-records">
          ${dnsHtml}
        </div>
      `; // security-audit-ignore

      if (!this.isRunningAll) {
        this.saveCurrentScanToHistory(domain, `DNS: ${domain}`);
        this.setScanningState(false);
        this.activeAbortController = null;
      }

    } catch (err) {
      if (err.name === 'AbortError') {
        this.setStatus('dns', 'idle');
        this.setErrorState(containerId, 'Scan was stopped by the user.');
      } else {
        console.error('DNS record resolution error:', err);
        this.setStatus('dns', 'failed');
        this.log(`DNS resolution failed for ${domain}: ${err.message}`, 'error');
        this.setErrorState(containerId, `Failed resolving DNS records. (${err.message})`);
      }
      if (!this.isRunningAll) {
        this.setScanningState(false);
        this.activeAbortController = null;
      }
    }
  },

  // =========================================================================
  // TOOL 4: IP INTELLIGENCE (ip-api + AbuseIPDB)
  // =========================================================================
  async runIPIntelligence() {
    const inputEl = document.getElementById('osint-ip-input');
    const containerId = 'osint-ip-results';

    if (!inputEl) return;
    let target = inputEl.value.trim();

    if (!target) {
      try {
        CyberNotify.alert('Please enter a target IP or domain.', { type: 'warning' });
      } catch (e) { /* CyberNotify unavailable */ }
      inputEl.focus();
      return;
    }

    if (!this.isRunningAll) {
      this.selectTool('ip');
      this.setScanningState(true);
      this.activeAbortController = new AbortController();
    }
    this.setStatus('ip', 'scanning');
    this.log(`Gathering IP intelligence for target: ${target}`, 'scanning');

    this.setLoadingState(containerId, 'Retrieving IP intelligence parameters...');

    try {
      // Check if input is domain. If so, resolve A records first
      const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
      if (!ipRegex.test(target)) {
        this.log(`Resolving target domain ${target} to IP...`, 'info');
        // Resolve target domain to IP
        const dnsResp = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(target)}&type=A`, {
          headers: { 'Accept': 'application/dns-json' },
          ...(OSINT.activeAbortController ? { signal: OSINT.activeAbortController.signal } : {})
        });
        if (dnsResp.ok) {
          const dnsData = await dnsResp.json();
          if (dnsData.Answer && dnsData.Answer.length > 0) {
            target = dnsData.Answer[0].data;
            this.log(`Target domain resolved to IP: ${target}`, 'success');
            console.log(`OSINT: Resolved domain to IP ${target}`);
          } else {
            throw new Error(`Could not resolve IP for domain ${target}`);
          }
        } else {
          throw new Error('Failed connecting to resolver service.');
        }
      }

      // 1. Fetch Geolocation
      const geoUrl = `http://ip-api.com/json/${target}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query`; // security-audit-ignore
      const geoResp = await fetchWithProxy(geoUrl);
      if (!geoResp.ok) {
        throw new Error('Geolocation database endpoint failed to respond.');
      }
      const geoData = await geoResp.json();
      if (geoData.status !== 'success') {
        throw new Error(geoData.message || 'Failed gathering geolocation coordinates.');
      }
      this.log(`IP Geolocation query completed. Country: ${geoData.country || 'Unknown'}, ISP: ${geoData.isp || 'Unknown'}`, 'success');

      // 2. Fetch Reputation Score (AbuseIPDB)
      let abuseData = null;
      let abuseKey = '';
      
      // Try resolving configured AbuseIPDB API key
      if (typeof window.getApiKey === "function") {
        abuseKey = window.getApiKey("abuseipdb");
      }
      if (!abuseKey) {
        const plain1 = localStorage.getItem('abuseipdb_api_key');
        const plain2 = localStorage.getItem('abuseipdb_key');
        const encrypted = localStorage.getItem('abuseipdbApiKey');
        if (plain1) abuseKey = plain1;
        else if (plain2) abuseKey = plain2;
        else if (encrypted) abuseKey = decryptApiKey(encrypted);
      }

      if (abuseKey) {
        try {
          const abuseUrl = `https://api.abuseipdb.com/api/v2/check?ipAddress=${target}&maxAgeInDays=90&verbose=true`;
          const abuseResp = await fetchWithProxy(abuseUrl, {
            headers: {
              'Key': abuseKey,
              'Accept': 'application/json'
            }
          });
          if (abuseResp.ok) {
            const payload = await abuseResp.json();
            abuseData = payload.data;
            this.log(`AbuseIPDB reputation query completed. Abuse confidence score: ${abuseData.abuseConfidenceScore || 0}%`, (abuseData.abuseConfidenceScore || 0) > 0 ? 'warning' : 'success');
          }
        } catch (e) {
          if (e.name === 'AbortError') throw e;
          console.warn('AbuseIPDB reputation query failed:', e);
          this.log(`AbuseIPDB reputation query failed: ${e.message}`, 'warning');
        }
      } else {
        this.log(`AbuseIPDB reputation query skipped (No key configured in localStorage).`, 'info');
      }

      // Store results
      this.results.ip = {
        target: target,
        geo: geoData,
        abuse: abuseData
      };
      this.updateReportButtonState();
      this.setStatus('ip', 'success');
      this.log(`IP intelligence compilation completed for target: ${target}`, 'success');

      const resultsContainer = document.getElementById(containerId);
      if (!resultsContainer) return;

      // Geolocation UI elements
      const org = geoData.org || geoData.isp || 'Unknown Provider';
      const location = `${geoData.city || 'Unknown'}, ${geoData.regionName || ''} (${geoData.country || 'Unknown'})`;
      
      let flagsHtml = '';
      if (geoData.as) {
        flagsHtml += `<span class="osint-flag-badge info">${geoData.as.split(' ')[0]}</span>`;
      }
      flagsHtml += `<span class="osint-flag-badge safe">${geoData.countryCode || 'IP'}</span>`;

      let abuseHtml = '';
      if (abuseData) {
        const score = abuseData.abuseConfidenceScore || 0;
        let colorClass = 'bg-emerald-500';
        if (score >= 50) colorClass = 'bg-red-500';
        else if (score >= 15) colorClass = 'bg-amber-500';

        abuseHtml = `
          <div class="osint-abuse-section">
            <div class="osint-abuse-header">
              <span>Abuse Confidence Score</span>
              <span>${score}%</span>
            </div>
            <div class="osint-abuse-bar-track">
              <div class="osint-abuse-bar-fill ${colorClass}" style="width: ${score}%"></div>
            </div>
            <div class="osint-abuse-meta">
              <span>Reports: <strong>${abuseData.totalReports || 0}</strong></span>
              <span>Last: ${abuseData.lastReportedAt ? new Date(abuseData.lastReportedAt).toLocaleDateString() : 'Never'}</span>
            </div>
          </div>
        `;
      } else {
        abuseHtml = `
          <div class="osint-api-hint flex items-center justify-center gap-1.5">
            <svg class="w-3.5 h-3.5 text-slate-400 inline-block align-text-bottom" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2" style="width: 0.875rem; height: 0.875rem; display: inline-block;"><path stroke-linecap="round" stroke-linejoin="round" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
            <span>Save AbuseIPDB key in API keys to display reputation score.</span>
          </div>
        `;
      }

      resultsContainer.innerHTML = `
        <div class="osint-info-grid">
          <div class="osint-info-item">
            <span class="osint-info-label">IP Address</span>
            <span class="osint-info-value">${escapeHtml(geoData.query || target)}</span>
          </div>
          <div class="osint-info-item">
            <span class="osint-info-label">ISP / ASN</span>
            <span class="osint-info-value">${escapeHtml(org)}</span>
          </div>
          <div class="osint-info-item">
            <span class="osint-info-label">Location</span>
            <span class="osint-info-value">${escapeHtml(location)}</span>
          </div>
          <div class="osint-info-item">
            <span class="osint-info-label">Coordinates</span>
            <span class="osint-info-value">${escapeHtml(geoData.lat || 0)}, ${escapeHtml(geoData.lon || 0)}</span>
          </div>
        </div>
        <div class="osint-ip-flags">
          ${flagsHtml}
        </div>
        ${abuseHtml}
      `;

      if (!this.isRunningAll) {
        this.saveCurrentScanToHistory(target, `IP: ${target}`);
        this.setScanningState(false);
        this.activeAbortController = null;
      }

    } catch (err) {
      if (err.name === 'AbortError') {
        this.setStatus('ip', 'idle');
        this.setErrorState(containerId, 'Scan was stopped by the user.');
      } else {
        console.error('IP Intelligence query error:', err);
        this.setStatus('ip', 'failed');
        this.log(`IP intelligence query failed for ${target}: ${err.message}`, 'error');
        this.setErrorState(containerId, `Failed compiling geolocation and reputation. (${err.message})`);
      }
      if (!this.isRunningAll) {
        this.setScanningState(false);
        this.activeAbortController = null;
      }
    }
  },

  // =========================================================================
  // TOOL 5: WAYBACK MACHINE (Availability + CDX History)
  // =========================================================================
  async runWaybackMachine() {
    const inputEl = document.getElementById('osint-wayback-input');
    const containerId = 'osint-wayback-results';

    if (!inputEl) return;
    const target = inputEl.value.trim().toLowerCase();

    if (!target) {
      try {
        CyberNotify.alert('Please enter a domain or URL target.', { type: 'warning' });
      } catch (e) { /* CyberNotify unavailable */ }
      inputEl.focus();
      return;
    }

    if (!this.isRunningAll) {
      this.selectTool('wayback');
      this.setScanningState(true);
      this.activeAbortController = new AbortController();
    }
    this.setStatus('wayback', 'scanning');
    this.log(`Querying archive registries for target URL: ${target}`, 'scanning');

    this.setLoadingState(containerId, 'Retrieving archival snapshots...');

    try {

    let closest = null;
    let snapshots = [];
    let querySuccessful = false;

    // 1. Fetch Availability
    try {
      this.log(`Querying Wayback availability index...`, 'info');
      const availUrl = `https://archive.org/wayback/available?url=${encodeURIComponent(target)}`;
      const availResp = await fetchWithProxy(availUrl);
      if (availResp.ok) {
        const text = await availResp.text();
        const trimmed = text.trim();
        if (trimmed && !trimmed.startsWith('<') && trimmed.startsWith('{')) {
          const availData = JSON.parse(trimmed);
          closest = availData.archived_snapshots?.closest;
          querySuccessful = true;
        }
      }
    } catch (availErr) {
      if (availErr.name === 'AbortError') throw availErr;
      console.warn('Wayback Machine: Availability API query failed, attempting CDX history API...', availErr);
      this.log(`Wayback availability check failed, attempting CDX lookup...`, 'warning');
    }

    // 2. Fetch CDX History (non-blocking)
    try {
      this.log(`Querying Wayback CDX snapshot history...`, 'info');
      const cdxUrl = `https://web.archive.org/cdx/search/cdx?url=${encodeURIComponent(target)}&output=json&limit=10&collapse=timestamp:6&fl=timestamp,original,mimetype,statuscode,length`;
      const cdxResp = await fetchWithProxy(cdxUrl);
      if (cdxResp.ok) {
        const text = await cdxResp.text();
        const trimmed = text.trim();
        if (trimmed && !trimmed.startsWith('<') && trimmed.startsWith('[')) {
          const cdxData = JSON.parse(trimmed);
          // Index 0 represents headers list
          if (Array.isArray(cdxData) && cdxData.length > 1) {
            snapshots = cdxData.slice(1).map(row => {
              return {
                timestamp: row[0],
                original: row[1],
                mimetype: row[2],
                status: row[3],
                length: row[4]
              };
            });
            querySuccessful = true;

            // Fallback for closest snapshot if availability check failed
            if (!closest && snapshots.length > 0) {
              const latest = [...snapshots].sort((a, b) => b.timestamp.localeCompare(a.timestamp))[0];
              closest = {
                available: true,
                url: `https://web.archive.org/web/${latest.timestamp}/${latest.original}`,
                timestamp: latest.timestamp
              };
            }
          }
        }
      }
    } catch (cdxErr) {
      if (cdxErr.name === 'AbortError') throw cdxErr;
      console.warn('Wayback Machine: CDX history API query failed...', cdxErr);
    }

    // 3. Store results and update UI
    const resultsContainer = document.getElementById(containerId);
    if (!resultsContainer) return;

    if (!querySuccessful) {
      this.setStatus('wayback', 'failed');
      this.log(`Wayback Machine API queries blocked/rate-limited. Direct search fallback link generated.`, 'warning');

      // Fallback UI layout when APIs are blocked or down
      resultsContainer.innerHTML = `
        <div class="osint-wayback-results" style="padding: 1.25rem; display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 0.75rem; text-align: center;">
          <div class="osint-empty-state" style="border: none; padding: 0;">
            <svg class="w-8 h-8 text-amber-500/80 mb-2" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.5" style="width: 2rem; height: 2rem; display: inline-block;">
              <path stroke-linecap="round" stroke-linejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
            </svg>
            <p class="text-sm text-slate-300 font-semibold" style="margin-bottom: 0.25rem;">Archive Registry Timeout</p>
            <p class="text-xs text-slate-400 max-w-md">Wayback Machine APIs are currently rate-limiting or blocking requests via CORS proxies. You can search the archive history directly on archive.org:</p>
          </div>
          <a href="https://web.archive.org/web/*/${escapeHtml(target)}" target="_blank" class="cyber-btn-primary px-4 py-2.5 rounded-lg text-xs font-semibold inline-flex items-center gap-2 mt-1" style="text-decoration: none;">
            <span>Search Wayback Machine</span>
            <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>
          </a>
        </div>
      `; // security-audit-ignore
      
      // Store empty state in results
      this.results.wayback = null;
      this.updateReportButtonState();
      return;
    }

    if (!closest || !closest.available) {
      this.setStatus('wayback', 'success');
      this.log(`Wayback search completed. No snapshots discovered for ${target}`, 'info');

      resultsContainer.innerHTML = `
        <div class="osint-empty-state">
          <span>No snapshots found in Wayback Machine for ${escapeHtml(target)}</span>
        </div>
      `; // security-audit-ignore
      this.results.wayback = {
        target: target,
        closest: null,
        snapshots: []
      };
      this.updateReportButtonState();
      return;
    }

    // Store state
    this.results.wayback = {
      target: target,
      closest: closest,
      snapshots: snapshots
    };
    this.updateReportButtonState();
    this.setStatus('wayback', 'success');
    this.log(`Wayback search completed. Found ${snapshots.length} historical snapshots for ${target}`, 'success');

    // Format Latest snapshot UI
    const formatTimestamp = (ts) => {
      if (!ts || ts.length < 14) return 'Unknown';
      const year = ts.substring(0, 4);
      const month = ts.substring(4, 6);
      const day = ts.substring(6, 8);
      const hour = ts.substring(8, 10);
      const min = ts.substring(10, 12);
      return `${year}-${month}-${day} ${hour}:${min}`;
    };

    let historyHtml = '';
    if (snapshots.length > 0) {
      let itemsHtml = '';
      const sorted = [...snapshots].sort((a, b) => b.timestamp.localeCompare(a.timestamp));
      sorted.forEach(s => {
        const snapshotUrl = `https://web.archive.org/web/${s.timestamp}/${s.original}`;
        const formattedDate = formatTimestamp(s.timestamp);
        const sizeKb = s.length ? `${(parseInt(s.length) / 1024).toFixed(1)} KB` : 'N/A';
        itemsHtml += `
          <a href="${escapeHtml(snapshotUrl)}" target="_blank" class="osint-wayback-item">
            <span class="osint-wayback-date">${formattedDate}</span>
            <span class="osint-wayback-size">${sizeKb}</span>
            <span class="osint-wayback-arrow"><svg class="w-3 h-3 text-slate-400" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2" style="width: 0.75rem; height: 0.75rem; display: inline-block;"><path stroke-linecap="round" stroke-linejoin="round" d="M9 5l7 7-7 7" /></svg></span>
          </a>
        `;
      });

      historyHtml = `
        <div class="osint-wayback-history">
          <span class="osint-label">Recent History Snapshots</span>
          <div class="osint-wayback-list">
            ${itemsHtml}
          </div>
          <a href="https://web.archive.org/web/*/${escapeHtml(target)}" target="_blank" class="osint-view-all-link">
            View full index on archive.org <svg class="w-3 h-3 inline-block" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2" style="width: 0.75rem; height: 0.75rem; display: inline-block; vertical-align: middle;"><path stroke-linecap="round" stroke-linejoin="round" d="M9 5l7 7-7 7" /></svg>
          </a>
        </div>
      `;
    }

    resultsContainer.innerHTML = `
      <div class="osint-wayback-results">
        <div class="osint-wayback-latest">
          <span class="osint-label">Latest Snapshot Available</span>
          <a href="${escapeHtml(closest.url)}" target="_blank" class="osint-wayback-link">
            ${formatTimestamp(closest.timestamp)}
            <span class="material-symbols-outlined" style="font-size: 1.1rem;">open_in_new</span>
          </a>
        </div>
        ${historyHtml}
      </div>
    `; // security-audit-ignore

      if (!this.isRunningAll) {
        this.saveCurrentScanToHistory(target, `Wayback: ${target}`);
        this.setScanningState(false);
        this.activeAbortController = null;
      }
    } catch (err) {
      if (err.name === 'AbortError') {
        this.setStatus('wayback', 'idle');
        this.setErrorState(containerId, 'Scan was stopped by the user.');
      } else {
        this.setStatus('wayback', 'failed');
        this.setErrorState(containerId, `Error: ${err.message}`);
      }
      if (!this.isRunningAll) {
        this.setScanningState(false);
        this.activeAbortController = null;
      }
    }
  },

  // =========================================================================
  // TOOL 6: USERNAME OSINT (Sherlock profile matches)
  // =========================================================================
  async runUsernameOSINT() {
    const inputEl = document.getElementById('osint-username-input');
    const containerId = 'osint-username-results';

    if (!inputEl) return;
    const username = inputEl.value.trim();

    if (!username) {
      try {
        CyberNotify.alert('Please enter a target username.', { type: 'warning' });
      } catch (e) { /* CyberNotify unavailable */ }
      inputEl.focus();
      return;
    }

    if (!this.isRunningAll) {
      this.selectTool('username');
      this.setScanningState(true);
      this.activeAbortController = new AbortController();
    }
    this.setStatus('username', 'scanning');
    this.log(`Initiating platform profile probe for username: ${username}`, 'scanning');

    const platforms = [
      { name: 'GitHub',        url: `https://github.com/${username}` },
      { name: 'Twitter/X',     url: `https://x.com/${username}` },
      { name: 'Reddit',        url: `https://www.reddit.com/user/${username}` },
      { name: 'LinkedIn',      url: `https://www.linkedin.com/in/${username}` },
      { name: 'Instagram',     url: `https://instagram.com/${username}` },
      { name: 'HackerOne',     url: `https://hackerone.com/${username}` },
      { name: 'Bugcrowd',      url: `https://bugcrowd.com/${username}` },
      { name: 'Keybase',       url: `https://keybase.io/${username}` },
      { name: 'Medium',        url: `https://medium.com/@${username}` },
      { name: 'dev.to',        url: `https://dev.to/${username}` },
      { name: 'StackOverflow', url: `https://stackoverflow.com/users/story/${username}` },
      { name: 'YouTube',       url: `https://www.youtube.com/@${username}` },
      { name: 'Pinterest',     url: `https://www.pinterest.com/${username}` },
      { name: 'Steam',         url: `https://steamcommunity.com/id/${username}` },
      { name: 'Spotify',       url: `https://open.spotify.com/user/${username}` },
      { name: 'DockerHub',     url: `https://hub.docker.com/u/${username}` },
      { name: 'GitLab',        url: `https://gitlab.com/${username}` },
      { name: 'TikTok',        url: `https://www.tiktok.com/@${username}` }
    ];

    const resultsContainer = document.getElementById(containerId);
    if (!resultsContainer) return;

    // Render loading grid first
    resultsContainer.innerHTML = `
      <div class="osint-username-checking">
        <div class="osint-progress-text">Probing profile availability: <strong id="osint-username-progress">0/18</strong></div>
        <div class="osint-username-grid" id="osint-username-grid-inner"></div>
      </div>
    `;

    const gridInner = document.getElementById('osint-username-grid-inner');
    if (!gridInner) return;

    // Populate initial unverified states
    let initialCards = '';
    platforms.forEach((p, idx) => {
      initialCards += `
        <div class="osint-platform-checking" id="osint-platform-card-${idx}">
          <span class="osint-platform-icon"><svg class="w-4 h-4 text-slate-400 inline-block align-middle" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2" style="width: 1rem; height: 1rem;"><path stroke-linecap="round" stroke-linejoin="round" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" /></svg></span>
          <span class="osint-platform-name">${p.name}</span>
          <span class="osint-platform-status" id="osint-platform-status-${idx}" style="color: var(--cg-text-3)">Queue</span>
        </div>
      `;
    });
    gridInner.innerHTML = initialCards; // security-audit-ignore

    try {
      const matchedPlatforms = [];
      let completedCount = 0;
    
    // Batch processing: check 3 platforms in parallel to prevent rate limits
    const checkBatch = async (batch) => {
      const promises = batch.map(async (pInfo) => {
        const { platform, index } = pInfo;
        const cardEl = document.getElementById(`osint-platform-card-${index}`);
        const statusEl = document.getElementById(`osint-platform-status-${index}`);
        
        if (statusEl) statusEl.textContent = 'Probing...';
        
        let found = false;
        try {
          // Perform GET request using CORS proxy. Since allOrigins or cors.lol are fine for GET
          // without headers, we try to resolve status code.
          const response = await fetchWithProxy(platform.url);
          
          if (response.status === 200) {
            found = true;
          }
        } catch (e) {
          if (e.name === 'AbortError') throw e;
          // If proxy fails or blocks, default to active match link to verify manually
          console.warn(`Profile validation failed for platform ${platform.name}:`, e.message);
          found = null; // Unverified
        }

        completedCount++;
        const progText = document.getElementById('osint-username-progress');
        if (progText) progText.textContent = `${completedCount}/18`;

        if (found === true) {
          matchedPlatforms.push({ name: platform.name, url: platform.url, status: 'Active' });
          if (cardEl) {
            cardEl.outerHTML = `
              <a href="${escapeHtml(platform.url)}" target="_blank" class="osint-platform-link" style="border-color: rgba(52, 211, 153, 0.2)">
                <span class="osint-platform-icon"><svg class="w-4 h-4 text-emerald-400 inline-block align-middle" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5" style="width: 1rem; height: 1rem;"><path stroke-linecap="round" stroke-linejoin="round" d="M5 13l4 4L19 7" /></svg></span>
                <div class="osint-platform-info">
                  <span class="osint-platform-name" style="color: var(--cg-success)">${escapeHtml(platform.name)}</span>
                  <span class="osint-platform-url">${escapeHtml(platform.url.replace(/^https?:\/\//, ''))}</span>
                </div>
                <span class="osint-platform-open"><svg class="w-3 h-3 text-slate-400" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2" style="width: 0.75rem; height: 0.75rem; display: inline-block;"><path stroke-linecap="round" stroke-linejoin="round" d="M9 5l7 7-7 7" /></svg></span>
              </a>
            `; // security-audit-ignore
          }
        } else if (found === false) {
          if (cardEl) {
            cardEl.outerHTML = `
              <div class="osint-platform-checking" style="opacity: 0.35;">
                <span class="osint-platform-icon"><svg class="w-4 h-4 text-red-500 inline-block align-middle" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5" style="width: 1rem; height: 1rem;"><path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12" /></svg></span>
                <span class="osint-platform-name">${escapeHtml(platform.name)}</span>
                <span class="osint-platform-status">Absent</span>
              </div>
            `; // security-audit-ignore
          }
        } else {
          // Unverified - show as link but with warning badge
          matchedPlatforms.push({ name: platform.name, url: platform.url, status: 'Unverified' });
          if (cardEl) {
            cardEl.outerHTML = `
              <a href="${escapeHtml(platform.url)}" target="_blank" class="osint-platform-link" style="border-color: rgba(251, 191, 36, 0.2)">
                <span class="osint-platform-icon"><svg class="w-4 h-4 text-amber-500 inline-block align-middle" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5" style="width: 1rem; height: 1rem;"><path stroke-linecap="round" stroke-linejoin="round" d="M8.228 9c.549-1.165 2.03-2 3.772-2 2.21 0 4 1.343 4 3 0 1.4-1.278 2.575-3.006 2.907-.542.104-.994.54-.994 1.093m0 3h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" /></svg></span>
                <div class="osint-platform-info">
                  <span class="osint-platform-name" style="color: var(--cg-warning)">${escapeHtml(platform.name)}</span>
                  <span class="osint-platform-url">${escapeHtml(platform.url.replace(/^https?:\/\//, ''))}</span>
                </div>
                <span class="osint-platform-open"><svg class="w-3 h-3 text-slate-400" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2" style="width: 0.75rem; height: 0.75rem; display: inline-block;"><path stroke-linecap="round" stroke-linejoin="round" d="M9 5l7 7-7 7" /></svg></span>
              </a>
            `; // security-audit-ignore
          }
        }
      });

      await Promise.all(promises);
    };

    this.log(`Probing platform profiles in batches to avoid rate limits...`, 'info');

    // Run platform verification in sequential batches
    const batchSize = 3;
    for (let i = 0; i < platforms.length; i += batchSize) {
      if (this.activeAbortController?.signal.aborted) {
        throw new DOMException('Aborted', 'AbortError');
      }
      const batch = platforms.slice(i, i + batchSize).map((p, idx) => ({ platform: p, index: i + idx }));
      await checkBatch(batch);
      // Brief sleep between batches
      await new Promise((resolve, reject) => {
        const timeoutId = setTimeout(resolve, 200);
        if (this.activeAbortController) {
          this.activeAbortController.signal.addEventListener('abort', () => {
            clearTimeout(timeoutId);
            reject(new DOMException('Aborted', 'AbortError'));
          });
        }
      });
    }

    // Store state
    this.results.username = {
      target: username,
      data: matchedPlatforms
    };
    this.updateReportButtonState();
    this.setStatus('username', 'success');
    this.log(`Platform profile probe completed. Discovered ${matchedPlatforms.filter(p => p.status === 'Active').length} active profiles for ${username}`, 'success');

    // Append username guidance note
    const noteEl = document.createElement('div');
    noteEl.className = 'osint-username-note flex items-center gap-1.5';
    noteEl.innerHTML = `
      <svg class="w-3.5 h-3.5 text-slate-400 inline-block align-text-bottom" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2" style="width: 0.875rem; height: 0.875rem; display: inline-block;"><path stroke-linecap="round" stroke-linejoin="round" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
      <span>Sherlock matches are based on target URL availability. Verify critical results manually.</span>
    `;
    resultsContainer.appendChild(noteEl);

    if (!this.isRunningAll) {
      this.saveCurrentScanToHistory(username, `Username: ${username}`);
      this.setScanningState(false);
      this.activeAbortController = null;
    }
  } catch (err) {
    if (err.name === 'AbortError') {
      this.setStatus('username', 'idle');
      this.setErrorState(containerId, 'Scan was stopped by the user.');
    } else {
      this.setStatus('username', 'failed');
      this.setErrorState(containerId, `Error: ${err.message}`);
    }
    if (!this.isRunningAll) {
      this.setScanningState(false);
      this.activeAbortController = null;
    }
  }
},

  // =========================================================================
  // TOOL 7: EMAIL FORMAT GUESSER
  // =========================================================================
  runEmailFormatGuesser() {
    const fnEl = document.getElementById('osint-emailformat-firstname');
    const lnEl = document.getElementById('osint-emailformat-lastname');
    const domEl = document.getElementById('osint-emailformat-domain');
    const containerId = 'osint-emailformat-results';

    if (!fnEl || !lnEl || !domEl) return;
    const fn = fnEl.value.trim().toLowerCase();
    const ln = lnEl.value.trim().toLowerCase();
    const domain = domEl.value.trim().toLowerCase();

    if (!domain) {
      try {
        CyberNotify.alert('Target domain is required to generate permutations.', { type: 'warning' });
      } catch (e) { /* CyberNotify unavailable */ }
      domEl.focus();
      return;
    }

    if (!fn && !ln) {
      try {
        CyberNotify.alert('At least a first name or last name is required.', { type: 'warning' });
      } catch (e) { /* CyberNotify unavailable */ }
      fnEl.focus();
      return;
    }

    if (!this.isRunningAll) {
      this.selectTool('emailformat');
    }
    this.setStatus('emailformat', 'scanning');
    this.log(`Generating email permutations for domain: ${domain}`, 'scanning');

    this.setLoadingState(containerId, 'Generating pattern permutations...');

    // Permutation calculations
    const f = fn ? fn.charAt(0) : '';
    const l = ln ? ln.charAt(0) : '';
    const permutations = [];

    if (fn && ln) {
      permutations.push({ email: `${fn}.${ln}@${domain}`, pattern: '{first}.{last}@{domain}', likely: true });
      permutations.push({ email: `${f}${ln}@${domain}`, pattern: '{f}{last}@{domain}', likely: true });
      permutations.push({ email: `${fn}@${domain}`, pattern: '{first}@{domain}', likely: false });
      permutations.push({ email: `${ln}@${domain}`, pattern: '{last}@{domain}', likely: false });
      permutations.push({ email: `${fn}${ln}@${domain}`, pattern: '{first}{last}@{domain}', likely: false });
      permutations.push({ email: `${fn}${l}@${domain}`, pattern: '{first}{l}@{domain}', likely: false });
      permutations.push({ email: `${fn}-${ln}@${domain}`, pattern: '{first}-{last}@{domain}', likely: false });
      permutations.push({ email: `${ln}.${fn}@${domain}`, pattern: '{last}.{first}@{domain}', likely: false });
      permutations.push({ email: `${f}.${ln}@${domain}`, pattern: '{f}.{last}@{domain}', likely: false });
      permutations.push({ email: `${fn}_${ln}@${domain}`, pattern: '{first}_{last}@{domain}', likely: false });
      permutations.push({ email: `${ln}${fn}@${domain}`, pattern: '{last}{first}@{domain}', likely: false });
      permutations.push({ email: `${ln}${f}@${domain}`, pattern: '{last}{f}@{domain}', likely: false });
    } else {
      const name = fn || ln;
      permutations.push({ email: `${name}@${domain}`, pattern: '{name}@{domain}', likely: true });
      if (name.length > 1) {
        permutations.push({ email: `${name.charAt(0)}@${domain}`, pattern: '{n}@{domain}', likely: false });
      }
    }

    // Store state
    this.results.emailformat = {
      firstName: fn,
      lastName: ln,
      domain: domain,
      data: permutations
    };
    this.updateReportButtonState();
    this.setStatus('emailformat', 'success');
    this.log(`Permutation generation completed. Generated ${permutations.length} pattern matches.`, 'success');

    const resultsContainer = document.getElementById(containerId);
    if (!resultsContainer) return;

    let itemsHtml = '';
    permutations.forEach(p => {
      const badgeHtml = p.likely ? '<span class="osint-format-badge">Likely</span>' : '';
      const cardClass = p.likely ? 'osint-email-format-item osint-format-likely' : 'osint-email-format-item';
      
      itemsHtml += `
        <div class="${cardClass}">
          <div class="osint-email-format-value">
            <span class="osint-email-at">${escapeHtml(p.email)}</span>
            <button class="osint-item-copy" onclick="OSINT.copyToClipboard('${escapeHtml(p.email)}')" title="Copy Email">
              <span class="material-symbols-outlined" style="font-size: 1rem;">content_copy</span>
            </button>
          </div>
          <div class="osint-email-format-meta">
            <span class="osint-format-pattern">${escapeHtml(p.pattern)}</span>
            ${badgeHtml}
          </div>
        </div>
      `;
    });

    resultsContainer.innerHTML = `
      <div class="osint-email-format-list">
        ${itemsHtml}
      </div>
    `; // security-audit-ignore

    if (!this.isRunningAll) this.saveCurrentScanToHistory(domain, `Email Format: ${domain}`);
  },

  // =========================================================================
  // TOOL 8: AGGREGATED REPORT GENERATION (jsPDF)
  // =========================================================================
  generateFullReport() {
    const { jsPDF } = window.jspdf;
    if (!jsPDF) {
      try {
        CyberNotify.alert('PDF generation library is not loaded. Try reloading the dashboard.', { type: 'error' });
      } catch (e) {
        alert('PDF library not loaded.');
      }
      return;
    }

    const reportBtn = document.getElementById('osint-generate-report-btn');
    const originalText = reportBtn ? reportBtn.innerHTML : 'Generate Report';
    
    if (reportBtn) {
      reportBtn.disabled = true;
      reportBtn.innerHTML = `
        <svg class="w-4 h-4 animate-spin inline-block mr-2" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" style="height: 1rem; width: 1rem;">
          <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
          <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
        </svg>
        Compiling PDF...
      `;
    }

    try {
      const doc = new jsPDF();
      let yOffset = 20;

      // Primary header
      doc.setFillColor(13, 19, 33); // Dark theme fill
      doc.rect(0, 0, 210, 45, 'F');

      doc.setTextColor(255, 255, 255);
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(22);
      doc.text('CyberGuard OSINT Intelligence Report', 15, 20);

      doc.setFont('helvetica', 'normal');
      doc.setFontSize(10);
      doc.setTextColor(167, 139, 250); // Accent purple
      doc.text('PASSIVE RECONNAISSANCE & TARGET INTELLIGENCE GATHERING', 15, 28);
      doc.setTextColor(156, 163, 175); // Muted gray
      doc.text(`Generated on: ${new Date().toLocaleString()}`, 15, 36);

      yOffset = 55;

      // Executive Summary
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(14);
      doc.setTextColor(13, 19, 33);
      doc.text('1. Executive Summary', 15, yOffset);
      yOffset += 8;

      doc.setFont('helvetica', 'normal');
      doc.setFontSize(10);
      doc.setTextColor(55, 65, 81);
      
      const executedTools = Object.keys(this.results).filter(k => this.results[k] !== null);
      const summaryText = `This report compiles intelligence data gathered passively using OSINT tools. A total of ${executedTools.length} intelligence databases and lookup engines were queried to discover publicly exposed information parameters without active penetration.`;
      
      const splitSummary = doc.splitTextToSize(summaryText, 180);
      doc.text(splitSummary, 15, yOffset);
      yOffset += (splitSummary.length * 5) + 10;

      // Section counter
      let sectionIdx = 2;

      // SUBDOMAINS
      if (this.results.subdomains) {
        if (yOffset > 240) { doc.addPage(); yOffset = 20; }
        doc.setFont('helvetica', 'bold');
        doc.setFontSize(12);
        doc.text(`${sectionIdx}. Subdomain Inventory (crt.sh)`, 15, yOffset);
        yOffset += 5;
        
        doc.setFont('helvetica', 'normal');
        doc.setFontSize(9);
        doc.text(`Target Domain: ${this.results.subdomains.target}`, 15, yOffset);
        yOffset += 5;

        const subdomains = this.results.subdomains.data;
        if (subdomains.length === 0) {
          doc.text('No subdomains resolved.', 15, yOffset);
          yOffset += 10;
        } else {
          const bodyData = subdomains.map((sub, idx) => [idx + 1, sub]);
          doc.autoTable({
            startY: yOffset,
            head: [['Index', 'Subdomain Name']],
            body: bodyData,
            theme: 'grid',
            headStyles: { fillColor: [124, 58, 237] },
            styles: { fontSize: 8, cellPadding: 2.5 },
            columnStyles: { 0: { cellWidth: 20 }, 1: { cellWidth: 160 } },
            margin: { left: 15 }
          });
          yOffset = doc.lastAutoTable.finalY + 12;
        }
        sectionIdx++;
      }



      // DNS LOOKUP
      if (this.results.dns) {
        if (yOffset > 240) { doc.addPage(); yOffset = 20; }
        doc.setFont('helvetica', 'bold');
        doc.setFontSize(12);
        doc.text(`${sectionIdx}. DNS Resolution Records`, 15, yOffset);
        yOffset += 5;

        doc.setFont('helvetica', 'normal');
        doc.setFontSize(9);
        doc.text(`Target Domain: ${this.results.dns.target}`, 15, yOffset);
        yOffset += 5;

        const bodyData = [];
        const dnsData = this.results.dns.data;
        Object.keys(dnsData).forEach(type => {
          dnsData[type].forEach(r => {
            bodyData.push([type, r.TTL, r.data.replace(/^"|"$/g, '')]);
          });
        });

        if (bodyData.length === 0) {
          doc.text('No DNS records recorded.', 15, yOffset);
          yOffset += 10;
        } else {
          doc.autoTable({
            startY: yOffset,
            head: [['Type', 'TTL', 'Resolved Record Value']],
            body: bodyData,
            theme: 'grid',
            headStyles: { fillColor: [124, 58, 237] },
            styles: { fontSize: 8, cellPadding: 2.5 },
            columnStyles: { 0: { cellWidth: 20 }, 1: { cellWidth: 20 }, 2: { cellWidth: 140 } },
            margin: { left: 15 }
          });
          yOffset = doc.lastAutoTable.finalY + 12;
        }
        sectionIdx++;
      }

      // IP INTELLIGENCE
      if (this.results.ip) {
        if (yOffset > 240) { doc.addPage(); yOffset = 20; }
        doc.setFont('helvetica', 'bold');
        doc.setFontSize(12);
        doc.text(`${sectionIdx}. IP Geolocation & Reputation`, 15, yOffset);
        yOffset += 5;

        doc.setFont('helvetica', 'normal');
        doc.setFontSize(9);
        doc.text(`Target IP: ${this.results.ip.target}`, 15, yOffset);
        yOffset += 5;

        const geo = this.results.ip.geo;
        const abuse = this.results.ip.abuse;

        const bodyData = [
          ['ISP / Provider', geo.org || geo.isp || 'N/A'],
          ['Country / Code', `${geo.country || 'N/A'} (${geo.countryCode || 'N/A'})`],
          ['Region / City', `${geo.regionName || 'N/A'} / ${geo.city || 'N/A'}`],
          ['Latitude & Longitude', `${geo.lat || 0}, ${geo.lon || 0}`]
        ];

        if (abuse) {
          bodyData.push(['Abuse Reputation Score', `${abuse.abuseConfidenceScore || 0}%`]);
          bodyData.push(['Abuse Reports Count', `${abuse.totalReports || 0} reports`]);
        } else {
          bodyData.push(['Abuse Reputation Score', 'N/A (No key saved)']);
        }

        doc.autoTable({
          startY: yOffset,
          head: [['Parameter', 'Gathered Value']],
          body: bodyData,
          theme: 'grid',
          headStyles: { fillColor: [124, 58, 237] },
          styles: { fontSize: 8, cellPadding: 3 },
          columnStyles: { 0: { cellWidth: 60 }, 1: { cellWidth: 120 } },
          margin: { left: 15 }
        });
        yOffset = doc.lastAutoTable.finalY + 12;
        sectionIdx++;
      }

      // WAYBACK snapshots
      if (this.results.wayback) {
        if (yOffset > 240) { doc.addPage(); yOffset = 20; }
        doc.setFont('helvetica', 'bold');
        doc.setFontSize(12);
        doc.text(`${sectionIdx}. Archival Snapshots (Wayback Machine)`, 15, yOffset);
        yOffset += 5;

        doc.setFont('helvetica', 'normal');
        doc.setFontSize(9);
        doc.text(`Target: ${this.results.wayback.target}`, 15, yOffset);
        yOffset += 5;

        const closest = this.results.wayback.closest;
        const snapshots = this.results.wayback.snapshots;

        if (closest && closest.available) {
          doc.text(`Closest snapshot: ${closest.timestamp} (${closest.url})`, 15, yOffset);
          yOffset += 6;
        }

        if (snapshots.length > 0) {
          const bodyData = snapshots.map(s => [
            s.timestamp,
            s.mimetype,
            s.status,
            s.length ? `${(parseInt(s.length) / 1024).toFixed(1)} KB` : 'N/A'
          ]);
          
          doc.autoTable({
            startY: yOffset,
            head: [['Snapshot Date', 'Content Type', 'HTTP Status', 'Length']],
            body: bodyData,
            theme: 'grid',
            headStyles: { fillColor: [124, 58, 237] },
            styles: { fontSize: 8, cellPadding: 2.5 },
            columnStyles: { 0: { cellWidth: 50 }, 1: { cellWidth: 50 }, 2: { cellWidth: 40 }, 3: { cellWidth: 40 } },
            margin: { left: 15 }
          });
          yOffset = doc.lastAutoTable.finalY + 12;
        } else {
          yOffset += 6;
        }
        sectionIdx++;
      }

      // USERNAME MATCHES
      if (this.results.username) {
        if (yOffset > 240) { doc.addPage(); yOffset = 20; }
        doc.setFont('helvetica', 'bold');
        doc.setFontSize(12);
        doc.text(`${sectionIdx}. Sherlock Profile Mapping`, 15, yOffset);
        yOffset += 5;

        doc.setFont('helvetica', 'normal');
        doc.setFontSize(9);
        doc.text(`Target Username: ${this.results.username.target}`, 15, yOffset);
        yOffset += 5;

        const matched = this.results.username.data;
        if (matched.length === 0) {
          doc.text('No active profiles found matching this username.', 15, yOffset);
          yOffset += 10;
        } else {
          const bodyData = matched.map(m => [m.name, m.url, m.status]);
          doc.autoTable({
            startY: yOffset,
            head: [['Platform', 'Profile URL', 'Verification Status']],
            body: bodyData,
            theme: 'grid',
            headStyles: { fillColor: [124, 58, 237] },
            styles: { fontSize: 8, cellPadding: 2.5 },
            columnStyles: { 0: { cellWidth: 40 }, 1: { cellWidth: 100 }, 2: { cellWidth: 40 } },
            margin: { left: 15 }
          });
          yOffset = doc.lastAutoTable.finalY + 12;
        }
        sectionIdx++;
      }

      // EMAIL FORMAT GUESSER
      if (this.results.emailformat) {
        if (yOffset > 240) { doc.addPage(); yOffset = 20; }
        doc.setFont('helvetica', 'bold');
        doc.setFontSize(12);
        doc.text(`${sectionIdx}. Email Format Patterns`, 15, yOffset);
        yOffset += 5;

        const guess = this.results.emailformat;
        doc.setFont('helvetica', 'normal');
        doc.setFontSize(9);
        doc.text(`Target Domain: ${guess.domain} (First Name: ${guess.firstName || '-'}, Last Name: ${guess.lastName || '-'})`, 15, yOffset);
        yOffset += 5;

        const bodyData = guess.data.map(p => [
          p.email,
          p.pattern,
          p.likely ? 'Likely Format' : 'Possible Format'
        ]);

        doc.autoTable({
          startY: yOffset,
          head: [['Generated Permutation', 'Pattern Structure', 'Assessment']],
          body: bodyData,
          theme: 'grid',
          headStyles: { fillColor: [124, 58, 237] },
          styles: { fontSize: 8, cellPadding: 2.5 },
          columnStyles: { 0: { cellWidth: 70 }, 1: { cellWidth: 60 }, 2: { cellWidth: 50 } },
          margin: { left: 15 }
        });
        yOffset = doc.lastAutoTable.finalY + 12;
      }

      // Save file
      const filename = `cyberguard-osint-report-${Date.now()}.pdf`;
      doc.save(filename);
      
      try {
        CyberNotify.alert(`OSINT Report successfully generated and saved as: ${filename}`, { type: 'success' });
      } catch (e) { /* CyberNotify unavailable */ }

    } catch (error) {
      console.error('PDF export failed:', error);
      try {
        CyberNotify.alert(`Failed to export OSINT report: ${error.message}`, { type: 'error' });
      } catch (e) { /* CyberNotify unavailable */ }
    } finally {
      if (reportBtn) {
        reportBtn.disabled = false;
        reportBtn.innerHTML = originalText; // security-audit-ignore
      }
    }
  },

  // =========================================================================
  // SCAN HISTORY
  // =========================================================================

  /**
   * Snapshot current results and save them to scan history.
   * @param {string} target - The query target (domain, IP, username, etc.)
   * @param {string} [label] - Optional display label
   */
  saveCurrentScanToHistory(target, label) {
    if (!target) return;

    // Only save if at least one result exists
    const hasAnyResult = Object.values(this.results).some(r => r !== null);
    if (!hasAnyResult) return;

    const toolStatuses = {};
    const tools = ['subdomain', 'dns', 'ip', 'wayback', 'username', 'emailformat'];
    tools.forEach(toolId => {
      const dot = document.getElementById(`osint-status-dot-${toolId}`);
      let status = 'idle';
      if (dot) {
        if (dot.classList.contains('success')) status = 'success';
        else if (dot.classList.contains('failed')) status = 'failed';
        else if (dot.classList.contains('scanning')) status = 'scanning';
      }
      toolStatuses[toolId] = status;
    });

    const historyItem = {
      id: 'osint_' + Date.now(),
      target: target,
      label: label || target,
      timestamp: new Date().toLocaleTimeString('en', { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
      toolStatuses: toolStatuses,
      results: JSON.parse(JSON.stringify(this.results))
    };

    this.scanHistory = this.scanHistory || [];
    this.scanHistory.unshift(historyItem);

    if (this.scanHistory.length > 10) {
      this.scanHistory.pop();
    }

    try {
      localStorage.setItem('osint_scan_history', JSON.stringify(this.scanHistory));
    } catch (e) {
      console.error('Failed to save OSINT scan history:', e);
    }

    this.renderScanHistoryList();
  },

  /**
   * Restore results from a history snapshot.
   * @param {string} scanId
   */
  loadScanFromHistory(scanId) {
    const item = this.scanHistory.find(h => h.id === scanId);
    if (!item) return;

    // Restore target input
    const input = document.getElementById('osint-global-target');
    if (input) input.value = item.target;

    // Restore results object
    this.results = JSON.parse(JSON.stringify(item.results));

    // Restore status dots
    Object.entries(item.toolStatuses).forEach(([toolId, status]) => {
      this.setStatus(toolId, status);
    });

    // Re-render each tool's result panel
    const tools = ['subdomain', 'dns', 'ip', 'wayback', 'username', 'emailformat'];
    tools.forEach(toolId => {
      this._renderRestoredResult(toolId);
    });

    // Highlight active history item
    const items = document.querySelectorAll('.osint-history-item');
    items.forEach(el => el.classList.toggle('active', el.dataset.scanId === scanId));

    this.updateReportButtonState();

    try {
      CyberNotify.alert(`Loaded OSINT scan for: ${item.target}`, { type: 'success' });
    } catch (e) { /* unavailable */ }
  },

  /**
   * Re-render a single result panel from the currently loaded this.results snapshot.
   * Uses simple fallback rendering (card list of key-value pairs) for restored results.
   */
  _renderRestoredResult(toolId) {
    const data = this.results[toolId === 'subdomain' ? 'subdomains' :
                              toolId === 'dns'       ? 'dns'       :
                              toolId === 'ip'        ? 'ip'        :
                              toolId === 'wayback'   ? 'wayback'   :
                              toolId === 'username'  ? 'username'  :
                                                       'emailformat'];

    const containerId = `osint-${toolId}-results`;
    const container = document.getElementById(containerId);
    if (!container) return;

    if (!data) {
      container.innerHTML = `<div class="osint-empty-state"><span>No data available for this module</span></div>`; // security-audit-ignore
      return;
    }

    // Each tool already stores its rendered state via innerHTML in the live run.
    // For restored snapshots we render a lightweight summary card.
    let html = `<div class="osint-restored-badge">Restored from history &middot; ${escapeHtml(data.target || '')}</div>`;

    if (toolId === 'subdomain' && data.data) {
      const list = data.data;
      html += `<div class="osint-results-header"><span class="osint-results-count">Discovered: <strong>${list.length}</strong> unique domains</span></div>`;
      html += `<div class="osint-subdomain-list">`;
      list.forEach(sub => {
        html += `<div class="osint-subdomain-item"><span class="osint-subdomain-name">${escapeHtml(sub)}</span><button class="osint-item-copy" onclick="OSINT.copyToClipboard('${escapeHtml(sub)}')" title="Copy"><span class="material-symbols-outlined" style="font-size:1rem">content_copy</span></button></div>`;
      });
      html += `</div>`;

    } else if (toolId === 'dns' && data.data) {
      const allTypes = Object.entries(data.data);
      html += `<div class="osint-dns-grid">`;
      allTypes.forEach(([type, records]) => {
        if (!records || records.length === 0) return;
        html += `<div class="osint-dns-card"><div class="osint-dns-type-badge">${escapeHtml(type)}</div><div class="osint-dns-records">`;
        records.forEach(r => {
          html += `<div class="osint-dns-record-item">${escapeHtml(r.data || r.name || JSON.stringify(r))}</div>`;
        });
        html += `</div></div>`;
      });
      html += `</div>`;

    } else if (toolId === 'wayback' && data.data) {
      const snapshots = data.data;
      html += `<div class="osint-results-header"><span class="osint-results-count">Snapshots: <strong>${snapshots.length}</strong></span></div>`;
      html += `<div class="osint-wayback-list">`;
      snapshots.slice(0, 50).forEach(snap => {
        html += `<div class="osint-wayback-item"><span class="osint-wayback-date">${escapeHtml(snap.timestamp || snap.date || '')}</span><a class="osint-wayback-link" href="${escapeHtml(snap.url || '')}" target="_blank" rel="noopener noreferrer">${escapeHtml(snap.url || '')}</a></div>`;
      });
      html += `</div>`;

    } else if (toolId === 'username' && data.data) {
      const platforms = data.data;
      html += `<div class="osint-results-header"><span class="osint-results-count">Platforms checked: <strong>${platforms.length}</strong></span></div>`;
      html += `<div class="osint-username-grid">`;
      platforms.forEach(p => {
        const cls = p.found ? 'found' : 'not-found';
        html += `<div class="osint-username-item ${cls}"><span class="osint-username-platform">${escapeHtml(p.platform || p.site || '')}</span></div>`;
      });
      html += `</div>`;

    } else if (toolId === 'emailformat' && data.data) {
      const patterns = data.data;
      html += `<div class="osint-results-header"><span class="osint-results-count">Patterns generated: <strong>${patterns.length}</strong></span></div>`;
      html += `<div class="osint-email-list">`;
      patterns.forEach(p => {
        html += `<div class="osint-email-item"><span class="osint-email-addr">${escapeHtml(p.email || '')}</span><span class="osint-email-pattern">${escapeHtml(p.pattern || '')}</span></div>`;
      });
      html += `</div>`;

    } else if (toolId === 'ip' && data.data) {
      html += `<div class="osint-ip-card"><pre class="osint-ip-raw">${escapeHtml(JSON.stringify(data.data, null, 2))}</pre></div>`;

    } else {
      html += `<div class="osint-empty-state"><span>Results available but no renderer matched</span></div>`;
    }

    container.innerHTML = html; // security-audit-ignore
  },

  /**
   * Clear all history entries and localStorage key.
   */
  clearScanHistory() {
    this.scanHistory = [];
    try {
      localStorage.removeItem('osint_scan_history');
    } catch (e) {
      console.error(e);
    }
    this.renderScanHistoryList();
    try {
      CyberNotify.alert('OSINT scan history cleared.', { type: 'success' });
    } catch (e) { /* unavailable */ }
  },

  /**
   * Render the history list in the control panel.
   */
  renderScanHistoryList() {
    const listEl = document.getElementById('osint-history-list');
    if (!listEl) return;

    if (!this.scanHistory || this.scanHistory.length === 0) {
      listEl.innerHTML = `<div class="text-xs text-slate-400 text-center py-4" id="osint-history-empty">No history available</div>`; // security-audit-ignore
      return;
    }

    listEl.innerHTML = this.scanHistory.map(item => {
      const displayTarget = String(item.target).replace(/^https?:\/\//, '').replace(/\/$/, '');
      // Count how many tools have success status
      const successCount = Object.values(item.toolStatuses || {}).filter(s => s === 'success').length;
      return `
        <div class="wa-history-item osint-history-item flex items-center justify-between p-2 rounded-lg cursor-pointer transition"
             data-scan-id="${escapeHtml(item.id)}"
             onclick="OSINT.loadScanFromHistory('${escapeHtml(item.id)}')">
          <div class="flex-grow min-w-0 pr-2">
            <div class="text-xs font-semibold text-slate-200 truncate font-mono">${escapeHtml(displayTarget)}</div>
            <div class="text-[10px] text-slate-400 mt-0.5">${escapeHtml(item.timestamp)} &middot; ${successCount} module${successCount !== 1 ? 's' : ''}</div>
          </div>
          <svg class="w-3.5 h-3.5 text-slate-500 hover:text-white shrink-0" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" d="M13.5 4.5L21 12m0 0l-7.5 7.5M21 12H3"></path>
          </svg>
        </div>
      `;
    }).join('');
  }
};

// Expose on global window object for HTML onclick references
window.OSINT = OSINT;

// Auto-initialize if DOM is ready and active tab is OSINT
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => {
    // If the active tab on load is already OSINT, initialize it
    const activeTab = document.querySelector('.tab-button.active');
    if (activeTab && activeTab.dataset.tab === 'osint') {
      OSINT.init();
    }
  });
} else {
  const activeTab = document.querySelector('.tab-button.active');
  if (activeTab && activeTab.dataset.tab === 'osint') {
    OSINT.init();
  }
}
})();

