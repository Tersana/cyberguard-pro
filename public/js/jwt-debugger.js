/**
 * CyberGuard JWT Debugger & Editor Module
 * Real-time JWT decoding, encoding, signature verification, and expiry validation
 */

const CyberGuardJWTDebugger = {
  _initialized: false,
  _eventListenersAttached: false,

  // UI elements
  jwtTokenBox: null,
  headerInput: null,
  payloadInput: null,
  secretInput: null,
  secretBase64Toggle: null,
  copyButton: null,
  clearButton: null,
  sampleButton: null,
  signatureStatus: null,
  expiryBadge: null,

  activeHighlightTarget: null,

  /**
   * Safe Base64URL Decoding
   */
  base64UrlDecode(str) {
    try {
      str = str.replace(/-/g, '+').replace(/_/g, '/');
      while (str.length % 4) str += '=';
      return decodeURIComponent(
        atob(str)
          .split('')
          .map(c => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2))
          .join('')
      );
    } catch (e) {
      throw new Error('Invalid Base64URL encoding');
    }
  },

  /**
   * Safe Base64URL Encoding
   */
  base64UrlEncode(str) {
    try {
      return btoa(unescape(encodeURIComponent(str)))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '');
    } catch (e) {
      throw new Error('Encoding error');
    }
  },

  /**
   * Initialize JWT Debugger & Editor
   */
  init() {
    if (this._initialized) {
      console.log('CyberGuardJWTDebugger: Already initialized, skipping');
      return;
    }

    console.log('CyberGuardJWTDebugger: Initializing...');

    // Cache elements
    this.jwtTokenBox = document.getElementById('jwtTokenBox');
    this.headerInput = document.getElementById('headerInput');
    this.payloadInput = document.getElementById('payloadInput');
    this.secretInput = document.getElementById('secretInput');
    this.secretBase64Toggle = document.getElementById('secretBase64Toggle');
    this.copyButton = document.getElementById('ht-jwt-copy');
    this.clearButton = document.getElementById('ht-jwt-clear');
    this.sampleButton = document.getElementById('ht-jwt-sample');
    this.signatureStatus = document.getElementById('jwt-signature-status');
    this.expiryBadge = document.getElementById('jwt-expiry-badge');

    // Confirm essential elements are loaded
    if (!this.jwtTokenBox || !this.headerInput || !this.payloadInput) {
      console.error('CyberGuardJWTDebugger: Missing essential UI components');
      return;
    }

    this.setupListeners();
    this._initialized = true;

    // Start with empty fields initially
    this.clearAll();
    console.log('CyberGuardJWTDebugger: Initialization complete (empty state)');
  },

  /**
   * Bind event listeners
   */
  setupListeners() {
    if (this._eventListenersAttached) return;

    // Real-time input synchronization
    this.jwtTokenBox.addEventListener('input', () => this.parseTopToken());
    this.headerInput.addEventListener('input', () => this.updateTokenFromInputs());
    this.payloadInput.addEventListener('input', () => this.updateTokenFromInputs());
    this.secretInput.addEventListener('input', () => this.updateTokenFromInputs());
    if (this.secretBase64Toggle) {
      this.secretBase64Toggle.addEventListener('change', () => this.updateTokenFromInputs());
    }

    // Utility actions
    if (this.copyButton) {
      this.copyButton.addEventListener('click', () => this.copyToClipboard());
    }
    if (this.clearButton) {
      this.clearButton.addEventListener('click', () => this.clearAll());
    }
    if (this.sampleButton) {
      this.sampleButton.addEventListener('click', () => this.loadSample());
    }

    // Interactive focuses highlights setup
    this.setupHighlightEvents(this.headerInput, 'header');
    this.setupHighlightEvents(this.payloadInput, 'payload');

    this._eventListenersAttached = true;
  },

  /**
   * Load standard working JWT sample
   */
  loadSample() {
    const defaultHeader = {
      alg: 'HS256',
      typ: 'JWT'
    };

    const defaultPayload = {
      sub: '1234567890',
      name: 'John Doe',
      admin: true,
      iat: Math.floor(Date.now() / 1000) - 3600, // 1 hour ago
      exp: Math.floor(Date.now() / 1000) + 86400 // 24 hours from now
    };

    this.headerInput.value = JSON.stringify(defaultHeader, null, 2);
    this.payloadInput.value = JSON.stringify(defaultPayload, null, 2);
    this.secretInput.value = 'secret';
    if (this.secretBase64Toggle) {
      this.secretBase64Toggle.checked = false; // sample secret is raw string
    }

    this.updateTokenFromInputs();
  },

  /**
   * Clear all inputs and reset badges
   */
  clearAll() {
    this.jwtTokenBox.innerHTML = '';
    this.headerInput.value = '';
    this.payloadInput.value = '';
    this.secretInput.value = '';
    if (this.secretBase64Toggle) {
      this.secretBase64Toggle.checked = true;
    }

    if (this.signatureStatus) {
      this.signatureStatus.classList.add('hidden');
    }
    if (this.expiryBadge) {
      this.expiryBadge.classList.add('hidden');
    }
  },

  /**
   * Copy generated JWT token to clipboard
   */
  async copyToClipboard() {
    const text = this.jwtTokenBox.innerText.trim();
    if (!text) return;

    try {
      await navigator.clipboard.writeText(text);

      const originalHTML = this.copyButton.innerHTML;
      this.copyButton.innerHTML = '<span class="material-symbols-outlined text-[14px]">check</span> Copied!';
      this.copyButton.classList.add('text-green-400');

      setTimeout(() => {
        this.copyButton.innerHTML = originalHTML;
        this.copyButton.classList.remove('text-green-400');
      }, 2000);
    } catch (err) {
      console.error('JWT clipboard copy failed:', err);
      CyberNotify.alert('Failed to copy token. Please select and copy manually.', { type: 'error' });
    }
  },

  /**
   * Resolve secret key buffer accounting for Base64 toggle
   */
  async getSecretKeyBuffer(secret, isBase64) {
    const enc = new TextEncoder();
    if (isBase64 && secret) {
      try {
        const cleanSecret = secret.replace(/-/g, '+').replace(/_/g, '/');
        const binaryString = atob(cleanSecret);
        const bytes = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
          bytes[i] = binaryString.charCodeAt(i);
        }
        return bytes;
      } catch (e) {
        console.warn('Secret key is not valid Base64, falling back to raw secret bytes.');
      }
    }
    return enc.encode(secret);
  },

  /**
   * Compute HMAC SHA-256 Signature using Web Crypto API
   */
  async computeSignature(headerB64, payloadB64, secret, isBase64) {
    if (!secret) return '';
    const keyBuffer = await this.getSecretKeyBuffer(secret, isBase64);
    const enc = new TextEncoder();
    const key = await crypto.subtle.importKey(
      'raw',
      keyBuffer,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );
    const data = enc.encode(`${headerB64}.${payloadB64}`);
    const sigBuffer = await crypto.subtle.sign('HMAC', key, data);

    const hashArray = Array.from(new Uint8Array(sigBuffer));
    const hashString = hashArray.map(b => String.fromCharCode(b)).join('');
    return this.base64UrlEncode(hashString);
  },

  /**
   * Parse token pasted into the display box
   */
  async parseTopToken() {
    const token = this.jwtTokenBox.innerText.trim();
    if (!token) {
      this.headerInput.value = '';
      this.payloadInput.value = '';
      if (this.signatureStatus) this.signatureStatus.classList.add('hidden');
      if (this.expiryBadge) this.expiryBadge.classList.add('hidden');
      return;
    }

    try {
      const parts = token.split('.');
      if (parts.length !== 3) {
        this.updateSignatureBadgeStatus('invalid_format');
        return;
      }

      const decodedHeader = JSON.parse(this.base64UrlDecode(parts[0]));
      const decodedPayload = JSON.parse(this.base64UrlDecode(parts[1]));

      this.headerInput.value = JSON.stringify(decodedHeader, null, 2);
      this.payloadInput.value = JSON.stringify(decodedPayload, null, 2);

      this.renderTokenStructure(parts[0], parts[1], parts[2]);
      this.checkExpiryStatus(decodedPayload);
      await this.verifySignature(parts[0], parts[1], parts[2]);
    } catch (e) {
      // Keep styling for pasted invalid token but show error
      this.updateSignatureBadgeStatus('invalid_format');
    }
  },

  /**
   * Rebuild JWT Token from current JSON inputs
   */
  async updateTokenFromInputs() {
    try {
      if (!this.headerInput.value.trim() && !this.payloadInput.value.trim()) {
        this.jwtTokenBox.innerHTML = '';
        if (this.signatureStatus) this.signatureStatus.classList.add('hidden');
        if (this.expiryBadge) this.expiryBadge.classList.add('hidden');
        return;
      }

      let headerObj = {};
      let payloadObj = {};

      try {
        headerObj = this.headerInput.value.trim() ? JSON.parse(this.headerInput.value) : {};
      } catch (e) {
        // Syntax error in header JSON
      }

      try {
        payloadObj = this.payloadInput.value.trim() ? JSON.parse(this.payloadInput.value) : {};
      } catch (e) {
        // Syntax error in payload JSON
      }

      const encHeader = this.base64UrlEncode(JSON.stringify(headerObj));
      const encPayload = this.base64UrlEncode(JSON.stringify(payloadObj));
      const secret = this.secretInput.value;
      const isBase64 = this.secretBase64Toggle ? this.secretBase64Toggle.checked : true;

      let signature = '';
      if (secret) {
        signature = await this.computeSignature(encHeader, encPayload, secret, isBase64);
      } else {
        // If no secret, try to keep signature from current display box if valid format
        const text = this.jwtTokenBox.innerText.trim();
        const parts = text.split('.');
        signature = parts.length === 3 ? parts[2] : '';
      }

      this.renderTokenStructure(encHeader, encPayload, signature);
      this.checkExpiryStatus(payloadObj);
      await this.verifySignature(encHeader, encPayload, signature);
    } catch (e) {
      console.error('JWT encode error:', e);
    }
  },

  /**
   * Validate token signature dynamically
   */
  async verifySignature(headerB64, payloadB64, signatureB64) {
    if (!this.signatureStatus) return;

    const secret = this.secretInput.value;
    const isBase64 = this.secretBase64Toggle ? this.secretBase64Toggle.checked : true;

    if (!secret) {
      this.updateSignatureBadgeStatus('no_secret');
      return;
    }

    try {
      const computed = await this.computeSignature(headerB64, payloadB64, secret, isBase64);
      if (computed === signatureB64) {
        this.updateSignatureBadgeStatus('valid');
      } else {
        this.updateSignatureBadgeStatus('invalid');
      }
    } catch (e) {
      this.updateSignatureBadgeStatus('error');
    }
  },

  /**
   * Update verification status badge layout
   */
  updateSignatureBadgeStatus(status) {
    if (!this.signatureStatus) return;

    switch (status) {
      case 'valid':
        this.signatureStatus.textContent = '✓ Signature Valid';
        this.signatureStatus.className =
          'text-[10px] uppercase font-bold tracking-wider px-2 py-0.5 rounded ml-2 bg-green-500/20 text-green-400';
        break;
      case 'invalid':
        this.signatureStatus.textContent = '✗ Signature Invalid';
        this.signatureStatus.className =
          'text-[10px] uppercase font-bold tracking-wider px-2 py-0.5 rounded ml-2 bg-red-500/20 text-red-400';
        break;
      case 'invalid_format':
        this.signatureStatus.textContent = '✗ Invalid JWT Format';
        this.signatureStatus.className =
          'text-[10px] uppercase font-bold tracking-wider px-2 py-0.5 rounded ml-2 bg-red-500/20 text-red-400';
        break;
      case 'no_secret':
        this.signatureStatus.textContent = 'Awaiting Secret';
        this.signatureStatus.className =
          'text-[10px] uppercase font-bold tracking-wider px-2 py-0.5 rounded ml-2 bg-yellow-500/20 text-yellow-400';
        break;
      default:
        this.signatureStatus.textContent = '✗ Verification Error';
        this.signatureStatus.className =
          'text-[10px] uppercase font-bold tracking-wider px-2 py-0.5 rounded ml-2 bg-red-500/20 text-red-400';
    }
    this.signatureStatus.classList.remove('hidden');
  },

  /**
   * Validate expiry claims on Payload JSON
   */
  checkExpiryStatus(payloadObj) {
    if (!this.expiryBadge) return;

    if (!payloadObj || typeof payloadObj !== 'object' || !('exp' in payloadObj)) {
      this.expiryBadge.textContent = 'No Expiry';
      this.expiryBadge.className =
        'text-[10px] uppercase font-bold tracking-wider px-2 py-0.5 rounded bg-slate-500/20 text-slate-400';
      this.expiryBadge.classList.remove('hidden');
      return;
    }

    const exp = Number(payloadObj.exp);
    if (isNaN(exp)) {
      this.expiryBadge.textContent = 'Invalid Expiry';
      this.expiryBadge.className =
        'text-[10px] uppercase font-bold tracking-wider px-2 py-0.5 rounded bg-yellow-500/20 text-yellow-400';
      this.expiryBadge.classList.remove('hidden');
      return;
    }

    const nowSeconds = Math.floor(Date.now() / 1000);
    if (exp < nowSeconds) {
      this.expiryBadge.textContent = 'Token Expired';
      this.expiryBadge.className =
        'text-[10px] uppercase font-bold tracking-wider px-2 py-0.5 rounded bg-red-500/20 text-red-400';
    } else {
      this.expiryBadge.textContent = 'Token Valid';
      this.expiryBadge.className =
        'text-[10px] uppercase font-bold tracking-wider px-2 py-0.5 rounded bg-green-500/20 text-green-400';
    }
    this.expiryBadge.classList.remove('hidden');
  },

  /**
   * Render color-coded token elements with appropriate highlight states
   */
  renderTokenStructure(h, p, s) {
    const hClass =
      this.activeHighlightTarget === 'header'
        ? 'jwt-part-header jwt-highlight-active'
        : 'jwt-part-header';
    const pClass =
      this.activeHighlightTarget === 'payload'
        ? 'jwt-part-payload jwt-highlight-active'
        : 'jwt-part-payload';

    this.jwtTokenBox.innerHTML = `<span class="${hClass}">${h}</span><span class="jwt-part-dot">.</span><span class="${pClass}">${p}</span><span class="jwt-part-dot">.</span><span class="jwt-part-signature">${s}</span>`;
  },

  /**
   * Sync active highlight based on editor field focuses
   */
  setupHighlightEvents(inputElement, targetName) {
    inputElement.addEventListener('focus', () => {
      this.activeHighlightTarget = targetName;
      const targetSpan = this.jwtTokenBox.querySelector(`.jwt-part-${targetName}`);
      if (targetSpan) targetSpan.classList.add('jwt-highlight-active');
    });

    inputElement.addEventListener('blur', () => {
      this.activeHighlightTarget = null;
      const targetSpan = this.jwtTokenBox.querySelector(`.jwt-part-${targetName}`);
      if (targetSpan) targetSpan.classList.remove('jwt-highlight-active');
    });
  }
};

// Export to window object for access by tab manager
window.CyberGuardJWTDebugger = CyberGuardJWTDebugger;
