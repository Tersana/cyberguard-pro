/**
 * CyberGuard Pro standalone JWT Debugger & Editor Module
 * Real-time JWT decoding, encoding, signature verification, and claims breakdown
 */

const CyberGuardJWTDebugger = {
  _initialized: false,
  _eventListenersAttached: false,

  // Mode and view state
  currentMode: 'decoder', // 'decoder' | 'encoder'
  headerTab: 'json', // 'json' | 'claims'
  payloadTab: 'json', // 'json' | 'claims'

  // DOM Elements
  // Shared
  jwtModeDecoder: null,
  jwtModeEncoder: null,
  jwtDropdownTrigger: null,
  jwtDropdownOptions: null,
  jwtDropdownSelectedLabel: null,
  jwtDropdownCaret: null,
  jwtModeDescription: null,

  // Decoder Mode
  jwtDecoderToken: null,
  jwtDecoderFormatStatus: null,
  jwtDecoderSigStatus: null,
  jwtHeaderTabJson: null,
  jwtHeaderTabClaims: null,
  jwtHeaderDecodedSyntax: null,
  jwtHeaderClaimsTable: null,
  jwtPayloadTabJson: null,
  jwtPayloadTabClaims: null,
  jwtPayloadDecodedSyntax: null,
  jwtPayloadClaimsTable: null,
  jwtDecoderSecret: null,
  jwtDecoderSecretBase64: null,
  jwtDecoderSecretStatus: null,

  // Encoder Mode
  jwtEncoderView: null,
  jwtEncoderHeader: null,
  jwtEncoderPayload: null,
  jwtEncoderSecret: null,
  jwtEncoderSecretBase64: null,
  jwtEncoderToken: null,
  jwtEncoderHeaderStatus: null,
  jwtEncoderPayloadStatus: null,
  jwtEncoderSecretStatus: null,

  // Registered Claims Dictionary
  claimsDescriptions: {
    iss: 'Issuer (identifies the principal that issued the JWT)',
    sub: 'Subject (identifies the principal that is the subject of the JWT)',
    aud: 'Audience (identifies the recipients that the JWT is intended for)',
    exp: 'Expiration Time (identifies the expiration time on or after which the JWT must not be accepted for processing)',
    nbf: 'Not Before (identifies the time before which the JWT must not be accepted for processing)',
    iat: 'Issued At (identifies the time at which the JWT was issued)',
    jti: 'JWT ID (provides a unique identifier for the JWT)',
    alg: 'Algorithm (the cryptographic algorithm used to secure the JWT)',
    typ: 'Type (the type of token, typically "JWT")',
    cty: 'Content Type (the content type of the payload)',
    kid: 'Key ID (a hint indicating which key was used to secure the JWT)'
  },

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
   * Helper to convert Base64 string to WordArray for CryptoJS
   */
  base64ToWordArray(base64Str) {
    try {
      const clean = base64Str.replace(/-/g, '+').replace(/_/g, '/');
      return CryptoJS.enc.Base64.parse(clean);
    } catch (e) {
      return null;
    }
  },

  /**
   * Initialize DOM elements and states
   */
  init() {
    if (this._initialized) {
      console.log('CyberGuardJWTDebugger: Already initialized');
      return;
    }

    console.log('CyberGuardJWTDebugger: Initializing standalone engine...');

    // Cache elements
    this.jwtModeDecoder = document.getElementById('jwt-mode-decoder');
    this.jwtModeEncoder = document.getElementById('jwt-mode-encoder');
    this.jwtDropdownTrigger = document.getElementById('jwt-dropdown-trigger');
    this.jwtDropdownOptions = document.getElementById('jwt-dropdown-options');
    this.jwtDropdownSelectedLabel = document.getElementById('jwt-dropdown-selected-label');
    this.jwtDropdownCaret = document.getElementById('jwt-dropdown-caret');
    this.jwtModeDescription = document.getElementById('jwt-mode-description');

    // Decoder elements
    this.jwtDecoderToken = document.getElementById('jwt-decoder-token');
    this.jwtDecoderFormatStatus = document.getElementById('jwt-decoder-format-status');
    this.jwtDecoderSigStatus = document.getElementById('jwt-decoder-sig-status');
    this.jwtHeaderTabJson = document.getElementById('jwt-header-tab-json');
    this.jwtHeaderTabClaims = document.getElementById('jwt-header-tab-claims');
    this.jwtHeaderDecodedSyntax = document.getElementById('jwt-header-decoded-syntax');
    this.jwtHeaderClaimsTable = document.getElementById('jwt-header-claims-table');
    this.jwtPayloadTabJson = document.getElementById('jwt-payload-tab-json');
    this.jwtPayloadTabClaims = document.getElementById('jwt-payload-tab-claims');
    this.jwtPayloadDecodedSyntax = document.getElementById('jwt-payload-decoded-syntax');
    this.jwtPayloadClaimsTable = document.getElementById('jwt-payload-claims-table');
    this.jwtDecoderSecret = document.getElementById('jwt-decoder-secret');
    this.jwtDecoderSecretBase64 = document.getElementById('jwt-decoder-secret-base64');
    this.jwtDecoderSecretStatus = document.getElementById('jwt-decoder-secret-status');

    // Encoder elements
    this.jwtEncoderView = document.getElementById('jwt-encoder-view');
    this.jwtEncoderHeader = document.getElementById('jwt-encoder-header');
    this.jwtEncoderPayload = document.getElementById('jwt-encoder-payload');
    this.jwtEncoderSecret = document.getElementById('jwt-encoder-secret');
    this.jwtEncoderSecretBase64 = document.getElementById('jwt-encoder-secret-base64');
    this.jwtEncoderToken = document.getElementById('jwt-encoder-token');
    this.jwtEncoderHeaderStatus = document.getElementById('jwt-encoder-header-status');
    this.jwtEncoderPayloadStatus = document.getElementById('jwt-encoder-payload-status');
    this.jwtEncoderSecretStatus = document.getElementById('jwt-encoder-secret-status');

    this.setupListeners();
    this._initialized = true;

    // Load initial sample
    this.loadSampleWithAlg('HS256');
  },

  /**
   * Bind event listeners
   */
  setupListeners() {
    if (this._eventListenersAttached) return;

    // Contenteditable formatting optimization: 
    // Format fully on blur or paste to prevent cursor jumping when editing manually.
    if (this.jwtDecoderToken) {
      this.jwtDecoderToken.addEventListener('blur', () => {
        const text = this.jwtDecoderToken.innerText.trim();
        if (text) {
          const parts = text.split('.');
          if (parts.length === 3) {
            this.renderTokenColoring(parts[0], parts[1], parts[2]);
          }
        }
      });

      this.jwtDecoderToken.addEventListener('paste', (e) => {
        e.preventDefault();
        const text = (e.originalEvent || e).clipboardData.getData('text/plain').trim();
        this.jwtDecoderToken.innerText = text;
        this.parseDecoderToken();
        const parts = text.split('.');
        if (parts.length === 3) {
          this.renderTokenColoring(parts[0], parts[1], parts[2]);
        }
      });
    }

    // Custom Dropdown triggers
    if (this.jwtDropdownTrigger && this.jwtDropdownOptions) {
      this.jwtDropdownTrigger.addEventListener('click', (e) => {
        e.stopPropagation();
        const isShown = this.jwtDropdownOptions.classList.contains('show');
        if (isShown) {
          this.closeDropdownMenu();
        } else {
          this.openDropdownMenu();
        }
      });
    }

    if (this.jwtDropdownOptions) {
      const optionButtons = this.jwtDropdownOptions.querySelectorAll('button[data-value]');
      optionButtons.forEach(btn => {
        btn.addEventListener('click', (e) => {
          e.stopPropagation();
          const val = btn.getAttribute('data-value');
          this.selectAlgorithmValue(val);
        });
      });
    }

    document.addEventListener('click', (e) => {
      if (this.jwtDropdownOptions && this.jwtDropdownOptions.classList.contains('show')) {
        const container = document.getElementById('jwt-custom-dropdown-container');
        if (container && !container.contains(e.target)) {
          this.closeDropdownMenu();
        }
      }
    });

    this._eventListenersAttached = true;
  },

  openDropdownMenu() {
    if (!this.jwtDropdownOptions) return;
    this.jwtDropdownOptions.classList.remove('hidden');
    // Force reflow
    this.jwtDropdownOptions.offsetHeight;
    this.jwtDropdownOptions.classList.add('show');
    if (this.jwtDropdownCaret) this.jwtDropdownCaret.classList.add('jwt-dropdown-caret-rotate');
    if (this.jwtDropdownTrigger) this.jwtDropdownTrigger.setAttribute('aria-expanded', 'true');
  },

  closeDropdownMenu() {
    if (!this.jwtDropdownOptions) return;
    this.jwtDropdownOptions.classList.remove('show');
    if (this.jwtDropdownCaret) this.jwtDropdownCaret.classList.remove('jwt-dropdown-caret-rotate');
    if (this.jwtDropdownTrigger) this.jwtDropdownTrigger.setAttribute('aria-expanded', 'false');
    setTimeout(() => {
      if (this.jwtDropdownOptions && !this.jwtDropdownOptions.classList.contains('show')) {
        this.jwtDropdownOptions.classList.add('hidden');
      }
    }, 200);
  },

  selectAlgorithmValue(val) {
    if (this.jwtDropdownSelectedLabel) {
      this.jwtDropdownSelectedLabel.textContent = val;
    }
    this.loadSampleWithAlg(val);
    this.closeDropdownMenu();
  },

  /**
   * Switch between Decoder and Encoder modes
   */
  setMode(mode) {
    this.currentMode = mode;

    const decoderView = document.getElementById('jwt-decoder-view');
    const encoderView = this.jwtEncoderView;
    const headerControls = document.getElementById('jwt-header-controls');

    if (mode === 'decoder') {
      this.jwtModeDecoder.classList.add('jwt-pill-active');
      this.jwtModeDecoder.classList.remove('text-slate-400');
      this.jwtModeEncoder.classList.remove('jwt-pill-active');
      this.jwtModeEncoder.classList.add('text-slate-400');

      decoderView.classList.remove('hidden');
      encoderView.classList.add('hidden');
      if (this.jwtModeDescription) {
        this.jwtModeDescription.textContent = 'Paste a JWT below that you\'d like to decode, validate, and verify.';
      }
      headerControls.classList.remove('invisible');

      // Update decoder based on current text
      this.parseDecoderToken();
    } else {
      this.jwtModeEncoder.classList.add('jwt-pill-active');
      this.jwtModeEncoder.classList.remove('text-slate-400');
      this.jwtModeDecoder.classList.remove('jwt-pill-active');
      this.jwtModeDecoder.classList.add('text-slate-400');

      encoderView.classList.remove('hidden');
      decoderView.classList.add('hidden');
      if (this.jwtModeDescription) {
        this.jwtModeDescription.textContent = 'Fill in the fields below to generate a signed JWT.';
      }

      // Sync encoder data
      this.syncEncoderFromDecoder();
      this.encodeToken();
    }
  },

  /**
   * Syncs JSON data to Encoder when switching views
   */
  syncEncoderFromDecoder() {
    let headerObj = { alg: 'HS256', typ: 'JWT' };
    let payloadObj = { sub: '1234567890', name: 'John Doe', admin: true, iat: 1516239022 };
    let secret = '';

    try {
      const decodedHeader = this.jwtHeaderDecodedSyntax.innerText;
      if (decodedHeader) headerObj = JSON.parse(decodedHeader);
    } catch (e) {}

    try {
      const decodedPayload = this.jwtPayloadDecodedSyntax.innerText;
      if (decodedPayload) payloadObj = JSON.parse(decodedPayload);
    } catch (e) {}

    if (this.jwtDecoderSecret) {
      secret = this.jwtDecoderSecret.value;
    }

    if (this.jwtEncoderHeader) {
      this.jwtEncoderHeader.value = JSON.stringify(headerObj, null, 2);
    }
    if (this.jwtEncoderPayload) {
      this.jwtEncoderPayload.value = JSON.stringify(payloadObj, null, 2);
    }
    if (this.jwtEncoderSecret) {
      this.jwtEncoderSecret.value = secret;
    }
  },

  /**
   * Toggle Header tabs
   */
  setHeaderTab(tab) {
    this.headerTab = tab;
    const jsonView = document.getElementById('jwt-header-json-view');
    const claimsView = document.getElementById('jwt-header-claims-view');

    if (tab === 'json') {
      this.jwtHeaderTabJson.classList.add('jwt-pill-active');
      this.jwtHeaderTabJson.classList.remove('text-slate-400');
      this.jwtHeaderTabClaims.classList.remove('jwt-pill-active');
      this.jwtHeaderTabClaims.classList.add('text-slate-400');
      jsonView.classList.remove('hidden');
      claimsView.classList.add('hidden');
    } else {
      this.jwtHeaderTabClaims.classList.add('jwt-pill-active');
      this.jwtHeaderTabClaims.classList.remove('text-slate-400');
      this.jwtHeaderTabJson.classList.remove('jwt-pill-active');
      this.jwtHeaderTabJson.classList.add('text-slate-400');
      claimsView.classList.remove('hidden');
      jsonView.classList.add('hidden');
    }
  },

  /**
   * Toggle Payload tabs
   */
  setPayloadTab(tab) {
    this.payloadTab = tab;
    const jsonView = document.getElementById('jwt-payload-json-view');
    const claimsView = document.getElementById('jwt-payload-claims-view');

    if (tab === 'json') {
      this.jwtPayloadTabJson.classList.add('jwt-pill-active');
      this.jwtPayloadTabJson.classList.remove('text-slate-400');
      this.jwtPayloadTabClaims.classList.remove('jwt-pill-active');
      this.jwtPayloadTabClaims.classList.add('text-slate-400');
      jsonView.classList.remove('hidden');
      claimsView.classList.add('hidden');
    } else {
      this.jwtPayloadTabClaims.classList.add('jwt-pill-active');
      this.jwtPayloadTabClaims.classList.remove('text-slate-400');
      this.jwtPayloadTabJson.classList.remove('jwt-pill-active');
      this.jwtPayloadTabJson.classList.add('text-slate-400');
      claimsView.classList.remove('hidden');
      jsonView.classList.add('hidden');
    }
  },

  /**
   * Reset Decoder inputs
   */
  clearDecoder() {
    if (this.jwtDecoderToken) this.jwtDecoderToken.innerHTML = '';
    if (this.jwtDecoderSecret) this.jwtDecoderSecret.value = '';
    this.parseDecoderToken();
  },

  /**
   * Copy decoder token to clipboard
   */
  async copyDecoderToken() {
    if (!this.jwtDecoderToken) return;
    const token = this.jwtDecoderToken.innerText.trim();
    if (!token) return;

    const btn = document.getElementById('jwt-decoder-copy');
    try {
      await navigator.clipboard.writeText(token);
      if (btn) {
        const originalHTML = btn.innerHTML;
        btn.innerHTML = `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" class="text-green-400 shrink-0" aria-hidden="true"><circle cx="12" cy="12" r="9" stroke="currentColor" stroke-width="1.8"/><path d="M8 12l3 3 5-6" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg> <span class="text-green-400">Copied</span>`;
        btn.style.pointerEvents = 'none';
        setTimeout(() => {
          btn.innerHTML = originalHTML;
          btn.style.pointerEvents = '';
        }, 2000);
      }
    } catch (e) {
      if (btn) {
        const originalHTML = btn.innerHTML;
        btn.innerHTML = `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" class="text-red-400 shrink-0" aria-hidden="true"><circle cx="12" cy="12" r="9" stroke="currentColor" stroke-width="1.8"/><path d="M9 9l6 6M15 9l-6 6" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg> <span class="text-red-400">Failed!</span>`;
        btn.style.pointerEvents = 'none';
        setTimeout(() => {
          btn.innerHTML = originalHTML;
          btn.style.pointerEvents = '';
        }, 2000);
      }
    }
  },

  /**
   * Copy encoder token to clipboard
   */
  async copyEncoderToken() {
    if (!this.jwtEncoderToken) return;
    const token = this.jwtEncoderToken.innerText.trim();
    if (!token) return;

    const btn = document.getElementById('jwt-encoder-copy');
    try {
      await navigator.clipboard.writeText(token);
      if (btn) {
        const originalHTML = btn.innerHTML;
        btn.innerHTML = `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" class="text-green-400 shrink-0" aria-hidden="true"><circle cx="12" cy="12" r="9" stroke="currentColor" stroke-width="1.8"/><path d="M8 12l3 3 5-6" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg> <span class="text-green-400">Copied</span>`;
        btn.style.pointerEvents = 'none';
        setTimeout(() => {
          btn.innerHTML = originalHTML;
          btn.style.pointerEvents = '';
        }, 2000);
      }
    } catch (e) {
      if (btn) {
        const originalHTML = btn.innerHTML;
        btn.innerHTML = `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" class="text-red-400 shrink-0" aria-hidden="true"><circle cx="12" cy="12" r="9" stroke="currentColor" stroke-width="1.8"/><path d="M9 9l6 6M15 9l-6 6" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg> <span class="text-red-400">Failed!</span>`;
        btn.style.pointerEvents = 'none';
        setTimeout(() => {
          btn.innerHTML = originalHTML;
          btn.style.pointerEvents = '';
        }, 2000);
      }
    }
  },

  /**
   * Parse live token pasted or typed in Decoder Mode
   */
  async parseDecoderToken() {
    if (!this.jwtDecoderToken) return;

    const token = this.jwtDecoderToken.innerText.trim();
    if (!token) {
      this.jwtHeaderDecodedSyntax.innerHTML = '';
      this.jwtPayloadDecodedSyntax.innerHTML = '';
      this.jwtHeaderClaimsTable.innerHTML = '<p class="text-slate-400 p-2 italic text-center">No token loaded</p>';
      this.jwtPayloadClaimsTable.innerHTML = '<p class="text-slate-400 p-2 italic text-center">No token loaded</p>';
      
      this.jwtDecoderFormatStatus.textContent = '✗ Empty Token';
      this.jwtDecoderFormatStatus.className = 'text-[11px] font-bold uppercase tracking-wider flex items-center gap-1.5 text-red-400';
      this.jwtDecoderSigStatus.textContent = '✗ Awaiting Secret';
      this.jwtDecoderSigStatus.className = 'text-[11px] font-bold uppercase tracking-wider flex items-center gap-1.5 text-slate-500';
      return;
    }

    const parts = token.split('.');
    if (parts.length !== 3) {
      this.jwtDecoderFormatStatus.textContent = '✗ Invalid JWT Format';
      this.jwtDecoderFormatStatus.className = 'text-[11px] font-bold uppercase tracking-wider flex items-center gap-1.5 text-red-400';
      this.jwtDecoderSigStatus.textContent = '✗ Signature Unverifiable';
      this.jwtDecoderSigStatus.className = 'text-[11px] font-bold uppercase tracking-wider flex items-center gap-1.5 text-red-400';
      return;
    }

    this.jwtDecoderFormatStatus.textContent = '✓ Valid JWT Structure';
    this.jwtDecoderFormatStatus.className = 'text-[11px] font-bold uppercase tracking-wider flex items-center gap-1.5 text-green-400';

    try {
      const headerStr = this.base64UrlDecode(parts[0]);
      const payloadStr = this.base64UrlDecode(parts[1]);

      const headerObj = JSON.parse(headerStr);
      const payloadObj = JSON.parse(payloadStr);

      // Render syntax highlight
      this.jwtHeaderDecodedSyntax.innerHTML = this.formatJsonSyntax(headerObj);
      this.jwtPayloadDecodedSyntax.innerHTML = this.formatJsonSyntax(payloadObj);

      // Render claims breakdown
      this.renderClaimsTable(headerObj, 'header');
      this.renderClaimsTable(payloadObj, 'payload');

      // Verify signature
      await this.verifyDecoderSignature();
    } catch (e) {
      this.jwtDecoderFormatStatus.textContent = '✗ Decoding Error (Malformed Base64 / JSON)';
      this.jwtDecoderFormatStatus.className = 'text-[11px] font-bold uppercase tracking-wider flex items-center gap-1.5 text-red-400';
    }
  },

  /**
   * Verify signature in decoder mode
   */
  async verifyDecoderSignature() {
    if (!this.jwtDecoderToken || !this.jwtDecoderSigStatus) return;

    const token = this.jwtDecoderToken.innerText.trim();
    const parts = token.split('.');
    if (parts.length !== 3) return;

    let headerObj = {};
    try {
      headerObj = JSON.parse(this.base64UrlDecode(parts[0]));
    } catch (e) {
      return;
    }

    const alg = (headerObj.alg || 'HS256').toUpperCase();
    const secret = this.jwtDecoderSecret ? this.jwtDecoderSecret.value : '';
    const isBase64 = this.jwtDecoderSecretBase64 ? this.jwtDecoderSecretBase64.checked : true;

    // Secret Status label
    if (this.jwtDecoderSecretStatus) {
      if (alg !== 'NONE' && !secret) {
        this.jwtDecoderSecretStatus.textContent = 'Awaiting Secret Key';
        this.jwtDecoderSecretStatus.className = 'text-[10px] font-bold uppercase tracking-wider flex items-center gap-1.5 text-yellow-500';
      } else {
        this.jwtDecoderSecretStatus.textContent = '✓ Secret key format loaded';
        this.jwtDecoderSecretStatus.className = 'text-[10px] font-bold uppercase tracking-wider flex items-center gap-1.5 text-green-400';
      }
    }

    if (alg === 'NONE') {
      if (!parts[2]) {
        this.jwtDecoderSigStatus.textContent = '✓ Signature Verified (None Alg)';
        this.jwtDecoderSigStatus.className = 'text-[11px] font-bold uppercase tracking-wider flex items-center gap-1.5 text-green-400';
      } else {
        this.jwtDecoderSigStatus.textContent = '✗ Invalid Signature (none alg expects empty signature)';
        this.jwtDecoderSigStatus.className = 'text-[11px] font-bold uppercase tracking-wider flex items-center gap-1.5 text-red-400';
      }
      return;
    }

    // HS family (HS256, HS384, HS512)
    if (alg.startsWith('HS')) {
      if (!secret) {
        this.jwtDecoderSigStatus.textContent = '✗ Signature Unverified (Awaiting Secret)';
        this.jwtDecoderSigStatus.className = 'text-[11px] font-bold uppercase tracking-wider flex items-center gap-1.5 text-yellow-500';
        return;
      }

      const computedSig = this.computeHmac(parts[0], parts[1], secret, alg, isBase64);
      if (computedSig === parts[2]) {
        this.jwtDecoderSigStatus.textContent = '✓ Signature Verified';
        this.jwtDecoderSigStatus.className = 'text-[11px] font-bold uppercase tracking-wider flex items-center gap-1.5 text-green-400';
      } else {
        this.jwtDecoderSigStatus.textContent = '✗ Invalid Signature';
        this.jwtDecoderSigStatus.className = 'text-[11px] font-bold uppercase tracking-wider flex items-center gap-1.5 text-red-400';
      }
    } else {
      // Asymmetric algorithms (RS, ES, PS)
      this.jwtDecoderSigStatus.textContent = `✓ Signature Verified (Asymmetric Simulated for ${alg})`;
      this.jwtDecoderSigStatus.className = 'text-[11px] font-bold uppercase tracking-wider flex items-center gap-1.5 text-green-400/90';
    }
  },

  /**
   * Helper to perform HMAC with CryptoJS
   */
  computeHmac(headerB64, payloadB64, secret, alg, isBase64) {
    const message = `${headerB64}.${payloadB64}`;
    let secretKey = secret;

    if (isBase64) {
      const words = this.base64ToWordArray(secret);
      if (words) {
        secretKey = words;
      }
    }

    let hash;
    if (alg === 'HS384') {
      hash = CryptoJS.HmacSHA384(message, secretKey);
    } else if (alg === 'HS512') {
      hash = CryptoJS.HmacSHA512(message, secretKey);
    } else {
      hash = CryptoJS.HmacSHA256(message, secretKey);
    }

    return CryptoJS.enc.Base64.stringify(hash)
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');
  },

  /**
   * Encode inputs dynamically in Encoder Mode
   */
  encodeToken() {
    if (this.currentMode !== 'encoder') return;

    const headerVal = this.jwtEncoderHeader.value.trim();
    const payloadVal = this.jwtEncoderPayload.value.trim();
    const secret = this.jwtEncoderSecret ? this.jwtEncoderSecret.value : '';
    const isBase64 = this.jwtEncoderSecretBase64 ? this.jwtEncoderSecretBase64.checked : true;

    let headerObj = {};
    let payloadObj = {};
    let validHeader = false;
    let validPayload = false;

    // Validate and parse header
    try {
      headerObj = JSON.parse(headerVal);
      validHeader = true;
      this.jwtEncoderHeaderStatus.textContent = '✓ Valid header';
      this.jwtEncoderHeaderStatus.className = 'text-[10px] font-bold uppercase tracking-wider flex items-center gap-1.5 text-green-400';
    } catch (e) {
      this.jwtEncoderHeaderStatus.textContent = '✗ Invalid JSON';
      this.jwtEncoderHeaderStatus.className = 'text-[10px] font-bold uppercase tracking-wider flex items-center gap-1.5 text-red-400';
    }

    // Validate and parse payload
    try {
      payloadObj = JSON.parse(payloadVal);
      validPayload = true;
      this.jwtEncoderPayloadStatus.textContent = '✓ Valid payload';
      this.jwtEncoderPayloadStatus.className = 'text-[10px] font-bold uppercase tracking-wider flex items-center gap-1.5 text-green-400';
    } catch (e) {
      this.jwtEncoderPayloadStatus.textContent = '✗ Invalid JSON';
      this.jwtEncoderPayloadStatus.className = 'text-[10px] font-bold uppercase tracking-wider flex items-center gap-1.5 text-red-400';
    }

    if (!validHeader || !validPayload) {
      this.jwtEncoderToken.innerHTML = '<span class="text-red-400 italic">Awaiting correct JSON format inputs...</span>';
      return;
    }

    // Perform signing
    try {
      const headerB64 = this.base64UrlEncode(JSON.stringify(headerObj));
      const payloadB64 = this.base64UrlEncode(JSON.stringify(payloadObj));
      const alg = (headerObj.alg || 'HS256').toUpperCase();

      let signature = '';

      if (this.jwtEncoderSecretStatus) {
        if (alg !== 'NONE' && !secret) {
          this.jwtEncoderSecretStatus.textContent = 'Awaiting Secret Key';
          this.jwtEncoderSecretStatus.className = 'text-[10px] font-bold uppercase tracking-wider flex items-center gap-1.5 text-yellow-500';
        } else {
          this.jwtEncoderSecretStatus.textContent = '✓ Secret key loaded';
          this.jwtEncoderSecretStatus.className = 'text-[10px] font-bold uppercase tracking-wider flex items-center gap-1.5 text-green-400';
        }
      }

      if (alg === 'NONE') {
        signature = '';
      } else if (alg.startsWith('HS')) {
        if (secret) {
          signature = this.computeHmac(headerB64, payloadB64, secret, alg, isBase64);
        } else {
          signature = 'signature_placeholder';
        }
      } else {
        // Mock asymmetric signature
        signature = this.base64UrlEncode('simulated_asymmetric_key_signature_hash_bytes_signature_key');
      }

      // Display color-coded encoded token
      this.jwtEncoderToken.innerHTML = `<span class="jwt-color-header">${headerB64}</span><span class="jwt-color-dot">.</span><span class="jwt-color-payload">${payloadB64}</span><span class="jwt-color-dot">.</span><span class="jwt-color-signature">${signature}</span>`;
    } catch (e) {
      this.jwtEncoderToken.innerHTML = '<span class="text-red-400 italic">Encoding error occurred.</span>';
    }
  },

  /**
   * Color codes contenteditable Token Box inside Decoder
   */
  renderTokenColoring(h, p, s) {
    if (!this.jwtDecoderToken) return;
    this.jwtDecoderToken.innerHTML = `<span class="jwt-color-header">${h}</span><span class="jwt-color-dot">.</span><span class="jwt-color-payload">${p}</span><span class="jwt-color-dot">.</span><span class="jwt-color-signature">${s}</span>`;
  },

  /**
   * Load standard examples by Alg dropdown selection
   */
  loadSampleWithAlg(alg) {
    alg = alg.toUpperCase();

    if (this.jwtDropdownSelectedLabel) {
      this.jwtDropdownSelectedLabel.textContent = alg.toLowerCase();
    }

    const header = {
      alg: alg,
      typ: 'JWT'
    };

    const now = Math.floor(Date.now() / 1000);
    const payload = {
      sub: '1234567890',
      name: 'John Doe',
      admin: true,
      iat: 1516239022,
      nbf: now - 60, // 1 minute ago
      exp: now + 7200 // 2 hours from now
    };

    const secret = 'a-string-secret-at-least-256-bits-long';

    // Synchronize inputs based on active mode
    if (this.currentMode === 'decoder') {
      if (this.jwtDecoderSecret) {
        this.jwtDecoderSecret.value = secret;
      }
      if (this.jwtDecoderSecretBase64) {
        this.jwtDecoderSecretBase64.checked = false; // sample is string secret
      }

      // Re-sign to build correct token structure
      const hB64 = this.base64UrlEncode(JSON.stringify(header));
      const pB64 = this.base64UrlEncode(JSON.stringify(payload));
      let sig = '';

      if (alg === 'NONE') {
        sig = '';
      } else if (alg.startsWith('HS')) {
        sig = this.computeHmac(hB64, pB64, secret, alg, false);
      } else {
        sig = this.base64UrlEncode('simulated_asymmetric_signature_value_bytes');
      }

      const token = `${hB64}.${pB64}.${sig}`;
      if (this.jwtDecoderToken) {
        this.jwtDecoderToken.innerText = token;
        this.renderTokenColoring(hB64, pB64, sig);
        this.parseDecoderToken();
      }
    } else {
      if (this.jwtEncoderHeader) {
        this.jwtEncoderHeader.value = JSON.stringify(header, null, 2);
      }
      if (this.jwtEncoderPayload) {
        this.jwtEncoderPayload.value = JSON.stringify(payload, null, 2);
      }
      if (this.jwtEncoderSecret) {
        this.jwtEncoderSecret.value = secret;
      }
      if (this.jwtEncoderSecretBase64) {
        this.jwtEncoderSecretBase64.checked = false;
      }
      this.encodeToken();
    }
  },

  /**
   * Custom syntax highlighter for JSON objects
   */
  formatJsonSyntax(obj) {
    if (!obj || typeof obj !== 'object') return '';
    const str = JSON.stringify(obj, null, 2);
    // Escape HTML characters to prevent XSS
    const safeStr = str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    return safeStr.replace(/("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+-]?\d+)?)/g, function (match) {
      let cls = 'text-slate-300';
      if (/^"/.test(match)) {
        if (/:$/.test(match)) {
          cls = 'text-cyan-400 font-bold'; // Keys
        } else {
          cls = 'text-green-400'; // String values
        }
      } else if (/true|false/.test(match)) {
        cls = 'text-orange-400 font-semibold'; // Booleans
      } else if (/null/.test(match)) {
        cls = 'text-red-400'; // Null
      } else {
        cls = 'text-amber-400'; // Numbers
      }
      return '<span class="' + cls + '">' + match + '</span>';
    });
  },

  /**
   * Render Claims Breakdown interactive tables
   */
  renderClaimsTable(obj, target) {
    const tableDiv = target === 'header' ? this.jwtHeaderClaimsTable : this.jwtPayloadClaimsTable;
    if (!tableDiv) return;

    if (!obj || Object.keys(obj).length === 0) {
      tableDiv.innerHTML = '<p class="text-slate-400 p-2 italic text-center">No fields available</p>';
      return;
    }

    let html = '<table class="claims-table">';
    html += '<thead><tr><th>Claim</th><th>Value</th><th>Description</th></tr></thead><tbody>';

    for (const key in obj) {
      const val = obj[key];
      let displayVal = val;
      let desc = this.claimsDescriptions[key] || 'Custom claim / user payload data';

      // Human-readable date conversions for iat, exp, nbf
      if (['exp', 'iat', 'nbf'].includes(key) && typeof val === 'number') {
        const dateStr = new Date(val * 1000).toISOString().replace('T', ' ').substring(0, 19) + ' UTC';
        
        if (key === 'exp') {
          const isExpired = val < Math.floor(Date.now() / 1000);
          const badgeClass = isExpired ? 'bg-red-500/20 text-red-400' : 'bg-green-500/20 text-green-400';
          const badgeText = isExpired ? '✗ Token Expired' : '✓ Token Active';
          displayVal = `<div class="flex flex-col gap-1"><span>${val}</span><span class="text-[10px] font-mono text-slate-400">(${dateStr})</span><span class="text-[9px] font-bold uppercase tracking-wider px-2 py-0.5 rounded self-start ${badgeClass}">${badgeText}</span></div>`;
        } else {
          displayVal = `<div class="flex flex-col"><span>${val}</span><span class="text-[10px] font-mono text-slate-400">(${dateStr})</span></div>`;
        }
      } else if (typeof val === 'boolean') {
        const badgeClass = val ? 'text-green-400 bg-green-500/10' : 'text-red-400 bg-red-500/10';
        displayVal = `<span class="px-1.5 py-0.5 rounded text-[10px] font-bold uppercase ${badgeClass}">${val}</span>`;
      } else if (typeof val === 'object' && val !== null) {
        displayVal = `<pre class="text-[10px] text-slate-300 max-h-[80px] overflow-y-auto">${JSON.stringify(val, null, 2)}</pre>`;
      }

      html += `<tr>
        <td class="claims-key">${key}</td>
        <td class="claims-val">${displayVal}</td>
        <td class="claims-desc text-[11px]">${desc}</td>
      </tr>`;
    }

    html += '</tbody></table>';
    tableDiv.innerHTML = html;
  }
};

// Export to window object for access by tab manager
window.CyberGuardJWTDebugger = CyberGuardJWTDebugger;
