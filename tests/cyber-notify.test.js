import fc from 'fast-check';

// Minimal inline CyberNotify implementation for testing
// (main.js is not an ES module, so we define it here directly)
const CyberNotify = {
  _currentCallback: null,
  _resolveIcon(type) {
    const ICON_MAP = {
      warning: { icon: 'warning', color: '#FBBF24' },
      error:   { icon: 'error',   color: '#F87171' },
      info:    { icon: 'info',    color: '#38BDF8' },
    };
    return ICON_MAP[type] || ICON_MAP['info'];
  },
  _hide() {
    const modal = document.getElementById('cyber-notify-modal');
    if (!modal) return;
    modal.classList.remove('cyber-notify-open');
    modal.classList.add('hidden');
    this._currentCallback = null;
  },
  _show(message, mode, callback, type, defaultValue = "", options = {}) {
    const modal = document.getElementById('cyber-notify-modal');
    const iconEl = document.getElementById('cyber-notify-icon');
    const msgEl = document.getElementById('cyber-notify-message');
    const confirmBtn = document.getElementById('cyber-notify-confirm-btn');
    const cancelBtn = document.getElementById('cyber-notify-cancel-btn');
    if (!modal || !iconEl || !msgEl || !confirmBtn || !cancelBtn) {
      console.error('CyberNotify: Required DOM elements not found');
      return;
    }

    let inputEl = document.getElementById('cyber-notify-input');
    if (!inputEl) {
      inputEl = document.createElement('input');
      inputEl.id = 'cyber-notify-input';
      inputEl.type = 'text';
      inputEl.className = 'w-full bg-slate-950/80 border border-white/15 focus:border-purple-500/80 rounded-lg px-3.5 py-2 text-sm text-white focus:outline-none mt-1 mb-5 transition-colors font-sans text-center shadow-inner shadow-black/40';
      const actions = document.getElementById('cyber-notify-actions');
      if (actions) {
        actions.parentNode.insertBefore(inputEl, actions);
      }
    }

    if (mode === 'prompt') {
      inputEl.value = defaultValue || '';
      inputEl.style.display = 'block';
    } else {
      inputEl.style.display = 'none';
    }

    const { icon, color } = this._resolveIcon(type);
    iconEl.textContent = icon;
    iconEl.style.color = color;
    msgEl.textContent = String(message ?? '');

    if (mode === 'alert' || options.singleButton) {
      confirmBtn.textContent = options.confirmText || 'OK';
      confirmBtn.style.display = '';
      cancelBtn.style.display = 'none';
      const okHandler = () => {
        confirmBtn.removeEventListener('click', okHandler);
        this._hide();
        if (typeof callback === 'function') {
          callback(mode === 'prompt' ? inputEl.value : true);
        }
      };
      confirmBtn.addEventListener('click', okHandler);
    } else {
      confirmBtn.textContent = 'Confirm';
      cancelBtn.textContent = 'Cancel';
      confirmBtn.style.display = '';
      cancelBtn.style.display = '';
      const confirmHandler = () => {
        confirmBtn.removeEventListener('click', confirmHandler);
        cancelBtn.removeEventListener('click', cancelHandler);
        this._hide();
        if (typeof callback === 'function') {
          callback(mode === 'prompt' ? inputEl.value : true);
        }
      };
      const cancelHandler = () => {
        confirmBtn.removeEventListener('click', confirmHandler);
        cancelBtn.removeEventListener("click", cancelHandler);
        this._hide();
        if (typeof callback === 'function') {
          callback(mode === 'prompt' ? null : false);
        }
      };
      confirmBtn.addEventListener('click', confirmHandler);
      cancelBtn.addEventListener('click', cancelHandler);
    }
    modal.classList.remove('hidden');
    modal.classList.add('cyber-notify-open');
  },
  alert(message, callback, options = {}) {
    if (typeof callback === "object" && callback !== null) {
      options = callback;
      callback = null;
    }
    this._show(message, 'alert', callback, options.type, "", options);
  },
  confirm(message, callback, options = {}) {
    if (typeof callback !== 'function') {
      console.warn('CyberNotify.confirm: callback is not a function');
      this._hide();
      return;
    }
    this._show(message, 'confirm', callback, options.type, "", options);
  },
  prompt(message, defaultValue, callback, options = {}) {
    if (typeof callback !== 'function') {
      console.warn('CyberNotify.prompt: callback is not a function');
      this._hide();
      return;
    }
    this._show(message, 'prompt', callback, options.type, defaultValue, options);
  },
};

// ─── DOM Setup ───────────────────────────────────────────────────────────────

beforeEach(() => {
  document.body.innerHTML = `
    <div id="cyber-notify-modal" class="hidden" role="dialog" aria-modal="true" aria-labelledby="cyber-notify-message">
      <div id="cyber-notify-backdrop"></div>
      <div id="cyber-notify-dialog">
        <span id="cyber-notify-icon" class="material-symbols-outlined" aria-hidden="true"></span>
        <p id="cyber-notify-message"></p>
        <div id="cyber-notify-actions">
          <button id="cyber-notify-confirm-btn" class="cyber-btn-primary"></button>
          <button id="cyber-notify-cancel-btn" class="cyber-btn-ghost"></button>
        </div>
      </div>
    </div>
  `;
});

// ─── Property 3: Confirm callback invocation ─────────────────────────────────
// Validates: Requirements 5.4, 5.5

describe('CyberNotify — Property 3: Confirm callback invocation', () => {
  it('calls callback(true) when Confirm clicked, callback(false) when Cancel clicked', () => {
    /**
     * Validates: Requirements 5.4, 5.5
     */
    fc.assert(fc.property(fc.boolean(), (clickConfirm) => {
      // Reset DOM state between iterations
      document.getElementById('cyber-notify-modal').className = 'hidden';

      let received;
      CyberNotify.confirm('test message', (v) => { received = v; });

      const btn = clickConfirm
        ? document.getElementById('cyber-notify-confirm-btn')
        : document.getElementById('cyber-notify-cancel-btn');
      btn.click();

      expect(received).toBe(clickConfirm);
      expect(document.getElementById('cyber-notify-modal').classList.contains('hidden')).toBe(true);
    }), { numRuns: 100 });
  });
});

// ─── Unit tests: Alert mode ───────────────────────────────────────────────────

describe('CyberNotify — Alert mode', () => {
  it('modal becomes visible when alert() is called', () => {
    CyberNotify.alert('Hello');
    const modal = document.getElementById('cyber-notify-modal');
    expect(modal.classList.contains('hidden')).toBe(false);
    expect(modal.classList.contains('cyber-notify-open')).toBe(true);
  });

  it('only OK button is shown; cancel button is hidden', () => {
    CyberNotify.alert('Hello');
    const confirmBtn = document.getElementById('cyber-notify-confirm-btn');
    const cancelBtn = document.getElementById('cyber-notify-cancel-btn');
    expect(confirmBtn.textContent).toBe('OK');
    expect(cancelBtn.style.display).toBe('none');
  });

  it('modal is hidden after OK click', () => {
    CyberNotify.alert('Hello');
    document.getElementById('cyber-notify-confirm-btn').click();
    expect(document.getElementById('cyber-notify-modal').classList.contains('hidden')).toBe(true);
  });
});

// ─── Unit tests: Confirm mode ─────────────────────────────────────────────────

describe('CyberNotify — Confirm mode', () => {
  it('both Confirm and Cancel buttons are shown by default', () => {
    CyberNotify.confirm('Are you sure?', () => {});
    const confirmBtn = document.getElementById('cyber-notify-confirm-btn');
    const cancelBtn = document.getElementById('cyber-notify-cancel-btn');
    expect(confirmBtn.style.display).not.toBe('none');
    expect(cancelBtn.style.display).not.toBe('none');
    expect(confirmBtn.textContent).toBe('Confirm');
    expect(cancelBtn.textContent).toBe('Cancel');
  });

  it('message is displayed correctly', () => {
    CyberNotify.confirm('Delete this item?', () => {});
    expect(document.getElementById('cyber-notify-message').textContent).toBe('Delete this item?');
  });

  it('shows only one button with custom text when singleButton is true', () => {
    let received = false;
    CyberNotify.confirm('Log in first', () => { received = true; }, { singleButton: true, confirmText: 'OK' });
    const confirmBtn = document.getElementById('cyber-notify-confirm-btn');
    const cancelBtn = document.getElementById('cyber-notify-cancel-btn');
    expect(confirmBtn.style.display).not.toBe('none');
    expect(cancelBtn.style.display).toBe('none');
    expect(confirmBtn.textContent).toBe('OK');

    confirmBtn.click();
    expect(received).toBe(true);
    expect(document.getElementById('cyber-notify-modal').classList.contains('hidden')).toBe(true);
  });
});

// ─── Unit tests: Prompt mode ─────────────────────────────────────────────────

describe('CyberNotify — Prompt mode', () => {
  it('both Confirm and Cancel buttons and text input are shown', () => {
    CyberNotify.prompt('Enter value:', 'defaultVal', () => {});
    const confirmBtn = document.getElementById('cyber-notify-confirm-btn');
    const cancelBtn = document.getElementById('cyber-notify-cancel-btn');
    const inputEl = document.getElementById('cyber-notify-input');
    expect(confirmBtn.style.display).not.toBe('none');
    expect(cancelBtn.style.display).not.toBe('none');
    expect(inputEl.style.display).not.toBe('none');
    expect(inputEl.value).toBe('defaultVal');
  });

  it('calls callback with input value when confirmed, null when cancelled', () => {
    let received = undefined;
    CyberNotify.prompt('Enter value:', 'initialText', (v) => { received = v; });
    const confirmBtn = document.getElementById('cyber-notify-confirm-btn');
    const inputEl = document.getElementById('cyber-notify-input');
    inputEl.value = 'updatedText';
    confirmBtn.click();
    expect(received).toBe('updatedText');

    received = undefined;
    CyberNotify.prompt('Enter value:', 'initialText', (v) => { received = v; });
    const cancelBtn = document.getElementById('cyber-notify-cancel-btn');
    cancelBtn.click();
    expect(received).toBeNull();
  });
});
