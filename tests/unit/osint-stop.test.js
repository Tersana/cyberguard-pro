import { describe, it, expect, beforeEach, vi } from 'vitest';
import { JSDOM } from 'jsdom';
import fs from 'fs';
import path from 'path';

describe('OSINT Stop Button & AbortController Integration', () => {
  let dom;
  let document;
  let window;

  beforeEach(() => {
    // Create a mock DOM environment matching public/dashboard.html
    dom = new JSDOM(`
      <!DOCTYPE html>
      <html>
        <body>
          <input type="text" id="osint-global-target" />
          <button id="osint-run-all-btn"></button>
          <button id="osint-stop-btn" class="hidden"></button>
          <button id="osint-clear-all-btn"></button>
          <button id="osint-generate-report-btn"></button>
          <button id="osint-clear-history-btn"></button>

          <div class="osint-console-tool-item" id="osint-tool-subdomain" data-tool="subdomain">
            <input type="checkbox" id="osint-toggle-subdomain" checked />
            <input type="text" id="osint-subdomain-input" value="example.com" />
            <button id="osint-subdomain-btn"></button>
            <span class="osint-tool-status-dot idle" id="osint-status-dot-subdomain"></span>
          </div>

          <div class="osint-console-tool-item" id="osint-tool-dns" data-tool="dns">
            <input type="checkbox" id="osint-toggle-dns" checked />
            <input type="text" id="osint-dns-input" value="example.com" />
            <button id="osint-dns-btn"></button>
            <span class="osint-tool-status-dot idle" id="osint-status-dot-dns"></span>
          </div>

          <div id="osint-subdomain-results"></div>
          <div id="osint-dns-results"></div>
          <div id="osint-terminal-log"></div>
        </body>
      </html>
    `, { url: 'http://localhost' });

    document = dom.window.document;
    window = dom.window;
    global.document = document;
    global.window = window;
    global.navigator = dom.window.navigator;
    global.DOMException = dom.window.DOMException;

    // Mock localStorage
    let storage = {};
    global.localStorage = {
      getItem: vi.fn(key => storage[key] || null),
      setItem: vi.fn((key, val) => { storage[key] = String(val); }),
      removeItem: vi.fn(key => { delete storage[key]; }),
      clear: vi.fn(() => { storage = {}; })
    };

    // Mock global CyberNotify
    global.CyberNotify = {
      alert: vi.fn(),
      confirm: vi.fn((msg, cb) => cb(true))
    };

    // Mock global escapeHtml
    global.escapeHtml = (str) => str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

    // Load the osint.js file and evaluate it inside the window context
    const osintPath = path.resolve(__dirname, '../../public/js/osint.js');
    const osintCode = fs.readFileSync(osintPath, 'utf-8');
    
    // Evaluate in JSDOM window context
    dom.window.eval(osintCode);
    
    // Bind global reference
    global.OSINT = window.OSINT;
  });

  it('should initialize successfully and bind the stop button', () => {
    // Manually run init since DOMContentLoaded won't fire in JSDOM eval
    window.OSINT.init();

    const stopBtn = document.getElementById('osint-stop-btn');
    expect(stopBtn).not.toBeNull();
  });

  it('should toggle scanning state correctly when running and stopping', async () => {
    window.OSINT.init();

    const runBtn = document.getElementById('osint-run-all-btn');
    const stopBtn = document.getElementById('osint-stop-btn');

    expect(runBtn.classList.contains('hidden')).toBe(false);
    expect(stopBtn.classList.contains('hidden')).toBe(true);

    // Mock fetch to simulate ongoing queries and support AbortController
    global.fetch = vi.fn().mockImplementation((url, options) => {
      return new Promise((resolve, reject) => {
        const signal = options?.signal;
        if (signal?.aborted) {
          return reject(new DOMException('The user aborted a request.', 'AbortError'));
        }
        if (signal) {
          signal.addEventListener('abort', () => {
            reject(new DOMException('The user aborted a request.', 'AbortError'));
          });
        }
      });
    });

    // Trigger scanning
    document.getElementById('osint-global-target').value = 'example.com';
    
    // Run tools
    const runPromise = window.OSINT.runAllTools();

    // Check button state toggled
    expect(runBtn.classList.contains('hidden')).toBe(true);
    expect(stopBtn.classList.contains('hidden')).toBe(false);
    expect(window.OSINT.activeAbortController).not.toBeNull();

    // Call stop
    window.OSINT.stopAllTools();

    // Wait for the promise to reject/settle
    try {
      await runPromise;
    } catch (e) {
      // should reject with AbortError
    }

    // Check buttons restored
    expect(runBtn.classList.contains('hidden')).toBe(false);
    expect(stopBtn.classList.contains('hidden')).toBe(true);
    expect(window.OSINT.activeAbortController).toBeNull();
  });

  it('should abort fetch requests when stop is clicked', async () => {
    window.OSINT.init();

    // Mock fetch and trace calls, handling already-aborted states
    const abortSignals = [];
    global.fetch = vi.fn().mockImplementation((url, options) => {
      const signal = options?.signal;
      if (signal) {
        abortSignals.push(signal);
      }
      return new Promise((resolve, reject) => {
        if (signal?.aborted) {
          return reject(new DOMException('The user aborted a request.', 'AbortError'));
        }
        if (signal) {
          signal.addEventListener('abort', () => {
            reject(new DOMException('The user aborted a request.', 'AbortError'));
          });
        }
      });
    });

    document.getElementById('osint-global-target').value = 'example.com';
    const runPromise = window.OSINT.runAllTools();

    // Verify abort signal was passed
    expect(abortSignals.length).toBeGreaterThan(0);
    expect(abortSignals[0].aborted).toBe(false);

    // Call stop
    window.OSINT.stopAllTools();

    // Wait for resolution
    try {
      await runPromise;
    } catch (e) {}

    // Verify signal is aborted
    expect(abortSignals[0].aborted).toBe(true);
    
    // Check results container HTML has stopped message
    const subResults = document.getElementById('osint-subdomain-results');
    expect(subResults.innerHTML).toContain('Scan was stopped by the user');
  });
});
