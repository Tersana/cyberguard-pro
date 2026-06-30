/**
 * Unit Tests for Scanner Filtering by Target Type (domain, ip, network/CIDR)
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { JSDOM } from 'jsdom';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

describe('ScanManager Scanner Filtering', () => {
  let dom;
  let window;
  let document;

  beforeEach(() => {
    // Setup isolated JSDOM environment
    dom = new JSDOM(`
      <!DOCTYPE html>
      <html>
        <body>
          <div id="scan-scanner-modal" class="hidden">
            <div id="scan-modal-target-label"></div>
            <div id="scan-modal-target-detail"></div>
            <div id="scan-modal-scanner-body"></div>
            <div id="selected-scanners-count-bar"></div>
            <button id="scan-start-btn">Start Scan</button>
          </div>
        </body>
      </html>
    `, {
      url: "http://localhost",
      runScripts: "dangerously",
      resources: "usable"
    });
    window = dom.window;
    document = window.document;

    // Set globals for test execution context
    global.window = window;
    global.document = document;
    
    // Explicit localStorage mock
    const store = {};
    const mockLocalStorage = {
      getItem: vi.fn((key) => store[key] || null),
      setItem: vi.fn((key, value) => { store[key] = String(value); }),
      removeItem: vi.fn((key) => { delete store[key]; }),
      clear: vi.fn(() => { for (const key in store) delete store[key]; })
    };
    Object.defineProperty(window, 'localStorage', {
      value: mockLocalStorage,
      configurable: true,
      enumerable: true,
      writable: true
    });
    global.localStorage = mockLocalStorage;
    global.sessionStorage = window.sessionStorage;
    global.CustomEvent = window.CustomEvent;

    // Mock notify function that scan-manager might call
    window.notify = vi.fn();
    global.notify = window.notify;

    // Track console.error
    vi.spyOn(console, 'error').mockImplementation((...args) => {
      console.warn('Console Error Captured:', ...args);
    });

    // Mock fetch API
    global.fetch = vi.fn().mockImplementation((url, options) => {
      console.log('Fetch called with URL:', url);
      return Promise.resolve({
        ok: true,
        status: 200,
        json: () => {
          console.log('Mock fetch resolving scanners list');
          return Promise.resolve({
            status: 'success',
            scanners: [
              { id: 'subdomain-enum', name: 'Custom Subdomain Enum & Analysis', category: 'recon' },
              { id: 'os-fingerprint', name: 'Host Operating System Fingerprinting', category: 'recon' },
              { id: 'endpoint-fuzzer', name: 'Web Endpoint Fuzzer & Classifier', category: 'web' },
              { id: 'sqli-scanner', name: 'SQL Injection Scanner', category: 'web' }
            ]
          });
        }
      });
    });
    window.fetch = global.fetch;

    // Read and evaluate source code
    const scanManagerCode = fs.readFileSync(path.resolve(__dirname, '../../public/js/scan-manager.js'), 'utf8');
    
    // Define helper globals that scan-manager needs
    window.escAttr = (val) => String(val || "").replace(/"/g, "&quot;");
    window.escHtml = (val) => String(val || "").replace(/</g, "&lt;").replace(/>/g, "&gt;");
    
    // Eval scan-manager in window context
    window.eval(scanManagerCode);
  });

  afterEach(() => {
    delete global.window;
    delete global.document;
    delete global.localStorage;
    delete global.sessionStorage;
    delete global.CustomEvent;
    delete global.fetch;
    delete global.notify;
    vi.clearAllMocks();
  });

  it('should initialize ScanManager on window', () => {
    expect(window.ScanManager).toBeDefined();
    expect(typeof window.ScanManager.openScanModal).toBe('function');
  });

  it('should filter scanners when target type is Domain', async () => {
    const mockBtn = document.createElement('button');
    mockBtn.dataset.tid = '1';
    mockBtn.dataset.lbl = 'My Domain Target';
    mockBtn.dataset.val = 'example.com';
    mockBtn.dataset.typ = 'domain';

    await window.ScanManager.openScanModal(mockBtn);

    const bodyEl = document.getElementById('scan-modal-scanner-body');
    const html = bodyEl.innerHTML;

    // Domain should support Subdomain Enum, OS Fingerprint, Fuzzer, SQLi Scanner
    expect(html).toContain('subdomain-enum');
    expect(html).toContain('os-fingerprint');
    expect(html).toContain('endpoint-fuzzer');
    expect(html).toContain('sqli-scanner');

    // Domain should support frontend tools except IP Geolocation
    expect(html).toContain('net-port-scanner');
    expect(html).toContain('net-tcp-connectivity');
    expect(html).toContain('net-udp-services');
    expect(html).not.toContain('net-ip-geolocation');
    expect(html).toContain('net-reverse-dns');
    expect(html).toContain('net-whois-lookup');
  });

  it('should filter scanners when target type is IP', async () => {
    const mockBtn = document.createElement('button');
    mockBtn.dataset.tid = '2';
    mockBtn.dataset.lbl = 'My IP Target';
    mockBtn.dataset.val = '8.8.8.8';
    mockBtn.dataset.typ = 'ip';

    await window.ScanManager.openScanModal(mockBtn);

    const bodyEl = document.getElementById('scan-modal-scanner-body');
    const html = bodyEl.innerHTML;

    // IP should support OS Fingerprint, Fuzzer, SQLi Scanner, but NOT Subdomain Enum
    expect(html).not.toContain('subdomain-enum');
    expect(html).toContain('os-fingerprint');
    expect(html).toContain('endpoint-fuzzer');
    expect(html).toContain('sqli-scanner');

    // IP should support all frontend tools including IP Geolocation
    expect(html).toContain('net-port-scanner');
    expect(html).toContain('net-tcp-connectivity');
    expect(html).toContain('net-udp-services');
    expect(html).toContain('net-ip-geolocation');
    expect(html).toContain('net-reverse-dns');
    expect(html).toContain('net-whois-lookup');
  });

  it('should filter scanners when target type is Network (CIDR)', async () => {
    const mockBtn = document.createElement('button');
    mockBtn.dataset.tid = '3';
    mockBtn.dataset.lbl = 'My CIDR Target';
    mockBtn.dataset.val = '192.168.1.0/24';
    mockBtn.dataset.typ = 'network';

    await window.ScanManager.openScanModal(mockBtn);

    const bodyEl = document.getElementById('scan-modal-scanner-body');
    const html = bodyEl.innerHTML;

    // CIDR should ONLY support OS Fingerprint
    expect(html).not.toContain('subdomain-enum');
    expect(html).toContain('os-fingerprint');
    expect(html).not.toContain('endpoint-fuzzer');
    expect(html).not.toContain('sqli-scanner');

    // CIDR should NOT support any frontend tools since they do not specify 'network'
    expect(html).not.toContain('net-port-scanner');
    expect(html).not.toContain('net-tcp-connectivity');
    expect(html).not.toContain('net-udp-services');
    expect(html).not.toContain('net-ip-geolocation');
    expect(html).not.toContain('net-reverse-dns');
    expect(html).not.toContain('net-whois-lookup');
  });

  it('should start a frontend-only scan without ReferenceError and save project_id', async () => {
    // Set target on scanState
    const mockBtn = document.createElement('button');
    mockBtn.dataset.tid = 't1';
    mockBtn.dataset.lbl = 'Test Label';
    mockBtn.dataset.val = 'example.com';
    mockBtn.dataset.typ = 'domain';
    await window.ScanManager.openScanModal(mockBtn);

    // Select a frontend tool
    const checkbox = document.createElement('input');
    checkbox.type = 'checkbox';
    checkbox.value = 'net-port-scanner';
    checkbox.checked = true;
    
    // Simulate checking a frontend scanner
    window.ScanManager._onFrontendCheckbox(checkbox);

    // Mock _projectId global
    window._projectId = 'p_test_123';

    // Mock notify
    window.notify = vi.fn();

    // Trigger startScan
    await window.ScanManager.startScan();

    // Verify localStorage has registered the scan with correct project_id
    const storedScansRaw = window.localStorage.getItem('cg_frontend_scans');
    expect(storedScansRaw).not.toBeNull();
    const storedScans = JSON.parse(storedScansRaw);
    expect(storedScans.length).toBeGreaterThan(0);
    expect(storedScans[0].project_id).toBe('p_test_123');

    // Verify sessionStorage has pending scan info with projectId
    const pendingRaw = window.sessionStorage.getItem('cg_pending_scan');
    expect(pendingRaw).not.toBeNull();
    const pending = JSON.parse(pendingRaw);
    expect(pending.projectId).toBe('p_test_123');
  });
});
