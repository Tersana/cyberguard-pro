import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { JSDOM, VirtualConsole } from 'jsdom';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const apiClientCode = fs.readFileSync(path.resolve(__dirname, '../../public/js/api-client.js'), 'utf8');
const scanProgressCode = fs.readFileSync(path.resolve(__dirname, '../../public/js/scan-progress.js'), 'utf8');
const scanProgressHtml = fs.readFileSync(path.resolve(__dirname, '../../public/scan-progress.html'), 'utf8');

describe('Scan Progress Findings Clickable Modal Integration', () => {
  let dom;
  let window;
  let document;

  beforeEach(() => {
    const virtualConsole = new VirtualConsole();
    virtualConsole.on("jsdomError", (err) => {
      console.error("JSDOM error:", err.stack || err);
    });

    // Setup clean DOM from the actual HTML file
    dom = new JSDOM(scanProgressHtml, {
      url: 'http://localhost/scan/scan_12345',
      runScripts: 'dangerously',
      virtualConsole,
      beforeParse(window) {
        window.tailwind = { config: {} };
      }
    });
    window = dom.window;
    document = window.document;

    // Set globally on node environment for scripts to access
    global.window = window;
    global.document = document;
    global.localStorage = window.localStorage;
    global.sessionStorage = window.sessionStorage;
    global.navigator = window.navigator;

    window.addEventListener('error', (event) => {
      console.error('JS Error in JSDOM:', event.error);
    });

    // Set fake token
    window.localStorage.setItem('cyberguard_jwt', 'fake-jwt-token');

    // Evaluate apiClient.js in JSDOM
    const apiScript = document.createElement('script');
    apiScript.textContent = apiClientCode;
    document.body.appendChild(apiScript);

    // Mock scannerAPI functions referenced during initial load
    window.scannerAPI = {
      getScanStatus: vi.fn().mockResolvedValue({
        id: 'scan_12345',
        status: 'completed',
        target_id: 't1',
        project_id: 'p1',
        started_at: new Date().toISOString(),
        finished_at: new Date().toISOString(),
        driver_id: 'WHOIS_LOOKUP',
        logs: []
      }),
      getScanFindings: vi.fn().mockResolvedValue([
        {
          id: 'finding_whois_123',
          title: 'WHOIS Lookup: Analysis Complete',
          severity: 'info',
          status: 'open',
          driver_id: 'WHOIS_LOOKUP',
          description: 'Domain WHOIS DATA - example.com\nRegistration\nDomain: example.com\nCreated: 8/14/1995',
          created_at: new Date().toISOString()
        }
      ]),
      rememberScanSession: vi.fn(scan => scan),
      rememberScanFindings: vi.fn((_scanId, findings) => findings),
      formatScanShortId: vi.fn(scan => String(scan.id || '').slice(0, 8)),
      addFrontendFinding: vi.fn(),
      updateFrontendScanProgress: vi.fn()
    };
  });

  afterEach(() => {
    delete global.window;
    delete global.document;
    delete global.localStorage;
    delete global.sessionStorage;
    delete global.navigator;
  });

  it('should render findings and open the modal with detailed information on row click', async () => {
    // Evaluate scan-progress.js to run DOMContentLoaded initPage
    const spScript = document.createElement('script');
    spScript.textContent = scanProgressCode;
    document.body.appendChild(spScript);

    // Manually trigger DOMContentLoaded since it already fired in JSDOM
    document.dispatchEvent(new window.Event('DOMContentLoaded'));

    // Wait for async initialization of page (initPage fetches status and findings)
    await new Promise(resolve => setTimeout(resolve, 50));

    const findingsContainer = document.getElementById('sp-findings-body');
    const rows = findingsContainer.querySelectorAll('.sp-table-row');
    expect(rows.length).toBe(1);

    const row = rows[0];
    expect(row.classList.contains('cursor-pointer')).toBe(true);
    expect(row.querySelector('.sp-td--title').textContent).toBe('WHOIS Lookup: Analysis Complete');

    // Modal should be hidden initially
    const modal = document.getElementById('finding-detail-modal');
    expect(modal.classList.contains('hidden')).toBe(true);

    // Click finding row
    row.click();

    // Modal should be visible now
    expect(modal.classList.contains('hidden')).toBe(false);

    // Verify modal is populated with correct finding detail content
    expect(document.getElementById('finding-detail-modal-title').textContent).toBe('WHOIS Lookup: Analysis Complete');
    expect(document.getElementById('fd-driver').textContent).toBe('WHOIS_LOOKUP');
    expect(document.getElementById('fd-severity-badge').textContent).toBe('INFO');
    expect(document.getElementById('fd-status-badge').textContent).toBe('OPEN');
    expect(document.getElementById('fd-id').textContent).toBe('finding_whois_123');

    // The description should be formatted by formatWhoisHtml
    const descriptionContainer = document.getElementById('fd-description');
    expect(descriptionContainer.innerHTML).toContain('whois-container');
    expect(descriptionContainer.innerHTML).toContain('Registration');
    expect(descriptionContainer.innerHTML).toContain('example.com');

    // Click close button
    const closeBtn = document.querySelector('button[aria-label="Close details"]');
    closeBtn.click();

    // Modal hides after animation timeout
    await new Promise(resolve => setTimeout(resolve, 200));
    expect(modal.classList.contains('hidden')).toBe(true);
  });

  it('should update the back button URL to target project targets tab when project_id is present', async () => {
    // Evaluate scan-progress.js
    const spScript = document.createElement('script');
    spScript.textContent = scanProgressCode;
    document.body.appendChild(spScript);

    // Manually trigger DOMContentLoaded
    document.dispatchEvent(new window.Event('DOMContentLoaded'));

    // Wait for async initialization
    await new Promise(resolve => setTimeout(resolve, 50));

    const backBtn = document.getElementById('sp-back-btn');
    expect(backBtn).not.toBeNull();
    expect(backBtn.getAttribute('href')).toBe('/project-detail?id=p1&tab=targets');
  });
  it('should cache loaded findings and dispatch finding and completion events', async () => {
    const receivedEvents = [];
    document.addEventListener('cyberguard:scanFindingsUpdated', (event) => {
      receivedEvents.push({ name: 'findings', detail: event.detail });
    });
    document.addEventListener('cyberguard:scanCompleted', (event) => {
      receivedEvents.push({ name: 'completed', detail: event.detail });
    });

    const spScript = document.createElement('script');
    spScript.textContent = scanProgressCode;
    document.body.appendChild(spScript);

    document.dispatchEvent(new window.Event('DOMContentLoaded'));

    await new Promise(resolve => setTimeout(resolve, 50));

    expect(window.scannerAPI.rememberScanFindings).toHaveBeenCalledWith(
      'scan_12345',
      expect.arrayContaining([
        expect.objectContaining({ id: 'finding_whois_123' })
      ]),
      expect.objectContaining({
        id: 'scan_12345',
        project_id: 'p1',
        target_id: 't1'
      })
    );

    expect(receivedEvents.map(event => event.name)).toEqual(expect.arrayContaining(['findings', 'completed']));
    expect(receivedEvents.find(event => event.name === 'findings').detail).toMatchObject({
      scanId: 'scan_12345',
      projectId: 'p1',
      targetId: 't1'
    });
    expect(receivedEvents.find(event => event.name === 'completed').detail.status).toBe('completed');
  });
});
