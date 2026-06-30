import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { JSDOM } from 'jsdom';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const apiClientCode = fs.readFileSync(path.resolve(__dirname, '../../public/js/api-client.js'), 'utf8');
const securityDashboardCode = fs.readFileSync(path.resolve(__dirname, '../../public/js/security-dashboard.js'), 'utf8');

describe('Frontend Scans Dashboard Integration', () => {
  let dom;
  let window;
  let document;

  beforeEach(() => {
    // Setup clean DOM environment
    dom = new JSDOM(`
      <!DOCTYPE html>
      <html>
        <body>
          <div id="security-dashboard">
            <div id="critical-findings-value">0</div>
            <div id="total-findings-value">0</div>
            <div id="resolved-value">0</div>
            <div id="targets-scans-value">0</div>
            <div id="targets-scans-subtext">0 active process</div>
            <div id="risk-score-display-container"></div>
            <div id="risk-targets-list-container"></div>
            <div id="active-scans-container"></div>
            <div id="recent-findings-container"></div>
            <div id="dashboard-subtitle-text"></div>
            <div id="dashboard-date-range-display"></div>
            <div id="donut-total-findings-count">0</div>
            <div id="severity-donut-chart"></div>
            <div id="severity-bar-list"></div>
          </div>
        </body>
      </html>
    `, {
      url: 'http://localhost',
      runScripts: 'dangerously'
    });
    window = dom.window;
    document = window.document;

    // Set globally on node environment for scripts to access
    global.window = window;
    global.document = document;
    global.localStorage = window.localStorage;
    global.sessionStorage = window.sessionStorage;

    // Mock projectManager
    window.projectManager = {
      fetchProjects: vi.fn().mockResolvedValue({ status: 'success', projects: [{ id: 'p1', name: 'Project 1' }] }),
      projects: [{ id: 'p1', name: 'Project 1' }]
    };

    // Evaluate apiClient.js in sandbox
    const apiScript = document.createElement('script');
    apiScript.textContent = apiClientCode;
    document.body.appendChild(apiScript);
  });

  afterEach(() => {
    delete global.window;
    delete global.document;
    delete global.localStorage;
    delete global.sessionStorage;
  });

  describe('api-client.js enhancements', () => {
    it('should expose updateFrontendScanProgress and update local storage progress', () => {
      expect(window.scannerAPI).toBeDefined();
      expect(window.scannerAPI.updateFrontendScanProgress).toBeTypeOf('function');

      const mockScanId = 'frontend_12345';
      const mockScan = {
        id: mockScanId,
        status: 'running',
        progress: 0,
        target_id: 't1',
        project_id: 'p1'
      };

      // Set initial scans list
      window.localStorage.setItem('cg_frontend_scans', JSON.stringify([mockScan]));

      // Update progress
      window.scannerAPI.updateFrontendScanProgress(mockScanId, 45);

      // Verify localStorage was updated
      const scans = JSON.parse(window.localStorage.getItem('cg_frontend_scans'));
      expect(scans[0].progress).toBe(45);
    });
  });

  describe('security-dashboard.js merge and render logic', () => {
    beforeEach(() => {
      // Mock apiClient.get
      window.apiClient = {
        get: vi.fn().mockImplementation((url) => {
          if (url === '/dashboard/metrics') {
            return Promise.resolve({
              status: 'success',
              data: {
                findings_summary: { total: 10, critical: 1, resolved: 5 },
                infrastructure: { total_targets: 3, total_scans: 5 },
                active_scans: { count: 0, scans: [] },
                recent_findings: { findings: [] },
                findings_by_severity: {},
                risk_score: { global_score: 25, risk_level: 'Low' }
              }
            });
          }
          if (url === '/targets') {
            return Promise.resolve({ status: 'success', targets: [] });
          }
          return Promise.reject(new Error('not found'));
        }),
        getToken: () => 'mock-jwt-token'
      };

      // Load security-dashboard.js
      const sdScript = document.createElement('script');
      sdScript.textContent = securityDashboardCode;
      document.body.appendChild(sdScript);
    });

    it('should merge active frontend scans from localStorage into dashboard active scans', async () => {
      const activeScan = {
        id: 'frontend_abc',
        status: 'running',
        progress: 60,
        driver_id: ['WHOIS Lookup'],
        target: { value: 'google.com' },
        project_id: 'p1',
        created_at: new Date().toISOString()
      };

      window.localStorage.setItem('cg_frontend_scans', JSON.stringify([activeScan]));

      // Load dashboard views
      await window.loadSecurityDashboard();

      // Verify local scan was merged and rendered
      const activeScansContainer = document.getElementById('active-scans-container');
      const scanRows = activeScansContainer.querySelectorAll('.active-scan-row');
      expect(scanRows.length).toBe(1);

      const row = scanRows[0];
      expect(row.getAttribute('data-scan-id')).toBe('frontend_abc');
      expect(row.querySelector('.scan-target-name').textContent).toBe('google.com');
      expect(row.querySelector('.scan-type').textContent).toBe('WHOIS Lookup');
      expect(row.querySelector('.scan-progress-text').textContent).toBe('60%');

      window.dashboardNavigateToScan = vi.fn();

      row.click();
      expect(window.dashboardNavigateToScan).toHaveBeenCalledWith('frontend_abc');
    });
  });
});
