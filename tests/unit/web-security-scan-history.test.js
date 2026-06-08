import { describe, it, expect, beforeEach, vi } from 'vitest';
import { JSDOM } from 'jsdom';

describe('Web Security Scan History', () => {
  let dom;
  let document;
  let WebAuditing;
  let resultsData = [];
  let localStorageMock = {};

  beforeEach(() => {
    // Mock localStorage
    localStorageMock = {};
    global.localStorage = {
      getItem: vi.fn((key) => localStorageMock[key] || null),
      setItem: vi.fn((key, value) => { localStorageMock[key] = String(value); }),
      removeItem: vi.fn((key) => { delete localStorageMock[key]; }),
      clear: vi.fn(() => { localStorageMock = {}; })
    };

    // Create fresh DOM
    dom = new JSDOM(`
      <!DOCTYPE html>
      <html>
        <body>
          <input type="url" id="target-url" value="" />
          <span id="wa-tool-status-headers" class="wa-tool-status wa-status-idle">Ready</span>
          <span id="wa-tool-status-links" class="wa-tool-status wa-status-idle">Ready</span>
          <span id="wa-tool-status-email" class="wa-tool-status wa-status-idle">Ready</span>
          <span id="wa-tool-status-ssl" class="wa-tool-status wa-status-idle">Ready</span>
          <span id="wa-tool-status-phishing" class="wa-tool-status wa-status-idle">Ready</span>
          <span id="wa-tool-status-dns-spoof" class="wa-tool-status wa-status-idle">Ready</span>
          
          <button id="wa-clear-history-btn">Clear History</button>
          <div id="wa-history-list">
            <div id="wa-history-empty">No history available</div>
          </div>
          
          <div id="wa-results-body"></div>
        </body>
      </html>
    `);

    document = dom.window.document;
    global.document = document;
    global.window = dom.window;
    global.escapeHtml = (str) => str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
    global.resultsData = [];
    global.updateResultsStats = vi.fn();
    global._dispatchRiskGaugeUpdate = vi.fn();
    global.CyberNotify = {
      alert: vi.fn()
    };

    // Component implementation (derived from main.js)
    WebAuditing = {
      activeToolId: 'headers',
      headersResults: null,
      linksResults: null,
      emailResults: null,
      scanHistory: [],

      init() {
        try {
          const stored = localStorage.getItem('wa_scan_history');
          if (stored) {
            this.scanHistory = JSON.parse(stored);
          } else {
            this.scanHistory = [];
          }
        } catch(e) {
          this.scanHistory = [];
        }
        this.renderScanHistoryList();
      },

      setToolStatus(toolId, status, badge = '') {
        const el = document.getElementById(`wa-tool-status-${toolId}`);
        if (!el) return;
        el.className = `wa-tool-status wa-status-${status}`;
        el.textContent = badge || status;
      },

      renderCurrentToolView() {
        const bodyEl = document.getElementById('wa-results-body');
        if (bodyEl) bodyEl.innerHTML = 'Rendered View';
      },

      saveCurrentScanToHistory(target) {
        if (!target) return;
        
        const hasAnyResults = this.headersResults || 
                              this.linksResults || 
                              this.emailResults || 
                              (global.resultsData && global.resultsData.length > 0);
        if (!hasAnyResults) return;

        const toolStates = {};
        const tools = ['headers', 'links', 'email', 'ssl', 'phishing', 'dns-spoof'];
        tools.forEach(toolId => {
          const el = document.getElementById(`wa-tool-status-${toolId}`);
          let status = 'idle';
          if (el) {
            if (el.className.includes('wa-status-done') || el.textContent.includes('Complete')) status = 'done';
            else if (el.className.includes('wa-status-running')) status = 'running';
            else if (el.className.includes('wa-status-error')) status = 'error';
          }
          toolStates[toolId] = status;
        });

        const historyItem = {
          id: 'scan_' + Date.now(),
          target: target,
          timestamp: '12:00:00 PM',
          toolStates: toolStates,
          headersResults: this.headersResults ? JSON.parse(JSON.stringify(this.headersResults)) : null,
          linksResults: this.linksResults ? JSON.parse(JSON.stringify(this.linksResults)) : null,
          emailResults: this.emailResults ? JSON.parse(JSON.stringify(this.emailResults)) : null,
          resultsData: [...global.resultsData]
        };

        this.scanHistory = this.scanHistory || [];
        this.scanHistory.unshift(historyItem);
        
        if (this.scanHistory.length > 10) {
          this.scanHistory.pop();
        }

        try {
          localStorage.setItem('wa_scan_history', JSON.stringify(this.scanHistory));
        } catch(e) {
          console.error('Failed to save scan history to localStorage:', e);
        }

        this.renderScanHistoryList();
      },

      loadScanFromHistory(scanId) {
        const item = this.scanHistory.find(h => h.id === scanId);
        if (!item) return;

        const input = document.getElementById("target-url");
        if (input) input.value = item.target;

        this.headersResults = item.headersResults;
        this.linksResults = item.linksResults;
        this.emailResults = item.emailResults;

        global.resultsData = [...item.resultsData];

        Object.entries(item.toolStates).forEach(([toolId, status]) => {
          let badge = '';
          if (status === 'done') {
            badge = 'Complete';
          }
          this.setToolStatus(toolId, status, badge);
        });

        this.renderCurrentToolView();
        global.updateResultsStats();
        global._dispatchRiskGaugeUpdate();
      },

      clearScanHistory() {
        this.scanHistory = [];
        try {
          localStorage.removeItem('wa_scan_history');
        } catch(e) {
          console.error(e);
        }
        this.renderScanHistoryList();
      },

      renderScanHistoryList() {
        const listEl = document.getElementById("wa-history-list");
        if (!listEl) return;

        if (!this.scanHistory || this.scanHistory.length === 0) {
          listEl.innerHTML = `<div id="wa-history-empty">No history available</div>`;
          return;
        }

        listEl.innerHTML = this.scanHistory.map(item => {
          return `
            <div class="wa-history-item" data-scan-id="${item.id}">
              <span class="target-name">${global.escapeHtml(item.target)}</span>
            </div>
          `;
        }).join("");
      }
    };
  });

  it('should initialize empty scanHistory if localStorage is empty', () => {
    WebAuditing.init();
    expect(WebAuditing.scanHistory).toEqual([]);
    expect(document.getElementById('wa-history-empty')).not.toBeNull();
  });

  it('should save completed scans to history and persist in localStorage', () => {
    WebAuditing.headersResults = { results: [], score: 80, grade: 'B', target: 'test.com' };
    global.resultsData = [{ id: '1', status: 'safe', message: 'Test message' }];

    WebAuditing.saveCurrentScanToHistory('test.com');

    expect(WebAuditing.scanHistory.length).toBe(1);
    expect(WebAuditing.scanHistory[0].target).toBe('test.com');
    expect(localStorageMock['wa_scan_history']).toBeDefined();
    expect(document.getElementById('wa-history-empty')).toBeNull();
    expect(document.querySelector('.wa-history-item')).not.toBeNull();
  });

  it('should load selected scan results back from history', () => {
    // Populate history
    const item = {
      id: 'scan_123',
      target: 'loaded.com',
      timestamp: '12:00:00 PM',
      toolStates: { headers: 'done', links: 'idle' },
      headersResults: { results: [], score: 90, grade: 'A', target: 'loaded.com' },
      linksResults: null,
      emailResults: null,
      resultsData: [{ id: '2', status: 'safe', message: 'Loaded message' }]
    };
    WebAuditing.scanHistory = [item];

    WebAuditing.loadScanFromHistory('scan_123');

    expect(document.getElementById('target-url').value).toBe('loaded.com');
    expect(WebAuditing.headersResults.target).toBe('loaded.com');
    expect(global.resultsData.length).toBe(1);
    expect(global.resultsData[0].message).toBe('Loaded message');
    expect(global.updateResultsStats).toHaveBeenCalled();
    expect(global._dispatchRiskGaugeUpdate).toHaveBeenCalled();
  });

  it('should clear scan history and remove from localStorage', () => {
    WebAuditing.scanHistory = [{ id: 'scan_1', target: 'test.com', toolStates: {}, resultsData: [] }];
    localStorageMock['wa_scan_history'] = JSON.stringify(WebAuditing.scanHistory);

    WebAuditing.clearScanHistory();

    expect(WebAuditing.scanHistory).toEqual([]);
    expect(localStorageMock['wa_scan_history']).toBeUndefined();
    expect(document.getElementById('wa-history-empty')).not.toBeNull();
  });
});
