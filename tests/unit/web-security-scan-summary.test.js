import { describe, it, expect, beforeEach, vi } from 'vitest';
import { JSDOM } from 'jsdom';
import fs from 'fs';
import path from 'path';

describe('Web Security Scan Summary View', () => {
  let dom;
  let document;
  let WebAuditing;
  let localStorageMock = {};

  beforeEach(() => {
    localStorageMock = {};
    global.localStorage = {
      getItem: vi.fn((key) => localStorageMock[key] || null),
      setItem: vi.fn((key, value) => { localStorageMock[key] = String(value); }),
      removeItem: vi.fn((key) => { delete localStorageMock[key]; }),
      clear: vi.fn(() => { localStorageMock = {}; })
    };

    dom = new JSDOM(`
      <!DOCTYPE html>
      <html>
        <body>
          <input type="url" id="target-url" value="" />
          
          <!-- Tab headers on the left panel -->
          <div id="wa-tool-tab-headers" class="wa-tool-tab active"></div>
          <div id="wa-tool-tab-links" class="wa-tool-tab"></div>
          <div id="wa-tool-tab-email" class="wa-tool-tab"></div>
          <div id="wa-tool-tab-ssl" class="wa-tool-tab"></div>
          <div id="wa-tool-tab-phishing" class="wa-tool-tab"></div>
          <div id="wa-tool-tab-dns-spoof" class="wa-tool-tab"></div>

          <!-- Tool status indicators on the left panel -->
          <span id="wa-tool-status-headers" class="wa-tool-status idle">Ready</span>
          <span id="wa-tool-status-links" class="wa-tool-status idle">Ready</span>
          <span id="wa-tool-status-email" class="wa-tool-status idle">Ready</span>
          <span id="wa-tool-status-ssl" class="wa-tool-status idle">Ready</span>
          <span id="wa-tool-status-phishing" class="wa-tool-status idle">Ready</span>
          <span id="wa-tool-status-dns-spoof" class="wa-tool-status idle">Ready</span>

          <!-- Tool alert count badges -->
          <div id="wa-tool-count-headers" class="hidden"></div>
          <div id="wa-tool-count-links" class="hidden"></div>
          <div id="wa-tool-count-email" class="hidden"></div>
          <div id="wa-tool-count-ssl" class="hidden"></div>
          <div id="wa-tool-count-phishing" class="hidden"></div>
          <div id="wa-tool-count-dns-spoof" class="hidden"></div>

          <!-- Filter Controls -->
          <div id="wa-filter-controls-container" class="filter-controls">
            <span>Filter</span>
          </div>

          <!-- Active tool titles -->
          <div id="wa-active-tool-name"></div>
          <div id="wa-active-tool-desc"></div>

          <!-- Main Results Panel -->
          <div id="wa-results-body" class="wa-results-body"></div>

          <!-- Summary Bar elements -->
          <span id="total-issues-count">0</span>
          <span id="scan-time-display">--</span>
          <span id="scanned-target-display">--</span>
        </body>
      </html>
    `);

    document = dom.window.document;
    global.document = document;
    global.window = dom.window;
    global.escapeHtml = (str) => str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
    
    // Setup global state and mock functions
    global.resultsData = [];
    global.updateResultsStats = vi.fn();
    global._dispatchRiskGaugeUpdate = vi.fn();
    global.CyberNotify = {
      alert: vi.fn()
    };
    global.ExecutionController = {
      showToast: vi.fn()
    };
    global.updateSummaryBar = vi.fn((totalIssues, timeTaken, target) => {
      const totalEl = document.getElementById("total-issues-count");
      const targetEl = document.getElementById("scanned-target-display");
      if (totalEl) totalEl.textContent = totalIssues;
      if (targetEl) targetEl.textContent = target;
    });

    // Make window reference WebAuditing dynamically for click event compatibility
    global.window.WebAuditing = {
      switchTool: (toolId) => WebAuditing.switchTool(toolId)
    };

    // Load the actual WebAuditing object from main.js
    const mainJsPath = path.resolve(__dirname, '../../public/js/main.js');
    const mainJsContent = fs.readFileSync(mainJsPath, 'utf-8');
    
    const moduleStart = mainJsContent.indexOf('const WebAuditing = {');
    if (moduleStart === -1) {
      throw new Error('WebAuditing module not found in main.js');
    }
    
    let braceCount = 0;
    let inModule = false;
    let moduleEnd = moduleStart;
    
    for (let i = moduleStart; i < mainJsContent.length; i++) {
      const char = mainJsContent[i];
      if (char === '{') {
        braceCount++;
        inModule = true;
      } else if (char === '}') {
        braceCount--;
        if (inModule && braceCount === 0) {
          moduleEnd = i + 1;
          break;
        }
      }
    }
    
    const moduleCode = mainJsContent.substring(moduleStart, moduleEnd);
    
    const moduleFunction = new Function(
      'document', 'window', 'localStorage', 'updateResultsStats', 
      '_dispatchRiskGaugeUpdate', 'CyberNotify', 'ExecutionController', 
      'escapeHtml', 'updateSummaryBar', `
      let resultsData = [];
      ${moduleCode}
      return WebAuditing;
    `);
    
    WebAuditing = moduleFunction(
      document, dom.window, global.localStorage, global.updateResultsStats, 
      global._dispatchRiskGaugeUpdate, global.CyberNotify, global.ExecutionController, 
      global.escapeHtml, global.updateSummaryBar
    );
  });

  it('should switch to summary view and render all cards on loadScanFromHistory', () => {
    // Mock a history item
    const item = {
      id: 'scan_123',
      target: 'https://test.com',
      timestamp: '12:00:00 PM',
      toolStates: {
        headers: 'done',
        links: 'done',
        email: 'done',
        ssl: 'done',
        phishing: 'idle',
        'dns-spoof': 'idle'
      },
      headersResults: {
        results: [
          { label: 'Content-Security-Policy', result: { status: 'missing' } }
        ],
        score: 75,
        grade: 'C',
        target: 'https://test.com'
      },
      linksResults: {
        results: {
          broken: [{ url: 'https://test.com/broken', type: 'Link' }],
          mixed: [],
          ok: [],
          images: [],
          scripts: []
        },
        total: 1,
        target: 'https://test.com'
      },
      emailResults: {
        domain: 'test.com',
        checks: [
          { name: 'SPF Record Check', status: 'missing', value: 'None' }
        ]
      },
      resultsData: [
        {
          feature: 'SSL/TLS Check',
          status: 'safe',
          message: 'Certificate is valid',
          details: {
            evidence: JSON.stringify({
              "Certificate Status Checks": ["[PASSED] Expiry Date Check", "[PASSED] Signature Check"]
            })
          }
        }
      ]
    };

    WebAuditing.scanHistory = [item];

    WebAuditing.loadScanFromHistory('scan_123');

    // 1. Verify target-url input has the correct target
    expect(document.getElementById('target-url').value).toBe('https://test.com');

    // 2. Verify activeToolId is set to 'summary'
    expect(WebAuditing.activeToolId).toBe('summary');

    // 3. Verify left tabs do NOT have 'active' class
    const tabHeaders = document.getElementById('wa-tool-tab-headers');
    const tabLinks = document.getElementById('wa-tool-tab-links');
    expect(tabHeaders.classList.contains('active')).toBe(false);
    expect(tabLinks.classList.contains('active')).toBe(false);

    // 4. Verify filters container is empty and hidden
    const filterContainer = document.getElementById('wa-filter-controls-container');
    expect(filterContainer.style.display).toBe('none');
    expect(filterContainer.innerHTML).toBe('');

    // 5. Verify the Summary Bar elements are updated (total issues computed)
    // 1 header issue + 1 link issue + 1 email issue + 0 ssl issues = 3 total issues
    expect(global.updateSummaryBar).toHaveBeenCalledWith(3, '--', 'https://test.com');
    expect(document.getElementById('total-issues-count').textContent).toBe('3');

    // 6. Verify toast notification is displayed instead of blocking alert
    expect(global.ExecutionController.showToast).toHaveBeenCalledWith('Loaded scan results for https://test.com');
    expect(global.CyberNotify.alert).not.toHaveBeenCalled();

    // 7. Verify the summary content contains key elements
    const resultsBody = document.getElementById('wa-results-body');
    expect(resultsBody.innerHTML).toContain('Session Target');
    expect(resultsBody.innerHTML).toContain('test.com');
    expect(resultsBody.innerHTML).toContain('Audit Module Summary');
    
    // Check cards list
    expect(resultsBody.innerHTML).toContain('HTTP Headers');
    expect(resultsBody.innerHTML).toContain('Link Scanner');
    expect(resultsBody.innerHTML).toContain('Email Security');
    expect(resultsBody.innerHTML).toContain('SSL / TLS Certificate');
  });

  it('should switch to the specific tool detailed results when clicking a card in summary view', () => {
    const item = {
      id: 'scan_123',
      target: 'https://test.com',
      timestamp: '12:00:00 PM',
      toolStates: {
        headers: 'done',
        links: 'idle',
        email: 'idle',
        ssl: 'idle',
        phishing: 'idle',
        'dns-spoof': 'idle'
      },
      headersResults: {
        results: [],
        score: 100,
        grade: 'A+',
        target: 'https://test.com'
      },
      linksResults: null,
      emailResults: null,
      resultsData: []
    };

    WebAuditing.scanHistory = [item];
    WebAuditing.loadScanFromHistory('scan_123');

    // Verify it started in summary
    expect(WebAuditing.activeToolId).toBe('summary');

    // Simulate clicking on the "HTTP Headers" card in summary view
    const resultsBody = document.getElementById('wa-results-body');
    const headersCard = resultsBody.querySelector('[onclick*="headers"]');
    expect(headersCard).toBeTruthy();
    
    // In JSDOM without runScripts: 'dangerously', inline onclick handlers do not execute automatically on click()
    const onclickStr = headersCard.getAttribute('onclick');
    const executeOnClick = new Function('window', onclickStr);
    executeOnClick(global.window);

    // Verify view has switched to headers tool
    expect(WebAuditing.activeToolId).toBe('headers');
    expect(document.getElementById('wa-tool-tab-headers').classList.contains('active')).toBe(true);
    expect(document.getElementById('wa-active-tool-name').textContent).toBe('HTTP Security Headers Analysis');
    expect(document.getElementById('wa-results-body').innerHTML).toContain('Security Headers Breakdown');
  });
});
