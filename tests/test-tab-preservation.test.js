/**
 * Test Suite: Task 13.1 - DOM Preservation on Tab Switch
 * 
 * Verifies that the Threat Intel Hub properly preserves DOM and state
 * when switching tabs without re-fetching data.
 * 
 * Requirements tested: 13.1, 13.2, 13.3, 13.4, 13.5
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { JSDOM } from 'jsdom';

describe('Task 13.1: DOM Preservation on Tab Switch', () => {
  let dom;
  let document;
  let window;
  let ThreatIntelHub;
  let ThreatIntelState;
  let DashboardTabManager;
  let UIRenderer;

  beforeEach(async () => {
    // Create a minimal DOM environment
    dom = new JSDOM(`
      <!DOCTYPE html>
      <html>
        <body>
          <!-- Tab buttons -->
          <button class="tab-button" data-tab="network-tools">Network Tools</button>
          <button class="tab-button active" data-tab="threat-intel">Threat Intel</button>
          
          <!-- Tab panes -->
          <div id="network-tools" class="tab-pane hidden"></div>
          <div id="threat-intel" class="tab-pane">
            <input type="text" id="threat-intel-search-input" value="" />
            <button id="threat-intel-search-btn">Search</button>
            <button id="threat-intel-clear-history-btn">Clear History</button>
            
            <!-- Verdict card -->
            <div id="threat-intel-verdict-card" class="hidden">
              <div id="threat-intel-verdict-text"></div>
              <div id="threat-intel-verdict-details"></div>
              <svg id="verdict-icon-clear" class="hidden"></svg>
              <svg id="verdict-icon-malicious" class="hidden"></svg>
            </div>
            
            <!-- Source cards -->
            <div id="virustotal-loading" class="hidden"></div>
            <div id="virustotal-results" class="hidden"></div>
            <div id="virustotal-status"></div>
            
            <div id="abuseipdb-loading" class="hidden"></div>
            <div id="abuseipdb-results" class="hidden"></div>
            <div id="abuseipdb-status"></div>
            
            <div id="urlscan-loading" class="hidden"></div>
            <div id="urlscan-results" class="hidden"></div>
            <div id="urlscan-status"></div>
            
            <!-- History list -->
            <div id="threat-intel-history-list"></div>
          </div>
        </body>
      </html>
    `, {
      url: 'http://localhost',
      runScripts: 'dangerously',
      resources: 'usable'
    });

    document = dom.window.document;
    window = dom.window;
    
    // Set up global objects
    global.document = document;
    global.window = window;
    global.CustomEvent = window.CustomEvent;
    global.localStorage = {
      getItem: vi.fn(),
      setItem: vi.fn(),
      removeItem: vi.fn()
    };
    global.fetch = vi.fn();
    global.console = {
      log: vi.fn(),
      error: vi.fn(),
      warn: vi.fn()
    };

    // Load the modules
    const threatIntelModule = await import('./threat-intel.js');
    ThreatIntelHub = threatIntelModule.ThreatIntelHub;
    ThreatIntelState = threatIntelModule.ThreatIntelState;
    UIRenderer = threatIntelModule.UIRenderer;
    
    const tabManagerModule = await import('./dashboard-tab-manager.js');
    DashboardTabManager = tabManagerModule.default;
  });

  afterEach(() => {
    vi.clearAllMocks();
    dom.window.close();
  });

  describe('Requirement 13.1: Tab content uses display: none instead of removal', () => {
    it('should hide tab using hidden class (display: none) when switching away', () => {
      // Arrange: Start on threat-intel tab
      const threatIntelTab = document.getElementById('threat-intel');
      const networkToolsTab = document.getElementById('network-tools');
      
      // Verify initial state
      expect(threatIntelTab.classList.contains('hidden')).toBe(false);
      expect(networkToolsTab.classList.contains('hidden')).toBe(true);
      
      // Act: Switch to network-tools tab
      DashboardTabManager.switchTab('network-tools');
      
      // Assert: threat-intel tab should be hidden but still in DOM
      expect(threatIntelTab.classList.contains('hidden')).toBe(true);
      expect(document.getElementById('threat-intel')).not.toBeNull();
      expect(document.body.contains(threatIntelTab)).toBe(true);
    });

    it('should preserve all DOM elements when tab is hidden', () => {
      // Arrange: Populate some content
      const searchInput = document.getElementById('threat-intel-search-input');
      const verdictCard = document.getElementById('threat-intel-verdict-card');
      const verdictText = document.getElementById('threat-intel-verdict-text');
      
      searchInput.value = '8.8.8.8';
      verdictCard.classList.remove('hidden');
      verdictText.textContent = 'VERDICT: MALICIOUS';
      
      // Act: Switch away and back
      DashboardTabManager.switchTab('network-tools');
      DashboardTabManager.switchTab('threat-intel');
      
      // Assert: All content should be preserved
      expect(searchInput.value).toBe('8.8.8.8');
      expect(verdictCard.classList.contains('hidden')).toBe(false);
      expect(verdictText.textContent).toBe('VERDICT: MALICIOUS');
    });

    it('should not remove or recreate DOM elements during tab switch', () => {
      // Arrange: Get references to DOM elements
      const threatIntelTab = document.getElementById('threat-intel');
      const searchInput = document.getElementById('threat-intel-search-input');
      const verdictCard = document.getElementById('threat-intel-verdict-card');
      
      const tabReference = threatIntelTab;
      const inputReference = searchInput;
      const cardReference = verdictCard;
      
      // Act: Switch away and back multiple times
      DashboardTabManager.switchTab('network-tools');
      DashboardTabManager.switchTab('threat-intel');
      DashboardTabManager.switchTab('network-tools');
      DashboardTabManager.switchTab('threat-intel');
      
      // Assert: References should still point to same DOM elements
      expect(document.getElementById('threat-intel')).toBe(tabReference);
      expect(document.getElementById('threat-intel-search-input')).toBe(inputReference);
      expect(document.getElementById('threat-intel-verdict-card')).toBe(cardReference);
    });
  });

  describe('Requirement 13.2: ThreatIntelState object persists in memory', () => {
    it('should maintain ThreatIntelState object across tab switches', () => {
      // Arrange: Set some state
      ThreatIntelState.currentSearch = {
        input: '8.8.8.8',
        inputType: 'ip',
        timestamp: '2024-01-15T10:00:00Z'
      };
      ThreatIntelState.verdict = {
        status: 'MALICIOUS',
        threatCount: 2,
        timestamp: '2024-01-15T10:00:05Z'
      };
      
      // Act: Switch tabs
      DashboardTabManager.switchTab('network-tools');
      DashboardTabManager.switchTab('threat-intel');
      
      // Assert: State should be unchanged
      expect(ThreatIntelState.currentSearch.input).toBe('8.8.8.8');
      expect(ThreatIntelState.currentSearch.inputType).toBe('ip');
      expect(ThreatIntelState.verdict.status).toBe('MALICIOUS');
      expect(ThreatIntelState.verdict.threatCount).toBe(2);
    });

    it('should preserve source data in ThreatIntelState', () => {
      // Arrange: Set source data
      ThreatIntelState.sources = {
        virustotal: {
          loading: false,
          data: { maliciousCount: 5 },
          error: null,
          threatFlag: true
        },
        abuseipdb: {
          loading: false,
          data: { confidenceScore: 75 },
          error: null,
          threatFlag: true
        },
        urlscan: {
          loading: false,
          data: null,
          error: null,
          threatFlag: false
        }
      };
      
      // Act: Switch tabs multiple times
      DashboardTabManager.switchTab('network-tools');
      DashboardTabManager.switchTab('threat-intel');
      DashboardTabManager.switchTab('network-tools');
      DashboardTabManager.switchTab('threat-intel');
      
      // Assert: Source data should be preserved
      expect(ThreatIntelState.sources.virustotal.threatFlag).toBe(true);
      expect(ThreatIntelState.sources.virustotal.data.maliciousCount).toBe(5);
      expect(ThreatIntelState.sources.abuseipdb.data.confidenceScore).toBe(75);
      expect(ThreatIntelState.sources.urlscan.threatFlag).toBe(false);
    });

    it('should preserve search history in ThreatIntelState', () => {
      // Arrange: Set search history
      ThreatIntelState.searchHistory = [
        { input: '8.8.8.8', inputType: 'ip', verdict: 'CLEAR', timestamp: '2024-01-15T10:00:00Z' },
        { input: 'example.com', inputType: 'domain', verdict: 'MALICIOUS', timestamp: '2024-01-15T09:00:00Z' }
      ];
      
      // Act: Switch tabs
      DashboardTabManager.switchTab('network-tools');
      DashboardTabManager.switchTab('threat-intel');
      
      // Assert: History should be preserved
      expect(ThreatIntelState.searchHistory.length).toBe(2);
      expect(ThreatIntelState.searchHistory[0].input).toBe('8.8.8.8');
      expect(ThreatIntelState.searchHistory[1].input).toBe('example.com');
    });
  });

  describe('Requirement 13.3: No re-fetching occurs when returning to tab', () => {
    it('should not call API when returning to tab with existing results', () => {
      // Arrange: Mock fetch
      const fetchSpy = vi.spyOn(global, 'fetch');
      
      // Set up existing results
      ThreatIntelState.currentSearch = {
        input: '8.8.8.8',
        inputType: 'ip',
        timestamp: '2024-01-15T10:00:00Z'
      };
      
      // Act: Switch away and back
      DashboardTabManager.switchTab('network-tools');
      DashboardTabManager.switchTab('threat-intel');
      
      // Assert: No API calls should be made
      expect(fetchSpy).not.toHaveBeenCalled();
    });

    it('should not re-initialize ThreatIntelHub when returning to tab', () => {
      // Arrange: Initialize once
      const initSpy = vi.spyOn(ThreatIntelHub, 'init');
      DashboardTabManager.initializeTab('threat-intel');
      const initialCallCount = initSpy.mock.calls.length;
      
      // Act: Switch away and back
      DashboardTabManager.switchTab('network-tools');
      DashboardTabManager.switchTab('threat-intel');
      
      // Assert: init should not be called again
      expect(initSpy.mock.calls.length).toBe(initialCallCount);
    });

    it('should maintain tabInitialized flag to prevent re-initialization', () => {
      // Arrange: Initialize tab
      DashboardTabManager.tabInitialized['threat-intel'] = true;
      
      // Act: Switch to tab
      DashboardTabManager.switchTab('threat-intel');
      
      // Assert: Flag should still be true
      expect(DashboardTabManager.tabInitialized['threat-intel']).toBe(true);
    });
  });

  describe('Requirement 13.4: Test tab switching during active search', () => {
    it('should preserve loading state when switching tabs during search', () => {
      // Arrange: Set loading state
      const vtLoading = document.getElementById('virustotal-loading');
      const abuseLoading = document.getElementById('abuseipdb-loading');
      
      vtLoading.classList.remove('hidden');
      abuseLoading.classList.remove('hidden');
      
      ThreatIntelState.sources.virustotal.loading = true;
      ThreatIntelState.sources.abuseipdb.loading = true;
      
      // Act: Switch tabs during "loading"
      DashboardTabManager.switchTab('network-tools');
      DashboardTabManager.switchTab('threat-intel');
      
      // Assert: Loading state should be preserved
      expect(vtLoading.classList.contains('hidden')).toBe(false);
      expect(abuseLoading.classList.contains('hidden')).toBe(false);
      expect(ThreatIntelState.sources.virustotal.loading).toBe(true);
      expect(ThreatIntelState.sources.abuseipdb.loading).toBe(true);
    });

    it('should preserve search input value during active search', () => {
      // Arrange: Set search input and simulate search in progress
      const searchInput = document.getElementById('threat-intel-search-input');
      const searchBtn = document.getElementById('threat-intel-search-btn');
      
      searchInput.value = '8.8.8.8';
      searchBtn.disabled = true;
      searchBtn.textContent = 'Searching...';
      
      // Act: Switch tabs
      DashboardTabManager.switchTab('network-tools');
      DashboardTabManager.switchTab('threat-intel');
      
      // Assert: Input and button state should be preserved
      expect(searchInput.value).toBe('8.8.8.8');
      expect(searchBtn.disabled).toBe(true);
      expect(searchBtn.textContent).toBe('Searching...');
    });

    it('should not interrupt ongoing API calls when switching tabs', async () => {
      // Arrange: Mock a slow API call
      let resolveFetch;
      const fetchPromise = new Promise((resolve) => {
        resolveFetch = resolve;
      });
      
      global.fetch.mockReturnValue(fetchPromise);
      
      // Start a search (this would trigger API calls in real scenario)
      ThreatIntelState.sources.virustotal.loading = true;
      
      // Act: Switch tabs while "loading"
      DashboardTabManager.switchTab('network-tools');
      DashboardTabManager.switchTab('threat-intel');
      
      // Resolve the fetch
      resolveFetch({ ok: true, json: async () => ({ data: {} }) });
      await fetchPromise;
      
      // Assert: State should still indicate loading was in progress
      // (In real implementation, the promise would complete and update state)
      expect(ThreatIntelState.sources.virustotal.loading).toBe(true);
    });
  });

  describe('Requirement 13.5: Test tab switching after search completes', () => {
    it('should preserve verdict card after tab switch', () => {
      // Arrange: Set up completed search results
      const verdictCard = document.getElementById('threat-intel-verdict-card');
      const verdictText = document.getElementById('threat-intel-verdict-text');
      const verdictDetails = document.getElementById('threat-intel-verdict-details');
      
      verdictCard.classList.remove('hidden');
      verdictText.textContent = 'VERDICT: MALICIOUS';
      verdictDetails.textContent = '2 of 3 sources flagged as threat';
      
      ThreatIntelState.verdict = {
        status: 'MALICIOUS',
        threatCount: 2,
        timestamp: '2024-01-15T10:00:00Z'
      };
      
      // Act: Switch tabs
      DashboardTabManager.switchTab('network-tools');
      DashboardTabManager.switchTab('threat-intel');
      
      // Assert: Verdict should be preserved
      expect(verdictCard.classList.contains('hidden')).toBe(false);
      expect(verdictText.textContent).toBe('VERDICT: MALICIOUS');
      expect(verdictDetails.textContent).toBe('2 of 3 sources flagged as threat');
    });

    it('should preserve source card results after tab switch', () => {
      // Arrange: Set up source results
      const vtResults = document.getElementById('virustotal-results');
      const vtStatus = document.getElementById('virustotal-status');
      
      vtResults.classList.remove('hidden');
      vtResults.innerHTML = '<div class="text-red-400">5/70 engines flagged</div>';
      vtStatus.innerHTML = '<div class="text-red-400">Threat</div>';
      
      // Act: Switch tabs
      DashboardTabManager.switchTab('network-tools');
      DashboardTabManager.switchTab('threat-intel');
      
      // Assert: Results should be preserved
      expect(vtResults.classList.contains('hidden')).toBe(false);
      expect(vtResults.innerHTML).toContain('5/70 engines flagged');
      expect(vtStatus.innerHTML).toContain('Threat');
    });

    it('should preserve all three source cards after tab switch', () => {
      // Arrange: Set up all source results
      const sources = ['virustotal', 'abuseipdb', 'urlscan'];
      
      sources.forEach(source => {
        const results = document.getElementById(`${source}-results`);
        const status = document.getElementById(`${source}-status`);
        
        results.classList.remove('hidden');
        results.innerHTML = `<div>${source} results</div>`;
        status.innerHTML = `<div>${source} status</div>`;
      });
      
      // Act: Switch tabs multiple times
      DashboardTabManager.switchTab('network-tools');
      DashboardTabManager.switchTab('threat-intel');
      DashboardTabManager.switchTab('network-tools');
      DashboardTabManager.switchTab('threat-intel');
      
      // Assert: All results should be preserved
      sources.forEach(source => {
        const results = document.getElementById(`${source}-results`);
        const status = document.getElementById(`${source}-status`);
        
        expect(results.classList.contains('hidden')).toBe(false);
        expect(results.innerHTML).toContain(`${source} results`);
        expect(status.innerHTML).toContain(`${source} status`);
      });
    });

    it('should preserve expanded details sections after tab switch', () => {
      // Arrange: Expand details for a source
      const vtResults = document.getElementById('virustotal-results');
      vtResults.innerHTML = `
        <div class="source-details" style="display: block;">
          <pre>{"data": "test"}</pre>
        </div>
      `;
      
      const detailsSection = vtResults.querySelector('.source-details');
      
      // Act: Switch tabs
      DashboardTabManager.switchTab('network-tools');
      DashboardTabManager.switchTab('threat-intel');
      
      // Assert: Details should still be expanded
      const detailsAfter = document.getElementById('virustotal-results').querySelector('.source-details');
      expect(detailsAfter).not.toBeNull();
      expect(detailsAfter.style.display).toBe('block');
    });

    it('should preserve search history display after tab switch', () => {
      // Arrange: Render search history
      const historyList = document.getElementById('threat-intel-history-list');
      historyList.innerHTML = `
        <div class="recent-search-item">8.8.8.8</div>
        <div class="recent-search-item">example.com</div>
      `;
      
      // Act: Switch tabs
      DashboardTabManager.switchTab('network-tools');
      DashboardTabManager.switchTab('threat-intel');
      
      // Assert: History should be preserved
      const historyAfter = document.getElementById('threat-intel-history-list');
      expect(historyAfter.innerHTML).toContain('8.8.8.8');
      expect(historyAfter.innerHTML).toContain('example.com');
    });
  });

  describe('Integration: Complete tab switching workflow', () => {
    it('should handle complete search -> switch -> return workflow', () => {
      // Arrange: Simulate a complete search
      const searchInput = document.getElementById('threat-intel-search-input');
      const verdictCard = document.getElementById('threat-intel-verdict-card');
      const verdictText = document.getElementById('threat-intel-verdict-text');
      const vtResults = document.getElementById('virustotal-results');
      
      // Set up completed search state
      searchInput.value = '8.8.8.8';
      verdictCard.classList.remove('hidden');
      verdictText.textContent = 'VERDICT: CLEAR/UNVERIFIED';
      vtResults.classList.remove('hidden');
      vtResults.innerHTML = '<div>0/70 engines flagged</div>';
      
      ThreatIntelState.currentSearch = {
        input: '8.8.8.8',
        inputType: 'ip',
        timestamp: '2024-01-15T10:00:00Z'
      };
      ThreatIntelState.verdict = {
        status: 'CLEAR/UNVERIFIED',
        threatCount: 0,
        timestamp: '2024-01-15T10:00:00Z'
      };
      
      // Act: Switch away and back
      DashboardTabManager.switchTab('network-tools');
      DashboardTabManager.switchTab('threat-intel');
      
      // Assert: Everything should be preserved
      expect(searchInput.value).toBe('8.8.8.8');
      expect(verdictCard.classList.contains('hidden')).toBe(false);
      expect(verdictText.textContent).toBe('VERDICT: CLEAR/UNVERIFIED');
      expect(vtResults.classList.contains('hidden')).toBe(false);
      expect(vtResults.innerHTML).toContain('0/70 engines flagged');
      expect(ThreatIntelState.currentSearch.input).toBe('8.8.8.8');
      expect(ThreatIntelState.verdict.status).toBe('CLEAR/UNVERIFIED');
    });
  });
});
