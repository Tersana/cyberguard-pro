/**
 * Integration tests for Threat Intel Hub main search orchestration
 * Tests Task 9: performSearch and API key validation
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { JSDOM } from 'jsdom';

describe('Task 9: Main Search Orchestration', () => {
  let dom;
  let document;
  let window;
  let ThreatIntelHub;
  let InputValidator;
  let APIOrchestrator;
  let DataExtractor;
  let VerdictCalculator;
  let UIRenderer;
  let ThreatIntelState;
  let CyberNotify;

  beforeEach(async () => {
    // Create a fresh DOM for each test
    dom = new JSDOM(`
      <!DOCTYPE html>
      <html>
        <body>
          <input id="threat-intel-search-input" />
          <button id="threat-intel-search-btn">Search</button>
          <button id="threat-intel-clear-history-btn">Clear History</button>
          <div id="threat-intel-verdict-card" class="hidden">
            <div id="threat-intel-verdict-text"></div>
            <div id="threat-intel-verdict-details"></div>
            <div id="verdict-icon-clear"></div>
            <div id="verdict-icon-malicious"></div>
          </div>
          <div id="virustotal-loading"></div>
          <div id="virustotal-results" class="hidden"></div>
          <div id="virustotal-status"></div>
          <div id="abuseipdb-loading"></div>
          <div id="abuseipdb-results" class="hidden"></div>
          <div id="abuseipdb-status"></div>
          <div id="urlscan-loading"></div>
          <div id="urlscan-results" class="hidden"></div>
          <div id="urlscan-status"></div>
        </body>
      </html>
    `, { url: 'http://localhost' });

    window = dom.window;
    document = window.document;
    global.document = document;
    global.window = window;
    global.localStorage = {
      getItem: vi.fn(),
      setItem: vi.fn(),
      removeItem: vi.fn()
    };

    // Mock CyberNotify
    global.CyberNotify = {
      show: vi.fn()
    };

    // Load the module
    const module = await import('./threat-intel.js');
    ThreatIntelHub = module.ThreatIntelHub;
    InputValidator = module.InputValidator;
    APIOrchestrator = module.APIOrchestrator;
    DataExtractor = module.DataExtractor;
    VerdictCalculator = module.VerdictCalculator;
    UIRenderer = module.UIRenderer;
    ThreatIntelState = module.ThreatIntelState;
  });

  describe('Task 9.1: performSearch method', () => {
    it('should validate input before proceeding', async () => {
      // Mock validation to fail
      const validateSpy = vi.spyOn(InputValidator, 'validate').mockReturnValue({
        valid: false,
        error: 'Invalid format'
      });

      await ThreatIntelHub.performSearch('invalid-input');

      expect(validateSpy).toHaveBeenCalledWith('invalid-input');
      expect(global.CyberNotify.show).toHaveBeenCalledWith('Invalid format', 'warning');
    });

    it('should detect input type correctly', async () => {
      const detectTypeSpy = vi.spyOn(InputValidator, 'detectType').mockReturnValue('ip');
      const sanitizeSpy = vi.spyOn(InputValidator, 'sanitize').mockReturnValue('8.8.8.8');
      vi.spyOn(InputValidator, 'validate').mockReturnValue({ valid: true, error: '' });
      
      // Mock API orchestrator to prevent actual API calls
      vi.spyOn(APIOrchestrator, 'fetchAll').mockResolvedValue({
        virustotal: { success: true, data: { data: { attributes: { last_analysis_stats: { malicious: 0 } } } } },
        abuseipdb: { success: true, data: { data: { abuseConfidenceScore: 0 } } },
        urlscan: { notApplicable: true }
      });

      await ThreatIntelHub.performSearch('8.8.8.8');

      expect(detectTypeSpy).toHaveBeenCalled();
      expect(sanitizeSpy).toHaveBeenCalled();
    });

    it('should show loading states for applicable sources', async () => {
      vi.spyOn(InputValidator, 'validate').mockReturnValue({ valid: true, error: '' });
      vi.spyOn(InputValidator, 'detectType').mockReturnValue('ip');
      vi.spyOn(InputValidator, 'sanitize').mockReturnValue('8.8.8.8');
      
      const showLoadingSpy = vi.spyOn(UIRenderer, 'showLoadingState');
      
      // Mock API orchestrator
      vi.spyOn(APIOrchestrator, 'fetchAll').mockResolvedValue({
        virustotal: { success: true, data: { data: { attributes: { last_analysis_stats: { malicious: 0 } } } } },
        abuseipdb: { success: true, data: { data: { abuseConfidenceScore: 0 } } },
        urlscan: { notApplicable: true }
      });

      await ThreatIntelHub.performSearch('8.8.8.8');

      expect(showLoadingSpy).toHaveBeenCalledWith('virustotal');
      expect(showLoadingSpy).toHaveBeenCalledWith('abuseipdb');
    });

    it('should call APIOrchestrator.fetchAll with correct parameters', async () => {
      vi.spyOn(InputValidator, 'validate').mockReturnValue({ valid: true, error: '' });
      vi.spyOn(InputValidator, 'detectType').mockReturnValue('domain');
      vi.spyOn(InputValidator, 'sanitize').mockReturnValue('example.com');
      
      const fetchAllSpy = vi.spyOn(APIOrchestrator, 'fetchAll').mockResolvedValue({
        virustotal: { success: true, data: { data: { attributes: { last_analysis_stats: { malicious: 0 } } } } },
        abuseipdb: { notApplicable: true },
        urlscan: { success: true, data: { verdicts: { overall: { malicious: false } } } }
      });

      await ThreatIntelHub.performSearch('example.com');

      expect(fetchAllSpy).toHaveBeenCalledWith('example.com', 'domain');
    });

    it('should process responses with DataExtractor', async () => {
      vi.spyOn(InputValidator, 'validate').mockReturnValue({ valid: true, error: '' });
      vi.spyOn(InputValidator, 'detectType').mockReturnValue('ip');
      vi.spyOn(InputValidator, 'sanitize').mockReturnValue('8.8.8.8');
      
      const extractVTSpy = vi.spyOn(DataExtractor, 'extractVirusTotal').mockReturnValue({
        threatFlag: false,
        maliciousCount: 0,
        totalEngines: 70,
        displayText: '0/70 engines flagged',
        rawData: {}
      });

      const extractAbuseSpy = vi.spyOn(DataExtractor, 'extractAbuseIPDB').mockReturnValue({
        threatFlag: false,
        confidenceScore: 0,
        displayText: 'Confidence: 0%',
        rawData: {}
      });

      vi.spyOn(APIOrchestrator, 'fetchAll').mockResolvedValue({
        virustotal: { success: true, data: { data: { attributes: { last_analysis_stats: { malicious: 0 } } } } },
        abuseipdb: { success: true, data: { data: { abuseConfidenceScore: 0 } } },
        urlscan: { notApplicable: true }
      });

      await ThreatIntelHub.performSearch('8.8.8.8');

      expect(extractVTSpy).toHaveBeenCalled();
      expect(extractAbuseSpy).toHaveBeenCalled();
    });

    it('should calculate verdict with VerdictCalculator', async () => {
      vi.spyOn(InputValidator, 'validate').mockReturnValue({ valid: true, error: '' });
      vi.spyOn(InputValidator, 'detectType').mockReturnValue('ip');
      vi.spyOn(InputValidator, 'sanitize').mockReturnValue('8.8.8.8');
      
      const calculateSpy = vi.spyOn(VerdictCalculator, 'calculate').mockReturnValue({
        status: 'CLEAR/UNVERIFIED',
        threatCount: 0,
        timestamp: new Date().toISOString(),
        sources: { virustotal: false, abuseipdb: false, urlscan: false }
      });

      vi.spyOn(APIOrchestrator, 'fetchAll').mockResolvedValue({
        virustotal: { success: true, data: { data: { attributes: { last_analysis_stats: { malicious: 0 } } } } },
        abuseipdb: { success: true, data: { data: { abuseConfidenceScore: 0 } } },
        urlscan: { notApplicable: true }
      });

      vi.spyOn(DataExtractor, 'extractVirusTotal').mockReturnValue({ threatFlag: false });
      vi.spyOn(DataExtractor, 'extractAbuseIPDB').mockReturnValue({ threatFlag: false });

      await ThreatIntelHub.performSearch('8.8.8.8');

      expect(calculateSpy).toHaveBeenCalled();
    });

    it('should update UI with verdict', async () => {
      vi.spyOn(InputValidator, 'validate').mockReturnValue({ valid: true, error: '' });
      vi.spyOn(InputValidator, 'detectType').mockReturnValue('ip');
      vi.spyOn(InputValidator, 'sanitize').mockReturnValue('8.8.8.8');
      
      const renderVerdictSpy = vi.spyOn(UIRenderer, 'renderVerdictCard');

      vi.spyOn(APIOrchestrator, 'fetchAll').mockResolvedValue({
        virustotal: { success: true, data: { data: { attributes: { last_analysis_stats: { malicious: 0 } } } } },
        abuseipdb: { success: true, data: { data: { abuseConfidenceScore: 0 } } },
        urlscan: { notApplicable: true }
      });

      vi.spyOn(DataExtractor, 'extractVirusTotal').mockReturnValue({ threatFlag: false });
      vi.spyOn(DataExtractor, 'extractAbuseIPDB').mockReturnValue({ threatFlag: false });

      await ThreatIntelHub.performSearch('8.8.8.8');

      expect(renderVerdictSpy).toHaveBeenCalled();
    });

    it('should save search to history', async () => {
      vi.spyOn(InputValidator, 'validate').mockReturnValue({ valid: true, error: '' });
      vi.spyOn(InputValidator, 'detectType').mockReturnValue('ip');
      vi.spyOn(InputValidator, 'sanitize').mockReturnValue('8.8.8.8');
      
      const saveToHistorySpy = vi.spyOn(ThreatIntelHub, 'saveToHistory');

      vi.spyOn(APIOrchestrator, 'fetchAll').mockResolvedValue({
        virustotal: { success: true, data: { data: { attributes: { last_analysis_stats: { malicious: 0 } } } } },
        abuseipdb: { success: true, data: { data: { abuseConfidenceScore: 0 } } },
        urlscan: { notApplicable: true }
      });

      vi.spyOn(DataExtractor, 'extractVirusTotal').mockReturnValue({ threatFlag: false });
      vi.spyOn(DataExtractor, 'extractAbuseIPDB').mockReturnValue({ threatFlag: false });

      await ThreatIntelHub.performSearch('8.8.8.8');

      expect(saveToHistorySpy).toHaveBeenCalled();
    });

    it('should disable search button during search', async () => {
      vi.spyOn(InputValidator, 'validate').mockReturnValue({ valid: true, error: '' });
      vi.spyOn(InputValidator, 'detectType').mockReturnValue('ip');
      vi.spyOn(InputValidator, 'sanitize').mockReturnValue('8.8.8.8');
      
      const searchBtn = document.getElementById('threat-intel-search-btn');
      
      // Mock API orchestrator with delay
      vi.spyOn(APIOrchestrator, 'fetchAll').mockImplementation(() => {
        // Check button state during API call
        expect(searchBtn.disabled).toBe(true);
        expect(searchBtn.textContent).toBe('Searching...');
        
        return Promise.resolve({
          virustotal: { success: true, data: { data: { attributes: { last_analysis_stats: { malicious: 0 } } } } },
          abuseipdb: { success: true, data: { data: { abuseConfidenceScore: 0 } } },
          urlscan: { notApplicable: true }
        });
      });

      vi.spyOn(DataExtractor, 'extractVirusTotal').mockReturnValue({ threatFlag: false });
      vi.spyOn(DataExtractor, 'extractAbuseIPDB').mockReturnValue({ threatFlag: false });

      await ThreatIntelHub.performSearch('8.8.8.8');

      // Button should be re-enabled after search
      expect(searchBtn.disabled).toBe(false);
    });
  });

  describe('Task 9.2: API key validation', () => {
    it('should check localStorage for URLScan API key', () => {
      const getItemSpy = vi.spyOn(global.localStorage, 'getItem');
      
      ThreatIntelHub.checkAPIKeys();

      expect(getItemSpy).toHaveBeenCalledWith('urlscanApiKey');
    });

    it('should show CyberNotify warning if URLScan key is missing', () => {
      global.localStorage.getItem.mockReturnValue(null);
      
      ThreatIntelHub.checkAPIKeys();

      expect(global.CyberNotify.show).toHaveBeenCalledWith(
        expect.stringContaining('URLScan API key not configured'),
        'warning'
      );
    });

    it('should not show warning if URLScan key exists', () => {
      global.localStorage.getItem.mockReturnValue('encrypted-key');
      
      ThreatIntelHub.checkAPIKeys();

      expect(global.CyberNotify.show).not.toHaveBeenCalled();
    });

    it('should check for VirusTotal and AbuseIPDB keys', () => {
      const getItemSpy = vi.spyOn(global.localStorage, 'getItem');
      
      ThreatIntelHub.checkAPIKeys();

      expect(getItemSpy).toHaveBeenCalledWith('urlscanApiKey');
      expect(getItemSpy).toHaveBeenCalledWith('vtApiKey');
      expect(getItemSpy).toHaveBeenCalledWith('abuseipdbApiKey');
    });

    it('should proceed with available APIs when URLScan key is missing', async () => {
      // URLScan key missing, but others present
      global.localStorage.getItem.mockImplementation((key) => {
        if (key === 'urlscanApiKey') return null;
        return 'encrypted-key';
      });

      vi.spyOn(InputValidator, 'validate').mockReturnValue({ valid: true, error: '' });
      vi.spyOn(InputValidator, 'detectType').mockReturnValue('domain');
      vi.spyOn(InputValidator, 'sanitize').mockReturnValue('example.com');
      
      const fetchAllSpy = vi.spyOn(APIOrchestrator, 'fetchAll').mockResolvedValue({
        virustotal: { success: true, data: { data: { attributes: { last_analysis_stats: { malicious: 0 } } } } },
        abuseipdb: { notApplicable: true },
        urlscan: { success: false, error: 'URLScan: API key not configured' }
      });

      vi.spyOn(DataExtractor, 'extractVirusTotal').mockReturnValue({ threatFlag: false });

      await ThreatIntelHub.performSearch('example.com');

      // Should still call fetchAll even with missing URLScan key
      expect(fetchAllSpy).toHaveBeenCalled();
    });
  });
});
