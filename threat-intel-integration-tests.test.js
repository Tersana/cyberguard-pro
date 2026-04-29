/**
 * Threat Intel Services Fix - Integration Tests
 * Task 9: Integration testing for complete Threat Intel Hub workflow
 * 
 * Tests all sub-tasks:
 * 9.1 Test full IP search flow
 * 9.2 Test full domain search flow
 * 9.3 Test full hash search flow
 * 9.4 Test tab initialization behavior
 * 9.5 Test error handling preservation
 * 9.6 Test search history preservation
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { JSDOM } from 'jsdom';

// Setup DOM environment
let dom;
let document;
let window;
let localStorage;

// Module imports (will be loaded after DOM setup)
let ThreatIntelHub;
let ThreatIntelState;
let InputValidator;
let APIOrchestrator;
let DataExtractor;
let VerdictCalculator;
let UIRenderer;

// Mock fetch globally
global.fetch = vi.fn();

beforeEach(async () => {
  // Create a fresh DOM for each test
  dom = new JSDOM(`
    <!DOCTYPE html>
    <html>
      <body>
        <!-- Search Input -->
        <input id="threat-intel-search-input" type="text" />
        <button id="threat-intel-search-btn">Search</button>
        
        <!-- Source Cards -->
        <div id="threat-intel-source-cards">
          <!-- VirusTotal Card -->
          <div id="virustotal-card">
            <div id="virustotal-loading" class="hidden">Loading...</div>
            <div id="virustotal-status"></div>
            <div id="virustotal-results" class="hidden"></div>
          </div>
          
          <!-- AbuseIPDB Card -->
          <div id="abuseipdb-card">
            <div id="abuseipdb-loading" class="hidden">Loading...</div>
            <div id="abuseipdb-status"></div>
            <div id="abuseipdb-results" class="hidden"></div>
          </div>
          
          <!-- URLScan Card -->
          <div id="urlscan-card">
            <div id="urlscan-loading" class="hidden">Loading...</div>
            <div id="urlscan-status"></div>
            <div id="urlscan-results" class="hidden"></div>
          </div>
        </div>
        
        <!-- Verdict Card -->
        <div id="threat-intel-verdict-card" class="hidden">
          <div id="threat-intel-verdict-text"></div>
          <div id="threat-intel-verdict-details"></div>
          <div id="verdict-icon-clear" class="hidden"></div>
          <div id="verdict-icon-malicious" class="hidden"></div>
        </div>
        
        <!-- Search History -->
        <div id="threat-intel-history-list"></div>
        <button id="threat-intel-clear-history-btn">Clear History</button>
      </body>
    </html>
  `, {
    url: 'http://localhost',
    runScripts: 'dangerously',
    resources: 'usable'
  });

  document = dom.window.document;
  window = dom.window;
  localStorage = {
    data: {},
    getItem(key) {
      return this.data[key] || null;
    },
    setItem(key, value) {
      this.data[key] = value;
    },
    removeItem(key) {
      delete this.data[key];
    },
    clear() {
      this.data = {};
    }
  };

  // Set up global objects
  global.document = document;
  global.window = window;
  global.localStorage = localStorage;

  // Mock CyberNotify
  global.CyberNotify = {
    alert: vi.fn(),
    confirm: vi.fn((message, callback) => callback(true))
  };

  // Load the threat-intel module
  const fs = await import('fs');
  const path = await import('path');
  const threatIntelCode = fs.readFileSync(path.join(process.cwd(), 'threat-intel.js'), 'utf-8');
  
  // Execute the code in the context
  const script = new Function('document', 'window', 'localStorage', 'CyberNotify', threatIntelCode);
  script(document, window, localStorage, global.CyberNotify);

  // Get the exported modules
  ThreatIntelHub = window.ThreatIntelHub || global.ThreatIntelHub;
  ThreatIntelState = window.ThreatIntelState || global.ThreatIntelState;
  InputValidator = window.InputValidator || global.InputValidator;
  APIOrchestrator = window.APIOrchestrator || global.APIOrchestrator;
  DataExtractor = window.DataExtractor || global.DataExtractor;
  VerdictCalculator = window.VerdictCalculator || global.VerdictCalculator;
  UIRenderer = window.UIRenderer || global.UIRenderer;

  // Reset fetch mock
  global.fetch.mockReset();
});

afterEach(() => {
  // Clean up
  vi.clearAllMocks();
  localStorage.clear();
  dom.window.close();
});

/**
 * Task 9.1: Test full IP search flow
 * Verifies VirusTotal and AbuseIPDB execute successfully
 * Verifies URLScan shows "N/A - URL/Domain only"
 * Verifies verdict is calculated after both services complete
 */
describe('Task 9.1: Full IP Search Flow', () => {
  it('should execute VirusTotal and AbuseIPDB for IP addresses', async () => {
    // Setup: Store API keys
    localStorage.setItem('vtApiKey', btoa('test-vt-key'));
    localStorage.setItem('abuseipdbApiKey', btoa('test-abuse-key'));

    // Mock VirusTotal response (malicious)
    const vtResponse = {
      data: {
        attributes: {
          last_analysis_stats: {
            malicious: 5,
            suspicious: 0,
            undetected: 85,
            harmless: 0,
            timeout: 0
          }
        }
      }
    };

    // Mock AbuseIPDB response (high confidence)
    const abuseResponse = {
      data: {
        abuseConfidenceScore: 75,
        totalReports: 10
      }
    };

    // Setup fetch mocks
    global.fetch
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => vtResponse
      })
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => abuseResponse
      });

    // Execute search
    await ThreatIntelHub.performSearch('8.8.8.8');

    // Verify VirusTotal was called
    expect(global.fetch).toHaveBeenCalledWith(
      expect.stringContaining('virustotal.com/api/v3/ip_addresses/8.8.8.8'),
      expect.objectContaining({
        headers: expect.objectContaining({
          'x-apikey': 'test-vt-key'
        })
      })
    );

    // Verify AbuseIPDB was called with correct headers
    expect(global.fetch).toHaveBeenCalledWith(
      expect.stringContaining('api.abuseipdb.com/api/v2/check'),
      expect.objectContaining({
        headers: expect.objectContaining({
          'Key': 'test-abuse-key',
          'Accept': 'application/json'
        })
      })
    );

    // Verify URLScan shows N/A
    const urlscanResults = document.getElementById('urlscan-results');
    expect(urlscanResults.textContent).toContain('N/A - URL/Domain only');

    // Verify verdict is calculated (2 threats = MALICIOUS)
    const verdictText = document.getElementById('threat-intel-verdict-text');
    expect(verdictText.textContent).toBe('VERDICT: MALICIOUS');
  });

  it('should wait for all services to complete before calculating verdict', async () => {
    localStorage.setItem('vtApiKey', btoa('test-vt-key'));
    localStorage.setItem('abuseipdbApiKey', btoa('test-abuse-key'));

    let vtResolved = false;
    let abuseResolved = false;
    let verdictCalculated = false;

    // Mock slow responses
    global.fetch
      .mockImplementationOnce(() => new Promise(resolve => {
        setTimeout(() => {
          vtResolved = true;
          resolve({
            ok: true,
            json: async () => ({
              data: {
                attributes: {
                  last_analysis_stats: {
                    malicious: 0,
                    suspicious: 0,
                    undetected: 90,
                    harmless: 0,
                    timeout: 0
                  }
                }
              }
            })
          });
        }, 100);
      }))
      .mockImplementationOnce(() => new Promise(resolve => {
        setTimeout(() => {
          abuseResolved = true;
          resolve({
            ok: true,
            json: async () => ({
              data: {
                abuseConfidenceScore: 0,
                totalReports: 0
              }
            })
          });
        }, 200);
      }));

    // Spy on VerdictCalculator
    const calculateSpy = vi.spyOn(VerdictCalculator, 'calculate');
    calculateSpy.mockImplementation((...args) => {
      verdictCalculated = true;
      // Verify both services completed before verdict calculation
      expect(vtResolved).toBe(true);
      expect(abuseResolved).toBe(true);
      return {
        status: 'CLEAR/UNVERIFIED',
        threatCount: 0,
        timestamp: new Date().toISOString(),
        sources: { virustotal: false, abuseipdb: false, urlscan: false }
      };
    });

    await ThreatIntelHub.performSearch('1.1.1.1');

    expect(verdictCalculated).toBe(true);
    expect(vtResolved).toBe(true);
    expect(abuseResolved).toBe(true);
  });
});

/**
 * Task 9.2: Test full domain search flow
 * Verifies VirusTotal executes successfully
 * Verifies URLScan executes submission + polling workflow
 * Verifies AbuseIPDB shows "N/A - IP only"
 */
describe('Task 9.2: Full Domain Search Flow', () => {
  it('should execute VirusTotal and URLScan for domains', async () => {
    localStorage.setItem('vtApiKey', btoa('test-vt-key'));
    localStorage.setItem('urlscanApiKey', btoa('test-urlscan-key'));

    // Mock VirusTotal response
    const vtResponse = {
      data: {
        attributes: {
          last_analysis_stats: {
            malicious: 0,
            suspicious: 0,
            undetected: 90,
            harmless: 0,
            timeout: 0
          }
        }
      }
    };

    // Mock URLScan submission response
    const urlscanSubmitResponse = {
      uuid: 'test-uuid-12345',
      api: 'https://urlscan.io/api/v1/result/test-uuid-12345/'
    };

    // Mock URLScan result response
    const urlscanResultResponse = {
      verdicts: {
        overall: {
          malicious: false,
          score: 0
        }
      }
    };

    // Setup fetch mocks: VT, URLScan submit, URLScan result
    global.fetch
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => vtResponse
      })
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => urlscanSubmitResponse
      })
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => urlscanResultResponse
      });

    await ThreatIntelHub.performSearch('example.com');

    // Verify VirusTotal was called
    expect(global.fetch).toHaveBeenCalledWith(
      expect.stringContaining('virustotal.com/api/v3/domains/example.com'),
      expect.any(Object)
    );

    // Verify URLScan submission was called
    expect(global.fetch).toHaveBeenCalledWith(
      expect.stringContaining('urlscan.io/api/v1/scan/'),
      expect.objectContaining({
        method: 'POST',
        headers: expect.objectContaining({
          'API-Key': 'test-urlscan-key',
          'Content-Type': 'application/json'
        }),
        body: expect.stringContaining('example.com')
      })
    );

    // Verify URLScan polling was called
    expect(global.fetch).toHaveBeenCalledWith(
      expect.stringContaining('urlscan.io/api/v1/result/test-uuid-12345'),
      expect.objectContaining({
        headers: expect.objectContaining({
          'API-Key': 'test-urlscan-key'
        })
      })
    );

    // Verify AbuseIPDB shows N/A
    const abuseResults = document.getElementById('abuseipdb-results');
    expect(abuseResults.textContent).toContain('N/A - IP only');
  });

  it('should poll URLScan until scan completes', async () => {
    localStorage.setItem('vtApiKey', btoa('test-vt-key'));
    localStorage.setItem('urlscanApiKey', btoa('test-urlscan-key'));

    let pollAttempts = 0;

    // Mock responses
    global.fetch
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          data: {
            attributes: {
              last_analysis_stats: {
                malicious: 0,
                suspicious: 0,
                undetected: 90,
                harmless: 0,
                timeout: 0
              }
            }
          }
        })
      })
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({ uuid: 'test-uuid' })
      })
      .mockResolvedValueOnce({
        ok: false,
        status: 404
      })
      .mockResolvedValueOnce({
        ok: false,
        status: 404
      })
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          verdicts: {
            overall: {
              malicious: false
            }
          }
        })
      });

    await ThreatIntelHub.performSearch('test.com');

    // Verify multiple polling attempts were made
    const urlscanCalls = global.fetch.mock.calls.filter(call =>
      call[0].includes('urlscan.io/api/v1/result/')
    );
    expect(urlscanCalls.length).toBeGreaterThan(1);
  });
});

/**
 * Task 9.3: Test full hash search flow
 * Verifies only VirusTotal executes
 * Verifies AbuseIPDB and URLScan show "N/A" messages
 */
describe('Task 9.3: Full Hash Search Flow', () => {
  it('should only execute VirusTotal for hash inputs', async () => {
    localStorage.setItem('vtApiKey', btoa('test-vt-key'));

    const vtResponse = {
      data: {
        attributes: {
          last_analysis_stats: {
            malicious: 10,
            suspicious: 2,
            undetected: 60,
            harmless: 0,
            timeout: 0
          }
        }
      }
    };

    global.fetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => vtResponse
    });

    const testHash = '5d41402abc4b2a76b9719d911017c592'; // MD5 hash

    await ThreatIntelHub.performSearch(testHash);

    // Verify only VirusTotal was called
    expect(global.fetch).toHaveBeenCalledTimes(1);
    expect(global.fetch).toHaveBeenCalledWith(
      expect.stringContaining('virustotal.com/api/v3/files/' + testHash),
      expect.any(Object)
    );

    // Verify AbuseIPDB shows N/A
    const abuseResults = document.getElementById('abuseipdb-results');
    expect(abuseResults.textContent).toContain('N/A - IP only');

    // Verify URLScan shows N/A
    const urlscanResults = document.getElementById('urlscan-results');
    expect(urlscanResults.textContent).toContain('N/A - URL/Domain only');

    // Verify verdict is calculated (only 1 source, should be CLEAR)
    const verdictText = document.getElementById('threat-intel-verdict-text');
    expect(verdictText.textContent).toBe('VERDICT: CLEAR/UNVERIFIED');
  });

  it('should support different hash types (MD5, SHA-1, SHA-256)', async () => {
    localStorage.setItem('vtApiKey', btoa('test-vt-key'));

    const vtResponse = {
      data: {
        attributes: {
          last_analysis_stats: {
            malicious: 0,
            suspicious: 0,
            undetected: 70,
            harmless: 0,
            timeout: 0
          }
        }
      }
    };

    global.fetch.mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => vtResponse
    });

    // Test MD5
    const md5Hash = '5d41402abc4b2a76b9719d911017c592';
    await ThreatIntelHub.performSearch(md5Hash);
    expect(InputValidator.detectType(md5Hash)).toBe('hash');

    // Test SHA-1
    const sha1Hash = '356a192b7913b04c54574d18c28d46e6395428ab';
    await ThreatIntelHub.performSearch(sha1Hash);
    expect(InputValidator.detectType(sha1Hash)).toBe('hash');

    // Test SHA-256
    const sha256Hash = '2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae';
    await ThreatIntelHub.performSearch(sha256Hash);
    expect(InputValidator.detectType(sha256Hash)).toBe('hash');
  });
});

/**
 * Task 9.4: Test tab initialization behavior
 * Verifies no loading spinners on tab initialization
 * Verifies idle state is shown before search
 * Verifies loading spinners only appear after search button click
 */
describe('Task 9.4: Tab Initialization Behavior', () => {
  it('should show idle state on initialization without loading spinners', () => {
    // Initialize the module
    ThreatIntelHub.init();

    // Verify no loading spinners are visible
    const vtLoading = document.getElementById('virustotal-loading');
    const abuseLoading = document.getElementById('abuseipdb-loading');
    const urlscanLoading = document.getElementById('urlscan-loading');

    expect(vtLoading.classList.contains('hidden')).toBe(true);
    expect(abuseLoading.classList.contains('hidden')).toBe(true);
    expect(urlscanLoading.classList.contains('hidden')).toBe(true);

    // Verify idle state messages are shown
    const vtStatus = document.getElementById('virustotal-status');
    const abuseStatus = document.getElementById('abuseipdb-status');
    const urlscanStatus = document.getElementById('urlscan-status');

    expect(vtStatus.textContent).toContain('Awaiting search');
    expect(abuseStatus.textContent).toContain('Awaiting search');
    expect(urlscanStatus.textContent).toContain('Awaiting search');
  });

  it('should show loading spinners only after search button click', async () => {
    localStorage.setItem('vtApiKey', btoa('test-vt-key'));
    localStorage.setItem('abuseipdbApiKey', btoa('test-abuse-key'));

    ThreatIntelHub.init();

    // Verify idle state initially
    const vtLoading = document.getElementById('virustotal-loading');
    expect(vtLoading.classList.contains('hidden')).toBe(true);

    // Mock slow API response
    global.fetch.mockImplementation(() => new Promise(resolve => {
      setTimeout(() => {
        resolve({
          ok: true,
          json: async () => ({
            data: {
              attributes: {
                last_analysis_stats: {
                  malicious: 0,
                  suspicious: 0,
                  undetected: 90,
                  harmless: 0,
                  timeout: 0
                }
              }
            }
          })
        });
      }, 100);
    }));

    // Trigger search
    const searchInput = document.getElementById('threat-intel-search-input');
    searchInput.value = '8.8.8.8';

    // Start search (don't await yet)
    const searchPromise = ThreatIntelHub.performSearch('8.8.8.8');

    // Check that loading spinner appears during search
    await new Promise(resolve => setTimeout(resolve, 10));
    expect(vtLoading.classList.contains('hidden')).toBe(false);

    // Wait for search to complete
    await searchPromise;
  });
});

/**
 * Task 9.5: Test error handling preservation
 * Verifies error messages display correctly
 * Verifies application doesn't crash on errors
 * Verifies error handling is consistent with original behavior
 */
describe('Task 9.5: Error Handling Preservation', () => {
  it('should handle invalid API key errors (401/403)', async () => {
    localStorage.setItem('vtApiKey', btoa('invalid-key'));
    localStorage.setItem('abuseipdbApiKey', btoa('invalid-key'));

    global.fetch
      .mockResolvedValueOnce({
        ok: false,
        status: 401
      })
      .mockResolvedValueOnce({
        ok: false,
        status: 403
      });

    await ThreatIntelHub.performSearch('8.8.8.8');

    // Verify error messages are displayed
    const vtStatus = document.getElementById('virustotal-status');
    const abuseStatus = document.getElementById('abuseipdb-status');

    expect(vtStatus.textContent).toContain('Error');
    expect(abuseStatus.textContent).toContain('Error');

    // Verify application didn't crash
    expect(document.getElementById('threat-intel-search-btn').disabled).toBe(false);
  });

  it('should handle rate limit errors (429)', async () => {
    localStorage.setItem('vtApiKey', btoa('test-key'));

    global.fetch.mockResolvedValueOnce({
      ok: false,
      status: 429
    });

    await ThreatIntelHub.performSearch('test-hash-123');

    const vtResults = document.getElementById('virustotal-results');
    expect(vtResults.textContent).toContain('Rate limit exceeded');
  });

  it('should handle network failures gracefully', async () => {
    localStorage.setItem('vtApiKey', btoa('test-key'));

    global.fetch.mockRejectedValueOnce(new TypeError('Network request failed'));

    await ThreatIntelHub.performSearch('8.8.8.8');

    // Verify error is displayed
    const vtResults = document.getElementById('virustotal-results');
    expect(vtResults.textContent).toContain('Network failure');

    // Verify app is still functional
    expect(document.getElementById('threat-intel-search-btn').disabled).toBe(false);
  });

  it('should handle missing API keys', async () => {
    // Don't set any API keys
    localStorage.clear();

    await ThreatIntelHub.performSearch('8.8.8.8');

    // Verify error messages about missing keys
    const vtResults = document.getElementById('virustotal-results');
    const abuseResults = document.getElementById('abuseipdb-results');

    expect(vtResults.textContent).toContain('API key not configured');
    expect(abuseResults.textContent).toContain('API key not configured');
  });
});

/**
 * Task 9.6: Test search history preservation
 * Verifies search history displays correctly
 * Verifies history shows timestamps and verdicts
 * Verifies clicking history item re-runs search
 * Verifies clear history functionality
 */
describe('Task 9.6: Search History Preservation', () => {
  it('should save searches to history with timestamps and verdicts', async () => {
    localStorage.setItem('vtApiKey', btoa('test-key'));

    global.fetch.mockResolvedValue({
      ok: true,
      json: async () => ({
        data: {
          attributes: {
            last_analysis_stats: {
              malicious: 0,
              suspicious: 0,
              undetected: 90,
              harmless: 0,
              timeout: 0
            }
          }
        }
      })
    });

    await ThreatIntelHub.performSearch('test-hash-abc123');

    // Verify history was saved
    const historyData = JSON.parse(localStorage.getItem('threat-intel-history'));
    expect(historyData).toBeDefined();
    expect(historyData.length).toBe(1);
    expect(historyData[0].input).toBe('test-hash-abc123');
    expect(historyData[0].verdict).toBeDefined();
    expect(historyData[0].timestamp).toBeDefined();
  });

  it('should display search history in UI', async () => {
    localStorage.setItem('vtApiKey', btoa('test-key'));

    global.fetch.mockResolvedValue({
      ok: true,
      json: async () => ({
        data: {
          attributes: {
            last_analysis_stats: {
              malicious: 0,
              suspicious: 0,
              undetected: 90,
              harmless: 0,
              timeout: 0
            }
          }
        }
      })
    });

    // Perform multiple searches
    await ThreatIntelHub.performSearch('8.8.8.8');
    await ThreatIntelHub.performSearch('example.com');

    // Verify history list is populated
    const historyList = document.getElementById('threat-intel-history-list');
    const historyItems = historyList.querySelectorAll('.recent-search-item');

    expect(historyItems.length).toBe(2);
    expect(historyItems[0].textContent).toContain('example.com');
    expect(historyItems[1].textContent).toContain('8.8.8.8');
  });

  it('should limit history to 10 most recent items', async () => {
    localStorage.setItem('vtApiKey', btoa('test-key'));

    global.fetch.mockResolvedValue({
      ok: true,
      json: async () => ({
        data: {
          attributes: {
            last_analysis_stats: {
              malicious: 0,
              suspicious: 0,
              undetected: 90,
              harmless: 0,
              timeout: 0
            }
          }
        }
      })
    });

    // Perform 12 searches
    for (let i = 0; i < 12; i++) {
      await ThreatIntelHub.performSearch(`test-${i}.com`);
    }

    // Verify only 10 items are kept
    const historyData = JSON.parse(localStorage.getItem('threat-intel-history'));
    expect(historyData.length).toBe(10);
    expect(historyData[0].input).toBe('test-11.com'); // Most recent
  });

  it('should clear history when clear button is clicked', async () => {
    localStorage.setItem('vtApiKey', btoa('test-key'));

    global.fetch.mockResolvedValue({
      ok: true,
      json: async () => ({
        data: {
          attributes: {
            last_analysis_stats: {
              malicious: 0,
              suspicious: 0,
              undetected: 90,
              harmless: 0,
              timeout: 0
            }
          }
        }
      })
    });

    // Add some history
    await ThreatIntelHub.performSearch('8.8.8.8');
    await ThreatIntelHub.performSearch('example.com');

    // Clear history
    ThreatIntelHub.clearHistory();

    // Verify history is cleared
    const historyData = localStorage.getItem('threat-intel-history');
    expect(historyData).toBeNull();

    // Verify UI shows empty state
    const historyList = document.getElementById('threat-intel-history-list');
    expect(historyList.textContent).toContain('No recent searches');
  });

  it('should re-run search when clicking history item', async () => {
    localStorage.setItem('vtApiKey', btoa('test-key'));

    global.fetch.mockResolvedValue({
      ok: true,
      json: async () => ({
        data: {
          attributes: {
            last_analysis_stats: {
              malicious: 0,
              suspicious: 0,
              undetected: 90,
              harmless: 0,
              timeout: 0
            }
          }
        }
      })
    });

    // Perform initial search
    await ThreatIntelHub.performSearch('8.8.8.8');

    // Get history item
    const historyList = document.getElementById('threat-intel-history-list');
    const historyItem = historyList.querySelector('.recent-search-item');

    // Click history item
    historyItem.click();

    // Verify search input is populated
    const searchInput = document.getElementById('threat-intel-search-input');
    expect(searchInput.value).toBe('8.8.8.8');
  });
});
