/**
 * Preservation Property Tests for Threat Intel Services Fix
 * Task 2: Write preservation property tests (BEFORE implementing fixes)
 * 
 * **Property 2: Preservation** - VirusTotal and Verdict Logic Preservation
 * 
 * **IMPORTANT**: Follow observation-first methodology
 * - Observe behavior on UNFIXED code for VirusTotal searches (IP, domain, hash)
 * - Observe verdict calculation logic on UNFIXED code (2+ sources = MALICIOUS threshold)
 * - Write property-based tests capturing observed behavior patterns
 * - Property-based testing generates many test cases for stronger guarantees
 * 
 * **EXPECTED OUTCOME**: Tests PASS on unfixed code (confirms baseline behavior to preserve)
 * 
 * Validates Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7, 3.8, 3.9, 3.10
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { JSDOM } from 'jsdom';
import * as fc from 'fast-check';

describe('Property 2: Preservation - VirusTotal and Verdict Logic Preservation', () => {
  let dom;
  let document;
  let window;
  let localStorage;
  let ThreatIntelHub;
  let UIRenderer;
  let APIOrchestrator;
  let DataExtractor;
  let VerdictCalculator;
  let InputValidator;
  let ThreatIntelState;

  beforeEach(async () => {
    // Create a fresh DOM environment for each test
    dom = new JSDOM(`
      <!DOCTYPE html>
      <html>
        <body>
          <div id="threat-intel-tab">
            <input id="threat-intel-search-input" type="text" />
            <button id="threat-intel-search-btn">Search</button>
            
            <div id="threat-intel-source-cards">
              <!-- VirusTotal Card -->
              <div id="virustotal-card">
                <div id="virustotal-loading" class="hidden">Loading...</div>
                <div id="virustotal-results" class="hidden"></div>
                <div id="virustotal-status"></div>
              </div>
              
              <!-- AbuseIPDB Card -->
              <div id="abuseipdb-card">
                <div id="abuseipdb-loading" class="hidden">Loading...</div>
                <div id="abuseipdb-results" class="hidden"></div>
                <div id="abuseipdb-status"></div>
              </div>
              
              <!-- URLScan Card -->
              <div id="urlscan-card">
                <div id="urlscan-loading" class="hidden">Loading...</div>
                <div id="urlscan-results" class="hidden"></div>
                <div id="urlscan-status"></div>
              </div>
            </div>
            
            <div id="threat-intel-verdict-card" class="hidden">
              <div id="threat-intel-verdict-text"></div>
              <div id="threat-intel-verdict-details"></div>
              <div id="verdict-icon-clear" class="hidden"></div>
              <div id="verdict-icon-malicious" class="hidden"></div>
            </div>
            
            <div id="threat-intel-history-list"></div>
            <button id="threat-intel-clear-history-btn">Clear History</button>
          </div>
        </body>
      </html>
    `, {
      url: 'http://localhost',
      runScripts: 'dangerously',
      resources: 'usable'
    });

    window = dom.window;
    document = window.document;
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

    // Make globals available
    global.window = window;
    global.document = document;
    global.localStorage = localStorage;
    global.btoa = (str) => Buffer.from(str).toString('base64');
    global.atob = (str) => Buffer.from(str, 'base64').toString();
    global.fetch = vi.fn();

    // Mock CyberNotify
    global.CyberNotify = {
      alert: vi.fn(),
      confirm: vi.fn()
    };

    // Load the threat-intel.js module
    const threatIntelModule = await import('./threat-intel.js');
    ThreatIntelHub = threatIntelModule.ThreatIntelHub;
    UIRenderer = threatIntelModule.UIRenderer;
    APIOrchestrator = threatIntelModule.APIOrchestrator;
    DataExtractor = threatIntelModule.DataExtractor;
    VerdictCalculator = threatIntelModule.VerdictCalculator;
    InputValidator = threatIntelModule.InputValidator;
    ThreatIntelState = threatIntelModule.ThreatIntelState;
  });

  afterEach(() => {
    vi.restoreAllMocks();
    localStorage.clear();
  });

  /**
   * PRESERVATION PROPERTY 1: VirusTotal Functionality for IP Addresses
   * 
   * For all valid IP addresses, VirusTotal integration should:
   * - Successfully make API requests
   * - Extract threat data correctly
   * - Display results in UI
   * - Calculate threat flags based on malicious count
   * 
   * Validates: Requirements 3.1, 3.2
   */
  describe('Preservation: VirusTotal IP Address Searches', () => {
    it('should preserve VirusTotal functionality for random IP addresses', async () => {
      await fc.assert(
        fc.asyncProperty(
          // Generate random valid IPv4 addresses
          fc.tuple(
            fc.integer({ min: 0, max: 255 }),
            fc.integer({ min: 0, max: 255 }),
            fc.integer({ min: 0, max: 255 }),
            fc.integer({ min: 0, max: 255 })
          ).map(([a, b, c, d]) => `${a}.${b}.${c}.${d}`),
          fc.integer({ min: 0, max: 70 }), // malicious count
          fc.integer({ min: 0, max: 70 }), // total engines
          async (ip, maliciousCount, totalEngines) => {
            // Set up VirusTotal API key
            localStorage.setItem('vtApiKey', btoa('test-vt-key'));

            // Mock VirusTotal response
            const mockResponse = {
              data: {
                attributes: {
                  last_analysis_stats: {
                    malicious: maliciousCount,
                    suspicious: 0,
                    undetected: Math.max(0, totalEngines - maliciousCount),
                    harmless: 0,
                    timeout: 0
                  }
                }
              }
            };

            global.fetch.mockResolvedValue({
              ok: true,
              json: async () => mockResponse
            });

            // Fetch VirusTotal data
            const result = await APIOrchestrator.fetchVirusTotal(ip, 'ip');

            // PRESERVATION: VirusTotal should return data successfully
            expect(result).toBeDefined();
            expect(result.data).toBeDefined();
            expect(result.data.attributes.last_analysis_stats).toBeDefined();

            // Extract data
            const extracted = DataExtractor.extractVirusTotal(result);

            // PRESERVATION: Threat flag should be true if malicious > 0
            expect(extracted.threatFlag).toBe(maliciousCount > 0);
            expect(extracted.maliciousCount).toBe(maliciousCount);
            expect(extracted.displayText).toContain(`${maliciousCount}/`);
          }
        ),
        { numRuns: 20 } // Run 20 random test cases
      );
    });

    it('should validate input type detection for IP addresses', () => {
      fc.assert(
        fc.property(
          fc.tuple(
            fc.integer({ min: 0, max: 255 }),
            fc.integer({ min: 0, max: 255 }),
            fc.integer({ min: 0, max: 255 }),
            fc.integer({ min: 0, max: 255 })
          ).map(([a, b, c, d]) => `${a}.${b}.${c}.${d}`),
          (ip) => {
            // PRESERVATION: Input validator should detect IP type
            const inputType = InputValidator.detectType(ip);
            expect(inputType).toBe('ip');

            // PRESERVATION: Validation should pass
            const validation = InputValidator.validate(ip);
            expect(validation.valid).toBe(true);
          }
        ),
        { numRuns: 20 }
      );
    });
  });

  /**
   * PRESERVATION PROPERTY 2: VirusTotal Functionality for Domains
   * 
   * For all valid domains, VirusTotal integration should:
   * - Successfully make API requests
   * - Extract threat data correctly
   * - Display results in UI
   * 
   * Validates: Requirements 3.1, 3.3
   */
  describe('Preservation: VirusTotal Domain Searches', () => {
    it('should preserve VirusTotal functionality for random domains', async () => {
      await fc.assert(
        fc.asyncProperty(
          // Generate random valid domains
          fc.tuple(
            fc.array(fc.constantFrom('a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j'), { minLength: 3, maxLength: 10 }).map(arr => arr.join('')),
            fc.constantFrom('com', 'org', 'net', 'io', 'dev')
          ).map(([name, tld]) => `${name}.${tld}`),
          fc.integer({ min: 0, max: 70 }), // malicious count
          async (domain, maliciousCount) => {
            // Set up VirusTotal API key
            localStorage.setItem('vtApiKey', btoa('test-vt-key'));

            // Mock VirusTotal response
            const mockResponse = {
              data: {
                attributes: {
                  last_analysis_stats: {
                    malicious: maliciousCount,
                    suspicious: 0,
                    undetected: 70 - maliciousCount,
                    harmless: 0,
                    timeout: 0
                  }
                }
              }
            };

            global.fetch.mockResolvedValue({
              ok: true,
              json: async () => mockResponse
            });

            // Fetch VirusTotal data
            const result = await APIOrchestrator.fetchVirusTotal(domain, 'domain');

            // PRESERVATION: VirusTotal should return data successfully
            expect(result).toBeDefined();
            expect(result.data).toBeDefined();

            // Extract data
            const extracted = DataExtractor.extractVirusTotal(result);

            // PRESERVATION: Threat flag and extraction should work correctly
            expect(extracted.threatFlag).toBe(maliciousCount > 0);
            expect(extracted.maliciousCount).toBe(maliciousCount);
          }
        ),
        { numRuns: 20 }
      );
    });

    it('should validate input type detection for domains', () => {
      fc.assert(
        fc.property(
          fc.tuple(
            fc.array(fc.constantFrom('a', 'b', 'c', 'd', 'e'), { minLength: 3, maxLength: 8 }).map(arr => arr.join('')),
            fc.constantFrom('com', 'org', 'net')
          ).map(([name, tld]) => `${name}.${tld}`),
          (domain) => {
            // PRESERVATION: Input validator should detect domain type
            const inputType = InputValidator.detectType(domain);
            expect(inputType).toBe('domain');

            // PRESERVATION: Validation should pass
            const validation = InputValidator.validate(domain);
            expect(validation.valid).toBe(true);
          }
        ),
        { numRuns: 20 }
      );
    });
  });

  /**
   * PRESERVATION PROPERTY 3: VirusTotal Functionality for Hashes
   * 
   * For all valid hashes (MD5, SHA-1, SHA-256), VirusTotal integration should:
   * - Successfully make API requests
   * - Extract threat data correctly
   * - Be the ONLY service queried (no AbuseIPDB or URLScan)
   * 
   * Validates: Requirements 3.1, 3.4
   */
  describe('Preservation: VirusTotal Hash Searches', () => {
    it('should preserve VirusTotal functionality for MD5 hashes', async () => {
      await fc.assert(
        fc.asyncProperty(
          // Generate random MD5 hashes (32 hex characters)
          fc.array(fc.integer({ min: 0, max: 15 }), { minLength: 32, maxLength: 32 })
            .map(arr => arr.map(n => n.toString(16)).join('')),
          fc.integer({ min: 0, max: 70 }),
          async (hash, maliciousCount) => {
            // Set up VirusTotal API key
            localStorage.setItem('vtApiKey', btoa('test-vt-key'));

            // Mock VirusTotal response
            const mockResponse = {
              data: {
                attributes: {
                  last_analysis_stats: {
                    malicious: maliciousCount,
                    suspicious: 0,
                    undetected: 70 - maliciousCount,
                    harmless: 0,
                    timeout: 0
                  }
                }
              }
            };

            global.fetch.mockResolvedValue({
              ok: true,
              json: async () => mockResponse
            });

            // Fetch VirusTotal data
            const result = await APIOrchestrator.fetchVirusTotal(hash, 'file');

            // PRESERVATION: VirusTotal should return data successfully
            expect(result).toBeDefined();
            expect(result.data).toBeDefined();

            // Extract data
            const extracted = DataExtractor.extractVirusTotal(result);

            // PRESERVATION: Extraction should work correctly
            expect(extracted.threatFlag).toBe(maliciousCount > 0);
            expect(extracted.maliciousCount).toBe(maliciousCount);
          }
        ),
        { numRuns: 10 }
      );
    });

    it('should validate input type detection for hashes', () => {
      fc.assert(
        fc.property(
          fc.oneof(
            fc.array(fc.integer({ min: 0, max: 15 }), { minLength: 32, maxLength: 32 }).map(arr => arr.map(n => n.toString(16)).join('')), // MD5
            fc.array(fc.integer({ min: 0, max: 15 }), { minLength: 40, maxLength: 40 }).map(arr => arr.map(n => n.toString(16)).join('')), // SHA-1
            fc.array(fc.integer({ min: 0, max: 15 }), { minLength: 64, maxLength: 64 }).map(arr => arr.map(n => n.toString(16)).join(''))  // SHA-256
          ),
          (hash) => {
            // PRESERVATION: Input validator should detect hash type
            const inputType = InputValidator.detectType(hash);
            expect(inputType).toBe('hash');

            // PRESERVATION: Validation should pass
            const validation = InputValidator.validate(hash);
            expect(validation.valid).toBe(true);
          }
        ),
        { numRuns: 15 }
      );
    });
  });

  /**
   * PRESERVATION PROPERTY 4: Verdict Threshold Logic (2+ sources = MALICIOUS)
   * 
   * For all combinations of threat flags from multiple sources:
   * - 2 or more sources flagged → MALICIOUS
   * - Fewer than 2 sources flagged → CLEAR/UNVERIFIED
   * - N/A services excluded from count
   * 
   * Validates: Requirements 3.5, 3.6, 3.7
   */
  describe('Preservation: Verdict Threshold Logic', () => {
    it('should apply 2+ threshold for MALICIOUS verdict', () => {
      fc.assert(
        fc.property(
          fc.boolean(), // VirusTotal threat flag
          fc.boolean(), // AbuseIPDB threat flag
          fc.boolean(), // URLScan threat flag
          (vtThreat, abuseThreat, urlscanThreat) => {
            // Create source data
            const sourcesData = {
              virustotal: { threatFlag: vtThreat },
              abuseipdb: { threatFlag: abuseThreat },
              urlscan: { threatFlag: urlscanThreat }
            };

            // Calculate verdict
            const verdict = VerdictCalculator.calculate(sourcesData);

            // Count threats
            const threatCount = [vtThreat, abuseThreat, urlscanThreat].filter(Boolean).length;

            // PRESERVATION: Verdict threshold should be 2+
            if (threatCount >= 2) {
              expect(verdict.status).toBe('MALICIOUS');
            } else {
              expect(verdict.status).toBe('CLEAR/UNVERIFIED');
            }

            expect(verdict.threatCount).toBe(threatCount);
          }
        ),
        { numRuns: 50 } // Test all 8 combinations multiple times
      );
    });

    it('should correctly count threat sources', () => {
      // Test specific combinations
      const testCases = [
        { vt: false, abuse: false, urlscan: false, expected: 'CLEAR/UNVERIFIED', count: 0 },
        { vt: true, abuse: false, urlscan: false, expected: 'CLEAR/UNVERIFIED', count: 1 },
        { vt: false, abuse: true, urlscan: false, expected: 'CLEAR/UNVERIFIED', count: 1 },
        { vt: false, abuse: false, urlscan: true, expected: 'CLEAR/UNVERIFIED', count: 1 },
        { vt: true, abuse: true, urlscan: false, expected: 'MALICIOUS', count: 2 },
        { vt: true, abuse: false, urlscan: true, expected: 'MALICIOUS', count: 2 },
        { vt: false, abuse: true, urlscan: true, expected: 'MALICIOUS', count: 2 },
        { vt: true, abuse: true, urlscan: true, expected: 'MALICIOUS', count: 3 }
      ];

      testCases.forEach(({ vt, abuse, urlscan, expected, count }) => {
        const sourcesData = {
          virustotal: { threatFlag: vt },
          abuseipdb: { threatFlag: abuse },
          urlscan: { threatFlag: urlscan }
        };

        const verdict = VerdictCalculator.calculate(sourcesData);

        // PRESERVATION: Verdict status and count should match expected
        expect(verdict.status).toBe(expected);
        expect(verdict.threatCount).toBe(count);
      });
    });
  });

  /**
   * PRESERVATION PROPERTY 5: Service Applicability Rules
   * 
   * For different input types, the correct services should be queried:
   * - IP → VirusTotal + AbuseIPDB (URLScan N/A)
   * - Domain → VirusTotal + URLScan (AbuseIPDB N/A)
   * - Hash → VirusTotal only (AbuseIPDB and URLScan N/A)
   * 
   * Validates: Requirements 3.2, 3.3, 3.4, 3.7
   */
  describe('Preservation: Service Applicability Rules', () => {
    it('should query correct services for IP addresses', async () => {
      // Set up API keys
      localStorage.setItem('vtApiKey', btoa('test-vt-key'));
      localStorage.setItem('abuseipdbApiKey', btoa('test-abuse-key'));

      // Mock responses
      global.fetch.mockResolvedValue({
        ok: true,
        json: async () => ({
          data: {
            attributes: {
              last_analysis_stats: {
                malicious: 0,
                suspicious: 0,
                undetected: 50,
                harmless: 0,
                timeout: 0
              }
            },
            abuseConfidenceScore: 0
          }
        })
      });

      // Fetch all services for IP
      const results = await APIOrchestrator.fetchAll('8.8.8.8', 'ip');

      // PRESERVATION: VirusTotal and AbuseIPDB should be queried
      expect(results.virustotal).toBeDefined();
      expect(results.abuseipdb).toBeDefined();

      // PRESERVATION: URLScan should be N/A for IPs
      expect(results.urlscan).toBeDefined();
      expect(results.urlscan.notApplicable).toBe(true);
      expect(results.urlscan.reason).toContain('URL/Domain only');
    });

    it('should query correct services for domains', async () => {
      // Set up API keys
      localStorage.setItem('vtApiKey', btoa('test-vt-key'));
      localStorage.setItem('urlscanApiKey', btoa('test-urlscan-key'));

      // Mock responses
      global.fetch.mockImplementation(async (url) => {
        if (url.includes('virustotal.com')) {
          return {
            ok: true,
            json: async () => ({
              data: {
                attributes: {
                  last_analysis_stats: {
                    malicious: 0,
                    suspicious: 0,
                    undetected: 50,
                    harmless: 0,
                    timeout: 0
                  }
                }
              }
            })
          };
        }
        if (url.includes('/scan/')) {
          return {
            ok: true,
            json: async () => ({ uuid: 'test-uuid' })
          };
        }
        if (url.includes('/result/')) {
          return {
            ok: true,
            status: 200,
            json: async () => ({
              verdicts: { overall: { malicious: false } }
            })
          };
        }
        return { ok: false, status: 404 };
      });

      // Fetch all services for domain
      const results = await APIOrchestrator.fetchAll('example.com', 'domain');

      // PRESERVATION: VirusTotal and URLScan should be queried
      expect(results.virustotal).toBeDefined();
      expect(results.urlscan).toBeDefined();

      // PRESERVATION: AbuseIPDB should be N/A for domains
      expect(results.abuseipdb).toBeDefined();
      expect(results.abuseipdb.notApplicable).toBe(true);
      expect(results.abuseipdb.reason).toContain('IP only');
    });

    it('should query only VirusTotal for hashes', async () => {
      // Set up API key
      localStorage.setItem('vtApiKey', btoa('test-vt-key'));

      // Mock response
      global.fetch.mockResolvedValue({
        ok: true,
        json: async () => ({
          data: {
            attributes: {
              last_analysis_stats: {
                malicious: 0,
                suspicious: 0,
                undetected: 50,
                harmless: 0,
                timeout: 0
              }
            }
          }
        })
      });

      // Fetch all services for hash
      const results = await APIOrchestrator.fetchAll('d41d8cd98f00b204e9800998ecf8427e', 'hash');

      // PRESERVATION: Only VirusTotal should be queried
      expect(results.virustotal).toBeDefined();

      // PRESERVATION: AbuseIPDB and URLScan should be N/A for hashes
      expect(results.abuseipdb).toBeDefined();
      expect(results.abuseipdb.notApplicable).toBe(true);
      expect(results.urlscan).toBeDefined();
      expect(results.urlscan.notApplicable).toBe(true);
    });
  });

  /**
   * PRESERVATION PROPERTY 6: Error Handling
   * 
   * When API errors occur, the system should:
   * - Display error messages in service cards
   * - Not crash the application
   * - Continue with other services
   * 
   * Validates: Requirement 3.9
   */
  describe('Preservation: Error Handling', () => {
    it('should handle VirusTotal API errors gracefully', async () => {
      // Set up API key
      localStorage.setItem('vtApiKey', btoa('test-vt-key'));

      // Mock error response
      global.fetch.mockResolvedValue({
        ok: false,
        status: 401
      });

      // Fetch VirusTotal data
      await expect(async () => {
        await APIOrchestrator.fetchVirusTotal('8.8.8.8', 'ip');
      }).rejects.toThrow('VirusTotal: Invalid API key');
    });

    it('should handle network failures gracefully', async () => {
      // Set up API key
      localStorage.setItem('vtApiKey', btoa('test-vt-key'));

      // Mock network error
      global.fetch.mockRejectedValue(new TypeError('fetch failed'));

      // Fetch VirusTotal data
      await expect(async () => {
        await APIOrchestrator.fetchVirusTotal('8.8.8.8', 'ip');
      }).rejects.toThrow('VirusTotal: Network failure');
    });

    it('should handle rate limit errors gracefully', async () => {
      // Set up API key
      localStorage.setItem('vtApiKey', btoa('test-vt-key'));

      // Mock rate limit response
      global.fetch.mockResolvedValue({
        ok: false,
        status: 429
      });

      // Fetch VirusTotal data
      await expect(async () => {
        await APIOrchestrator.fetchVirusTotal('8.8.8.8', 'ip');
      }).rejects.toThrow('VirusTotal: Rate limit exceeded');
    });
  });

  /**
   * PRESERVATION PROPERTY 7: Search History
   * 
   * Search history should:
   * - Store last 10 searches
   * - Persist to localStorage
   * - Display with timestamps and verdicts
   * 
   * Validates: Requirement 3.8
   */
  describe('Preservation: Search History', () => {
    it('should save searches to history', () => {
      // Initialize
      ThreatIntelHub.init();

      // Save a search
      ThreatIntelHub.saveToHistory({
        input: '8.8.8.8',
        inputType: 'ip',
        verdict: 'CLEAR/UNVERIFIED',
        timestamp: new Date().toISOString()
      });

      // PRESERVATION: History should contain the search
      expect(ThreatIntelState.searchHistory.length).toBe(1);
      expect(ThreatIntelState.searchHistory[0].input).toBe('8.8.8.8');
    });

    it('should limit history to 10 items', () => {
      // Initialize
      ThreatIntelHub.init();

      // Add 15 searches
      for (let i = 0; i < 15; i++) {
        ThreatIntelHub.saveToHistory({
          input: `192.168.1.${i}`,
          inputType: 'ip',
          verdict: 'CLEAR/UNVERIFIED',
          timestamp: new Date().toISOString()
        });
      }

      // PRESERVATION: History should be limited to 10 items
      expect(ThreatIntelState.searchHistory.length).toBe(10);
    });

    it('should persist history to localStorage', () => {
      // Initialize
      ThreatIntelHub.init();

      // Save a search
      ThreatIntelHub.saveToHistory({
        input: 'example.com',
        inputType: 'domain',
        verdict: 'MALICIOUS',
        timestamp: new Date().toISOString()
      });

      // PRESERVATION: History should be in localStorage
      const stored = localStorage.getItem('threat-intel-history');
      expect(stored).not.toBeNull();
      
      const parsed = JSON.parse(stored);
      expect(parsed.length).toBe(1);
      expect(parsed[0].input).toBe('example.com');
    });
  });

  /**
   * PRESERVATION PROPERTY 8: UI Details Expansion
   * 
   * "View Details" functionality should:
   * - Toggle raw JSON display
   * - Rotate chevron icon
   * - Work for all service cards
   * 
   * Validates: Requirement 3.10
   */
  describe('Preservation: UI Details Expansion', () => {
    it('should toggle details visibility', () => {
      // Render a source card with data
      const mockData = {
        threatFlag: true,
        displayText: 'Test threat detected',
        rawData: { test: 'data' }
      };

      UIRenderer.renderSourceCard('virustotal', mockData);

      // Get details element
      const resultsEl = document.getElementById('virustotal-results');
      const detailsEl = resultsEl.querySelector('.source-details');

      // PRESERVATION: Details should be hidden initially
      expect(detailsEl.classList.contains('hidden')).toBe(true);

      // Toggle details
      UIRenderer.toggleDetails('virustotal');

      // PRESERVATION: Details should now be visible
      expect(detailsEl.classList.contains('hidden')).toBe(false);

      // Toggle again
      UIRenderer.toggleDetails('virustotal');

      // PRESERVATION: Details should be hidden again
      expect(detailsEl.classList.contains('hidden')).toBe(true);
    });
  });
});

