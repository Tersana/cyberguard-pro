/**
 * Unit tests for Threat Intel Hub module
 * Tests VirusTotal API integration
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { JSDOM } from 'jsdom';

// Set up DOM environment with proper URL
const dom = new JSDOM('<!DOCTYPE html><html><body></body></html>', {
  url: 'http://localhost'
});
global.window = dom.window;
global.document = dom.window.document;
global.localStorage = {
  store: {},
  getItem(key) {
    return this.store[key] || null;
  },
  setItem(key, value) {
    this.store[key] = String(value);
  },
  removeItem(key) {
    delete this.store[key];
  },
  clear() {
    this.store = {};
  }
};
global.fetch = vi.fn();
global.btoa = (str) => Buffer.from(str, 'binary').toString('base64');
global.atob = (str) => Buffer.from(str, 'base64').toString('binary');

// Import module after setting up globals
const { APIOrchestrator } = await import('./threat-intel.js');

describe('VirusTotal API Integration', () => {
  beforeEach(() => {
    // Clear localStorage before each test
    localStorage.clear();
    // Reset fetch mock
    vi.clearAllMocks();
  });

  afterEach(() => {
    localStorage.clear();
  });

  describe('fetchVirusTotal', () => {
    it('should fetch IP address data from VirusTotal', async () => {
      // Set up API key in localStorage (encrypted)
      const apiKey = 'test-vt-api-key';
      const encrypted = btoa(apiKey); // Simplified for test
      localStorage.setItem('vtApiKey', encrypted);

      // Mock successful response
      const mockResponse = {
        data: {
          attributes: {
            last_analysis_stats: {
              malicious: 5,
              suspicious: 2,
              undetected: 63,
              harmless: 0,
              timeout: 0
            }
          }
        }
      };

      global.fetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => mockResponse
      });

      const result = await APIOrchestrator.fetchVirusTotal('8.8.8.8', 'ip');

      expect(result).toEqual(mockResponse);
      expect(global.fetch).toHaveBeenCalledTimes(1);
      
      // Verify the URL includes the correct endpoint
      const callArgs = global.fetch.mock.calls[0];
      expect(callArgs[0]).toContain('ip_addresses');
      expect(callArgs[0]).toContain('8.8.8.8');
      
      // Verify headers include API key
      expect(callArgs[1].headers['x-apikey']).toBeDefined();
    });

    it('should fetch domain data from VirusTotal', async () => {
      const apiKey = 'test-vt-api-key';
      const encrypted = btoa(apiKey);
      localStorage.setItem('vtApiKey', encrypted);

      const mockResponse = {
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

      global.fetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => mockResponse
      });

      const result = await APIOrchestrator.fetchVirusTotal('example.com', 'domain');

      expect(result).toEqual(mockResponse);
      
      const callArgs = global.fetch.mock.calls[0];
      expect(callArgs[0]).toContain('domains');
      expect(callArgs[0]).toContain('example.com');
    });

    it('should fetch file hash data from VirusTotal', async () => {
      const apiKey = 'test-vt-api-key';
      const encrypted = btoa(apiKey);
      localStorage.setItem('vtApiKey', encrypted);

      const mockResponse = {
        data: {
          attributes: {
            last_analysis_stats: {
              malicious: 10,
              suspicious: 5,
              undetected: 55,
              harmless: 0,
              timeout: 0
            }
          }
        }
      };

      global.fetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => mockResponse
      });

      const hash = 'a'.repeat(64); // SHA-256 hash
      const result = await APIOrchestrator.fetchVirusTotal(hash, 'file');

      expect(result).toEqual(mockResponse);
      
      const callArgs = global.fetch.mock.calls[0];
      expect(callArgs[0]).toContain('files');
      expect(callArgs[0]).toContain(hash);
    });

    it('should throw error when API key is missing', async () => {
      // No API key in localStorage
      
      await expect(
        APIOrchestrator.fetchVirusTotal('8.8.8.8', 'ip')
      ).rejects.toThrow('VirusTotal API key not configured');
    });

    it('should handle 401 unauthorized error', async () => {
      const apiKey = 'invalid-key';
      const encrypted = btoa(apiKey);
      localStorage.setItem('vtApiKey', encrypted);

      global.fetch.mockResolvedValueOnce({
        ok: false,
        status: 401
      });

      await expect(
        APIOrchestrator.fetchVirusTotal('8.8.8.8', 'ip')
      ).rejects.toThrow('VirusTotal: Invalid API key');
    });

    it('should handle 429 rate limit error', async () => {
      const apiKey = 'test-key';
      const encrypted = btoa(apiKey);
      localStorage.setItem('vtApiKey', encrypted);

      global.fetch.mockResolvedValueOnce({
        ok: false,
        status: 429
      });

      await expect(
        APIOrchestrator.fetchVirusTotal('8.8.8.8', 'ip')
      ).rejects.toThrow('VirusTotal: Rate limit exceeded');
    });

    it('should handle 404 not found error', async () => {
      const apiKey = 'test-key';
      const encrypted = btoa(apiKey);
      localStorage.setItem('vtApiKey', encrypted);

      global.fetch.mockResolvedValueOnce({
        ok: false,
        status: 404
      });

      await expect(
        APIOrchestrator.fetchVirusTotal('nonexistent-hash', 'file')
      ).rejects.toThrow('VirusTotal: Resource not found');
    });

    it('should handle network errors', async () => {
      const apiKey = 'test-key';
      const encrypted = btoa(apiKey);
      localStorage.setItem('vtApiKey', encrypted);

      global.fetch.mockRejectedValueOnce(new TypeError('Failed to fetch'));

      await expect(
        APIOrchestrator.fetchVirusTotal('8.8.8.8', 'ip')
      ).rejects.toThrow('VirusTotal: Network failure');
    });

    it('should throw error for invalid type', async () => {
      const apiKey = 'test-key';
      const encrypted = btoa(apiKey);
      localStorage.setItem('vtApiKey', encrypted);

      await expect(
        APIOrchestrator.fetchVirusTotal('test', 'invalid')
      ).rejects.toThrow('Invalid type: invalid');
    });

    it('should use PROXY_URL for CORS bypass', async () => {
      const apiKey = 'test-key';
      const encrypted = btoa(apiKey);
      localStorage.setItem('vtApiKey', encrypted);

      global.fetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ data: {} })
      });

      await APIOrchestrator.fetchVirusTotal('8.8.8.8', 'ip');

      const callArgs = global.fetch.mock.calls[0];
      expect(callArgs[0]).toContain('corsproxy.io');
    });
  });
});

describe('AbuseIPDB API Integration', () => {
  beforeEach(() => {
    localStorage.clear();
    vi.clearAllMocks();
  });

  afterEach(() => {
    localStorage.clear();
  });

  describe('fetchAbuseIPDB', () => {
    it('should fetch IP reputation data from AbuseIPDB', async () => {
      // Set up API key in localStorage (encrypted)
      const apiKey = 'test-abuseipdb-api-key';
      const encrypted = btoa(apiKey);
      localStorage.setItem('abuseipdbApiKey', encrypted);

      // Mock successful response
      const mockResponse = {
        data: {
          abuseConfidenceScore: 75,
          usageType: 'Data Center/Web Hosting/Transit',
          isp: 'Google LLC',
          domain: 'google.com',
          totalReports: 150
        }
      };

      global.fetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => mockResponse
      });

      const result = await APIOrchestrator.fetchAbuseIPDB('8.8.8.8');

      expect(result).toEqual(mockResponse);
      expect(global.fetch).toHaveBeenCalledTimes(1);
      
      // Verify the URL includes the correct endpoint and query parameters
      const callArgs = global.fetch.mock.calls[0];
      const url = callArgs[0];
      
      // URL is encoded through proxy, so decode it to check
      const decodedUrl = decodeURIComponent(url);
      expect(decodedUrl).toContain('api.abuseipdb.com');
      expect(decodedUrl).toContain('check');
      expect(decodedUrl).toContain('ipAddress=8.8.8.8');
      expect(decodedUrl).toContain('maxAgeInDays=90');
      
      // Verify headers include Key and Accept
      expect(callArgs[1].headers['Key']).toBeDefined();
      expect(callArgs[1].headers['Accept']).toBe('application/json');
    });

    it('should include maxAgeInDays parameter set to 90', async () => {
      const apiKey = 'test-key';
      const encrypted = btoa(apiKey);
      localStorage.setItem('abuseipdbApiKey', encrypted);

      global.fetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ data: { abuseConfidenceScore: 0 } })
      });

      await APIOrchestrator.fetchAbuseIPDB('192.168.1.1');

      const callArgs = global.fetch.mock.calls[0];
      const decodedUrl = decodeURIComponent(callArgs[0]);
      expect(decodedUrl).toContain('maxAgeInDays=90');
    });

    it('should throw error when API key is missing', async () => {
      // No API key in localStorage
      
      await expect(
        APIOrchestrator.fetchAbuseIPDB('8.8.8.8')
      ).rejects.toThrow('AbuseIPDB API key not configured');
    });

    it('should handle 401 unauthorized error', async () => {
      const apiKey = 'invalid-key';
      const encrypted = btoa(apiKey);
      localStorage.setItem('abuseipdbApiKey', encrypted);

      global.fetch.mockResolvedValueOnce({
        ok: false,
        status: 401
      });

      await expect(
        APIOrchestrator.fetchAbuseIPDB('8.8.8.8')
      ).rejects.toThrow('AbuseIPDB: Invalid API key');
    });

    it('should handle 403 forbidden error', async () => {
      const apiKey = 'test-key';
      const encrypted = btoa(apiKey);
      localStorage.setItem('abuseipdbApiKey', encrypted);

      global.fetch.mockResolvedValueOnce({
        ok: false,
        status: 403
      });

      await expect(
        APIOrchestrator.fetchAbuseIPDB('8.8.8.8')
      ).rejects.toThrow('AbuseIPDB: Invalid API key');
    });

    it('should handle 429 rate limit error', async () => {
      const apiKey = 'test-key';
      const encrypted = btoa(apiKey);
      localStorage.setItem('abuseipdbApiKey', encrypted);

      global.fetch.mockResolvedValueOnce({
        ok: false,
        status: 429
      });

      await expect(
        APIOrchestrator.fetchAbuseIPDB('8.8.8.8')
      ).rejects.toThrow('AbuseIPDB: Rate limit exceeded');
    });

    it('should handle 404 not found error', async () => {
      const apiKey = 'test-key';
      const encrypted = btoa(apiKey);
      localStorage.setItem('abuseipdbApiKey', encrypted);

      global.fetch.mockResolvedValueOnce({
        ok: false,
        status: 404
      });

      await expect(
        APIOrchestrator.fetchAbuseIPDB('8.8.8.8')
      ).rejects.toThrow('AbuseIPDB: Resource not found');
    });

    it('should handle network errors', async () => {
      const apiKey = 'test-key';
      const encrypted = btoa(apiKey);
      localStorage.setItem('abuseipdbApiKey', encrypted);

      global.fetch.mockRejectedValueOnce(new TypeError('Failed to fetch'));

      await expect(
        APIOrchestrator.fetchAbuseIPDB('8.8.8.8')
      ).rejects.toThrow('AbuseIPDB: Network failure');
    });

    it('should use PROXY_URL for CORS bypass', async () => {
      const apiKey = 'test-key';
      const encrypted = btoa(apiKey);
      localStorage.setItem('abuseipdbApiKey', encrypted);

      global.fetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ data: { abuseConfidenceScore: 0 } })
      });

      await APIOrchestrator.fetchAbuseIPDB('8.8.8.8');

      const callArgs = global.fetch.mock.calls[0];
      expect(callArgs[0]).toContain('corsproxy.io');
    });

    it('should handle high confidence score response', async () => {
      const apiKey = 'test-key';
      const encrypted = btoa(apiKey);
      localStorage.setItem('abuseipdbApiKey', encrypted);

      const mockResponse = {
        data: {
          abuseConfidenceScore: 100,
          usageType: 'Unknown',
          isp: 'Malicious ISP',
          totalReports: 500
        }
      };

      global.fetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => mockResponse
      });

      const result = await APIOrchestrator.fetchAbuseIPDB('1.2.3.4');

      expect(result.data.abuseConfidenceScore).toBe(100);
      expect(result.data.totalReports).toBe(500);
    });

    it('should handle zero confidence score response', async () => {
      const apiKey = 'test-key';
      const encrypted = btoa(apiKey);
      localStorage.setItem('abuseipdbApiKey', encrypted);

      const mockResponse = {
        data: {
          abuseConfidenceScore: 0,
          usageType: 'Content Delivery Network',
          isp: 'Cloudflare',
          totalReports: 0
        }
      };

      global.fetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => mockResponse
      });

      const result = await APIOrchestrator.fetchAbuseIPDB('1.1.1.1');

      expect(result.data.abuseConfidenceScore).toBe(0);
      expect(result.data.totalReports).toBe(0);
    });
  });
});

describe('URLScan.io API Integration', () => {
  beforeEach(() => {
    localStorage.clear();
    vi.clearAllMocks();
  });

  afterEach(() => {
    localStorage.clear();
  });

  describe('fetchURLScan', () => {
    it('should submit scan and poll for results successfully', async () => {
      // Set up API key in localStorage (encrypted)
      const apiKey = 'test-urlscan-api-key';
      const encrypted = btoa(apiKey);
      localStorage.setItem('urlscanApiKey', encrypted);

      // Mock scan submission response
      const submitResponse = {
        uuid: 'test-uuid-12345',
        api: 'https://urlscan.io/api/v1/result/test-uuid-12345/'
      };

      // Mock scan result response
      const resultResponse = {
        verdicts: {
          overall: {
            score: 0,
            malicious: false,
            categories: []
          }
        }
      };

      // Mock fetch calls: first for submission, second for result
      global.fetch
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          json: async () => submitResponse
        })
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          json: async () => resultResponse
        });

      const result = await APIOrchestrator.fetchURLScan('example.com');

      expect(result).toEqual(resultResponse);
      expect(global.fetch).toHaveBeenCalledTimes(2);
      
      // Verify submission call
      const submitCall = global.fetch.mock.calls[0];
      expect(submitCall[1].method).toBe('POST');
      expect(submitCall[1].headers['API-Key']).toBeDefined();
      expect(submitCall[1].headers['Content-Type']).toBe('application/json');
      
      const submitBody = JSON.parse(submitCall[1].body);
      expect(submitBody.url).toBe('example.com');
      expect(submitBody.visibility).toBe('private');
      
      // Verify result polling call
      const resultCall = global.fetch.mock.calls[1];
      expect(resultCall[1].method).toBe('GET');
      expect(resultCall[1].headers['API-Key']).toBeDefined();
    });

    it('should handle 404 during polling and retry', async () => {
      const apiKey = 'test-key';
      const encrypted = btoa(apiKey);
      localStorage.setItem('urlscanApiKey', encrypted);

      const submitResponse = {
        uuid: 'test-uuid-12345'
      };

      const resultResponse = {
        verdicts: {
          overall: {
            score: 100,
            malicious: true,
            categories: ['malware']
          }
        }
      };

      // Mock: submission succeeds, first poll returns 404, second poll returns 200
      global.fetch
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          json: async () => submitResponse
        })
        .mockResolvedValueOnce({
          ok: false,
          status: 404
        })
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          json: async () => resultResponse
        });

      const result = await APIOrchestrator.fetchURLScan('malicious.com');

      expect(result).toEqual(resultResponse);
      expect(global.fetch).toHaveBeenCalledTimes(3); // 1 submit + 2 polls
    });

    it('should timeout after 30 seconds of polling', async () => {
      const apiKey = 'test-key';
      const encrypted = btoa(apiKey);
      localStorage.setItem('urlscanApiKey', encrypted);

      const submitResponse = {
        uuid: 'test-uuid-12345'
      };

      // Mock: submission succeeds, all polls return 404
      global.fetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => submitResponse
      });

      // Mock 30 consecutive 404 responses
      for (let i = 0; i < 30; i++) {
        global.fetch.mockResolvedValueOnce({
          ok: false,
          status: 404
        });
      }

      await expect(
        APIOrchestrator.fetchURLScan('slow-domain.com')
      ).rejects.toThrow('URLScan: Request timeout - scan did not complete in 30 seconds');

      // Should have made 1 submit + 30 poll attempts
      expect(global.fetch).toHaveBeenCalledTimes(31);
    }, 35000); // Increase test timeout to 35 seconds

    it('should throw error when API key is missing', async () => {
      // No API key in localStorage
      
      await expect(
        APIOrchestrator.fetchURLScan('example.com')
      ).rejects.toThrow('URLScan API key not configured');
    });

    it('should handle 401 unauthorized error during submission', async () => {
      const apiKey = 'invalid-key';
      const encrypted = btoa(apiKey);
      localStorage.setItem('urlscanApiKey', encrypted);

      global.fetch.mockResolvedValueOnce({
        ok: false,
        status: 401
      });

      await expect(
        APIOrchestrator.fetchURLScan('example.com')
      ).rejects.toThrow('URLScan: Invalid API key');
    });

    it('should handle 403 forbidden error during submission', async () => {
      const apiKey = 'test-key';
      const encrypted = btoa(apiKey);
      localStorage.setItem('urlscanApiKey', encrypted);

      global.fetch.mockResolvedValueOnce({
        ok: false,
        status: 403
      });

      await expect(
        APIOrchestrator.fetchURLScan('example.com')
      ).rejects.toThrow('URLScan: Invalid API key');
    });

    it('should handle 429 rate limit error during submission', async () => {
      const apiKey = 'test-key';
      const encrypted = btoa(apiKey);
      localStorage.setItem('urlscanApiKey', encrypted);

      global.fetch.mockResolvedValueOnce({
        ok: false,
        status: 429
      });

      await expect(
        APIOrchestrator.fetchURLScan('example.com')
      ).rejects.toThrow('URLScan: Rate limit exceeded');
    });

    it('should handle network errors during submission', async () => {
      const apiKey = 'test-key';
      const encrypted = btoa(apiKey);
      localStorage.setItem('urlscanApiKey', encrypted);

      global.fetch.mockRejectedValueOnce(new TypeError('Failed to fetch'));

      await expect(
        APIOrchestrator.fetchURLScan('example.com')
      ).rejects.toThrow('URLScan: Network failure');
    });

    it('should handle missing UUID in submission response', async () => {
      const apiKey = 'test-key';
      const encrypted = btoa(apiKey);
      localStorage.setItem('urlscanApiKey', encrypted);

      // Mock submission response without UUID
      global.fetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ message: 'Scan submitted' })
      });

      await expect(
        APIOrchestrator.fetchURLScan('example.com')
      ).rejects.toThrow('URLScan: No UUID returned from scan submission');
    });

    it('should use PROXY_URL for CORS bypass', async () => {
      const apiKey = 'test-key';
      const encrypted = btoa(apiKey);
      localStorage.setItem('urlscanApiKey', encrypted);

      const submitResponse = { uuid: 'test-uuid' };
      const resultResponse = { verdicts: { overall: { malicious: false } } };

      global.fetch
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          json: async () => submitResponse
        })
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          json: async () => resultResponse
        });

      await APIOrchestrator.fetchURLScan('example.com');

      // Both calls should use proxy
      const submitCall = global.fetch.mock.calls[0];
      const resultCall = global.fetch.mock.calls[1];
      
      expect(submitCall[0]).toContain('corsproxy.io');
      expect(resultCall[0]).toContain('corsproxy.io');
    });

    it('should set visibility to private in submission', async () => {
      const apiKey = 'test-key';
      const encrypted = btoa(apiKey);
      localStorage.setItem('urlscanApiKey', encrypted);

      const submitResponse = { uuid: 'test-uuid' };
      const resultResponse = { verdicts: { overall: { malicious: false } } };

      global.fetch
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          json: async () => submitResponse
        })
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          json: async () => resultResponse
        });

      await APIOrchestrator.fetchURLScan('example.com');

      const submitCall = global.fetch.mock.calls[0];
      const submitBody = JSON.parse(submitCall[1].body);
      
      expect(submitBody.visibility).toBe('private');
    });

    it('should handle unexpected status during polling', async () => {
      const apiKey = 'test-key';
      const encrypted = btoa(apiKey);
      localStorage.setItem('urlscanApiKey', encrypted);

      const submitResponse = { uuid: 'test-uuid' };

      global.fetch
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          json: async () => submitResponse
        })
        .mockResolvedValueOnce({
          ok: false,
          status: 500
        });

      await expect(
        APIOrchestrator.fetchURLScan('example.com')
      ).rejects.toThrow('URLScan: Unexpected status 500 while polling results');
    });

    it('should retry on network errors during polling', async () => {
      const apiKey = 'test-key';
      const encrypted = btoa(apiKey);
      localStorage.setItem('urlscanApiKey', encrypted);

      const submitResponse = { uuid: 'test-uuid' };
      const resultResponse = { verdicts: { overall: { malicious: false } } };

      global.fetch
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          json: async () => submitResponse
        })
        .mockRejectedValueOnce(new TypeError('Failed to fetch'))
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          json: async () => resultResponse
        });

      const result = await APIOrchestrator.fetchURLScan('example.com');

      expect(result).toEqual(resultResponse);
      expect(global.fetch).toHaveBeenCalledTimes(3); // 1 submit + 1 failed poll + 1 successful poll
    });

    it('should poll every 1 second', async () => {
      const apiKey = 'test-key';
      const encrypted = btoa(apiKey);
      localStorage.setItem('urlscanApiKey', encrypted);

      const submitResponse = { uuid: 'test-uuid' };
      const resultResponse = { verdicts: { overall: { malicious: false } } };

      global.fetch
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          json: async () => submitResponse
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
          json: async () => resultResponse
        });

      const startTime = Date.now();
      await APIOrchestrator.fetchURLScan('example.com');
      const endTime = Date.now();

      // Should take at least 2 seconds (2 retries with 1 second delay each)
      const duration = endTime - startTime;
      expect(duration).toBeGreaterThanOrEqual(2000);
      expect(duration).toBeLessThan(3000); // But not too long
    }, 5000);
  });

  describe('pollURLScanResult', () => {
    it('should return result immediately if scan is complete', async () => {
      const apiKey = 'test-key';
      const resultResponse = { verdicts: { overall: { malicious: false } } };

      global.fetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => resultResponse
      });

      const result = await APIOrchestrator.pollURLScanResult('test-uuid', apiKey);

      expect(result).toEqual(resultResponse);
      expect(global.fetch).toHaveBeenCalledTimes(1);
    });

    it('should retry multiple times before succeeding', async () => {
      const apiKey = 'test-key';
      const resultResponse = { verdicts: { overall: { malicious: true } } };

      // Mock 5 404s followed by success
      for (let i = 0; i < 5; i++) {
        global.fetch.mockResolvedValueOnce({
          ok: false,
          status: 404
        });
      }
      global.fetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => resultResponse
      });

      const result = await APIOrchestrator.pollURLScanResult('test-uuid', apiKey);

      expect(result).toEqual(resultResponse);
      expect(global.fetch).toHaveBeenCalledTimes(6);
    }, 10000);
  });
});
