/**
 * Unit tests for DataExtractor module
 * Tests threat indicator extraction from API responses
 */

import { describe, it, expect } from 'vitest';

// Import DataExtractor module
const { DataExtractor } = await import('./threat-intel.js');

describe('DataExtractor', () => {
  describe('extractVirusTotal', () => {
    it('should extract threat indicators with malicious count > 0', () => {
      const response = {
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
      
      const result = DataExtractor.extractVirusTotal(response);
      
      expect(result.threatFlag).toBe(true);
      expect(result.maliciousCount).toBe(5);
      expect(result.totalEngines).toBe(70);
      expect(result.displayText).toBe('5/70 engines flagged');
      expect(result.rawData).toBe(response);
    });
    
    it('should extract threat indicators with malicious count = 0', () => {
      const response = {
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
      
      const result = DataExtractor.extractVirusTotal(response);
      
      expect(result.threatFlag).toBe(false);
      expect(result.maliciousCount).toBe(0);
      expect(result.totalEngines).toBe(70);
      expect(result.displayText).toBe('0/70 engines flagged');
    });
    
    it('should handle N/A case for non-applicable inputs', () => {
      const response = {
        notApplicable: true,
        reason: 'N/A - IP only'
      };
      
      const result = DataExtractor.extractVirusTotal(response);
      
      expect(result.threatFlag).toBe(false);
      expect(result.maliciousCount).toBe(0);
      expect(result.totalEngines).toBe(0);
      expect(result.displayText).toBe('N/A - IP only');
      expect(result.rawData).toBe(null);
    });
    
    it('should throw error for invalid response structure', () => {
      const response = {
        data: {
          attributes: {}
        }
      };
      
      expect(() => DataExtractor.extractVirusTotal(response)).toThrow('Invalid VirusTotal response structure');
    });
  });
  
  describe('extractAbuseIPDB', () => {
    it('should extract threat indicators with confidence score > 50', () => {
      const response = {
        data: {
          abuseConfidenceScore: 75,
          usageType: 'Data Center/Web Hosting/Transit',
          isp: 'Google LLC',
          domain: 'google.com',
          totalReports: 150
        }
      };
      
      const result = DataExtractor.extractAbuseIPDB(response);
      
      expect(result.threatFlag).toBe(true);
      expect(result.confidenceScore).toBe(75);
      expect(result.displayText).toBe('Confidence: 75%');
      expect(result.rawData).toBe(response);
    });
    
    it('should extract threat indicators with confidence score <= 50', () => {
      const response = {
        data: {
          abuseConfidenceScore: 25,
          usageType: 'Fixed Line ISP',
          isp: 'Comcast',
          totalReports: 5
        }
      };
      
      const result = DataExtractor.extractAbuseIPDB(response);
      
      expect(result.threatFlag).toBe(false);
      expect(result.confidenceScore).toBe(25);
      expect(result.displayText).toBe('Confidence: 25%');
    });
    
    it('should extract threat indicators with confidence score = 50 (boundary)', () => {
      const response = {
        data: {
          abuseConfidenceScore: 50
        }
      };
      
      const result = DataExtractor.extractAbuseIPDB(response);
      
      expect(result.threatFlag).toBe(false);
      expect(result.confidenceScore).toBe(50);
    });
    
    it('should handle N/A case for non-applicable inputs', () => {
      const response = {
        notApplicable: true,
        reason: 'N/A - IP only'
      };
      
      const result = DataExtractor.extractAbuseIPDB(response);
      
      expect(result.threatFlag).toBe(false);
      expect(result.confidenceScore).toBe(0);
      expect(result.displayText).toBe('N/A - IP only');
      expect(result.rawData).toBe(null);
    });
    
    it('should throw error for invalid response structure', () => {
      const response = {
        data: {}
      };
      
      expect(() => DataExtractor.extractAbuseIPDB(response)).toThrow('Invalid AbuseIPDB response structure');
    });
  });
  
  describe('extractURLScan', () => {
    it('should extract threat indicators with malicious verdict', () => {
      const response = {
        verdicts: {
          overall: {
            score: 100,
            malicious: true,
            categories: ['phishing', 'malware']
          }
        }
      };
      
      const result = DataExtractor.extractURLScan(response);
      
      expect(result.threatFlag).toBe(true);
      expect(result.verdict).toBe('Malicious');
      expect(result.displayText).toBe('Verdict: Malicious');
      expect(result.rawData).toBe(response);
    });
    
    it('should extract threat indicators with clean verdict', () => {
      const response = {
        verdicts: {
          overall: {
            score: 0,
            malicious: false,
            categories: []
          }
        }
      };
      
      const result = DataExtractor.extractURLScan(response);
      
      expect(result.threatFlag).toBe(false);
      expect(result.verdict).toBe('Clean');
      expect(result.displayText).toBe('Verdict: Clean');
    });
    
    it('should handle N/A case for non-applicable inputs', () => {
      const response = {
        notApplicable: true,
        reason: 'N/A - URL/Domain only'
      };
      
      const result = DataExtractor.extractURLScan(response);
      
      expect(result.threatFlag).toBe(false);
      expect(result.verdict).toBe('N/A');
      expect(result.displayText).toBe('N/A - URL/Domain only');
      expect(result.rawData).toBe(null);
    });
    
    it('should throw error for invalid response structure', () => {
      const response = {
        verdicts: {}
      };
      
      expect(() => DataExtractor.extractURLScan(response)).toThrow('Invalid URLScan response structure');
    });
  });
});
