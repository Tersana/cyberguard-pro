/**
 * Integration tests for VerdictCalculator with DataExtractor
 * Tests the complete flow from API responses to verdict calculation
 */

import { describe, it, expect } from 'vitest';
import { VerdictCalculator, DataExtractor } from './threat-intel.js';

describe('VerdictCalculator Integration', () => {
  describe('Integration with DataExtractor', () => {
    it('should calculate MALICIOUS verdict when VirusTotal and AbuseIPDB both flag threats', () => {
      // Mock VirusTotal response with malicious detections
      const vtResponse = {
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

      // Mock AbuseIPDB response with high confidence score
      const abuseResponse = {
        data: {
          abuseConfidenceScore: 85
        }
      };

      // Mock URLScan response as clean
      const urlscanResponse = {
        verdicts: {
          overall: {
            malicious: false
          }
        }
      };

      // Extract data from each source
      const vtData = DataExtractor.extractVirusTotal(vtResponse);
      const abuseData = DataExtractor.extractAbuseIPDB(abuseResponse);
      const urlscanData = DataExtractor.extractURLScan(urlscanResponse);

      // Calculate verdict
      const verdict = VerdictCalculator.calculate({
        virustotal: vtData,
        abuseipdb: abuseData,
        urlscan: urlscanData
      });

      expect(verdict.status).toBe('MALICIOUS');
      expect(verdict.threatCount).toBe(2);
      expect(verdict.sources.virustotal).toBe(true);
      expect(verdict.sources.abuseipdb).toBe(true);
      expect(verdict.sources.urlscan).toBe(false);
    });

    it('should calculate CLEAR/UNVERIFIED when only one source flags threat', () => {
      // Mock VirusTotal response with no malicious detections
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

      // Mock AbuseIPDB response with low confidence score
      const abuseResponse = {
        data: {
          abuseConfidenceScore: 25
        }
      };

      // Mock URLScan response as malicious
      const urlscanResponse = {
        verdicts: {
          overall: {
            malicious: true
          }
        }
      };

      // Extract data from each source
      const vtData = DataExtractor.extractVirusTotal(vtResponse);
      const abuseData = DataExtractor.extractAbuseIPDB(abuseResponse);
      const urlscanData = DataExtractor.extractURLScan(urlscanResponse);

      // Calculate verdict
      const verdict = VerdictCalculator.calculate({
        virustotal: vtData,
        abuseipdb: abuseData,
        urlscan: urlscanData
      });

      expect(verdict.status).toBe('CLEAR/UNVERIFIED');
      expect(verdict.threatCount).toBe(1);
      expect(verdict.sources.urlscan).toBe(true);
    });

    it('should calculate CLEAR/UNVERIFIED when all sources are clean', () => {
      // Mock VirusTotal response with no malicious detections
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

      // Mock AbuseIPDB response with zero confidence score
      const abuseResponse = {
        data: {
          abuseConfidenceScore: 0
        }
      };

      // Mock URLScan response as clean
      const urlscanResponse = {
        verdicts: {
          overall: {
            malicious: false
          }
        }
      };

      // Extract data from each source
      const vtData = DataExtractor.extractVirusTotal(vtResponse);
      const abuseData = DataExtractor.extractAbuseIPDB(abuseResponse);
      const urlscanData = DataExtractor.extractURLScan(urlscanResponse);

      // Calculate verdict
      const verdict = VerdictCalculator.calculate({
        virustotal: vtData,
        abuseipdb: abuseData,
        urlscan: urlscanData
      });

      expect(verdict.status).toBe('CLEAR/UNVERIFIED');
      expect(verdict.threatCount).toBe(0);
      expect(verdict.sources.virustotal).toBe(false);
      expect(verdict.sources.abuseipdb).toBe(false);
      expect(verdict.sources.urlscan).toBe(false);
    });

    it('should handle N/A sources correctly (IP lookup scenario)', () => {
      // Mock VirusTotal response with malicious detections
      const vtResponse = {
        data: {
          attributes: {
            last_analysis_stats: {
              malicious: 3,
              suspicious: 1,
              undetected: 66,
              harmless: 0,
              timeout: 0
            }
          }
        }
      };

      // Mock AbuseIPDB response with high confidence
      const abuseResponse = {
        data: {
          abuseConfidenceScore: 75
        }
      };

      // URLScan is N/A for IP addresses
      const urlscanResponse = {
        notApplicable: true,
        reason: 'N/A - URL/Domain only'
      };

      // Extract data from each source
      const vtData = DataExtractor.extractVirusTotal(vtResponse);
      const abuseData = DataExtractor.extractAbuseIPDB(abuseResponse);
      const urlscanData = DataExtractor.extractURLScan(urlscanResponse);

      // Calculate verdict
      const verdict = VerdictCalculator.calculate({
        virustotal: vtData,
        abuseipdb: abuseData,
        urlscan: urlscanData
      });

      expect(verdict.status).toBe('MALICIOUS');
      expect(verdict.threatCount).toBe(2);
      expect(verdict.sources.virustotal).toBe(true);
      expect(verdict.sources.abuseipdb).toBe(true);
      expect(verdict.sources.urlscan).toBe(false);
    });

    it('should handle threshold edge case (exactly 2 threats)', () => {
      // Mock VirusTotal response with 1 malicious detection
      const vtResponse = {
        data: {
          attributes: {
            last_analysis_stats: {
              malicious: 1,
              suspicious: 0,
              undetected: 69,
              harmless: 0,
              timeout: 0
            }
          }
        }
      };

      // Mock AbuseIPDB response at threshold (51%)
      const abuseResponse = {
        data: {
          abuseConfidenceScore: 51
        }
      };

      // Mock URLScan response as clean
      const urlscanResponse = {
        verdicts: {
          overall: {
            malicious: false
          }
        }
      };

      // Extract data from each source
      const vtData = DataExtractor.extractVirusTotal(vtResponse);
      const abuseData = DataExtractor.extractAbuseIPDB(abuseResponse);
      const urlscanData = DataExtractor.extractURLScan(urlscanResponse);

      // Calculate verdict
      const verdict = VerdictCalculator.calculate({
        virustotal: vtData,
        abuseipdb: abuseData,
        urlscan: urlscanData
      });

      // Should be MALICIOUS because 2 sources flagged
      expect(verdict.status).toBe('MALICIOUS');
      expect(verdict.threatCount).toBe(2);
    });
  });
});
