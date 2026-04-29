/**
 * Unit tests for VerdictCalculator module
 * Tests verdict calculation logic and threshold application
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { VerdictCalculator } from './threat-intel.js';

describe('VerdictCalculator', () => {
  describe('calculate()', () => {
    it('should return CLEAR/UNVERIFIED when no sources flag threats', () => {
      const sourcesData = {
        virustotal: { threatFlag: false },
        abuseipdb: { threatFlag: false },
        urlscan: { threatFlag: false }
      };

      const result = VerdictCalculator.calculate(sourcesData);

      expect(result.status).toBe('CLEAR/UNVERIFIED');
      expect(result.threatCount).toBe(0);
      expect(result.sources.virustotal).toBe(false);
      expect(result.sources.abuseipdb).toBe(false);
      expect(result.sources.urlscan).toBe(false);
      expect(result.timestamp).toBeDefined();
      expect(typeof result.timestamp).toBe('string');
    });

    it('should return CLEAR/UNVERIFIED when only 1 source flags threat', () => {
      const sourcesData = {
        virustotal: { threatFlag: true },
        abuseipdb: { threatFlag: false },
        urlscan: { threatFlag: false }
      };

      const result = VerdictCalculator.calculate(sourcesData);

      expect(result.status).toBe('CLEAR/UNVERIFIED');
      expect(result.threatCount).toBe(1);
      expect(result.sources.virustotal).toBe(true);
      expect(result.sources.abuseipdb).toBe(false);
      expect(result.sources.urlscan).toBe(false);
    });

    it('should return MALICIOUS when exactly 2 sources flag threats', () => {
      const sourcesData = {
        virustotal: { threatFlag: true },
        abuseipdb: { threatFlag: true },
        urlscan: { threatFlag: false }
      };

      const result = VerdictCalculator.calculate(sourcesData);

      expect(result.status).toBe('MALICIOUS');
      expect(result.threatCount).toBe(2);
      expect(result.sources.virustotal).toBe(true);
      expect(result.sources.abuseipdb).toBe(true);
      expect(result.sources.urlscan).toBe(false);
    });

    it('should return MALICIOUS when all 3 sources flag threats', () => {
      const sourcesData = {
        virustotal: { threatFlag: true },
        abuseipdb: { threatFlag: true },
        urlscan: { threatFlag: true }
      };

      const result = VerdictCalculator.calculate(sourcesData);

      expect(result.status).toBe('MALICIOUS');
      expect(result.threatCount).toBe(3);
      expect(result.sources.virustotal).toBe(true);
      expect(result.sources.abuseipdb).toBe(true);
      expect(result.sources.urlscan).toBe(true);
    });

    it('should handle missing source data gracefully', () => {
      const sourcesData = {
        virustotal: { threatFlag: true },
        abuseipdb: null,
        urlscan: undefined
      };

      const result = VerdictCalculator.calculate(sourcesData);

      expect(result.status).toBe('CLEAR/UNVERIFIED');
      expect(result.threatCount).toBe(1);
      expect(result.sources.virustotal).toBe(true);
      expect(result.sources.abuseipdb).toBe(false);
      expect(result.sources.urlscan).toBe(false);
    });

    it('should handle sources with threatFlag explicitly false', () => {
      const sourcesData = {
        virustotal: { threatFlag: false },
        abuseipdb: { threatFlag: false },
        urlscan: { threatFlag: true }
      };

      const result = VerdictCalculator.calculate(sourcesData);

      expect(result.status).toBe('CLEAR/UNVERIFIED');
      expect(result.threatCount).toBe(1);
      expect(result.sources.urlscan).toBe(true);
    });

    it('should return valid ISO 8601 timestamp', () => {
      const sourcesData = {
        virustotal: { threatFlag: false },
        abuseipdb: { threatFlag: false },
        urlscan: { threatFlag: false }
      };

      const result = VerdictCalculator.calculate(sourcesData);

      // Verify timestamp is valid ISO 8601 format
      const timestamp = new Date(result.timestamp);
      expect(timestamp.toISOString()).toBe(result.timestamp);
    });

    it('should handle different combinations of 2 threat sources', () => {
      // Test VirusTotal + URLScan
      const combo1 = {
        virustotal: { threatFlag: true },
        abuseipdb: { threatFlag: false },
        urlscan: { threatFlag: true }
      };

      const result1 = VerdictCalculator.calculate(combo1);
      expect(result1.status).toBe('MALICIOUS');
      expect(result1.threatCount).toBe(2);

      // Test AbuseIPDB + URLScan
      const combo2 = {
        virustotal: { threatFlag: false },
        abuseipdb: { threatFlag: true },
        urlscan: { threatFlag: true }
      };

      const result2 = VerdictCalculator.calculate(combo2);
      expect(result2.status).toBe('MALICIOUS');
      expect(result2.threatCount).toBe(2);
    });

    it('should only count threatFlag === true (not truthy values)', () => {
      const sourcesData = {
        virustotal: { threatFlag: 1 }, // truthy but not true
        abuseipdb: { threatFlag: 'yes' }, // truthy but not true
        urlscan: { threatFlag: true }
      };

      const result = VerdictCalculator.calculate(sourcesData);

      // Should only count the one with true
      expect(result.status).toBe('CLEAR/UNVERIFIED');
      expect(result.threatCount).toBe(1);
      expect(result.sources.urlscan).toBe(true);
    });

    it('should handle empty sourcesData object', () => {
      const sourcesData = {};

      const result = VerdictCalculator.calculate(sourcesData);

      expect(result.status).toBe('CLEAR/UNVERIFIED');
      expect(result.threatCount).toBe(0);
      expect(result.sources.virustotal).toBe(false);
      expect(result.sources.abuseipdb).toBe(false);
      expect(result.sources.urlscan).toBe(false);
    });
  });
});
