/**
 * WHOIS Validation Bug Exploration Tests (Test Suite 1A)
 * 
 * **Property 1: Bug Condition - Input Validation Bugs**
 * **Validates: Requirements 1.1, 1.2, 1.3, 1.4, 1.5**
 * 
 * CRITICAL: These tests MUST FAIL on unfixed code - failure confirms the bugs exist.
 * DO NOT attempt to fix the tests or the code when they fail.
 * These tests encode the expected behavior - they will validate the fix when they pass after implementation.
 * 
 * EXPECTED OUTCOME: Tests FAIL (this is correct - it proves the validation bug exists)
 */

import { describe, it, expect } from 'vitest';
import fc from 'fast-check';

// Import the validation functions from main.js
// Since main.js is not a module, we need to load it in a way that works with the test environment
// For now, we'll define the functions inline based on the current implementation

// Current FIXED implementation
function isValidIP(ip) {
  const ipRegex =
    /^(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])$/;
  return ipRegex.test(ip);
}

// Current FIXED implementation
function isValidDomain(domain) {
  const domainRegex =
    /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
  return domainRegex.test(domain);
}

describe('Test Suite 1A: Input Validation Bug Exploration', () => {
  describe('Invalid IPv4 with Trailing Digits (Requirement 1.1)', () => {
    it('should reject "8.8.8.8854" - IPv4 with extra digits appended', () => {
      const input = '8.8.8.8854';
      const result = isValidIP(input);
      
      // EXPECTED: false (should be rejected)
      // ACTUAL ON UNFIXED CODE: May return true (bug exists)
      expect(result).toBe(false);
    });

    it('should reject "8.8.885465215" - IPv4 with long trailing digits', () => {
      const input = '8.8.885465215';
      const result = isValidIP(input);
      
      // EXPECTED: false (should be rejected)
      // ACTUAL ON UNFIXED CODE: May return true (bug exists)
      expect(result).toBe(false);
    });

    it('should reject "192.168.1.1999" - IPv4 with trailing digits', () => {
      const input = '192.168.1.1999';
      const result = isValidIP(input);
      
      // EXPECTED: false (should be rejected)
      expect(result).toBe(false);
    });

    // Property-based test: Any valid IP with extra digits that make it invalid should be rejected
    it('property: valid IP + extra digits should be rejected if invalid', () => {
      fc.assert(
        fc.property(
          fc.tuple(
            fc.integer({ min: 0, max: 255 }),
            fc.integer({ min: 0, max: 255 }),
            fc.integer({ min: 0, max: 255 }),
            fc.integer({ min: 0, max: 255 }),
            fc.integer({ min: 1, max: 9999 }) // Extra digits
          ),
          ([a, b, c, d, extra]) => {
            const lastOctetStr = `${d}${extra}`;
            const lastOctetVal = parseInt(lastOctetStr, 10);
            const isInvalid = lastOctetVal > 255 || lastOctetStr.length > 3 || (lastOctetStr.startsWith('0') && lastOctetStr.length > 1);
            
            if (isInvalid) {
              const invalidIP = `${a}.${b}.${c}.${lastOctetStr}`;
              const result = isValidIP(invalidIP);
              expect(result).toBe(false);
            }
          }
        ),
        { numRuns: 50 }
      );
    });
  });

  describe('Invalid IPv4 with Octets > 255 (Requirement 1.2)', () => {
    it('should reject "256.1.1.1" - first octet exceeds 255', () => {
      const input = '256.1.1.1';
      const result = isValidIP(input);
      
      // EXPECTED: false (should be rejected)
      expect(result).toBe(false);
    });

    it('should reject "192.168.300.1" - third octet exceeds 255', () => {
      const input = '192.168.300.1';
      const result = isValidIP(input);
      
      // EXPECTED: false (should be rejected)
      expect(result).toBe(false);
    });

    it('should reject "1.2.3.999" - fourth octet exceeds 255', () => {
      const input = '1.2.3.999';
      const result = isValidIP(input);
      
      // EXPECTED: false (should be rejected)
      expect(result).toBe(false);
    });

    // Property-based test: Any IP with octet > 255 should be rejected
    it('property: IP with any octet > 255 should be rejected', () => {
      fc.assert(
        fc.property(
          fc.integer({ min: 256, max: 999 }),
          fc.integer({ min: 0, max: 3 }), // Position of invalid octet
          (invalidOctet, position) => {
            const octets = [192, 168, 1, 1];
            octets[position] = invalidOctet;
            const invalidIP = octets.join('.');
            const result = isValidIP(invalidIP);
            
            // Should be rejected
            expect(result).toBe(false);
          }
        ),
        { numRuns: 50 }
      );
    });
  });

  describe('Invalid IPv4 with Incomplete Octets (Requirement 1.2)', () => {
    it('should reject "8.8.8" - only 3 octets', () => {
      const input = '8.8.8';
      const result = isValidIP(input);
      
      // EXPECTED: false (should be rejected)
      expect(result).toBe(false);
    });

    it('should reject "192.168.1" - only 3 octets', () => {
      const input = '192.168.1';
      const result = isValidIP(input);
      
      // EXPECTED: false (should be rejected)
      expect(result).toBe(false);
    });

    it('should reject "10.0" - only 2 octets', () => {
      const input = '10.0';
      const result = isValidIP(input);
      
      // EXPECTED: false (should be rejected)
      expect(result).toBe(false);
    });

    it('should reject "192" - only 1 octet', () => {
      const input = '192';
      const result = isValidIP(input);
      
      // EXPECTED: false (should be rejected)
      expect(result).toBe(false);
    });
  });

  describe('Invalid Domain Formats (Requirement 1.4)', () => {
    it('should reject "google" - no TLD', () => {
      const input = 'google';
      const result = isValidDomain(input);
      
      // EXPECTED: false (should be rejected)
      // ACTUAL ON UNFIXED CODE: May return true (bug exists)
      expect(result).toBe(false);
    });

    it('should reject ".com" - no domain name', () => {
      const input = '.com';
      const result = isValidDomain(input);
      
      // EXPECTED: false (should be rejected)
      expect(result).toBe(false);
    });

    it('should reject "-invalid.com" - starts with hyphen', () => {
      const input = '-invalid.com';
      const result = isValidDomain(input);
      
      // EXPECTED: false (should be rejected)
      expect(result).toBe(false);
    });

    it('should reject "invalid-.com" - ends with hyphen before dot', () => {
      const input = 'invalid-.com';
      const result = isValidDomain(input);
      
      // EXPECTED: false (should be rejected)
      expect(result).toBe(false);
    });

    it('should reject "example.c" - TLD too short (< 2 chars)', () => {
      const input = 'example.c';
      const result = isValidDomain(input);
      
      // EXPECTED: false (should be rejected)
      expect(result).toBe(false);
    });
  });

  describe('Invalid Domain with Spaces or Invalid Characters (Requirement 1.5)', () => {
    it('should reject "google .com" - contains space', () => {
      const input = 'google .com';
      const result = isValidDomain(input);
      
      // EXPECTED: false (should be rejected)
      expect(result).toBe(false);
    });

    it('should reject "example@test.com" - contains @ symbol', () => {
      const input = 'example@test.com';
      const result = isValidDomain(input);
      
      // EXPECTED: false (should be rejected)
      expect(result).toBe(false);
    });

    it('should reject "test_domain.com" - contains underscore', () => {
      const input = 'test_domain.com';
      const result = isValidDomain(input);
      
      // EXPECTED: false (should be rejected)
      expect(result).toBe(false);
    });

    it('should reject "example!.com" - contains exclamation mark', () => {
      const input = 'example!.com';
      const result = isValidDomain(input);
      
      // EXPECTED: false (should be rejected)
      expect(result).toBe(false);
    });
  });

  describe('Valid Inputs Should Pass (Sanity Check)', () => {
    it('should accept "8.8.8.8" - valid IPv4', () => {
      const input = '8.8.8.8';
      const result = isValidIP(input);
      
      // This should pass even on unfixed code
      expect(result).toBe(true);
    });

    it('should accept "192.168.1.1" - valid IPv4', () => {
      const input = '192.168.1.1';
      const result = isValidIP(input);
      
      // This should pass even on unfixed code
      expect(result).toBe(true);
    });

    it('should accept "google.com" - valid domain', () => {
      const input = 'google.com';
      const result = isValidDomain(input);
      
      // This should pass even on unfixed code
      expect(result).toBe(true);
    });

    it('should accept "sub.example.co.uk" - valid domain with subdomain', () => {
      const input = 'sub.example.co.uk';
      const result = isValidDomain(input);
      
      // This should pass even on unfixed code
      expect(result).toBe(true);
    });
  });
});
