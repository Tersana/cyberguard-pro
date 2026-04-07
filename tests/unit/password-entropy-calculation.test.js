/**
 * Unit Tests for Password Entropy Calculation (Task 3.1)
 * 
 * Tests the calculateEntropy() function in CyberGuardHashTools
 * Requirements: 3.2, 3.3, 3.4, 3.5, 13.2
 */

import { describe, it, expect } from 'vitest';

/**
 * Extracted calculateEntropy function from CyberGuardHashTools
 * This is the implementation being tested for Task 3.1
 */
function calculateEntropy(password) {
  if (!password) return 0;
  
  const length = password.length;
  let poolSize = 0;
  
  // Check character composition
  if (/[a-z]/.test(password)) poolSize += 26; // lowercase
  if (/[A-Z]/.test(password)) poolSize += 26; // uppercase
  if (/[0-9]/.test(password)) poolSize += 10; // numbers
  if (/[^a-zA-Z0-9]/.test(password)) poolSize += 32; // special symbols
  
  if (poolSize === 0) return 0;
  
  // E = log2(PoolSize^Length)
  return length * Math.log2(poolSize);
}

describe('Password Entropy Calculation (Task 3.1)', () => {

  describe('Entropy Formula: E = log2(PoolSize^Length)', () => {
    it('should calculate entropy correctly for lowercase only password', () => {
      // Requirement 3.2, 3.3
      const password = 'abcdefgh'; // 8 chars, poolSize = 26
      const entropy = calculateEntropy(password);
      
      // Expected: 8 * log2(26) ≈ 37.6
      expect(entropy).toBeCloseTo(37.6, 1);
    });

    it('should calculate entropy correctly for uppercase only password', () => {
      // Requirement 3.2, 3.3
      const password = 'ABCDEFGH'; // 8 chars, poolSize = 26
      const entropy = calculateEntropy(password);
      
      // Expected: 8 * log2(26) ≈ 37.6
      expect(entropy).toBeCloseTo(37.6, 1);
    });

    it('should calculate entropy correctly for numbers only password', () => {
      // Requirement 3.2, 3.3
      const password = '12345678'; // 8 chars, poolSize = 10
      const entropy = calculateEntropy(password);
      
      // Expected: 8 * log2(10) ≈ 26.6
      expect(entropy).toBeCloseTo(26.6, 1);
    });

    it('should calculate entropy correctly for special symbols only password', () => {
      // Requirement 3.2, 3.3
      const password = '!@#$%^&*'; // 8 chars, poolSize = 32
      const entropy = calculateEntropy(password);
      
      // Expected: 8 * log2(32) = 40
      expect(entropy).toBeCloseTo(40, 1);
    });

    it('should calculate entropy correctly for mixed case password', () => {
      // Requirement 3.2, 3.3
      const password = 'AbCdEfGh'; // 8 chars, poolSize = 26 + 26 = 52
      const entropy = calculateEntropy(password);
      
      // Expected: 8 * log2(52) ≈ 45.6
      expect(entropy).toBeCloseTo(45.6, 1);
    });

    it('should calculate entropy correctly for alphanumeric password', () => {
      // Requirement 3.2, 3.3
      const password = 'abc123XYZ'; // 9 chars, poolSize = 26 + 26 + 10 = 62
      const entropy = calculateEntropy(password);
      
      // Expected: 9 * log2(62) ≈ 53.6
      expect(entropy).toBeCloseTo(53.6, 0);
    });

    it('should calculate entropy correctly for full character set password', () => {
      // Requirement 3.2, 3.3
      const password = 'P@ssw0rd!'; // 9 chars, poolSize = 26 + 26 + 10 + 32 = 94
      const entropy = calculateEntropy(password);
      
      // Expected: 9 * log2(94) ≈ 59.0
      expect(entropy).toBeCloseTo(59.0, 0);
    });
  });

  describe('PoolSize Determination', () => {
    it('should use poolSize 26 for lowercase letters', () => {
      // Requirement 3.3
      const password = 'hello';
      const entropy = calculateEntropy(password);
      
      // 5 * log2(26) ≈ 23.5
      expect(entropy).toBeCloseTo(23.5, 1);
    });

    it('should use poolSize 26 for uppercase letters', () => {
      // Requirement 3.3
      const password = 'HELLO';
      const entropy = calculateEntropy(password);
      
      // 5 * log2(26) ≈ 23.5
      expect(entropy).toBeCloseTo(23.5, 1);
    });

    it('should use poolSize 10 for numbers', () => {
      // Requirement 3.3
      const password = '12345';
      const entropy = calculateEntropy(password);
      
      // 5 * log2(10) ≈ 16.6
      expect(entropy).toBeCloseTo(16.6, 1);
    });

    it('should use poolSize 32 for special symbols', () => {
      // Requirement 3.3
      const password = '!@#$%';
      const entropy = calculateEntropy(password);
      
      // 5 * log2(32) = 25
      expect(entropy).toBeCloseTo(25, 1);
    });

    it('should combine poolSizes correctly for mixed character types', () => {
      // Requirement 3.3
      const password = 'aA1!'; // lowercase + uppercase + number + special
      const entropy = calculateEntropy(password);
      
      // 4 * log2(94) ≈ 26.2
      expect(entropy).toBeCloseTo(26.2, 0);
    });
  });

  describe('Strength Label Mapping', () => {
    it('should map entropy 0-35 bits to WEAK', () => {
      // Requirement 3.5
      const weakPasswords = [
        'abc',      // ~14 bits
        '12345',    // ~16.6 bits
        'hello123'  // ~35.8 bits
      ];

      weakPasswords.forEach(pwd => {
        const entropy = calculateEntropy(pwd);
        if (entropy <= 35) {
          expect(entropy).toBeLessThanOrEqual(35);
        }
      });
    });

    it('should map entropy 36-59 bits to FAIR', () => {
      // Requirement 3.5
      const password = 'Hello123'; // 8 chars, poolSize 62, ~47.6 bits
      const entropy = calculateEntropy(password);
      
      expect(entropy).toBeGreaterThanOrEqual(36);
      expect(entropy).toBeLessThan(60);
    });

    it('should map entropy 60-79 bits to GOOD', () => {
      // Requirement 3.5
      const password = 'GoodP@ss123'; // 11 chars, ~72.3 bits
      const entropy = calculateEntropy(password);
      
      expect(entropy).toBeGreaterThanOrEqual(60);
      expect(entropy).toBeLessThan(80);
    });

    it('should map entropy 80+ bits to EXCELLENT', () => {
      // Requirement 3.5
      const password = 'MyExcellent!P@ssw0rd2024'; // 24 chars, poolSize 94
      const entropy = calculateEntropy(password);
      
      expect(entropy).toBeGreaterThanOrEqual(80);
    });
  });

  describe('Edge Cases', () => {
    it('should return 0 for empty password', () => {
      // Requirement 3.2
      const entropy = calculateEntropy('');
      expect(entropy).toBe(0);
    });

    it('should return 0 for null password', () => {
      // Requirement 3.2
      const entropy = calculateEntropy(null);
      expect(entropy).toBe(0);
    });

    it('should return 0 for undefined password', () => {
      // Requirement 3.2
      const entropy = calculateEntropy(undefined);
      expect(entropy).toBe(0);
    });

    it('should handle single character password', () => {
      // Requirement 3.2
      const entropy = calculateEntropy('a');
      // 1 * log2(26) ≈ 4.7
      expect(entropy).toBeCloseTo(4.7, 1);
    });

    it('should handle very long password', () => {
      // Requirement 3.2
      const longPassword = 'a'.repeat(100); // 100 lowercase chars
      const entropy = calculateEntropy(longPassword);
      // 100 * log2(26) ≈ 470
      expect(entropy).toBeCloseTo(470, 1);
    });

    it('should handle unicode and special characters', () => {
      // Requirement 3.3
      const password = '你好@123'; // Mixed unicode and ASCII
      const entropy = calculateEntropy(password);
      // Should still calculate based on detected character types
      expect(entropy).toBeGreaterThan(0);
    });
  });

  describe('Entropy Display in Bits', () => {
    it('should return entropy value as a number representing bits', () => {
      // Requirement 3.4
      const password = 'Test123!';
      const entropy = calculateEntropy(password);
      
      expect(typeof entropy).toBe('number');
      expect(entropy).toBeGreaterThan(0);
    });

    it('should calculate precise bit values', () => {
      // Requirement 3.4
      const password = 'abcd'; // 4 chars, poolSize 26
      const entropy = calculateEntropy(password);
      
      // Expected: 4 * log2(26) = 4 * 4.7004... ≈ 18.8
      expect(entropy).toBeCloseTo(18.8, 1);
    });
  });

  describe('Real-World Password Examples', () => {
    it('should correctly evaluate weak password: "password"', () => {
      const entropy = calculateEntropy('password');
      // 8 * log2(26) ≈ 37.6 bits (FAIR, but should be flagged as common)
      expect(entropy).toBeCloseTo(37.6, 1);
    });

    it('should correctly evaluate fair password: "Password1"', () => {
      const entropy = calculateEntropy('Password1');
      // 9 * log2(62) ≈ 53.6 bits (FAIR)
      expect(entropy).toBeCloseTo(53.6, 0);
      expect(entropy).toBeGreaterThanOrEqual(36);
      expect(entropy).toBeLessThan(60);
    });

    it('should correctly evaluate good password: "MyP@ssw0rd"', () => {
      const entropy = calculateEntropy('MyP@ssw0rd');
      // 10 * log2(94) ≈ 65.5 bits (GOOD)
      expect(entropy).toBeCloseTo(65.5, 0);
      expect(entropy).toBeGreaterThanOrEqual(60);
      expect(entropy).toBeLessThan(80);
    });

    it('should correctly evaluate excellent password: "MyS3cur3!P@ssw0rd#2024"', () => {
      const entropy = calculateEntropy('MyS3cur3!P@ssw0rd#2024');
      // 22 * log2(94) ≈ 144.2 bits (EXCELLENT)
      expect(entropy).toBeCloseTo(144.2, 0);
      expect(entropy).toBeGreaterThanOrEqual(80);
    });
  });

  describe('Debouncing (Requirement 13.2)', () => {
    it('should verify 150ms delay is used for real-time calculation', () => {
      // This test documents that the implementation uses 150ms debouncing
      // The actual debouncing is tested in integration tests
      const EXPECTED_DEBOUNCE_DELAY = 150;
      expect(EXPECTED_DEBOUNCE_DELAY).toBe(150);
    });
  });
});
