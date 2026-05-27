import { describe, it, expect, vi, beforeEach } from 'vitest';

// We mock the DOM environment here or import the functions in a testable way.
// To avoid loading the whole DOM window dependency structure, we can import/define the core logic functions.

// Define local testable equivalents of the OSINT methods to verify their algorithms.
const ENCRYPTION_KEY = 'CyberGuard2024!@#';

function decryptApiKey(encryptedKey) {
  if (!encryptedKey) return '';
  try {
    const decoded = atob(encryptedKey);
    let decrypted = '';
    for (let i = 0; i < decoded.length; i++) {
      decrypted += String.fromCharCode(
        decoded.charCodeAt(i) ^ ENCRYPTION_KEY.charCodeAt(i % ENCRYPTION_KEY.length)
      );
    }
    return decrypted;
  } catch (e) {
    return encryptedKey;
  }
}

function detectInputType(input) {
  input = input.trim();
  if (!input) return null;

  if (input.includes('@') && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(input)) {
    return 'email';
  }

  const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  if (ipRegex.test(input)) {
    return 'ip';
  }

  const domainRegex = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$/i;
  if (domainRegex.test(input)) {
    return 'domain';
  }

  if (/^[a-zA-Z0-9_\-\.]{3,30}$/.test(input)) {
    return 'username';
  }

  return null;
}

function generateEmailPermutations(firstName, lastName, domain) {
  const fn = firstName.trim().toLowerCase();
  const ln = lastName.trim().toLowerCase();
  const dom = domain.trim().toLowerCase();
  
  const f = fn ? fn.charAt(0) : '';
  const l = ln ? ln.charAt(0) : '';
  const permutations = [];

  if (fn && ln) {
    permutations.push({ email: `${fn}.${ln}@${dom}`, likely: true });
    permutations.push({ email: `${f}${ln}@${dom}`, likely: true });
    permutations.push({ email: `${fn}@${dom}`, likely: false });
    permutations.push({ email: `${ln}@${dom}`, likely: false });
  } else {
    const name = fn || ln;
    permutations.push({ email: `${name}@${dom}`, likely: true });
  }
  return permutations;
}

describe('OSINT Module Unit Tests', () => {
  describe('detectInputType() target categorization', () => {
    it('should identify valid emails', () => {
      expect(detectInputType('test@domain.com')).toBe('email');
      expect(detectInputType('first.last@company.org')).toBe('email');
    });

    it('should identify valid IP addresses', () => {
      expect(detectInputType('8.8.8.8')).toBe('ip');
      expect(detectInputType('192.168.1.1')).toBe('ip');
      expect(detectInputType('255.255.255.255')).toBe('ip');
    });

    it('should identify valid domain names', () => {
      expect(detectInputType('google.com')).toBe('domain');
      expect(detectInputType('sub.domain.co.uk')).toBe('domain');
      expect(detectInputType('github.io')).toBe('domain');
    });

    it('should identify usernames', () => {
      expect(detectInputType('sherlock_123')).toBe('username');
      expect(detectInputType('john_doe')).toBe('username');
    });

    it('should return null on invalid target strings', () => {
      expect(detectInputType('')).toBeNull();
      expect(detectInputType('    ')).toBeNull();
      expect(detectInputType('a')).toBeNull(); // username too short
    });
  });

  describe('decryptApiKey() storage integration', () => {
    it('should return empty string if no key is provided', () => {
      expect(decryptApiKey('')).toBe('');
    });

    it('should decrypt XOR encrypted keys correctly', () => {
      // "testkey" XOR "CyberGuard2024!@#" base64 encoded
      const key = 'testkey';
      
      // Let's manually encrypt
      let encrypted = '';
      for (let i = 0; i < key.length; i++) {
        encrypted += String.fromCharCode(
          key.charCodeAt(i) ^ ENCRYPTION_KEY.charCodeAt(i % ENCRYPTION_KEY.length)
        );
      }
      const b64 = btoa(encrypted);
      
      expect(decryptApiKey(b64)).toBe(key);
    });
  });

  describe('generateEmailPermutations() algorithm', () => {
    it('should generate permutations for first and last names', () => {
      const results = generateEmailPermutations('John', 'Doe', 'company.com');
      expect(results).toHaveLength(4);
      expect(results[0]).toEqual({ email: 'john.doe@company.com', likely: true });
      expect(results[1]).toEqual({ email: 'jdoe@company.com', likely: true });
      expect(results[2]).toEqual({ email: 'john@company.com', likely: false });
    });

    it('should generate simple format if only first name is present', () => {
      const results = generateEmailPermutations('John', '', 'company.com');
      expect(results).toHaveLength(1);
      expect(results[0]).toEqual({ email: 'john@company.com', likely: true });
    });
  });
});
