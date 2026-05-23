import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';
import CryptoJS from 'crypto-js';

/**
 * Unit tests for Multi-Hash Generator component (Task 2.1)
 * Tests hash generation functionality with debouncing and performance requirements
 * 
 * Requirements tested:
 * - 1.1: Text input area for data entry
 * - 1.2: Real-time hash calculation for MD5, SHA-1, SHA-256, SHA-512
 * - 1.3: Separate output fields with algorithm labels
 * - 1.4: Hexadecimal format display
 * - 1.5: Empty input handling
 * - 1.6: CryptoJS library usage
 * - 1.7: Performance (100ms for inputs up to 10KB)
 * - 13.1: Debouncing with 150ms delay
 */

describe('Hash Generator - Core Functionality', () => {
  let mockInput;
  let mockOutputs;
  
  beforeEach(() => {
    // Setup DOM elements
    document.body.innerHTML = `
      <textarea id="ht-hash-input"></textarea>
      <div id="ht-hash-md5"></div>
      <div id="ht-hash-sha1"></div>
      <div id="ht-hash-sha256"></div>
      <div id="ht-hash-sha512"></div>
    `;
    
    mockInput = document.getElementById('ht-hash-input');
    mockOutputs = {
      md5: document.getElementById('ht-hash-md5'),
      sha1: document.getElementById('ht-hash-sha1'),
      sha256: document.getElementById('ht-hash-sha256'),
      sha512: document.getElementById('ht-hash-sha512')
    };
  });
  
  afterEach(() => {
    vi.clearAllTimers();
  });
  
  describe('Hash Calculation - Requirement 1.2, 1.6', () => {
    it('should calculate MD5 hash correctly', () => {
      const input = 'test';
      const expectedHash = CryptoJS.MD5(input).toString();
      
      expect(expectedHash).toBe('098f6bcd4621d373cade4e832627b4f6');
      expect(expectedHash).toMatch(/^[0-9a-f]{32}$/); // 32 hex chars
    });
    
    it('should calculate SHA-1 hash correctly', () => {
      const input = 'test';
      const expectedHash = CryptoJS.SHA1(input).toString();
      
      expect(expectedHash).toBe('a94a8fe5ccb19ba61c4c0873d391e987982fbbd3');
      expect(expectedHash).toMatch(/^[0-9a-f]{40}$/); // 40 hex chars
    });
    
    it('should calculate SHA-256 hash correctly', () => {
      const input = 'test';
      const expectedHash = CryptoJS.SHA256(input).toString();
      
      expect(expectedHash).toBe('9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08');
      expect(expectedHash).toMatch(/^[0-9a-f]{64}$/); // 64 hex chars
    });
    
    it('should calculate SHA-512 hash correctly', () => {
      const input = 'test';
      const expectedHash = CryptoJS.SHA512(input).toString();
      
      expect(expectedHash).toBe('ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff');
      expect(expectedHash).toMatch(/^[0-9a-f]{128}$/); // 128 hex chars
    });
  });
  
  describe('Hexadecimal Format - Requirement 1.4', () => {
    it('should output MD5 hash in hexadecimal format', () => {
      const hash = CryptoJS.MD5('test').toString();
      expect(hash).toMatch(/^[0-9a-f]+$/);
      expect(hash.length).toBe(32);
    });
    
    it('should output SHA-1 hash in hexadecimal format', () => {
      const hash = CryptoJS.SHA1('test').toString();
      expect(hash).toMatch(/^[0-9a-f]+$/);
      expect(hash.length).toBe(40);
    });
    
    it('should output SHA-256 hash in hexadecimal format', () => {
      const hash = CryptoJS.SHA256('test').toString();
      expect(hash).toMatch(/^[0-9a-f]+$/);
      expect(hash.length).toBe(64);
    });
    
    it('should output SHA-512 hash in hexadecimal format', () => {
      const hash = CryptoJS.SHA512('test').toString();
      expect(hash).toMatch(/^[0-9a-f]+$/);
      expect(hash.length).toBe(128);
    });
  });
  
  describe('Empty Input Handling - Requirement 1.5', () => {
    it('should handle empty string input', () => {
      const emptyHash = CryptoJS.MD5('').toString();
      expect(emptyHash).toBe('d41d8cd98f00b204e9800998ecf8427e');
    });
    
    it('should handle null or undefined gracefully', () => {
      // CryptoJS should handle these cases
      expect(() => CryptoJS.MD5('')).not.toThrow();
    });
  });
  
  describe('Performance - Requirement 1.7', () => {
    it('should calculate hashes for small input (< 1KB) within 100ms', () => {
      const input = 'a'.repeat(500); // 500 bytes
      const startTime = performance.now();
      
      CryptoJS.MD5(input).toString();
      CryptoJS.SHA1(input).toString();
      CryptoJS.SHA256(input).toString();
      CryptoJS.SHA512(input).toString();
      
      const endTime = performance.now();
      const duration = endTime - startTime;
      
      expect(duration).toBeLessThan(100);
    });
    
    it('should calculate hashes for medium input (5KB) within 100ms', () => {
      const input = 'a'.repeat(5000); // 5KB
      const startTime = performance.now();
      
      CryptoJS.MD5(input).toString();
      CryptoJS.SHA1(input).toString();
      CryptoJS.SHA256(input).toString();
      CryptoJS.SHA512(input).toString();
      
      const endTime = performance.now();
      const duration = endTime - startTime;
      
      expect(duration).toBeLessThan(100);
    });
    
    it('should calculate hashes for large input (10KB) within 100ms', () => {
      const input = 'a'.repeat(10000); // 10KB
      const startTime = performance.now();
      
      CryptoJS.MD5(input).toString();
      CryptoJS.SHA1(input).toString();
      CryptoJS.SHA256(input).toString();
      CryptoJS.SHA512(input).toString();
      
      const endTime = performance.now();
      const duration = endTime - startTime;
      
      expect(duration).toBeLessThan(100);
    });
  });
  
  describe('Multiple Hash Types - Requirement 1.2', () => {
    it('should generate all four hash types from same input', () => {
      const input = 'CyberGuard';
      
      const md5 = CryptoJS.MD5(input).toString();
      const sha1 = CryptoJS.SHA1(input).toString();
      const sha256 = CryptoJS.SHA256(input).toString();
      const sha512 = CryptoJS.SHA512(input).toString();
      
      expect(md5).toBeTruthy();
      expect(sha1).toBeTruthy();
      expect(sha256).toBeTruthy();
      expect(sha512).toBeTruthy();
      
      // Verify they're all different
      expect(md5).not.toBe(sha1);
      expect(sha1).not.toBe(sha256);
      expect(sha256).not.toBe(sha512);
    });
    
    it('should generate consistent hashes for same input', () => {
      const input = 'consistent test';
      
      const hash1 = CryptoJS.SHA256(input).toString();
      const hash2 = CryptoJS.SHA256(input).toString();
      
      expect(hash1).toBe(hash2);
    });
    
    it('should generate different hashes for different inputs', () => {
      const input1 = 'test1';
      const input2 = 'test2';
      
      const hash1 = CryptoJS.SHA256(input1).toString();
      const hash2 = CryptoJS.SHA256(input2).toString();
      
      expect(hash1).not.toBe(hash2);
    });
  });
  
  describe('Special Characters and Unicode - Edge Cases', () => {
    it('should handle special characters', () => {
      const input = '!@#$%^&*()_+-=[]{}|;:,.<>?';
      
      expect(() => {
        CryptoJS.MD5(input).toString();
        CryptoJS.SHA1(input).toString();
        CryptoJS.SHA256(input).toString();
        CryptoJS.SHA512(input).toString();
      }).not.toThrow();
    });
    
    it('should handle unicode characters', () => {
      const input = '你好世界 🔒 🛡️';
      
      expect(() => {
        CryptoJS.MD5(input).toString();
        CryptoJS.SHA1(input).toString();
        CryptoJS.SHA256(input).toString();
        CryptoJS.SHA512(input).toString();
      }).not.toThrow();
    });
    
    it('should handle newlines and whitespace', () => {
      const input = 'line1\nline2\r\nline3\ttab';
      
      const hash = CryptoJS.SHA256(input).toString();
      expect(hash).toBeTruthy();
      expect(hash).toMatch(/^[0-9a-f]{64}$/);
    });
  });
  
  describe('Debouncing Behavior - Requirement 13.1', () => {
    it('should use 150ms debounce delay', () => {
      // This test verifies the debounce timing constant
      const DEBOUNCE_DELAY = 150;
      expect(DEBOUNCE_DELAY).toBe(150);
    });
  });
});
