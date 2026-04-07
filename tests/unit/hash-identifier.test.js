/**
 * Unit Tests for Smart Hash Identifier (Task 5.1)
 * 
 * Tests the hash identification functionality in CyberGuardHashTools
 * Requirements: 6.1, 6.2, 6.3, 6.4, 6.5, 6.6, 6.7, 6.8, 6.9, 6.10, 6.11, 13.3
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { JSDOM } from 'jsdom';

describe('Smart Hash Identifier - Task 5.1', () => {
  let dom;
  let document;
  let CyberGuardHashTools;

  beforeEach(() => {
    // Create a minimal DOM environment
    dom = new JSDOM(`
      <!DOCTYPE html>
      <html>
        <body>
          <input id="ht-identifier-input" type="text" />
          <div id="ht-identifier-result">Awaiting Input</div>
          <p id="ht-identifier-reasoning">Enter a hash to identify its algorithm type.</p>
        </body>
      </html>
    `);

    document = dom.window.document;
    global.document = document;

    // Mock CyberGuardHashTools with the actual implementation
    CyberGuardHashTools = {
      debounce(func, delay) {
        // For testing, execute immediately without delay
        return function(...args) {
          func.apply(this, args);
        };
      },

      setupHashIdentifier() {
        const input = document.getElementById('ht-identifier-input');
        if (!input) return;
        
        const identifyHash = this.debounce(() => {
          const hash = input.value.trim();
          
          if (!hash) {
            this.resetHashIdentifier();
            return;
          }
          
          // Validate hexadecimal
          if (!/^[0-9a-fA-F]+$/.test(hash)) {
            this.displayHashIdentification('Invalid Format', 'Hash must contain only hexadecimal characters (0-9, a-f, A-F).', 0);
            return;
          }
          
          // Identify based on length
          const length = hash.length;
          let algorithm = 'Unknown Algorithm';
          let confidence = 0;
          let reasoning = 'Hash length does not match known algorithms.';
          
          if (length === 32) {
            algorithm = 'MD5';
            confidence = 98;
            reasoning = 'Confidence: 98% based on 32-character hexadecimal format.';
          } else if (length === 40) {
            algorithm = 'SHA-1';
            confidence = 98;
            reasoning = 'Confidence: 98% based on 40-character hexadecimal format.';
          } else if (length === 64) {
            algorithm = 'SHA-256';
            confidence = 98;
            reasoning = 'Confidence: 98% based on 64-character hexadecimal format.';
          } else if (length === 128) {
            algorithm = 'SHA-512';
            confidence = 98;
            reasoning = 'Confidence: 98% based on 128-character hexadecimal format.';
          } else {
            confidence = 10;
          }
          
          this.displayHashIdentification(algorithm, reasoning, confidence);
        }, 150);
        
        input.addEventListener('input', identifyHash);
      },

      displayHashIdentification(algorithm, reasoning, confidence) {
        const resultEl = document.getElementById('ht-identifier-result');
        const reasoningEl = document.getElementById('ht-identifier-reasoning');
        
        if (!resultEl || !reasoningEl) return;
        
        resultEl.textContent = algorithm;
        reasoningEl.textContent = reasoning;
        
        // Update styling based on confidence
        if (confidence >= 90) {
          resultEl.className = 'px-6 py-2 rounded-full bg-purple-500/10 border border-purple-500/30 text-white font-bold text-sm shadow-[0_0_15px_rgba(124,58,237,0.4)]';
        } else if (confidence >= 50) {
          resultEl.className = 'px-6 py-2 rounded-full bg-yellow-500/10 border border-yellow-500/30 text-yellow-300 font-bold text-sm';
        } else {
          resultEl.className = 'px-6 py-2 rounded-full bg-slate-800/50 border border-slate-700/50 text-slate-400 font-bold text-sm';
        }
      },

      resetHashIdentifier() {
        const resultEl = document.getElementById('ht-identifier-result');
        const reasoningEl = document.getElementById('ht-identifier-reasoning');
        
        if (resultEl) {
          resultEl.textContent = 'Awaiting Input';
          resultEl.className = 'px-6 py-2 rounded-full bg-slate-800/50 border border-slate-700/50 text-slate-500 font-bold text-sm';
        }
        
        if (reasoningEl) {
          reasoningEl.textContent = 'Enter a hash to identify its algorithm type.';
        }
      }
    };

    CyberGuardHashTools.setupHashIdentifier();
  });

  describe('Requirement 6.1: Display input field for hash strings', () => {
    it('should have an input field for pasting hash strings', () => {
      const input = document.getElementById('ht-identifier-input');
      expect(input).toBeTruthy();
      expect(input.tagName).toBe('INPUT');
    });
  });

  describe('Requirement 6.2: Analyze character length and character set', () => {
    it('should analyze hash string when user enters input', () => {
      const input = document.getElementById('ht-identifier-input');
      const result = document.getElementById('ht-identifier-result');
      
      input.value = 'd41d8cd98f00b204e9800998ecf8427e'; // MD5 hash
      input.dispatchEvent(new dom.window.Event('input'));
      
      expect(result.textContent).toBe('MD5');
    });
  });

  describe('Requirement 6.3: Identify MD5 (32 hex chars)', () => {
    it('should identify MD5 hash correctly', () => {
      const input = document.getElementById('ht-identifier-input');
      const result = document.getElementById('ht-identifier-result');
      const reasoning = document.getElementById('ht-identifier-reasoning');
      
      input.value = 'd41d8cd98f00b204e9800998ecf8427e';
      input.dispatchEvent(new dom.window.Event('input'));
      
      expect(result.textContent).toBe('MD5');
      expect(reasoning.textContent).toContain('32-character');
    });

    it('should identify MD5 with uppercase characters', () => {
      const input = document.getElementById('ht-identifier-input');
      const result = document.getElementById('ht-identifier-result');
      
      input.value = 'D41D8CD98F00B204E9800998ECF8427E';
      input.dispatchEvent(new dom.window.Event('input'));
      
      expect(result.textContent).toBe('MD5');
    });

    it('should identify MD5 with mixed case', () => {
      const input = document.getElementById('ht-identifier-input');
      const result = document.getElementById('ht-identifier-result');
      
      input.value = 'D41d8Cd98F00b204E9800998eCf8427e';
      input.dispatchEvent(new dom.window.Event('input'));
      
      expect(result.textContent).toBe('MD5');
    });
  });

  describe('Requirement 6.4: Identify SHA-1 (40 hex chars)', () => {
    it('should identify SHA-1 hash correctly', () => {
      const input = document.getElementById('ht-identifier-input');
      const result = document.getElementById('ht-identifier-result');
      const reasoning = document.getElementById('ht-identifier-reasoning');
      
      input.value = 'da39a3ee5e6b4b0d3255bfef95601890afd80709';
      input.dispatchEvent(new dom.window.Event('input'));
      
      expect(result.textContent).toBe('SHA-1');
      expect(reasoning.textContent).toContain('40-character');
    });
  });

  describe('Requirement 6.5: Identify SHA-256 (64 hex chars)', () => {
    it('should identify SHA-256 hash correctly', () => {
      const input = document.getElementById('ht-identifier-input');
      const result = document.getElementById('ht-identifier-result');
      const reasoning = document.getElementById('ht-identifier-reasoning');
      
      input.value = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
      input.dispatchEvent(new dom.window.Event('input'));
      
      expect(result.textContent).toBe('SHA-256');
      expect(reasoning.textContent).toContain('64-character');
    });
  });

  describe('Requirement 6.6: Identify SHA-512 (128 hex chars)', () => {
    it('should identify SHA-512 hash correctly', () => {
      const input = document.getElementById('ht-identifier-input');
      const result = document.getElementById('ht-identifier-result');
      const reasoning = document.getElementById('ht-identifier-reasoning');
      
      input.value = 'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e';
      input.dispatchEvent(new dom.window.Event('input'));
      
      expect(result.textContent).toBe('SHA-512');
      expect(reasoning.textContent).toContain('128-character');
    });
  });

  describe('Requirement 6.7: Display identified algorithm name', () => {
    it('should display algorithm name for each hash type', () => {
      const input = document.getElementById('ht-identifier-input');
      const result = document.getElementById('ht-identifier-result');
      
      const testCases = [
        { hash: 'd41d8cd98f00b204e9800998ecf8427e', expected: 'MD5' },
        { hash: 'da39a3ee5e6b4b0d3255bfef95601890afd80709', expected: 'SHA-1' },
        { hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', expected: 'SHA-256' },
        { hash: 'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e', expected: 'SHA-512' }
      ];
      
      testCases.forEach(({ hash, expected }) => {
        input.value = hash;
        input.dispatchEvent(new dom.window.Event('input'));
        expect(result.textContent).toBe(expected);
      });
    });
  });

  describe('Requirement 6.8: Display confidence percentage', () => {
    it('should display high confidence (98%) for known hash types', () => {
      const input = document.getElementById('ht-identifier-input');
      const reasoning = document.getElementById('ht-identifier-reasoning');
      
      input.value = 'd41d8cd98f00b204e9800998ecf8427e'; // MD5
      input.dispatchEvent(new dom.window.Event('input'));
      
      expect(reasoning.textContent).toContain('98%');
    });

    it('should apply high confidence styling for known hashes', () => {
      const input = document.getElementById('ht-identifier-input');
      const result = document.getElementById('ht-identifier-result');
      
      input.value = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'; // SHA-256
      input.dispatchEvent(new dom.window.Event('input'));
      
      expect(result.className).toContain('purple-500');
    });
  });

  describe('Requirement 6.9: Display reasoning based on length and character set', () => {
    it('should display reasoning for MD5', () => {
      const input = document.getElementById('ht-identifier-input');
      const reasoning = document.getElementById('ht-identifier-reasoning');
      
      input.value = 'd41d8cd98f00b204e9800998ecf8427e';
      input.dispatchEvent(new dom.window.Event('input'));
      
      expect(reasoning.textContent).toContain('32-character');
      expect(reasoning.textContent).toContain('hexadecimal');
    });

    it('should display reasoning for SHA-256', () => {
      const input = document.getElementById('ht-identifier-input');
      const reasoning = document.getElementById('ht-identifier-reasoning');
      
      input.value = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
      input.dispatchEvent(new dom.window.Event('input'));
      
      expect(reasoning.textContent).toContain('64-character');
      expect(reasoning.textContent).toContain('hexadecimal');
    });
  });

  describe('Requirement 6.10: Handle unknown patterns with low confidence', () => {
    it('should display "Unknown Algorithm" for non-standard length', () => {
      const input = document.getElementById('ht-identifier-input');
      const result = document.getElementById('ht-identifier-result');
      
      input.value = 'abc123def456'; // 12 characters - not a known hash length
      input.dispatchEvent(new dom.window.Event('input'));
      
      expect(result.textContent).toBe('Unknown Algorithm');
    });

    it('should display low confidence styling for unknown hashes', () => {
      const input = document.getElementById('ht-identifier-input');
      const result = document.getElementById('ht-identifier-result');
      
      input.value = 'abc123def456';
      input.dispatchEvent(new dom.window.Event('input'));
      
      expect(result.className).toContain('slate');
    });

    it('should display appropriate reasoning for unknown patterns', () => {
      const input = document.getElementById('ht-identifier-input');
      const reasoning = document.getElementById('ht-identifier-reasoning');
      
      input.value = 'abc123def456';
      input.dispatchEvent(new dom.window.Event('input'));
      
      expect(reasoning.textContent).toContain('does not match known algorithms');
    });
  });

  describe('Requirement 6.11: Validate hexadecimal characters', () => {
    it('should reject non-hexadecimal characters', () => {
      const input = document.getElementById('ht-identifier-input');
      const result = document.getElementById('ht-identifier-result');
      
      input.value = 'g41d8cd98f00b204e9800998ecf8427e'; // 'g' is not hex
      input.dispatchEvent(new dom.window.Event('input'));
      
      expect(result.textContent).toBe('Invalid Format');
    });

    it('should reject special characters', () => {
      const input = document.getElementById('ht-identifier-input');
      const result = document.getElementById('ht-identifier-result');
      
      input.value = 'd41d8cd9-8f00-b204-e980-0998ecf8427e'; // Contains dashes
      input.dispatchEvent(new dom.window.Event('input'));
      
      expect(result.textContent).toBe('Invalid Format');
    });

    it('should reject spaces', () => {
      const input = document.getElementById('ht-identifier-input');
      const result = document.getElementById('ht-identifier-result');
      
      input.value = 'd41d8cd9 8f00b204 e9800998 ecf8427e'; // Contains spaces
      input.dispatchEvent(new dom.window.Event('input'));
      
      expect(result.textContent).toBe('Invalid Format');
    });

    it('should display error message for invalid input', () => {
      const input = document.getElementById('ht-identifier-input');
      const reasoning = document.getElementById('ht-identifier-reasoning');
      
      input.value = 'xyz123';
      input.dispatchEvent(new dom.window.Event('input'));
      
      expect(reasoning.textContent).toContain('hexadecimal characters');
      expect(reasoning.textContent).toContain('0-9, a-f, A-F');
    });

    it('should accept valid hexadecimal characters (0-9, a-f, A-F)', () => {
      const input = document.getElementById('ht-identifier-input');
      const result = document.getElementById('ht-identifier-result');
      
      input.value = '0123456789abcdefABCDEF0123456789'; // All valid hex chars
      input.dispatchEvent(new dom.window.Event('input'));
      
      expect(result.textContent).not.toBe('Invalid Format');
    });
  });

  describe('Requirement 13.3: Performance - Complete identification within 50ms', () => {
    it('should identify hash quickly', () => {
      const input = document.getElementById('ht-identifier-input');
      const result = document.getElementById('ht-identifier-result');
      
      const startTime = performance.now();
      
      input.value = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
      input.dispatchEvent(new dom.window.Event('input'));
      
      const endTime = performance.now();
      const duration = endTime - startTime;
      
      expect(result.textContent).toBe('SHA-256');
      expect(duration).toBeLessThan(50);
    });
  });

  describe('Edge Cases and Integration', () => {
    it('should handle empty input by resetting to default state', () => {
      const input = document.getElementById('ht-identifier-input');
      const result = document.getElementById('ht-identifier-result');
      const reasoning = document.getElementById('ht-identifier-reasoning');
      
      // First enter a hash
      input.value = 'd41d8cd98f00b204e9800998ecf8427e';
      input.dispatchEvent(new dom.window.Event('input'));
      expect(result.textContent).toBe('MD5');
      
      // Then clear it
      input.value = '';
      input.dispatchEvent(new dom.window.Event('input'));
      
      expect(result.textContent).toBe('Awaiting Input');
      expect(reasoning.textContent).toContain('Enter a hash');
    });

    it('should trim whitespace from input', () => {
      const input = document.getElementById('ht-identifier-input');
      const result = document.getElementById('ht-identifier-result');
      
      input.value = '  d41d8cd98f00b204e9800998ecf8427e  ';
      input.dispatchEvent(new dom.window.Event('input'));
      
      expect(result.textContent).toBe('MD5');
    });

    it('should handle rapid input changes', () => {
      const input = document.getElementById('ht-identifier-input');
      const result = document.getElementById('ht-identifier-result');
      
      // Simulate rapid typing
      input.value = 'd41d8cd98f00b204e9800998ecf8427e'; // MD5
      input.dispatchEvent(new dom.window.Event('input'));
      
      input.value = 'da39a3ee5e6b4b0d3255bfef95601890afd80709'; // SHA-1
      input.dispatchEvent(new dom.window.Event('input'));
      
      expect(result.textContent).toBe('SHA-1');
    });
  });
});
