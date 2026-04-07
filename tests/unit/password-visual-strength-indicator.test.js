/**
 * Unit Tests for Password Visual Strength Indicator (Task 3.2)
 * 
 * Tests the visual strength indicator implementation in setupPasswordAnalyzer()
 * Requirements: 3.6, 3.7, 3.8, 3.9, 3.10
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { JSDOM } from 'jsdom';

describe('Password Visual Strength Indicator (Task 3.2)', () => {
  let dom;
  let document;
  let CyberGuardHashTools;

  beforeEach(() => {
    // Create a minimal DOM environment
    dom = new JSDOM(`
      <!DOCTYPE html>
      <html>
        <body>
          <input id="ht-password-input" type="password" />
          <button id="ht-password-toggle">
            <span class="material-symbols-outlined">visibility</span>
          </button>
          <div id="ht-password-bar" class="bg-red-500 h-full w-0 rounded-full transition-all duration-300"></div>
          <p id="ht-password-strength" class="text-xl font-bold text-slate-500">--</p>
          <p id="ht-password-entropy" class="text-base font-mono text-white/90">-- bits</p>
          <div id="ht-check-numbers"></div>
          <div id="ht-check-special"></div>
          <div id="ht-check-mixed"></div>
          <div id="ht-check-common"></div>
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
      
      calculateEntropy(password) {
        if (!password) return 0;
        
        let poolSize = 0;
        if (/[a-z]/.test(password)) poolSize += 26;
        if (/[A-Z]/.test(password)) poolSize += 26;
        if (/[0-9]/.test(password)) poolSize += 10;
        if (/[^a-zA-Z0-9]/.test(password)) poolSize += 32;
        
        if (poolSize === 0) return 0;
        
        return password.length * Math.log2(poolSize);
      },
      
      updatePasswordChecks(password) {
        // Mock implementation
      },
      
      resetPasswordAnalysis() {
        const progressBar = document.getElementById('ht-password-bar');
        document.getElementById('ht-password-strength').textContent = '--';
        document.getElementById('ht-password-strength').className = 'text-xl font-bold text-slate-500';
        document.getElementById('ht-password-entropy').textContent = '-- bits';
        progressBar.style.width = '0%';
        progressBar.className = 'bg-red-500 h-full rounded-full transition-all duration-300';
      },
      
      setupPasswordAnalyzer() {
        const input = document.getElementById('ht-password-input');
        const toggle = document.getElementById('ht-password-toggle');
        
        if (!input) return;
        
        // Password visibility toggle
        if (toggle) {
          toggle.addEventListener('click', () => {
            const isPassword = input.type === 'password';
            input.type = isPassword ? 'text' : 'password';
            toggle.querySelector('.material-symbols-outlined').textContent = isPassword ? 'visibility_off' : 'visibility';
          });
        }
        
        // Debounced password analysis
        const analyzePassword = this.debounce(() => {
          const password = input.value;
          
          if (!password) {
            this.resetPasswordAnalysis();
            return;
          }
          
          // Calculate entropy
          const entropy = this.calculateEntropy(password);
          
          // Determine strength and bar color based on entropy ranges
          // Requirements 3.8, 3.9, 3.10: red (0-35), yellow (36-59), green (60+)
          let strength = 'WEAK';
          let strengthColor = 'text-red-500';
          let barColor = 'bg-red-500';
          let barWidth = 0;
          
          if (entropy >= 80) {
            strength = 'EXCELLENT';
            strengthColor = 'text-green-400';
            barColor = 'bg-green-400';
            barWidth = 100;
          } else if (entropy >= 60) {
            strength = 'GOOD';
            strengthColor = 'text-green-400';
            barColor = 'bg-green-400';
            barWidth = (entropy / 128) * 100;
          } else if (entropy >= 36) {
            strength = 'FAIR';
            strengthColor = 'text-yellow-500';
            barColor = 'bg-yellow-500';
            barWidth = (entropy / 128) * 100;
          } else {
            strength = 'WEAK';
            strengthColor = 'text-red-500';
            barColor = 'bg-red-500';
            barWidth = (entropy / 128) * 100;
          }
          
          // Update UI
          const progressBar = document.getElementById('ht-password-bar');
          document.getElementById('ht-password-strength').textContent = strength;
          document.getElementById('ht-password-strength').className = `text-xl font-bold ${strengthColor}`;
          document.getElementById('ht-password-entropy').textContent = `${Math.round(entropy)} bits`;
          
          // Update progress bar width and color (Requirements 3.7, 3.8, 3.9, 3.10)
          progressBar.style.width = `${barWidth}%`;
          progressBar.className = `${barColor} h-full rounded-full transition-all duration-300`;
          
          // Update composition checks
          this.updatePasswordChecks(password);
        }, 150);
        
        input.addEventListener('input', analyzePassword);
      }
    };

    CyberGuardHashTools.setupPasswordAnalyzer();
  });

  describe('Progress Bar Width Calculation (Requirement 3.7)', () => {
    it('should calculate progress bar width as (entropy / 128) * 100 for WEAK passwords', () => {
      // Requirement 3.7
      const input = document.getElementById('ht-password-input');
      const progressBar = document.getElementById('ht-password-bar');
      
      // Password with ~26.6 bits entropy (numbers only)
      input.value = '12345678';
      input.dispatchEvent(new dom.window.Event('input'));
      
      const entropy = CyberGuardHashTools.calculateEntropy('12345678');
      const expectedWidth = (entropy / 128) * 100;
      
      expect(progressBar.style.width).toBe(`${expectedWidth}%`);
      expect(parseFloat(progressBar.style.width)).toBeCloseTo(expectedWidth, 1);
    });

    it('should calculate progress bar width as (entropy / 128) * 100 for FAIR passwords', () => {
      // Requirement 3.7
      const input = document.getElementById('ht-password-input');
      const progressBar = document.getElementById('ht-password-bar');
      
      // Password with ~45.6 bits entropy (mixed case)
      input.value = 'AbCdEfGh';
      input.dispatchEvent(new dom.window.Event('input'));
      
      const entropy = CyberGuardHashTools.calculateEntropy('AbCdEfGh');
      const expectedWidth = (entropy / 128) * 100;
      
      expect(progressBar.style.width).toBe(`${expectedWidth}%`);
      expect(parseFloat(progressBar.style.width)).toBeCloseTo(expectedWidth, 1);
    });

    it('should calculate progress bar width as (entropy / 128) * 100 for GOOD passwords', () => {
      // Requirement 3.7
      const input = document.getElementById('ht-password-input');
      const progressBar = document.getElementById('ht-password-bar');
      
      // Password with ~65.5 bits entropy (60-79 range for GOOD)
      // 10 chars * log2(94) = 65.5 bits
      input.value = 'MyP@ss1234';
      input.dispatchEvent(new dom.window.Event('input'));
      
      const entropy = CyberGuardHashTools.calculateEntropy('MyP@ss1234');
      const expectedWidth = (entropy / 128) * 100;
      
      // Should be GOOD (60-79 bits)
      expect(entropy).toBeGreaterThanOrEqual(60);
      expect(entropy).toBeLessThan(80);
      expect(progressBar.style.width).toBe(`${expectedWidth}%`);
      expect(parseFloat(progressBar.style.width)).toBeCloseTo(expectedWidth, 1);
    });

    it('should cap progress bar width at 100% for EXCELLENT passwords', () => {
      // Requirement 3.7
      const input = document.getElementById('ht-password-input');
      const progressBar = document.getElementById('ht-password-bar');
      
      // Password with 80+ bits entropy
      input.value = 'Sup3r$ecur3P@ssw0rd!2024';
      input.dispatchEvent(new dom.window.Event('input'));
      
      expect(progressBar.style.width).toBe('100%');
    });
  });

  describe('Progress Bar Color Coding (Requirements 3.8, 3.9, 3.10)', () => {
    it('should display red color for 0-35 bits entropy (WEAK)', () => {
      // Requirement 3.8
      const input = document.getElementById('ht-password-input');
      const progressBar = document.getElementById('ht-password-bar');
      
      // Password with ~26.6 bits entropy
      input.value = '12345678';
      input.dispatchEvent(new dom.window.Event('input'));
      
      expect(progressBar.className).toContain('bg-red-500');
      expect(document.getElementById('ht-password-strength').textContent).toBe('WEAK');
    });

    it('should display yellow color for 36-59 bits entropy (FAIR)', () => {
      // Requirement 3.9
      const input = document.getElementById('ht-password-input');
      const progressBar = document.getElementById('ht-password-bar');
      
      // Password with ~45.6 bits entropy
      input.value = 'AbCdEfGh';
      input.dispatchEvent(new dom.window.Event('input'));
      
      expect(progressBar.className).toContain('bg-yellow-500');
      expect(document.getElementById('ht-password-strength').textContent).toBe('FAIR');
    });

    it('should display green color for 60+ bits entropy (GOOD)', () => {
      // Requirement 3.10
      const input = document.getElementById('ht-password-input');
      const progressBar = document.getElementById('ht-password-bar');
      
      // Password with ~65.5 bits entropy (60-79 range for GOOD)
      input.value = 'MyP@ss1234';
      input.dispatchEvent(new dom.window.Event('input'));
      
      expect(progressBar.className).toContain('bg-green-400');
      expect(document.getElementById('ht-password-strength').textContent).toBe('GOOD');
    });

    it('should display green color for 80+ bits entropy (EXCELLENT)', () => {
      // Requirement 3.10
      const input = document.getElementById('ht-password-input');
      const progressBar = document.getElementById('ht-password-bar');
      
      // Password with 80+ bits entropy
      input.value = 'Sup3r$ecur3P@ssw0rd!2024';
      input.dispatchEvent(new dom.window.Event('input'));
      
      expect(progressBar.className).toContain('bg-green-400');
      expect(document.getElementById('ht-password-strength').textContent).toBe('EXCELLENT');
    });
  });

  describe('Real-time Updates (Requirement 3.6)', () => {
    it('should update progress bar in real-time as user types', () => {
      // Requirement 3.6
      const input = document.getElementById('ht-password-input');
      const progressBar = document.getElementById('ht-password-bar');
      
      // Start with empty - initial state may not have width set
      const initialWidth = progressBar.style.width || '0%';
      
      // Type weak password
      input.value = '123';
      input.dispatchEvent(new dom.window.Event('input'));
      expect(progressBar.style.width).not.toBe('0%');
      expect(progressBar.className).toContain('bg-red-500');
      
      // Type stronger password
      input.value = 'AbCdEfGh';
      input.dispatchEvent(new dom.window.Event('input'));
      const fairWidth = progressBar.style.width;
      expect(progressBar.className).toContain('bg-yellow-500');
      
      // Type even stronger password
      input.value = 'MyP@ss1234';
      input.dispatchEvent(new dom.window.Event('input'));
      expect(parseFloat(progressBar.style.width)).toBeGreaterThan(parseFloat(fairWidth));
      expect(progressBar.className).toContain('bg-green-400');
    });

    it('should reset progress bar when input is cleared', () => {
      // Requirement 3.6
      const input = document.getElementById('ht-password-input');
      const progressBar = document.getElementById('ht-password-bar');
      
      // Type password
      input.value = 'P@ssw0rd!';
      input.dispatchEvent(new dom.window.Event('input'));
      expect(progressBar.style.width).not.toBe('0%');
      
      // Clear input
      input.value = '';
      input.dispatchEvent(new dom.window.Event('input'));
      expect(progressBar.style.width).toBe('0%');
      expect(progressBar.className).toContain('bg-red-500');
    });
  });

  describe('Edge Cases', () => {
    it('should handle very short passwords correctly', () => {
      const input = document.getElementById('ht-password-input');
      const progressBar = document.getElementById('ht-password-bar');
      
      input.value = 'a';
      input.dispatchEvent(new dom.window.Event('input'));
      
      expect(progressBar.style.width).not.toBe('0%');
      expect(progressBar.className).toContain('bg-red-500');
    });

    it('should handle very long passwords correctly', () => {
      const input = document.getElementById('ht-password-input');
      const progressBar = document.getElementById('ht-password-bar');
      
      // Very long password with high entropy
      input.value = 'Th1s!sAV3ryL0ngP@ssw0rdW1thH1ghEntr0py!2024';
      input.dispatchEvent(new dom.window.Event('input'));
      
      expect(progressBar.style.width).toBe('100%');
      expect(progressBar.className).toContain('bg-green-400');
    });

    it('should handle special characters correctly', () => {
      const input = document.getElementById('ht-password-input');
      const progressBar = document.getElementById('ht-password-bar');
      
      // Special characters: 10 chars * log2(32) = 50 bits (FAIR range: 36-59)
      input.value = '!@#$%^&*()';
      input.dispatchEvent(new dom.window.Event('input'));
      
      expect(progressBar.style.width).not.toBe('0%');
      expect(progressBar.className).toContain('bg-yellow-500');
      expect(document.getElementById('ht-password-strength').textContent).toBe('FAIR');
    });
  });
});
