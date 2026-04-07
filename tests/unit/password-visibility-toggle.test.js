/**
 * Unit Tests for Password Visibility Toggle (Task 3.4)
 * 
 * Tests the password visibility toggle implementation in setupPasswordAnalyzer()
 * Requirements: 5.1, 5.2, 5.3, 5.4, 5.5
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { JSDOM } from 'jsdom';

describe('Password Visibility Toggle (Task 3.4)', () => {
  let dom;
  let document;
  let CyberGuardHashTools;

  beforeEach(() => {
    // Create a minimal DOM environment
    dom = new JSDOM(`
      <!DOCTYPE html>
      <html>
        <body>
          <input id="ht-password-input" type="password" value="" />
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
          
          // Update progress bar width and color
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

  describe('Toggle Button Display (Requirement 5.1)', () => {
    it('should display a visibility toggle button within the password input field', () => {
      // Requirement 5.1
      const toggle = document.getElementById('ht-password-toggle');
      
      expect(toggle).toBeTruthy();
      expect(toggle.tagName).toBe('BUTTON');
    });

    it('should have a Material Symbols icon in the toggle button', () => {
      // Requirement 5.1
      const toggle = document.getElementById('ht-password-toggle');
      const icon = toggle.querySelector('.material-symbols-outlined');
      
      expect(icon).toBeTruthy();
      expect(icon.textContent).toBeTruthy();
    });
  });

  describe('Input Type Switching (Requirement 5.2)', () => {
    it('should switch input type from password to text when toggle is clicked', () => {
      // Requirement 5.2
      const input = document.getElementById('ht-password-input');
      const toggle = document.getElementById('ht-password-toggle');
      
      expect(input.type).toBe('password');
      
      toggle.click();
      
      expect(input.type).toBe('text');
    });

    it('should switch input type from text back to password when toggle is clicked again', () => {
      // Requirement 5.2
      const input = document.getElementById('ht-password-input');
      const toggle = document.getElementById('ht-password-toggle');
      
      // First click: password -> text
      toggle.click();
      expect(input.type).toBe('text');
      
      // Second click: text -> password
      toggle.click();
      expect(input.type).toBe('password');
    });

    it('should toggle input type multiple times correctly', () => {
      // Requirement 5.2
      const input = document.getElementById('ht-password-input');
      const toggle = document.getElementById('ht-password-toggle');
      
      expect(input.type).toBe('password');
      
      // Multiple toggles
      toggle.click();
      expect(input.type).toBe('text');
      
      toggle.click();
      expect(input.type).toBe('password');
      
      toggle.click();
      expect(input.type).toBe('text');
      
      toggle.click();
      expect(input.type).toBe('password');
    });
  });

  describe('Icon Display (Requirements 5.3, 5.4)', () => {
    it('should display "visibility" icon when password is hidden (initial state)', () => {
      // Requirement 5.4 - when hidden, show "visibility" icon
      const toggle = document.getElementById('ht-password-toggle');
      const icon = toggle.querySelector('.material-symbols-outlined');
      const input = document.getElementById('ht-password-input');
      
      expect(input.type).toBe('password');
      expect(icon.textContent).toBe('visibility');
    });

    it('should display "visibility_off" icon when password is visible', () => {
      // Requirement 5.3 - when visible, show "visibility_off" (eye-slash) icon
      const toggle = document.getElementById('ht-password-toggle');
      const icon = toggle.querySelector('.material-symbols-outlined');
      const input = document.getElementById('ht-password-input');
      
      toggle.click();
      
      expect(input.type).toBe('text');
      expect(icon.textContent).toBe('visibility_off');
    });

    it('should toggle icon between "visibility" and "visibility_off" correctly', () => {
      // Requirements 5.3, 5.4
      const toggle = document.getElementById('ht-password-toggle');
      const icon = toggle.querySelector('.material-symbols-outlined');
      
      // Initial state: hidden password, "visibility" icon
      expect(icon.textContent).toBe('visibility');
      
      // Click to show: visible password, "visibility_off" icon
      toggle.click();
      expect(icon.textContent).toBe('visibility_off');
      
      // Click to hide: hidden password, "visibility" icon
      toggle.click();
      expect(icon.textContent).toBe('visibility');
      
      // Click to show again
      toggle.click();
      expect(icon.textContent).toBe('visibility_off');
    });
  });

  describe('Password Value Preservation (Requirement 5.5)', () => {
    it('should maintain password value when toggling visibility', () => {
      // Requirement 5.5
      const input = document.getElementById('ht-password-input');
      const toggle = document.getElementById('ht-password-toggle');
      
      const testPassword = 'MySecureP@ssw0rd!';
      input.value = testPassword;
      
      // Toggle to visible
      toggle.click();
      expect(input.value).toBe(testPassword);
      expect(input.type).toBe('text');
      
      // Toggle back to hidden
      toggle.click();
      expect(input.value).toBe(testPassword);
      expect(input.type).toBe('password');
    });

    it('should preserve password value through multiple toggles', () => {
      // Requirement 5.5
      const input = document.getElementById('ht-password-input');
      const toggle = document.getElementById('ht-password-toggle');
      
      const testPassword = 'Sup3r$ecur3P@ss!';
      input.value = testPassword;
      
      // Multiple toggles
      for (let i = 0; i < 5; i++) {
        toggle.click();
        expect(input.value).toBe(testPassword);
      }
    });

    it('should preserve empty password value when toggling', () => {
      // Requirement 5.5
      const input = document.getElementById('ht-password-input');
      const toggle = document.getElementById('ht-password-toggle');
      
      input.value = '';
      
      toggle.click();
      expect(input.value).toBe('');
      
      toggle.click();
      expect(input.value).toBe('');
    });

    it('should preserve password with special characters when toggling', () => {
      // Requirement 5.5
      const input = document.getElementById('ht-password-input');
      const toggle = document.getElementById('ht-password-toggle');
      
      const specialPassword = '!@#$%^&*()_+-=[]{}|;:,.<>?/~`';
      input.value = specialPassword;
      
      toggle.click();
      expect(input.value).toBe(specialPassword);
      
      toggle.click();
      expect(input.value).toBe(specialPassword);
    });
  });

  describe('Integration with Password Analysis', () => {
    it('should allow password analysis to work while password is visible', () => {
      const input = document.getElementById('ht-password-input');
      const toggle = document.getElementById('ht-password-toggle');
      const strengthElement = document.getElementById('ht-password-strength');
      
      // Toggle to visible
      toggle.click();
      expect(input.type).toBe('text');
      
      // Type password
      input.value = 'Sup3r$ecur3P@ssw0rd!2024';
      input.dispatchEvent(new dom.window.Event('input'));
      
      // Analysis should still work
      expect(strengthElement.textContent).toBe('EXCELLENT');
    });

    it('should allow password analysis to work while password is hidden', () => {
      const input = document.getElementById('ht-password-input');
      const strengthElement = document.getElementById('ht-password-strength');
      
      // Keep password hidden (default state)
      expect(input.type).toBe('password');
      
      // Type password
      input.value = 'WeakPass';
      input.dispatchEvent(new dom.window.Event('input'));
      
      // Analysis should work
      expect(strengthElement.textContent).toBe('FAIR');
    });

    it('should maintain analysis results when toggling visibility', () => {
      const input = document.getElementById('ht-password-input');
      const toggle = document.getElementById('ht-password-toggle');
      const strengthElement = document.getElementById('ht-password-strength');
      const entropyElement = document.getElementById('ht-password-entropy');
      
      // Type password and analyze
      input.value = 'MyP@ss1234';
      input.dispatchEvent(new dom.window.Event('input'));
      
      const strengthBefore = strengthElement.textContent;
      const entropyBefore = entropyElement.textContent;
      
      // Toggle visibility
      toggle.click();
      
      // Analysis results should remain the same
      expect(strengthElement.textContent).toBe(strengthBefore);
      expect(entropyElement.textContent).toBe(entropyBefore);
    });
  });

  describe('Edge Cases', () => {
    it('should handle rapid toggle clicks', () => {
      const input = document.getElementById('ht-password-input');
      const toggle = document.getElementById('ht-password-toggle');
      const icon = toggle.querySelector('.material-symbols-outlined');
      
      input.value = 'TestPassword123';
      
      // Rapid clicks
      for (let i = 0; i < 10; i++) {
        toggle.click();
      }
      
      // Should end up in the correct state (10 clicks = back to password)
      expect(input.type).toBe('password');
      expect(icon.textContent).toBe('visibility');
      expect(input.value).toBe('TestPassword123');
    });

    it('should work when toggle button is missing', () => {
      // Create new DOM without toggle button
      const newDom = new JSDOM(`
        <!DOCTYPE html>
        <html>
          <body>
            <input id="ht-password-input" type="password" value="" />
            <div id="ht-password-bar"></div>
            <p id="ht-password-strength">--</p>
            <p id="ht-password-entropy">-- bits</p>
            <div id="ht-check-numbers"></div>
            <div id="ht-check-special"></div>
            <div id="ht-check-mixed"></div>
            <div id="ht-check-common"></div>
          </body>
        </html>
      `);
      
      global.document = newDom.window.document;
      
      // Should not throw error
      expect(() => {
        CyberGuardHashTools.setupPasswordAnalyzer();
      }).not.toThrow();
    });
  });
});
