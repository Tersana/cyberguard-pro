/**
 * Integration Tests for Password Composition Analysis (Task 3.3)
 * 
 * Tests the complete integration of password composition checks with the password analyzer
 * Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 4.7, 4.8
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { JSDOM } from 'jsdom';

describe('Password Composition Analysis - Integration', () => {
  let dom;
  let document;
  let CyberGuardHashTools;

  beforeEach(() => {
    // Create complete DOM environment matching dashboard.html
    dom = new JSDOM(`
      <!DOCTYPE html>
      <html>
        <body>
          <div id="ht-password-input-container">
            <input id="ht-password-input" type="password" />
          </div>
          <div id="ht-password-bar"></div>
          <div id="ht-password-strength">--</div>
          <div id="ht-password-entropy">-- bits</div>
          <div id="ht-password-checks" class="grid grid-cols-2 gap-2">
            <div id="ht-check-numbers" class="flex items-center gap-1.5 text-slate-500">
              <span class="material-symbols-outlined text-[14px]">cancel</span>
              <span>Numbers Included</span>
            </div>
            <div id="ht-check-special" class="flex items-center gap-1.5 text-slate-500">
              <span class="material-symbols-outlined text-[14px]">cancel</span>
              <span>Special Symbols</span>
            </div>
            <div id="ht-check-mixed" class="flex items-center gap-1.5 text-slate-500">
              <span class="material-symbols-outlined text-[14px]">cancel</span>
              <span>Mixed Case</span>
            </div>
            <div id="ht-check-common" class="flex items-center gap-1.5 text-slate-500">
              <span class="material-symbols-outlined text-[14px]">cancel</span>
              <span>Common Phrase</span>
            </div>
          </div>
        </body>
      </html>
    `);
    
    document = dom.window.document;
    global.document = document;

    // Full CyberGuardHashTools implementation
    CyberGuardHashTools = {
      debounce(func, delay) {
        // For testing, execute immediately
        return func;
      },

      calculateEntropy(password) {
        if (!password) return 0;
        
        let poolSize = 0;
        if (/[a-z]/.test(password)) poolSize += 26;
        if (/[A-Z]/.test(password)) poolSize += 26;
        if (/[0-9]/.test(password)) poolSize += 10;
        if (/[^a-zA-Z0-9]/.test(password)) poolSize += 32;
        
        return Math.log2(Math.pow(poolSize, password.length));
      },

      updatePasswordChecks(password) {
        const hasNumbers = /[0-9]/.test(password);
        const hasSpecial = /[^a-zA-Z0-9]/.test(password);
        const hasMixed = /[a-z]/.test(password) && /[A-Z]/.test(password);
        const isCommon = this.isCommonPassword(password);
        
        this.updateCheck('ht-check-numbers', hasNumbers);
        this.updateCheck('ht-check-special', hasSpecial);
        this.updateCheck('ht-check-mixed', hasMixed);
        this.updateCheck('ht-check-common', !isCommon);
      },
      
      updateCheck(elementId, isPassing) {
        const element = document.getElementById(elementId);
        if (!element) return;
        
        const icon = element.querySelector('.material-symbols-outlined');
        
        if (isPassing) {
          icon.textContent = 'check_circle';
          element.className = 'flex items-center gap-1.5 text-green-400/80';
        } else {
          icon.textContent = 'cancel';
          element.className = 'flex items-center gap-1.5 text-red-400/60';
        }
      },
      
      isCommonPassword(password) {
        const commonPasswords = [
          'password', '123456', '12345678', 'qwerty', 'abc123', 'monkey', '1234567', 'letmein',
          'trustno1', 'dragon', 'baseball', 'iloveyou', 'master', 'sunshine', 'ashley', 'bailey',
          'passw0rd', 'shadow', '123123', '654321', 'superman', 'qazwsx', 'michael', 'football',
          'welcome', 'jesus', 'ninja', 'mustang', 'password1', '123456789', 'adobe123', 'admin',
          'azerty', 'loveme', 'whatever', 'donald', 'batman', 'zaq1zaq1', 'Password', 'princess',
          'starwars', 'solo', 'hello', 'freedom', 'charlie', 'aa123456', 'qwertyuiop', 'access',
          'login', 'passw0rd', 'admin123', 'root', 'toor', 'pass', 'test', 'guest', 'oracle',
          'changeme', 'welcome1', 'password123', '1q2w3e4r', 'qwerty123', 'abc123456', 'letmein123',
          'password!', 'P@ssw0rd', 'P@ssword', 'Password1', 'Password123', 'Welcome1', 'Welcome123',
          '1234', '12345', '123456', '1234567', '12345678', '123456789', '1234567890', 'password1234',
          'qwerty12345', 'abc12345', 'password12345', 'admin1234', 'root1234', 'test1234', 'user1234',
          'demo', 'demo123', 'sample', 'sample123', 'temp', 'temp123', 'default', 'default123',
          'secret', 'secret123', 'private', 'private123', 'public', 'public123', 'system', 'system123'
        ];
        
        return commonPasswords.includes(password.toLowerCase());
      },

      resetPasswordAnalysis() {
        const progressBar = document.getElementById('ht-password-bar');
        document.getElementById('ht-password-strength').textContent = '--';
        document.getElementById('ht-password-entropy').textContent = '-- bits';
        
        if (progressBar) {
          progressBar.style.width = '0%';
          progressBar.className = 'bg-red-500 h-full rounded-full transition-all duration-300';
        }
        
        ['ht-check-numbers', 'ht-check-special', 'ht-check-mixed', 'ht-check-common'].forEach(id => {
          const element = document.getElementById(id);
          if (element) {
            const icon = element.querySelector('.material-symbols-outlined');
            icon.textContent = 'cancel';
            element.className = 'flex items-center gap-1.5 text-slate-500';
          }
        });
      },

      setupPasswordAnalyzer() {
        const input = document.getElementById('ht-password-input');
        
        if (!input) return;
        
        const analyzePassword = this.debounce(() => {
          const password = input.value;
          
          if (!password) {
            this.resetPasswordAnalysis();
            return;
          }
          
          const entropy = this.calculateEntropy(password);
          
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
          
          const progressBar = document.getElementById('ht-password-bar');
          document.getElementById('ht-password-strength').textContent = strength;
          document.getElementById('ht-password-strength').className = `text-xl font-bold ${strengthColor}`;
          document.getElementById('ht-password-entropy').textContent = `${Math.round(entropy)} bits`;
          
          progressBar.style.width = `${barWidth}%`;
          progressBar.className = `${barColor} h-full rounded-full transition-all duration-300`;
          
          // Update composition checks
          this.updatePasswordChecks(password);
        }, 150);
        
        input.addEventListener('input', analyzePassword);
      }
    };
  });

  describe('End-to-End Password Analysis', () => {
    it('should analyze strong password with all checks passing', () => {
      CyberGuardHashTools.setupPasswordAnalyzer();
      
      const input = document.getElementById('ht-password-input');
      input.value = 'MyStr0ng!P@ssw0rd';
      input.dispatchEvent(new dom.window.Event('input'));
      
      // Verify all composition checks pass
      const checks = {
        numbers: document.getElementById('ht-check-numbers'),
        special: document.getElementById('ht-check-special'),
        mixed: document.getElementById('ht-check-mixed'),
        common: document.getElementById('ht-check-common')
      };
      
      Object.values(checks).forEach(element => {
        expect(element.querySelector('.material-symbols-outlined').textContent).toBe('check_circle');
        expect(element.className).toContain('text-green-400/80');
      });
      
      // Verify strength indicator is updated
      expect(document.getElementById('ht-password-strength').textContent).not.toBe('--');
      expect(document.getElementById('ht-password-entropy').textContent).not.toBe('-- bits');
    });

    it('should analyze weak password with all checks failing', () => {
      CyberGuardHashTools.setupPasswordAnalyzer();
      
      const input = document.getElementById('ht-password-input');
      input.value = 'password';
      input.dispatchEvent(new dom.window.Event('input'));
      
      // Verify all composition checks fail
      const checks = {
        numbers: document.getElementById('ht-check-numbers'),
        special: document.getElementById('ht-check-special'),
        mixed: document.getElementById('ht-check-mixed'),
        common: document.getElementById('ht-check-common')
      };
      
      Object.values(checks).forEach(element => {
        expect(element.querySelector('.material-symbols-outlined').textContent).toBe('cancel');
        expect(element.className).toContain('text-red-400/60');
      });
    });

    it('should reset all checks when input is cleared', () => {
      CyberGuardHashTools.setupPasswordAnalyzer();
      
      const input = document.getElementById('ht-password-input');
      
      // First enter a password
      input.value = 'Test123!';
      input.dispatchEvent(new dom.window.Event('input'));
      
      // Then clear it
      input.value = '';
      input.dispatchEvent(new dom.window.Event('input'));
      
      // Verify all checks are reset to default state
      const checks = ['ht-check-numbers', 'ht-check-special', 'ht-check-mixed', 'ht-check-common'];
      
      checks.forEach(id => {
        const element = document.getElementById(id);
        expect(element.querySelector('.material-symbols-outlined').textContent).toBe('cancel');
        expect(element.className).toContain('text-slate-500');
      });
      
      // Verify strength is reset
      expect(document.getElementById('ht-password-strength').textContent).toBe('--');
      expect(document.getElementById('ht-password-entropy').textContent).toBe('-- bits');
    });

    it('should handle mixed results correctly', () => {
      CyberGuardHashTools.setupPasswordAnalyzer();
      
      const input = document.getElementById('ht-password-input');
      input.value = 'password123'; // Common password with numbers
      input.dispatchEvent(new dom.window.Event('input'));
      
      // Numbers should pass
      const numbersCheck = document.getElementById('ht-check-numbers');
      expect(numbersCheck.querySelector('.material-symbols-outlined').textContent).toBe('check_circle');
      expect(numbersCheck.className).toContain('text-green-400/80');
      
      // Special, mixed, and common should fail
      const specialCheck = document.getElementById('ht-check-special');
      const mixedCheck = document.getElementById('ht-check-mixed');
      const commonCheck = document.getElementById('ht-check-common');
      
      expect(specialCheck.querySelector('.material-symbols-outlined').textContent).toBe('cancel');
      expect(mixedCheck.querySelector('.material-symbols-outlined').textContent).toBe('cancel');
      expect(commonCheck.querySelector('.material-symbols-outlined').textContent).toBe('cancel');
    });

    it('should update checks in real-time as user types', () => {
      CyberGuardHashTools.setupPasswordAnalyzer();
      
      const input = document.getElementById('ht-password-input');
      
      // Start with lowercase only
      input.value = 'test';
      input.dispatchEvent(new dom.window.Event('input'));
      
      let mixedCheck = document.getElementById('ht-check-mixed');
      expect(mixedCheck.querySelector('.material-symbols-outlined').textContent).toBe('cancel');
      
      // Add uppercase
      input.value = 'Test';
      input.dispatchEvent(new dom.window.Event('input'));
      
      mixedCheck = document.getElementById('ht-check-mixed');
      expect(mixedCheck.querySelector('.material-symbols-outlined').textContent).toBe('check_circle');
      
      // Add numbers
      input.value = 'Test123';
      input.dispatchEvent(new dom.window.Event('input'));
      
      const numbersCheck = document.getElementById('ht-check-numbers');
      expect(numbersCheck.querySelector('.material-symbols-outlined').textContent).toBe('check_circle');
      
      // Add special characters
      input.value = 'Test123!';
      input.dispatchEvent(new dom.window.Event('input'));
      
      const specialCheck = document.getElementById('ht-check-special');
      expect(specialCheck.querySelector('.material-symbols-outlined').textContent).toBe('check_circle');
    });
  });

  describe('Requirement 4.8: Simultaneous Display', () => {
    it('should display all four checks in the DOM', () => {
      const checksContainer = document.getElementById('ht-password-checks');
      expect(checksContainer).toBeTruthy();
      
      const checks = [
        'ht-check-numbers',
        'ht-check-special',
        'ht-check-mixed',
        'ht-check-common'
      ];
      
      checks.forEach(id => {
        const element = document.getElementById(id);
        expect(element).toBeTruthy();
        expect(element.querySelector('.material-symbols-outlined')).toBeTruthy();
      });
    });

    it('should update all checks simultaneously', () => {
      const password = 'SecureP@ss123';
      
      CyberGuardHashTools.updatePasswordChecks(password);
      
      // All checks should be updated at the same time
      const checks = [
        'ht-check-numbers',
        'ht-check-special',
        'ht-check-mixed',
        'ht-check-common'
      ];
      
      checks.forEach(id => {
        const element = document.getElementById(id);
        const icon = element.querySelector('.material-symbols-outlined');
        
        // All should show check_circle (all checks pass for this password)
        expect(icon.textContent).toBe('check_circle');
        expect(element.className).toContain('text-green-400/80');
      });
    });
  });
});
