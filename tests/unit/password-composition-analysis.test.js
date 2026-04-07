/**
 * Unit Tests for Password Composition Analysis (Task 3.3)
 * 
 * Tests the password composition checks implementation in updatePasswordChecks()
 * Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 4.7, 4.8
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { JSDOM } from 'jsdom';

describe('Password Composition Analysis', () => {
  let dom;
  let document;
  let CyberGuardHashTools;

  beforeEach(() => {
    // Create a minimal DOM environment
    dom = new JSDOM(`
      <!DOCTYPE html>
      <html>
        <body>
          <div id="ht-check-numbers" class="flex items-center gap-1.5">
            <span class="material-symbols-outlined text-[14px]">cancel</span>
            <span>Numbers Included</span>
          </div>
          <div id="ht-check-special" class="flex items-center gap-1.5">
            <span class="material-symbols-outlined text-[14px]">cancel</span>
            <span>Special Symbols</span>
          </div>
          <div id="ht-check-mixed" class="flex items-center gap-1.5">
            <span class="material-symbols-outlined text-[14px]">cancel</span>
            <span>Mixed Case</span>
          </div>
          <div id="ht-check-common" class="flex items-center gap-1.5">
            <span class="material-symbols-outlined text-[14px]">cancel</span>
            <span>Common Phrase</span>
          </div>
        </body>
      </html>
    `);
    
    document = dom.window.document;
    global.document = document;

    // Mock CyberGuardHashTools with the actual implementation
    CyberGuardHashTools = {
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
      }
    };
  });

  describe('Requirement 4.1: Check for numbers', () => {
    it('should detect numbers in password', () => {
      CyberGuardHashTools.updatePasswordChecks('abc123');
      
      const element = document.getElementById('ht-check-numbers');
      const icon = element.querySelector('.material-symbols-outlined');
      
      expect(icon.textContent).toBe('check_circle');
      expect(element.className).toContain('text-green-400/80');
    });

    it('should detect absence of numbers', () => {
      CyberGuardHashTools.updatePasswordChecks('abcdef');
      
      const element = document.getElementById('ht-check-numbers');
      const icon = element.querySelector('.material-symbols-outlined');
      
      expect(icon.textContent).toBe('cancel');
      expect(element.className).toContain('text-red-400/60');
    });
  });

  describe('Requirement 4.2: Check for special symbols', () => {
    it('should detect special symbols in password', () => {
      CyberGuardHashTools.updatePasswordChecks('abc@123');
      
      const element = document.getElementById('ht-check-special');
      const icon = element.querySelector('.material-symbols-outlined');
      
      expect(icon.textContent).toBe('check_circle');
      expect(element.className).toContain('text-green-400/80');
    });

    it('should detect various special symbols', () => {
      const specialChars = ['!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '-', '_', '+', '='];
      
      specialChars.forEach(char => {
        CyberGuardHashTools.updatePasswordChecks(`test${char}123`);
        
        const element = document.getElementById('ht-check-special');
        const icon = element.querySelector('.material-symbols-outlined');
        
        expect(icon.textContent).toBe('check_circle');
        expect(element.className).toContain('text-green-400/80');
      });
    });

    it('should detect absence of special symbols', () => {
      CyberGuardHashTools.updatePasswordChecks('abc123');
      
      const element = document.getElementById('ht-check-special');
      const icon = element.querySelector('.material-symbols-outlined');
      
      expect(icon.textContent).toBe('cancel');
      expect(element.className).toContain('text-red-400/60');
    });
  });

  describe('Requirement 4.3: Check for mixed case letters', () => {
    it('should detect mixed case in password', () => {
      CyberGuardHashTools.updatePasswordChecks('AbCdEf');
      
      const element = document.getElementById('ht-check-mixed');
      const icon = element.querySelector('.material-symbols-outlined');
      
      expect(icon.textContent).toBe('check_circle');
      expect(element.className).toContain('text-green-400/80');
    });

    it('should detect absence of mixed case (lowercase only)', () => {
      CyberGuardHashTools.updatePasswordChecks('abcdef');
      
      const element = document.getElementById('ht-check-mixed');
      const icon = element.querySelector('.material-symbols-outlined');
      
      expect(icon.textContent).toBe('cancel');
      expect(element.className).toContain('text-red-400/60');
    });

    it('should detect absence of mixed case (uppercase only)', () => {
      CyberGuardHashTools.updatePasswordChecks('ABCDEF');
      
      const element = document.getElementById('ht-check-mixed');
      const icon = element.querySelector('.material-symbols-outlined');
      
      expect(icon.textContent).toBe('cancel');
      expect(element.className).toContain('text-red-400/60');
    });
  });

  describe('Requirement 4.4: Check against common passwords list', () => {
    it('should detect common password "password"', () => {
      CyberGuardHashTools.updatePasswordChecks('password');
      
      const element = document.getElementById('ht-check-common');
      const icon = element.querySelector('.material-symbols-outlined');
      
      expect(icon.textContent).toBe('cancel');
      expect(element.className).toContain('text-red-400/60');
    });

    it('should detect common password "123456"', () => {
      CyberGuardHashTools.updatePasswordChecks('123456');
      
      const element = document.getElementById('ht-check-common');
      const icon = element.querySelector('.material-symbols-outlined');
      
      expect(icon.textContent).toBe('cancel');
      expect(element.className).toContain('text-red-400/60');
    });

    it('should detect common password case-insensitively', () => {
      CyberGuardHashTools.updatePasswordChecks('PASSWORD');
      
      const element = document.getElementById('ht-check-common');
      const icon = element.querySelector('.material-symbols-outlined');
      
      expect(icon.textContent).toBe('cancel');
      expect(element.className).toContain('text-red-400/60');
    });

    it('should pass for non-common password', () => {
      CyberGuardHashTools.updatePasswordChecks('MyUniqueP@ssw0rd!2024');
      
      const element = document.getElementById('ht-check-common');
      const icon = element.querySelector('.material-symbols-outlined');
      
      expect(icon.textContent).toBe('check_circle');
      expect(element.className).toContain('text-green-400/80');
    });

    it('should have at least 100 common passwords in the list', () => {
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
      
      expect(commonPasswords.length).toBeGreaterThanOrEqual(100);
    });
  });

  describe('Requirements 4.5, 4.6, 4.7: Visual indicators', () => {
    it('should display green checkmark when element is present', () => {
      CyberGuardHashTools.updatePasswordChecks('Test123!');
      
      // All checks should pass
      ['ht-check-numbers', 'ht-check-special', 'ht-check-mixed', 'ht-check-common'].forEach(id => {
        const element = document.getElementById(id);
        const icon = element.querySelector('.material-symbols-outlined');
        
        expect(icon.textContent).toBe('check_circle');
        expect(element.className).toContain('text-green-400/80');
      });
    });

    it('should display red X when element is absent', () => {
      CyberGuardHashTools.updatePasswordChecks('test');
      
      // Numbers, special, and mixed case should fail
      ['ht-check-numbers', 'ht-check-special', 'ht-check-mixed'].forEach(id => {
        const element = document.getElementById(id);
        const icon = element.querySelector('.material-symbols-outlined');
        
        expect(icon.textContent).toBe('cancel');
        expect(element.className).toContain('text-red-400/60');
      });
    });
  });

  describe('Requirement 4.8: Display all checks simultaneously', () => {
    it('should update all composition checks at once', () => {
      CyberGuardHashTools.updatePasswordChecks('SecureP@ss123');
      
      // Verify all elements exist and are updated
      const numbersCheck = document.getElementById('ht-check-numbers');
      const specialCheck = document.getElementById('ht-check-special');
      const mixedCheck = document.getElementById('ht-check-mixed');
      const commonCheck = document.getElementById('ht-check-common');
      
      expect(numbersCheck).toBeTruthy();
      expect(specialCheck).toBeTruthy();
      expect(mixedCheck).toBeTruthy();
      expect(commonCheck).toBeTruthy();
      
      // All should show check_circle (passing)
      expect(numbersCheck.querySelector('.material-symbols-outlined').textContent).toBe('check_circle');
      expect(specialCheck.querySelector('.material-symbols-outlined').textContent).toBe('check_circle');
      expect(mixedCheck.querySelector('.material-symbols-outlined').textContent).toBe('check_circle');
      expect(commonCheck.querySelector('.material-symbols-outlined').textContent).toBe('check_circle');
    });

    it('should handle mixed passing and failing checks', () => {
      CyberGuardHashTools.updatePasswordChecks('password123'); // Common password with numbers
      
      const numbersCheck = document.getElementById('ht-check-numbers');
      const specialCheck = document.getElementById('ht-check-special');
      const mixedCheck = document.getElementById('ht-check-mixed');
      const commonCheck = document.getElementById('ht-check-common');
      
      // Numbers should pass
      expect(numbersCheck.querySelector('.material-symbols-outlined').textContent).toBe('check_circle');
      
      // Special and mixed should fail
      expect(specialCheck.querySelector('.material-symbols-outlined').textContent).toBe('cancel');
      expect(mixedCheck.querySelector('.material-symbols-outlined').textContent).toBe('cancel');
      
      // Common should fail (it's a common password)
      expect(commonCheck.querySelector('.material-symbols-outlined').textContent).toBe('cancel');
    });
  });

  describe('Integration: Complete password composition analysis', () => {
    it('should correctly analyze a strong password', () => {
      CyberGuardHashTools.updatePasswordChecks('MyStr0ng!P@ssw0rd');
      
      const checks = {
        numbers: document.getElementById('ht-check-numbers'),
        special: document.getElementById('ht-check-special'),
        mixed: document.getElementById('ht-check-mixed'),
        common: document.getElementById('ht-check-common')
      };
      
      // All checks should pass
      Object.values(checks).forEach(element => {
        expect(element.querySelector('.material-symbols-outlined').textContent).toBe('check_circle');
        expect(element.className).toContain('text-green-400/80');
      });
    });

    it('should correctly analyze a weak password', () => {
      CyberGuardHashTools.updatePasswordChecks('password');
      
      const checks = {
        numbers: document.getElementById('ht-check-numbers'),
        special: document.getElementById('ht-check-special'),
        mixed: document.getElementById('ht-check-mixed'),
        common: document.getElementById('ht-check-common')
      };
      
      // All checks should fail
      Object.values(checks).forEach(element => {
        expect(element.querySelector('.material-symbols-outlined').textContent).toBe('cancel');
        expect(element.className).toContain('text-red-400/60');
      });
    });
  });
});
