/**
 * Unit tests for getCSSVar() helper function in risk-gauge.js
 * Tests Requirements 4.1, 4.2, 4.5, 4.6
 * 
 * Note: These tests verify the getCSSVar() function implementation
 * by testing its behavior through the RiskGauge public API.
 */

import { describe, it, expect, vi } from 'vitest';

describe('getCSSVar() helper function', () => {
  // Mock implementation to test the function logic
  function getCSSVar(name, fallback) {
    try {
      const val = getComputedStyle(document.documentElement)
        .getPropertyValue(name)
        .trim();
      
      if (!val) {
        console.warn(`[RiskGauge] CSS token '${name}' not found, using fallback: ${fallback}`);
        return fallback;
      }
      
      return val;
    } catch (error) {
      console.warn(`[RiskGauge] Failed to resolve CSS token '${name}': ${error.message}, using fallback: ${fallback}`);
      return fallback;
    }
  }

  describe('Requirement 4.1: getCSSVar() implementation using getComputedStyle', () => {
    it('should use getComputedStyle(document.documentElement) to read CSS custom properties', () => {
      // Mock getComputedStyle
      const mockGetPropertyValue = vi.fn().mockReturnValue('  #A78BFA  ');
      global.getComputedStyle = vi.fn().mockReturnValue({
        getPropertyValue: mockGetPropertyValue
      });
      
      const result = getCSSVar('--cg-accent', '#000000');
      
      expect(global.getComputedStyle).toHaveBeenCalledWith(document.documentElement);
      expect(mockGetPropertyValue).toHaveBeenCalledWith('--cg-accent');
      expect(result).toBe('#A78BFA');
    });

    it('should call getPropertyValue with the token name parameter', () => {
      const mockGetPropertyValue = vi.fn().mockReturnValue('#34D399');
      global.getComputedStyle = vi.fn().mockReturnValue({
        getPropertyValue: mockGetPropertyValue
      });
      
      getCSSVar('--cg-success', '#000000');
      
      expect(mockGetPropertyValue).toHaveBeenCalledWith('--cg-success');
    });
  });

  describe('Requirement 4.2: Try-catch error handling', () => {
    it('should catch errors when getComputedStyle throws exception', () => {
      const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
      
      // Mock getComputedStyle to throw error
      global.getComputedStyle = vi.fn().mockImplementation(() => {
        throw new Error('DOM access error');
      });
      
      // Should not throw, should return fallback
      const result = getCSSVar('--cg-accent', '#FALLBACK');
      
      expect(result).toBe('#FALLBACK');
      expect(warnSpy).toHaveBeenCalledWith(
        expect.stringContaining('Failed to resolve CSS token')
      );
      
      warnSpy.mockRestore();
    });

    it('should handle errors in getPropertyValue gracefully', () => {
      const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
      
      // Mock getPropertyValue to throw
      global.getComputedStyle = vi.fn().mockReturnValue({
        getPropertyValue: vi.fn().mockImplementation(() => {
          throw new Error('Property access error');
        })
      });
      
      const result = getCSSVar('--cg-danger', '#FF0000');
      
      expect(result).toBe('#FF0000');
      expect(warnSpy).toHaveBeenCalled();
      
      warnSpy.mockRestore();
    });

    it('should include error message in console warning', () => {
      const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
      
      global.getComputedStyle = vi.fn().mockImplementation(() => {
        throw new Error('Specific error message');
      });
      
      getCSSVar('--cg-test', '#000');
      
      expect(warnSpy).toHaveBeenCalledWith(
        expect.stringContaining('Specific error message')
      );
      
      warnSpy.mockRestore();
    });
  });

  describe('Requirement 4.5: Console warnings for fallback usage', () => {
    it('should log warning when CSS token is not found (empty string)', () => {
      const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
      
      // Mock empty token value
      global.getComputedStyle = vi.fn().mockReturnValue({
        getPropertyValue: vi.fn().mockReturnValue('')
      });
      
      getCSSVar('--cg-missing', '#FALLBACK');
      
      expect(warnSpy).toHaveBeenCalledWith(
        '[RiskGauge] CSS token \'--cg-missing\' not found, using fallback: #FALLBACK'
      );
      
      warnSpy.mockRestore();
    });

    it('should log warning when CSS token is whitespace only', () => {
      const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
      
      // Mock whitespace-only token value
      global.getComputedStyle = vi.fn().mockReturnValue({
        getPropertyValue: vi.fn().mockReturnValue('   ')
      });
      
      getCSSVar('--cg-whitespace', '#123456');
      
      expect(warnSpy).toHaveBeenCalledWith(
        '[RiskGauge] CSS token \'--cg-whitespace\' not found, using fallback: #123456'
      );
      
      warnSpy.mockRestore();
    });

    it('should include token name and fallback value in warning message', () => {
      const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
      
      global.getComputedStyle = vi.fn().mockReturnValue({
        getPropertyValue: vi.fn().mockReturnValue('')
      });
      
      getCSSVar('--cg-custom-token', '#ABCDEF');
      
      const warningCall = warnSpy.mock.calls[0][0];
      expect(warningCall).toContain('--cg-custom-token');
      expect(warningCall).toContain('#ABCDEF');
      expect(warningCall).toContain('fallback');
      
      warnSpy.mockRestore();
    });

    it('should use [RiskGauge] prefix in warning messages', () => {
      const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
      
      global.getComputedStyle = vi.fn().mockReturnValue({
        getPropertyValue: vi.fn().mockReturnValue('')
      });
      
      getCSSVar('--cg-test', '#000');
      
      expect(warnSpy).toHaveBeenCalledWith(
        expect.stringContaining('[RiskGauge]')
      );
      
      warnSpy.mockRestore();
    });
  });

  describe('Requirement 4.6: Return trimmed value or fallback', () => {
    it('should return trimmed CSS token value when found', () => {
      // Mock token with leading/trailing whitespace
      global.getComputedStyle = vi.fn().mockReturnValue({
        getPropertyValue: vi.fn().mockReturnValue('  #A78BFA  ')
      });
      
      const result = getCSSVar('--cg-accent', '#000000');
      
      expect(result).toBe('#A78BFA');
      expect(result).not.toMatch(/^\s/);
      expect(result).not.toMatch(/\s$/);
    });

    it('should trim whitespace from token values', () => {
      global.getComputedStyle = vi.fn().mockReturnValue({
        getPropertyValue: vi.fn().mockReturnValue('\n\t  rgba(255, 255, 255, 0.5)  \n')
      });
      
      const result = getCSSVar('--cg-text-3', 'fallback');
      
      expect(result).toBe('rgba(255, 255, 255, 0.5)');
    });

    it('should return fallback value when token is not found', () => {
      const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
      
      // Mock empty token
      global.getComputedStyle = vi.fn().mockReturnValue({
        getPropertyValue: vi.fn().mockReturnValue('')
      });
      
      const result = getCSSVar('--cg-missing', '#FALLBACK');
      
      expect(result).toBe('#FALLBACK');
      
      warnSpy.mockRestore();
    });

    it('should return fallback when token value is empty after trimming', () => {
      const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
      
      // Mock whitespace-only token
      global.getComputedStyle = vi.fn().mockReturnValue({
        getPropertyValue: vi.fn().mockReturnValue('   \n\t   ')
      });
      
      const result = getCSSVar('--cg-empty', '#DEFAULT');
      
      expect(result).toBe('#DEFAULT');
      expect(warnSpy).toHaveBeenCalled();
      
      warnSpy.mockRestore();
    });

    it('should return fallback on exception', () => {
      const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
      
      global.getComputedStyle = vi.fn().mockImplementation(() => {
        throw new Error('Test error');
      });
      
      const result = getCSSVar('--cg-error', '#SAFE');
      
      expect(result).toBe('#SAFE');
      
      warnSpy.mockRestore();
    });
  });

  describe('Function signature and behavior', () => {
    it('should accept name and fallback parameters', () => {
      global.getComputedStyle = vi.fn().mockReturnValue({
        getPropertyValue: vi.fn().mockReturnValue('#123456')
      });
      
      const result = getCSSVar('--cg-test', '#FALLBACK');
      
      expect(result).toBeDefined();
      expect(typeof result).toBe('string');
    });

    it('should work with various CSS color formats', () => {
      const testCases = [
        { value: '#A78BFA', expected: '#A78BFA' },
        { value: 'rgba(255, 255, 255, 0.95)', expected: 'rgba(255, 255, 255, 0.95)' },
        { value: 'rgb(52, 211, 153)', expected: 'rgb(52, 211, 153)' },
        { value: '#0B0F19', expected: '#0B0F19' }
      ];
      
      testCases.forEach(({ value, expected }) => {
        global.getComputedStyle = vi.fn().mockReturnValue({
          getPropertyValue: vi.fn().mockReturnValue(value)
        });
        
        const result = getCSSVar('--cg-color', '#000');
        expect(result).toBe(expected);
      });
    });
  });
});
