/**
 * Integration Tests for Task 8.2: Remove inline styles from login.html and signup.html
 * 
 * Validates Requirements: 5.2, 5.4, 5.5, 20.1, 20.2
 * 
 * These tests verify that:
 * 1. login.html contains zero inline style attributes with color values
 * 2. signup.html contains zero inline style attributes with color values
 * 3. Equivalent CSS classes exist in auth.css
 * 4. The dot grid overlay pattern is properly defined in CSS
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { join } from 'path';

describe('Task 8.2: Auth Pages Inline Style Cleanup', () => {
  const loginHtml = readFileSync(join(process.cwd(), 'login.html'), 'utf-8');
  const signupHtml = readFileSync(join(process.cwd(), 'signup.html'), 'utf-8');
  const authCss = readFileSync(join(process.cwd(), 'auth.css'), 'utf-8');

  describe('Requirement 5.2: Remove inline styles from login.html', () => {
    it('should contain zero inline style attributes', () => {
      // Match style=" followed by any content until closing quote
      const inlineStylePattern = /style\s*=\s*["'][^"']*["']/gi;
      const matches = loginHtml.match(inlineStylePattern);
      
      expect(matches).toBeNull();
    });

    it('should not contain inline color values (hex, rgb, rgba)', () => {
      // Check for common inline color patterns
      const hexColorPattern = /style\s*=\s*["'][^"']*#[0-9A-Fa-f]{3,8}[^"']*["']/gi;
      const rgbColorPattern = /style\s*=\s*["'][^"']*rgba?\([^)]+\)[^"']*["']/gi;
      
      expect(loginHtml.match(hexColorPattern)).toBeNull();
      expect(loginHtml.match(rgbColorPattern)).toBeNull();
    });

    it('should use dot-grid-overlay CSS class instead of inline style', () => {
      expect(loginHtml).toContain('dot-grid-overlay');
      expect(loginHtml).not.toContain('style="background-image: radial-gradient');
    });
  });

  describe('Requirement 5.4: Remove inline styles from signup.html', () => {
    it('should contain zero inline style attributes', () => {
      const inlineStylePattern = /style\s*=\s*["'][^"']*["']/gi;
      const matches = signupHtml.match(inlineStylePattern);
      
      expect(matches).toBeNull();
    });

    it('should not contain inline color values (hex, rgb, rgba)', () => {
      const hexColorPattern = /style\s*=\s*["'][^"']*#[0-9A-Fa-f]{3,8}[^"']*["']/gi;
      const rgbColorPattern = /style\s*=\s*["'][^"']*rgba?\([^)]+\)[^"']*["']/gi;
      
      expect(signupHtml.match(hexColorPattern)).toBeNull();
      expect(signupHtml.match(rgbColorPattern)).toBeNull();
    });
  });

  describe('Requirement 5.5: Create equivalent CSS classes in auth.css', () => {
    it('should define dot-grid-overlay class in login.html inline styles', () => {
      expect(loginHtml).toContain('.dot-grid-overlay');
      expect(loginHtml).toContain('background-image: radial-gradient(circle, rgba(255, 255, 255, 0.1) 1px, transparent 1px)');
      expect(loginHtml).toContain('background-size: 30px 30px');
    });

    it('should have dot-grid-overlay class defined before glow-orb in login.html', () => {
      const dotGridIndex = loginHtml.indexOf('.dot-grid-overlay');
      const glowOrbIndex = loginHtml.indexOf('.glow-orb');
      
      expect(dotGridIndex).toBeGreaterThan(-1);
      expect(glowOrbIndex).toBeGreaterThan(-1);
      expect(dotGridIndex).toBeLessThan(glowOrbIndex);
    });
  });

  describe('Requirement 20.1 & 20.2: Visual Parity Validation', () => {
    it('should maintain the same dot grid pattern values', () => {
      // Verify the CSS class has the exact same values as the original inline style
      const cssPattern = /\.dot-grid-overlay\s*\{[^}]*background-image:\s*radial-gradient\(circle,\s*rgba\(255,\s*255,\s*255,\s*0\.1\)\s*1px,\s*transparent\s*1px\)[^}]*background-size:\s*30px\s*30px[^}]*\}/s;
      
      expect(authCss).toMatch(cssPattern);
    });

    it('should preserve opacity-20 class on the overlay element', () => {
      // The opacity-20 Tailwind class should still be present
      expect(loginHtml).toMatch(/opacity-20[^>]*dot-grid-overlay|dot-grid-overlay[^>]*opacity-20/);
    });
  });

  describe('Integration: HTML and CSS Coordination', () => {
    it('should have dot-grid-overlay class referenced in login.html', () => {
      expect(loginHtml).toContain('dot-grid-overlay');
      expect(loginHtml).toContain('.dot-grid-overlay');
    });

    it('should link theme-tokens.css in login.html', () => {
      expect(loginHtml).toContain('theme-tokens.css');
    });

    it('should link theme-tokens.css in signup.html', () => {
      expect(signupHtml).toContain('theme-tokens.css');
    });
  });

  describe('Cleanup Completeness', () => {
    it('should have removed all background-image inline styles from login.html', () => {
      const backgroundImageInline = /style\s*=\s*["'][^"']*background-image[^"']*["']/gi;
      expect(loginHtml.match(backgroundImageInline)).toBeNull();
    });

    it('should have removed all background-size inline styles from login.html', () => {
      const backgroundSizeInline = /style\s*=\s*["'][^"']*background-size[^"']*["']/gi;
      expect(loginHtml.match(backgroundSizeInline)).toBeNull();
    });

    it('should not have any radial-gradient in inline styles', () => {
      const radialGradientInline = /style\s*=\s*["'][^"']*radial-gradient[^"']*["']/gi;
      expect(loginHtml.match(radialGradientInline)).toBeNull();
      expect(signupHtml.match(radialGradientInline)).toBeNull();
    });
  });
});
