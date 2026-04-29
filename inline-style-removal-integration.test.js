/**
 * Integration Tests for Task 8.5: Write integration tests for inline style removal
 * 
 * Validates Requirements: 5.1, 5.2, 5.3, 5.4, 5.5
 * 
 * These tests verify that:
 * 1. dashboard.html contains zero inline style attributes with color values
 * 2. login.html contains zero inline style attributes with color values
 * 3. signup.html contains zero inline style attributes with color values
 * 4. index.html contains zero inline style attributes with color values
 * 5. All HTML files link theme-tokens.css as the first stylesheet
 * 6. No hard-coded color values remain in inline styles across all pages
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { join } from 'path';

describe('Task 8.5: Inline Style Removal Integration Tests', () => {
  // Load all HTML files
  const dashboardHtml = readFileSync(join(process.cwd(), 'dashboard.html'), 'utf-8');
  const loginHtml = readFileSync(join(process.cwd(), 'login.html'), 'utf-8');
  const signupHtml = readFileSync(join(process.cwd(), 'signup.html'), 'utf-8');
  const indexHtml = readFileSync(join(process.cwd(), 'index.html'), 'utf-8');

  describe('Requirement 5.1: dashboard.html inline style removal', () => {
    it('should contain zero inline style attributes', () => {
      const inlineStylePattern = /style\s*=\s*["'][^"']*["']/gi;
      const matches = dashboardHtml.match(inlineStylePattern);
      
      expect(matches).toBeNull();
    });

    it('should not contain inline color values (hex, rgb, rgba)', () => {
      const hexColorPattern = /style\s*=\s*["'][^"']*#[0-9A-Fa-f]{3,8}[^"']*["']/gi;
      const rgbColorPattern = /style\s*=\s*["'][^"']*rgba?\([^)]+\)[^"']*["']/gi;
      
      expect(dashboardHtml.match(hexColorPattern)).toBeNull();
      expect(dashboardHtml.match(rgbColorPattern)).toBeNull();
    });

    it('should not contain inline background-color styles', () => {
      const backgroundColorPattern = /style\s*=\s*["'][^"']*background-color[^"']*["']/gi;
      expect(dashboardHtml.match(backgroundColorPattern)).toBeNull();
    });

    it('should not contain inline color property styles', () => {
      const colorPropertyPattern = /style\s*=\s*["'][^"']*\bcolor\s*:[^"']*["']/gi;
      expect(dashboardHtml.match(colorPropertyPattern)).toBeNull();
    });

    it('should not contain inline border-color styles', () => {
      const borderColorPattern = /style\s*=\s*["'][^"']*border-color[^"']*["']/gi;
      expect(dashboardHtml.match(borderColorPattern)).toBeNull();
    });
  });

  describe('Requirement 5.2: login.html inline style removal', () => {
    it('should contain zero inline style attributes', () => {
      const inlineStylePattern = /style\s*=\s*["'][^"']*["']/gi;
      const matches = loginHtml.match(inlineStylePattern);
      
      expect(matches).toBeNull();
    });

    it('should not contain inline color values (hex, rgb, rgba)', () => {
      const hexColorPattern = /style\s*=\s*["'][^"']*#[0-9A-Fa-f]{3,8}[^"']*["']/gi;
      const rgbColorPattern = /style\s*=\s*["'][^"']*rgba?\([^)]+\)[^"']*["']/gi;
      
      expect(loginHtml.match(hexColorPattern)).toBeNull();
      expect(loginHtml.match(rgbColorPattern)).toBeNull();
    });

    it('should not contain inline background-color styles', () => {
      const backgroundColorPattern = /style\s*=\s*["'][^"']*background-color[^"']*["']/gi;
      expect(loginHtml.match(backgroundColorPattern)).toBeNull();
    });

    it('should not contain inline color property styles', () => {
      const colorPropertyPattern = /style\s*=\s*["'][^"']*\bcolor\s*:[^"']*["']/gi;
      expect(loginHtml.match(colorPropertyPattern)).toBeNull();
    });
  });

  describe('Requirement 5.4: signup.html inline style removal', () => {
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

    it('should not contain inline background-color styles', () => {
      const backgroundColorPattern = /style\s*=\s*["'][^"']*background-color[^"']*["']/gi;
      expect(signupHtml.match(backgroundColorPattern)).toBeNull();
    });

    it('should not contain inline color property styles', () => {
      const colorPropertyPattern = /style\s*=\s*["'][^"']*\bcolor\s*:[^"']*["']/gi;
      expect(signupHtml.match(colorPropertyPattern)).toBeNull();
    });
  });

  describe('Requirement 5.3: index.html inline style removal', () => {
    it('should contain zero inline style attributes', () => {
      const inlineStylePattern = /style\s*=\s*["'][^"']*["']/gi;
      const matches = indexHtml.match(inlineStylePattern);
      
      expect(matches).toBeNull();
    });

    it('should not contain inline color values (hex, rgb, rgba)', () => {
      const hexColorPattern = /style\s*=\s*["'][^"']*#[0-9A-Fa-f]{3,8}[^"']*["']/gi;
      const rgbColorPattern = /style\s*=\s*["'][^"']*rgba?\([^)]+\)[^"']*["']/gi;
      
      expect(indexHtml.match(hexColorPattern)).toBeNull();
      expect(indexHtml.match(rgbColorPattern)).toBeNull();
    });

    it('should not contain inline stop-color attributes in SVG gradients', () => {
      const stopColorPattern = /style\s*=\s*["'][^"']*stop-color[^"']*["']/gi;
      expect(indexHtml.match(stopColorPattern)).toBeNull();
    });

    it('should not contain inline background-color styles', () => {
      const backgroundColorPattern = /style\s*=\s*["'][^"']*background-color[^"']*["']/gi;
      expect(indexHtml.match(backgroundColorPattern)).toBeNull();
    });
  });

  describe('Requirement 5.5: Theme tokens integration', () => {
    it('should link theme-tokens.css in dashboard.html', () => {
      expect(dashboardHtml).toContain('theme-tokens.css');
    });

    it('should link theme-tokens.css in login.html', () => {
      expect(loginHtml).toContain('theme-tokens.css');
    });

    it('should link theme-tokens.css in signup.html', () => {
      expect(signupHtml).toContain('theme-tokens.css');
    });

    it('should link theme-tokens.css in index.html', () => {
      expect(indexHtml).toContain('theme-tokens.css');
    });

    it('should link theme-tokens.css FIRST in dashboard.html', () => {
      const themeTokensIndex = dashboardHtml.indexOf('theme-tokens.css');
      const cyberThemeIndex = dashboardHtml.indexOf('cyber-theme.css');
      
      expect(themeTokensIndex).toBeGreaterThan(-1);
      expect(cyberThemeIndex).toBeGreaterThan(-1);
      expect(themeTokensIndex).toBeLessThan(cyberThemeIndex);
    });

    it('should link theme-tokens.css FIRST in login.html (before inline styles)', () => {
      const themeTokensIndex = loginHtml.indexOf('theme-tokens.css');
      const inlineStyleIndex = loginHtml.indexOf('<style>');
      
      expect(themeTokensIndex).toBeGreaterThan(-1);
      // If there are inline styles, theme-tokens should come before them
      if (inlineStyleIndex > -1) {
        expect(themeTokensIndex).toBeLessThan(inlineStyleIndex);
      }
    });

    it('should link theme-tokens.css FIRST in signup.html (before inline styles)', () => {
      const themeTokensIndex = signupHtml.indexOf('theme-tokens.css');
      const inlineStyleIndex = signupHtml.indexOf('<style>');
      
      expect(themeTokensIndex).toBeGreaterThan(-1);
      // If there are inline styles, theme-tokens should come before them
      if (inlineStyleIndex > -1) {
        expect(themeTokensIndex).toBeLessThan(inlineStyleIndex);
      }
    });

    it('should link theme-tokens.css FIRST in index.html', () => {
      const themeTokensIndex = indexHtml.indexOf('theme-tokens.css');
      const landingCssIndex = indexHtml.indexOf('landing.css');
      
      expect(themeTokensIndex).toBeGreaterThan(-1);
      expect(landingCssIndex).toBeGreaterThan(-1);
      expect(themeTokensIndex).toBeLessThan(landingCssIndex);
    });
  });

  describe('Cross-page consistency: No hard-coded colors in inline styles', () => {
    const allHtmlFiles = [
      { name: 'dashboard.html', content: dashboardHtml },
      { name: 'login.html', content: loginHtml },
      { name: 'signup.html', content: signupHtml },
      { name: 'index.html', content: indexHtml }
    ];

    allHtmlFiles.forEach(({ name, content }) => {
      describe(`${name}`, () => {
        it('should not contain hard-coded hex colors in inline styles', () => {
          const hexInStylePattern = /style\s*=\s*["'][^"']*#[0-9A-Fa-f]{3,8}[^"']*["']/gi;
          expect(content.match(hexInStylePattern)).toBeNull();
        });

        it('should not contain hard-coded rgb/rgba colors in inline styles', () => {
          const rgbInStylePattern = /style\s*=\s*["'][^"']*rgba?\([^)]+\)[^"']*["']/gi;
          expect(content.match(rgbInStylePattern)).toBeNull();
        });

        it('should not contain inline background-image with color gradients', () => {
          const gradientPattern = /style\s*=\s*["'][^"']*background-image[^"']*gradient[^"']*["']/gi;
          expect(content.match(gradientPattern)).toBeNull();
        });

        it('should not contain inline box-shadow with color values', () => {
          const boxShadowPattern = /style\s*=\s*["'][^"']*box-shadow[^"']*["']/gi;
          expect(content.match(boxShadowPattern)).toBeNull();
        });

        it('should not contain inline text-shadow with color values', () => {
          const textShadowPattern = /style\s*=\s*["'][^"']*text-shadow[^"']*["']/gi;
          expect(content.match(textShadowPattern)).toBeNull();
        });

        it('should not contain inline border with color values', () => {
          const borderWithColorPattern = /style\s*=\s*["'][^"']*border[^"']*(?:#[0-9A-Fa-f]{3,8}|rgba?\([^)]+\))[^"']*["']/gi;
          expect(content.match(borderWithColorPattern)).toBeNull();
        });
      });
    });
  });

  describe('Cleanup completeness verification', () => {
    it('should have zero total inline style attributes across all pages', () => {
      const inlineStylePattern = /style\s*=\s*["'][^"']*["']/gi;
      
      const dashboardMatches = dashboardHtml.match(inlineStylePattern);
      const loginMatches = loginHtml.match(inlineStylePattern);
      const signupMatches = signupHtml.match(inlineStylePattern);
      const indexMatches = indexHtml.match(inlineStylePattern);
      
      const totalMatches = [
        ...(dashboardMatches || []),
        ...(loginMatches || []),
        ...(signupMatches || []),
        ...(indexMatches || [])
      ];
      
      expect(totalMatches.length).toBe(0);
    });

    it('should have zero color-related inline styles across all pages', () => {
      const colorRelatedPattern = /style\s*=\s*["'][^"']*(?:color|background|border|shadow|gradient)[^"']*["']/gi;
      
      const allContent = dashboardHtml + loginHtml + signupHtml + indexHtml;
      const matches = allContent.match(colorRelatedPattern);
      
      expect(matches).toBeNull();
    });

    it('should have all pages linking theme-tokens.css', () => {
      expect(dashboardHtml).toContain('theme-tokens.css');
      expect(loginHtml).toContain('theme-tokens.css');
      expect(signupHtml).toContain('theme-tokens.css');
      expect(indexHtml).toContain('theme-tokens.css');
    });
  });

  describe('Specific color value removal verification', () => {
    const specificColors = [
      { name: 'violet accent', value: '#A78BFA' },
      { name: 'violet hover', value: '#8B5CF6' },
      { name: 'cyan accent', value: '#06B6D4' },
      { name: 'cyan light', value: '#22D3EE' },
      { name: 'cyan info', value: '#38BDF8' },
      { name: 'success green', value: '#34D399' },
      { name: 'warning yellow', value: '#FBBF24' },
      { name: 'danger red', value: '#F87171' },
      { name: 'deep space navy', value: '#0B0F19' }
    ];

    specificColors.forEach(({ name, value }) => {
      it(`should not contain ${name} (${value}) in inline styles across all pages`, () => {
        const pattern = new RegExp(`style\\s*=\\s*["'][^"']*${value.replace('#', '\\#')}[^"']*["']`, 'gi');
        
        expect(dashboardHtml.match(pattern)).toBeNull();
        expect(loginHtml.match(pattern)).toBeNull();
        expect(signupHtml.match(pattern)).toBeNull();
        expect(indexHtml.match(pattern)).toBeNull();
      });
    });

    it('should not contain rgba(255, 255, 255, ...) in inline styles', () => {
      const whiteRgbaPattern = /style\s*=\s*["'][^"']*rgba\(255,\s*255,\s*255[^)]*\)[^"']*["']/gi;
      
      expect(dashboardHtml.match(whiteRgbaPattern)).toBeNull();
      expect(loginHtml.match(whiteRgbaPattern)).toBeNull();
      expect(signupHtml.match(whiteRgbaPattern)).toBeNull();
      expect(indexHtml.match(whiteRgbaPattern)).toBeNull();
    });

    it('should not contain rgba(17, 24, 39, ...) in inline styles', () => {
      const surfaceRgbaPattern = /style\s*=\s*["'][^"']*rgba\(17,\s*24,\s*39[^)]*\)[^"']*["']/gi;
      
      expect(dashboardHtml.match(surfaceRgbaPattern)).toBeNull();
      expect(loginHtml.match(surfaceRgbaPattern)).toBeNull();
      expect(signupHtml.match(surfaceRgbaPattern)).toBeNull();
      expect(indexHtml.match(surfaceRgbaPattern)).toBeNull();
    });

    it('should not contain rgba(167, 139, 250, ...) in inline styles', () => {
      const accentRgbaPattern = /style\s*=\s*["'][^"']*rgba\(167,\s*139,\s*250[^)]*\)[^"']*["']/gi;
      
      expect(dashboardHtml.match(accentRgbaPattern)).toBeNull();
      expect(loginHtml.match(accentRgbaPattern)).toBeNull();
      expect(signupHtml.match(accentRgbaPattern)).toBeNull();
      expect(indexHtml.match(accentRgbaPattern)).toBeNull();
    });
  });

  describe('Visual parity indicators', () => {
    it('should maintain CSS class usage for styling in dashboard.html', () => {
      // Verify that CSS classes are being used instead of inline styles
      expect(dashboardHtml).toMatch(/class\s*=\s*["'][^"']*cyber-[^"']*["']/);
    });

    it('should maintain CSS class usage for styling in login.html', () => {
      expect(loginHtml).toMatch(/class\s*=\s*["'][^"']*["']/);
    });

    it('should maintain CSS class usage for styling in signup.html', () => {
      expect(signupHtml).toMatch(/class\s*=\s*["'][^"']*["']/);
    });

    it('should maintain CSS class usage for styling in index.html', () => {
      expect(indexHtml).toMatch(/class\s*=\s*["'][^"']*["']/);
    });
  });
});
