/**
 * Integration Tests for Task 8.3: Remove inline styles from index.html (landing page)
 * 
 * Validates Requirements: 5.3, 5.5, 20.1, 20.2
 * 
 * These tests verify that:
 * 1. index.html contains zero inline style attributes with color values
 * 2. Equivalent CSS classes exist in landing.css for SVG gradient stops
 * 3. The gradient colors use design tokens (--cg-accent and --cg-info)
 * 4. Visual appearance is maintained after cleanup
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { join } from 'path';

describe('Task 8.3: Landing Page Inline Style Cleanup', () => {
  const indexHtml = readFileSync(join(process.cwd(), 'index.html'), 'utf-8');
  const landingCss = readFileSync(join(process.cwd(), 'landing.css'), 'utf-8');

  describe('Requirement 5.3: Remove inline styles from index.html', () => {
    it('should contain zero inline style attributes', () => {
      // Match style=" followed by any content until closing quote
      const inlineStylePattern = /style\s*=\s*["'][^"']*["']/gi;
      const matches = indexHtml.match(inlineStylePattern);
      
      expect(matches).toBeNull();
    });

    it('should not contain inline color values (hex, rgb, rgba)', () => {
      // Check for common inline color patterns in style attributes
      const hexColorPattern = /style\s*=\s*["'][^"']*#[0-9A-Fa-f]{3,8}[^"']*["']/gi;
      const rgbColorPattern = /style\s*=\s*["'][^"']*rgba?\([^)]+\)[^"']*["']/gi;
      
      expect(indexHtml.match(hexColorPattern)).toBeNull();
      expect(indexHtml.match(rgbColorPattern)).toBeNull();
    });

    it('should not contain inline stop-color attributes in SVG gradients', () => {
      // Verify no inline stop-color in style attributes
      const stopColorPattern = /style\s*=\s*["'][^"']*stop-color[^"']*["']/gi;
      expect(indexHtml.match(stopColorPattern)).toBeNull();
    });

    it('should use CSS classes for SVG gradient stops', () => {
      // Verify gradient stops use class attributes instead of inline styles
      expect(indexHtml).toContain('class="gradient-stop-start"');
      expect(indexHtml).toContain('class="gradient-stop-end"');
    });
  });

  describe('Requirement 5.5: Create equivalent CSS classes in landing.css', () => {
    it('should define gradient-stop-start class with design token', () => {
      expect(landingCss).toContain('.gradient-stop-start');
      expect(landingCss).toMatch(/\.gradient-stop-start\s*\{[^}]*stop-color:\s*var\(--cg-accent\)/);
      expect(landingCss).toMatch(/\.gradient-stop-start\s*\{[^}]*stop-opacity:\s*1/);
    });

    it('should define gradient-stop-end class with design token', () => {
      expect(landingCss).toContain('.gradient-stop-end');
      expect(landingCss).toMatch(/\.gradient-stop-end\s*\{[^}]*stop-color:\s*var\(--cg-info\)/);
      expect(landingCss).toMatch(/\.gradient-stop-end\s*\{[^}]*stop-opacity:\s*1/);
    });

    it('should use design tokens instead of hard-coded colors', () => {
      // Verify the CSS classes use var(--cg-*) tokens
      const gradientStopStartSection = landingCss.match(/\.gradient-stop-start\s*\{[^}]*\}/s);
      const gradientStopEndSection = landingCss.match(/\.gradient-stop-end\s*\{[^}]*\}/s);
      
      expect(gradientStopStartSection).toBeTruthy();
      expect(gradientStopEndSection).toBeTruthy();
      
      expect(gradientStopStartSection[0]).toContain('var(--cg-accent)');
      expect(gradientStopEndSection[0]).toContain('var(--cg-info)');
    });
  });

  describe('Requirement 20.1 & 20.2: Visual Parity Validation', () => {
    it('should maintain the same gradient definition structure', () => {
      // Verify the SVG gradient structure is preserved
      expect(indexHtml).toContain('<linearGradient id="progressGradient"');
      expect(indexHtml).toMatch(/<stop offset="0%"/);
      expect(indexHtml).toMatch(/<stop offset="100%"/);
    });

    it('should preserve the gradient ID for stroke reference', () => {
      // The progress-ring-fill CSS class should still reference the gradient
      expect(landingCss).toContain('stroke: url(#progressGradient)');
    });

    it('should map original colors to correct design tokens', () => {
      // Original: #A855F7 (purple) -> --cg-accent
      // Original: #06B6D4 (cyan) -> --cg-info
      const gradientStartMatch = landingCss.match(/\.gradient-stop-start\s*\{[^}]*stop-color:\s*var\(--cg-accent\)/);
      const gradientEndMatch = landingCss.match(/\.gradient-stop-end\s*\{[^}]*stop-color:\s*var\(--cg-info\)/);
      
      expect(gradientStartMatch).toBeTruthy();
      expect(gradientEndMatch).toBeTruthy();
    });
  });

  describe('Integration: HTML and CSS Coordination', () => {
    it('should link theme-tokens.css in index.html', () => {
      expect(indexHtml).toContain('theme-tokens.css');
    });

    it('should link landing.css after theme-tokens.css', () => {
      const themeTokensIndex = indexHtml.indexOf('theme-tokens.css');
      const landingCssIndex = indexHtml.indexOf('landing.css');
      
      expect(themeTokensIndex).toBeGreaterThan(-1);
      expect(landingCssIndex).toBeGreaterThan(-1);
      expect(themeTokensIndex).toBeLessThan(landingCssIndex);
    });

    it('should have gradient classes defined in landing.css', () => {
      expect(landingCss).toContain('.gradient-stop-start');
      expect(landingCss).toContain('.gradient-stop-end');
    });
  });

  describe('Cleanup Completeness', () => {
    it('should have removed all stop-color inline styles', () => {
      const stopColorInline = /style\s*=\s*["'][^"']*stop-color[^"']*["']/gi;
      expect(indexHtml.match(stopColorInline)).toBeNull();
    });

    it('should have removed all stop-opacity inline styles', () => {
      const stopOpacityInline = /style\s*=\s*["'][^"']*stop-opacity[^"']*["']/gi;
      expect(indexHtml.match(stopOpacityInline)).toBeNull();
    });

    it('should not have any hard-coded hex colors in inline styles', () => {
      // Check for #A855F7 (original purple) and #06B6D4 (original cyan)
      const purpleInline = /style\s*=\s*["'][^"']*#A855F7[^"']*["']/gi;
      const cyanInline = /style\s*=\s*["'][^"']*#06B6D4[^"']*["']/gi;
      
      expect(indexHtml.match(purpleInline)).toBeNull();
      expect(indexHtml.match(cyanInline)).toBeNull();
    });
  });

  describe('SVG Gradient Functionality', () => {
    it('should maintain proper SVG gradient structure', () => {
      // Verify the gradient is properly defined with defs
      expect(indexHtml).toMatch(/<defs>[\s\S]*<linearGradient[\s\S]*<\/linearGradient>[\s\S]*<\/defs>/);
    });

    it('should have gradient stops with correct offsets', () => {
      // Verify gradient stops have 0% and 100% offsets
      const gradientSection = indexHtml.match(/<linearGradient[^>]*id="progressGradient"[^>]*>[\s\S]*?<\/linearGradient>/);
      expect(gradientSection).toBeTruthy();
      expect(gradientSection[0]).toContain('offset="0%"');
      expect(gradientSection[0]).toContain('offset="100%"');
    });

    it('should reference gradient in progress-ring-fill class', () => {
      // The CSS should still reference the gradient by ID
      expect(landingCss).toContain('stroke: url(#progressGradient)');
    });
  });
});
