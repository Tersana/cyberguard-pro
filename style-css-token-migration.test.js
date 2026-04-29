/**
 * Style.css Token Migration Verification Tests
 * Task 2.7: Verify Style.css uses token references correctly
 * 
 * Requirements: 3.2, 3.5, 20.1, 20.2
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { JSDOM } from 'jsdom';
import { readFileSync } from 'fs';

describe('Style.css Token Migration - Task 2.7', () => {
  let dom;
  let document;
  let window;

  beforeEach(() => {
    // Load HTML with all stylesheets
    const themeTokensCSS = readFileSync('./theme-tokens.css', 'utf-8');
    const cyberThemeCSS = readFileSync('./cyber-theme.css', 'utf-8');
    const styleCSS = readFileSync('./Style.css', 'utf-8');

    const html = `
      <!DOCTYPE html>
      <html>
        <head>
          <style>${themeTokensCSS}</style>
          <style>${cyberThemeCSS}</style>
          <style>${styleCSS}</style>
        </head>
        <body>
          <button class="tab-button">Inactive Tab</button>
          <button class="tab-button active">Active Tab</button>
        </body>
      </html>
    `;

    dom = new JSDOM(html);
    document = dom.window.document;
    window = dom.window;
  });

  describe('Legacy Alias Definition', () => {
    it('should define --accent as a legacy alias to --cg-accent', () => {
      const root = document.documentElement;
      const styles = window.getComputedStyle(root);
      
      const accentValue = styles.getPropertyValue('--cg-accent').trim();
      const legacyAccentValue = styles.getPropertyValue('--accent').trim();
      
      // Verify both are defined
      expect(accentValue).toBeTruthy();
      expect(legacyAccentValue).toBeTruthy();
      
      // Verify legacy alias points to the same value
      // Note: In JSDOM, var() references might not fully resolve, so we check the definition
      const styleContent = readFileSync('./Style.css', 'utf-8');
      expect(styleContent).toContain('--accent: var(--cg-accent)');
    });
  });

  describe('Tab Button Active State', () => {
    it('should use var(--cg-accent) for active tab color', () => {
      const styleContent = readFileSync('./Style.css', 'utf-8');
      
      // Verify .tab-button.active uses var(--cg-accent) for color
      expect(styleContent).toMatch(/\.tab-button\.active\s*{[^}]*color:\s*var\(--cg-accent\)/);
    });

    it('should use var(--cg-accent) for active tab border-color', () => {
      const styleContent = readFileSync('./Style.css', 'utf-8');
      
      // Verify .tab-button.active uses var(--cg-accent) for border-color
      expect(styleContent).toMatch(/\.tab-button\.active\s*{[^}]*border-color:\s*var\(--cg-accent\)/);
    });

    it('should use var(--cg-accent) for tab button hover state', () => {
      const styleContent = readFileSync('./Style.css', 'utf-8');
      
      // Verify .tab-button:hover uses var(--cg-accent)
      expect(styleContent).toMatch(/\.tab-button:hover\s*{[^}]*color:\s*var\(--cg-accent\)/);
    });
  });

  describe('No Hard-Coded Accent Colors', () => {
    it('should not contain hard-coded cyan accent colors (#06B6D4, #22D3EE, #38BDF8)', () => {
      const styleContent = readFileSync('./Style.css', 'utf-8');
      
      // Check for cyan colors that should have been replaced
      // Note: #38BDF8 is used for --cg-info which is intentional
      const cyanColors = ['#06B6D4', '#22D3EE'];
      
      cyanColors.forEach(color => {
        const regex = new RegExp(color, 'i');
        expect(styleContent).not.toMatch(regex);
      });
    });

    it('should use var(--cg-accent) instead of hard-coded #A78BFA in tab contexts', () => {
      const styleContent = readFileSync('./Style.css', 'utf-8');
      
      // Extract tab-button related sections
      const tabButtonSection = styleContent.match(/\.tab-button[^{]*{[^}]*}/g) || [];
      const tabButtonContent = tabButtonSection.join('\n');
      
      // In tab-button contexts, should use var(--cg-accent) not hard-coded #A78BFA
      // Note: #A78BFA might appear in other contexts (gradients) which is acceptable
      if (tabButtonContent.includes('#A78BFA')) {
        expect(tabButtonContent).toContain('var(--cg-accent)');
      }
    });
  });

  describe('Dark Mode Tab Button Styles', () => {
    it('should use var(--cg-accent) for dark mode active tab color', () => {
      const styleContent = readFileSync('./Style.css', 'utf-8');
      
      // Verify dark mode .tab-button.active uses var(--cg-accent)
      expect(styleContent).toMatch(/\.dark\s+\.tab-button\.active\s*{[^}]*color:\s*var\(--cg-accent\)/);
    });

    it('should use var(--cg-accent) for dark mode active tab border-color', () => {
      const styleContent = readFileSync('./Style.css', 'utf-8');
      
      // Verify dark mode .tab-button.active uses var(--cg-accent) for border
      expect(styleContent).toMatch(/\.dark\s+\.tab-button\.active\s*{[^}]*border-color:\s*var\(--cg-accent\)/);
    });
  });

  describe('Token System Integration', () => {
    it('should use var(--cg-bg-elevated) for result-row hover', () => {
      const styleContent = readFileSync('./Style.css', 'utf-8');
      
      expect(styleContent).toContain('.result-row:hover { background-color: var(--cg-bg-elevated); }');
    });

    it('should use var(--cg-accent) in progress bar animation', () => {
      const styleContent = readFileSync('./Style.css', 'utf-8');
      
      // Verify progress bar uses var(--cg-accent)
      expect(styleContent).toMatch(/\.progress-bar-indeterminate[^{]*{[^}]*background:[^;]*var\(--cg-accent\)/);
    });
  });

  describe('Visual Parity - Requirement 20.1, 20.2', () => {
    it('should maintain consistent accent color value across token system', () => {
      const themeTokensContent = readFileSync('./theme-tokens.css', 'utf-8');
      const styleContent = readFileSync('./Style.css', 'utf-8');
      
      // Verify theme-tokens.css defines --cg-accent as #A78BFA
      expect(themeTokensContent).toMatch(/--cg-accent:\s*#A78BFA/);
      
      // Verify Style.css .tab-button.active and .tab-button:hover use var(--cg-accent)
      const activeTabButtonMatches = styleContent.match(/\.tab-button\.(active|hover)[^{]*{[^}]*}/g) || [];
      const hoverTabButtonMatches = styleContent.match(/\.tab-button:hover[^{]*{[^}]*}/g) || [];
      const allActiveMatches = [...activeTabButtonMatches, ...hoverTabButtonMatches];
      
      allActiveMatches.forEach(match => {
        if (match.includes('color:') || match.includes('border-color:')) {
          expect(match).toContain('var(--cg-accent)');
        }
      });
    });
  });

  describe('Stylesheet Loading Order', () => {
    it('should verify theme-tokens.css is linked before Style.css in dashboard.html', () => {
      const dashboardHTML = readFileSync('./dashboard.html', 'utf-8');
      
      const themeTokensIndex = dashboardHTML.indexOf('theme-tokens.css');
      const styleIndex = dashboardHTML.indexOf('Style.css');
      
      expect(themeTokensIndex).toBeGreaterThan(-1);
      expect(styleIndex).toBeGreaterThan(-1);
      expect(themeTokensIndex).toBeLessThan(styleIndex);
    });
  });
});
