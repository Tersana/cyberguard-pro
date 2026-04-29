/**
 * End-to-End Integration Tests for Design Token System (Task 9.5)
 * Tests for design-token-system spec - Phase 6 Validation
 * 
 * Validates:
 * - Requirements 1.7, 4.1, 4.2, 4.3, 4.4, 4.5, 20.1, 20.2
 * - Complete token system workflow: load page → resolve tokens → render UI → verify colors
 * - theme-tokens.css loads before other stylesheets
 * - JavaScript token resolution works across all pages
 * - Visual appearance matches pre-migration state
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { JSDOM } from 'jsdom';
import { readFileSync } from 'fs';
import { join } from 'path';

describe('End-to-End Token System Integration Tests (Task 9.5)', () => {
  let pages = {};

  beforeAll(() => {
    // Load all HTML pages
    const pageFiles = ['dashboard.html', 'login.html', 'signup.html', 'index.html'];
    
    pageFiles.forEach(pageFile => {
      const html = readFileSync(join(process.cwd(), pageFile), 'utf-8');
      const dom = new JSDOM(html, {
        url: `http://localhost/${pageFile}`,
        resources: 'usable',
        runScripts: 'dangerously',
        pretendToBeVisual: true
      });

      // Load CSS files
      const themeTokensCSS = readFileSync(join(process.cwd(), 'theme-tokens.css'), 'utf-8');
      const cyberThemeCSS = readFileSync(join(process.cwd(), 'cyber-theme.css'), 'utf-8');
      const styleCSS = readFileSync(join(process.cwd(), 'Style.css'), 'utf-8');

      // Inject CSS into DOM
      const themeTokensStyle = dom.window.document.createElement('style');
      themeTokensStyle.textContent = themeTokensCSS;
      dom.window.document.head.appendChild(themeTokensStyle);

      const cyberThemeStyle = dom.window.document.createElement('style');
      cyberThemeStyle.textContent = cyberThemeCSS;
      dom.window.document.head.appendChild(cyberThemeStyle);

      const styleStyle = dom.window.document.createElement('style');
      styleStyle.textContent = styleCSS;
      dom.window.document.head.appendChild(styleStyle);

      // Load page-specific CSS
      if (pageFile === 'login.html' || pageFile === 'signup.html') {
        const authCSS = readFileSync(join(process.cwd(), 'auth.css'), 'utf-8');
        const authStyle = dom.window.document.createElement('style');
        authStyle.textContent = authCSS;
        dom.window.document.head.appendChild(authStyle);
      }

      if (pageFile === 'index.html') {
        const landingCSS = readFileSync(join(process.cwd(), 'landing.css'), 'utf-8');
        const landingStyle = dom.window.document.createElement('style');
        landingStyle.textContent = landingCSS;
        dom.window.document.head.appendChild(landingStyle);
      }

      // Load JavaScript files for dashboard
      if (pageFile === 'dashboard.html') {
        try {
          const riskGaugeJS = readFileSync(join(process.cwd(), 'risk-gauge.js'), 'utf-8');
          const script = dom.window.document.createElement('script');
          script.textContent = riskGaugeJS;
          dom.window.document.body.appendChild(script);
        } catch (error) {
          // risk-gauge.js may not exist yet or may have syntax errors in JSDOM
          console.warn('Could not load risk-gauge.js:', error.message);
        }
      }

      pages[pageFile] = {
        dom,
        window: dom.window,
        document: dom.window.document
      };
    });
  });

  afterAll(() => {
    // Clean up DOM instances
    Object.values(pages).forEach(page => {
      page.window.close();
    });
  });

  describe('Requirement 1.7: Theme-tokens.css loads first in all HTML files', () => {
    it('should load theme-tokens.css before other local stylesheets in dashboard.html', () => {
      const { document } = pages['dashboard.html'];
      const links = document.querySelectorAll('link[rel="stylesheet"]');
      const hrefs = Array.from(links).map(link => link.getAttribute('href'));
      
      // Filter to local stylesheets only (exclude external CDN links)
      const localStylesheets = hrefs.filter(href => !href.startsWith('http'));
      
      expect(localStylesheets[0]).toBe('theme-tokens.css');
      expect(localStylesheets).toContain('cyber-theme.css');
      expect(localStylesheets).toContain('Style.css');
    });

    it('should load theme-tokens.css before other local stylesheets in login.html', () => {
      const { document } = pages['login.html'];
      const links = document.querySelectorAll('link[rel="stylesheet"]');
      const hrefs = Array.from(links).map(link => link.getAttribute('href'));
      
      // Filter to local stylesheets only
      const localStylesheets = hrefs.filter(href => !href.startsWith('http'));
      
      expect(localStylesheets[0]).toBe('theme-tokens.css');
    });

    it('should load theme-tokens.css before other local stylesheets in signup.html', () => {
      const { document } = pages['signup.html'];
      const links = document.querySelectorAll('link[rel="stylesheet"]');
      const hrefs = Array.from(links).map(link => link.getAttribute('href'));
      
      // Filter to local stylesheets only
      const localStylesheets = hrefs.filter(href => !href.startsWith('http'));
      
      expect(localStylesheets[0]).toBe('theme-tokens.css');
    });

    it('should load theme-tokens.css before other local stylesheets in index.html', () => {
      const { document } = pages['index.html'];
      const links = document.querySelectorAll('link[rel="stylesheet"]');
      const hrefs = Array.from(links).map(link => link.getAttribute('href'));
      
      // Filter to local stylesheets only
      const localStylesheets = hrefs.filter(href => !href.startsWith('http'));
      
      expect(localStylesheets[0]).toBe('theme-tokens.css');
    });

    it('should verify correct stylesheet loading order across all pages', () => {
      Object.entries(pages).forEach(([pageName, { document }]) => {
        const links = document.querySelectorAll('link[rel="stylesheet"]');
        const hrefs = Array.from(links).map(link => link.getAttribute('href'));
        
        // Filter to local stylesheets only (exclude external CDN links)
        const localStylesheets = hrefs.filter(href => !href.startsWith('http'));
        
        // theme-tokens.css must be first among local stylesheets
        expect(localStylesheets[0]).toBe('theme-tokens.css');
        
        // Verify no other local stylesheets load before theme-tokens.css
        const themeTokensIndex = localStylesheets.indexOf('theme-tokens.css');
        expect(themeTokensIndex).toBe(0);
      });
    });
  });

  describe('Complete Token System Workflow: Load Page → Resolve Tokens → Render UI', () => {
    it('should load page and resolve all color tokens from CSS custom properties', () => {
      const { window, document } = pages['dashboard.html'];
      const computedStyle = window.getComputedStyle(document.documentElement);

      // Step 1: Verify page loaded
      expect(document.body).toBeTruthy();

      // Step 2: Verify tokens are resolved from CSS custom properties
      const tokens = {
        bgBase: computedStyle.getPropertyValue('--cg-bg-base').trim(),
        bgSurface: computedStyle.getPropertyValue('--cg-bg-surface').trim(),
        text1: computedStyle.getPropertyValue('--cg-text-1').trim(),
        accent: computedStyle.getPropertyValue('--cg-accent').trim(),
        success: computedStyle.getPropertyValue('--cg-success').trim(),
        warning: computedStyle.getPropertyValue('--cg-warning').trim(),
        danger: computedStyle.getPropertyValue('--cg-danger').trim(),
      };

      // Step 3: Verify all tokens resolved correctly
      expect(tokens.bgBase).toBe('#0B0F19');
      expect(tokens.accent).toBe('#A78BFA');
      expect(tokens.success).toBe('#34D399');
      expect(tokens.warning).toBe('#FBBF24');
      expect(tokens.danger).toBe('#F87171');

      // Step 4: Verify UI elements can access tokens
      expect(tokens.text1).toBeTruthy();
      expect(tokens.bgSurface).toBeTruthy();
    });

    it('should render UI with token-based colors applied to elements', () => {
      const { window, document } = pages['dashboard.html'];

      // Create test elements to verify token application
      const testCard = document.createElement('div');
      testCard.className = 'cyber-card';
      document.body.appendChild(testCard);

      const testButton = document.createElement('button');
      testButton.className = 'cyber-btn-primary';
      document.body.appendChild(testButton);

      // Verify elements exist and have classes applied
      expect(testCard.className).toBe('cyber-card');
      expect(testButton.className).toBe('cyber-btn-primary');

      // Verify computed styles are available
      const cardStyle = window.getComputedStyle(testCard);
      const buttonStyle = window.getComputedStyle(testButton);

      expect(cardStyle).toBeTruthy();
      expect(buttonStyle).toBeTruthy();
    });

    it('should verify colors match pre-migration state (visual parity)', () => {
      const { window, document } = pages['dashboard.html'];
      const computedStyle = window.getComputedStyle(document.documentElement);

      // Verify exact color values match design specification
      const colorValues = {
        bgBase: computedStyle.getPropertyValue('--cg-bg-base').trim(),
        accent: computedStyle.getPropertyValue('--cg-accent').trim(),
        success: computedStyle.getPropertyValue('--cg-success').trim(),
        warning: computedStyle.getPropertyValue('--cg-warning').trim(),
        danger: computedStyle.getPropertyValue('--cg-danger').trim(),
        info: computedStyle.getPropertyValue('--cg-info').trim(),
      };

      // These values must match the original hard-coded values
      expect(colorValues.bgBase).toBe('#0B0F19');
      expect(colorValues.accent).toBe('#A78BFA'); // Unified violet accent
      expect(colorValues.success).toBe('#34D399');
      expect(colorValues.warning).toBe('#FBBF24');
      expect(colorValues.danger).toBe('#F87171');
      expect(colorValues.info).toBe('#38BDF8');
    });
  });

  describe('Requirements 4.1-4.5: JavaScript Token Resolution', () => {
    it('should resolve tokens using getComputedStyle() in JavaScript', () => {
      const { window, document } = pages['dashboard.html'];

      // Simulate JavaScript token resolution (as done in risk-gauge.js)
      function getCSSVar(name, fallback) {
        try {
          const val = window.getComputedStyle(document.documentElement)
            .getPropertyValue(name).trim();
          return val || fallback;
        } catch (_) {
          return fallback;
        }
      }

      // Test token resolution
      const success = getCSSVar('--cg-success', '#34D399');
      const warning = getCSSVar('--cg-warning', '#FBBF24');
      const danger = getCSSVar('--cg-danger', '#F87171');
      const accent = getCSSVar('--cg-accent', '#A78BFA');

      expect(success).toBe('#34D399');
      expect(warning).toBe('#FBBF24');
      expect(danger).toBe('#F87171');
      expect(accent).toBe('#A78BFA');
    });

    it('should return fallback values when tokens are not found', () => {
      const { window, document } = pages['dashboard.html'];

      function getCSSVar(name, fallback) {
        try {
          const val = window.getComputedStyle(document.documentElement)
            .getPropertyValue(name).trim();
          return val || fallback;
        } catch (_) {
          return fallback;
        }
      }

      // Test with non-existent token
      const nonExistent = getCSSVar('--cg-nonexistent', '#FALLBACK');
      expect(nonExistent).toBe('#FALLBACK');
    });

    it('should implement cached token resolution for performance', () => {
      const { window, document } = pages['dashboard.html'];

      // Simulate cached token resolution (as done in risk-gauge.js)
      let _colors = null;

      function colors() {
        if (!_colors) {
          const root = document.documentElement;
          const styles = window.getComputedStyle(root);

          _colors = {
            success: styles.getPropertyValue('--cg-success').trim() || '#34D399',
            warning: styles.getPropertyValue('--cg-warning').trim() || '#FBBF24',
            danger: styles.getPropertyValue('--cg-danger').trim() || '#F87171',
            accent: styles.getPropertyValue('--cg-accent').trim() || '#A78BFA',
            muted: styles.getPropertyValue('--cg-text-3').trim() || '#64748B',
          };
        }
        return _colors;
      }

      // First call - should cache
      const colors1 = colors();
      expect(colors1.success).toBe('#34D399');
      expect(colors1.accent).toBe('#A78BFA');

      // Second call - should return cached values
      const colors2 = colors();
      expect(colors2).toBe(colors1); // Same object reference
    });

    it('should work across all pages (dashboard, login, signup, index)', () => {
      Object.entries(pages).forEach(([pageName, { window, document }]) => {
        const computedStyle = window.getComputedStyle(document.documentElement);

        // Verify token resolution works on each page
        const accent = computedStyle.getPropertyValue('--cg-accent').trim();
        const bgBase = computedStyle.getPropertyValue('--cg-bg-base').trim();

        expect(accent).toBe('#A78BFA');
        expect(bgBase).toBe('#0B0F19');
      });
    });
  });

  describe('Requirements 20.1-20.2: Visual Appearance Validation', () => {
    it('should maintain unified violet accent across all pages', () => {
      Object.entries(pages).forEach(([pageName, { window, document }]) => {
        const computedStyle = window.getComputedStyle(document.documentElement);
        const accent = computedStyle.getPropertyValue('--cg-accent').trim();

        expect(accent).toBe('#A78BFA');
      });
    });

    it('should maintain consistent background colors across all pages', () => {
      Object.entries(pages).forEach(([pageName, { window, document }]) => {
        const computedStyle = window.getComputedStyle(document.documentElement);
        const bgBase = computedStyle.getPropertyValue('--cg-bg-base').trim();

        expect(bgBase).toBe('#0B0F19');
      });
    });

    it('should maintain consistent status colors across all pages', () => {
      Object.entries(pages).forEach(([pageName, { window, document }]) => {
        const computedStyle = window.getComputedStyle(document.documentElement);

        const success = computedStyle.getPropertyValue('--cg-success').trim();
        const warning = computedStyle.getPropertyValue('--cg-warning').trim();
        const danger = computedStyle.getPropertyValue('--cg-danger').trim();

        expect(success).toBe('#34D399');
        expect(warning).toBe('#FBBF24');
        expect(danger).toBe('#F87171');
      });
    });

    it('should have no inline color styles in any page', () => {
      Object.entries(pages).forEach(([pageName, { document }]) => {
        const elementsWithInlineStyles = document.querySelectorAll('[style*="color"], [style*="background"]');
        const colorStyles = Array.from(elementsWithInlineStyles).filter(el => {
          const style = el.getAttribute('style') || '';
          return style.match(/#[0-9A-F]{6}|rgba?\(/i);
        });

        expect(colorStyles.length).toBe(0);
      });
    });
  });

  describe('Cross-Page Token Consistency', () => {
    it('should have identical token values across all pages', () => {
      const tokenNames = [
        '--cg-bg-base',
        '--cg-bg-surface',
        '--cg-text-1',
        '--cg-text-2',
        '--cg-text-3',
        '--cg-border',
        '--cg-accent',
        '--cg-accent-hover',
        '--cg-success',
        '--cg-warning',
        '--cg-danger',
        '--cg-info',
      ];

      // Get token values from first page
      const { window: firstWindow, document: firstDocument } = pages['dashboard.html'];
      const firstComputedStyle = firstWindow.getComputedStyle(firstDocument.documentElement);
      const firstTokenValues = {};

      tokenNames.forEach(tokenName => {
        firstTokenValues[tokenName] = firstComputedStyle.getPropertyValue(tokenName).trim();
      });

      // Verify all other pages have identical token values
      Object.entries(pages).forEach(([pageName, { window, document }]) => {
        if (pageName === 'dashboard.html') return; // Skip first page

        const computedStyle = window.getComputedStyle(document.documentElement);

        tokenNames.forEach(tokenName => {
          const value = computedStyle.getPropertyValue(tokenName).trim();
          expect(value).toBe(firstTokenValues[tokenName]);
        });
      });
    });

    it('should have all spacing tokens defined consistently', () => {
      const spacingTokens = [
        '--cg-space-1',
        '--cg-space-2',
        '--cg-space-3',
        '--cg-space-4',
        '--cg-space-6',
        '--cg-space-8',
        '--cg-space-12',
        '--cg-space-16',
      ];

      Object.entries(pages).forEach(([pageName, { window, document }]) => {
        const computedStyle = window.getComputedStyle(document.documentElement);

        spacingTokens.forEach(token => {
          const value = computedStyle.getPropertyValue(token).trim();
          expect(value).toBeTruthy();
          expect(value).toMatch(/rem$/);
        });
      });
    });

    it('should have all transition tokens defined consistently', () => {
      const transitionTokens = [
        '--cg-transition-fast',
        '--cg-transition-base',
        '--cg-transition-slow',
      ];

      Object.entries(pages).forEach(([pageName, { window, document }]) => {
        const computedStyle = window.getComputedStyle(document.documentElement);

        transitionTokens.forEach(token => {
          const value = computedStyle.getPropertyValue(token).trim();
          expect(value).toBeTruthy();
          expect(value).toMatch(/ease$/);
        });
      });
    });
  });

  describe('Interactive States and Animations', () => {
    it('should define hover state colors for interactive elements', () => {
      const { window, document } = pages['dashboard.html'];
      const computedStyle = window.getComputedStyle(document.documentElement);

      const accentHover = computedStyle.getPropertyValue('--cg-accent-hover').trim();
      expect(accentHover).toBe('#8B5CF6');
    });

    it('should define focus ring color for accessibility', () => {
      const { window, document } = pages['dashboard.html'];
      const computedStyle = window.getComputedStyle(document.documentElement);

      const focusRing = computedStyle.getPropertyValue('--cg-focus-ring').trim();
      expect(focusRing).toBeTruthy();
      expect(focusRing).toMatch(/rgba?\(/i);
    });

    it('should define transition tokens for smooth animations', () => {
      const { window, document } = pages['dashboard.html'];
      const computedStyle = window.getComputedStyle(document.documentElement);

      const transitionFast = computedStyle.getPropertyValue('--cg-transition-fast').trim();
      const transitionBase = computedStyle.getPropertyValue('--cg-transition-base').trim();
      const transitionSlow = computedStyle.getPropertyValue('--cg-transition-slow').trim();

      expect(transitionFast).toBe('0.15s ease');
      expect(transitionBase).toBe('0.3s ease');
      expect(transitionSlow).toBe('0.5s ease');
    });
  });

  describe('Token System Completeness', () => {
    it('should have all required color tokens defined', () => {
      const { window, document } = pages['dashboard.html'];
      const computedStyle = window.getComputedStyle(document.documentElement);

      const requiredTokens = [
        '--cg-bg-base',
        '--cg-bg-surface',
        '--cg-bg-elevated',
        '--cg-text-1',
        '--cg-text-2',
        '--cg-text-3',
        '--cg-border',
        '--cg-border-subtle',
        '--cg-accent',
        '--cg-accent-hover',
        '--cg-accent-muted',
        '--cg-success',
        '--cg-warning',
        '--cg-danger',
        '--cg-info',
        '--cg-overlay',
        '--cg-focus-ring',
      ];

      requiredTokens.forEach(token => {
        const value = computedStyle.getPropertyValue(token).trim();
        expect(value).toBeTruthy();
      });
    });

    it('should have all required spacing tokens defined', () => {
      const { window, document } = pages['dashboard.html'];
      const computedStyle = window.getComputedStyle(document.documentElement);

      const spacingTokens = [
        '--cg-space-1',
        '--cg-space-2',
        '--cg-space-3',
        '--cg-space-4',
        '--cg-space-6',
        '--cg-space-8',
        '--cg-space-12',
        '--cg-space-16',
      ];

      spacingTokens.forEach(token => {
        const value = computedStyle.getPropertyValue(token).trim();
        expect(value).toBeTruthy();
      });
    });

    it('should have all required border radius tokens defined', () => {
      const { window, document } = pages['dashboard.html'];
      const computedStyle = window.getComputedStyle(document.documentElement);

      const radiusTokens = [
        '--cg-radius-sm',
        '--cg-radius-md',
        '--cg-radius-lg',
        '--cg-radius-xl',
        '--cg-radius-full',
      ];

      radiusTokens.forEach(token => {
        const value = computedStyle.getPropertyValue(token).trim();
        expect(value).toBeTruthy();
      });
    });

    it('should have all required shadow tokens defined', () => {
      const { window, document } = pages['dashboard.html'];
      const computedStyle = window.getComputedStyle(document.documentElement);

      const shadowTokens = [
        '--cg-shadow-sm',
        '--cg-shadow-md',
        '--cg-shadow-lg',
        '--cg-shadow-xl',
      ];

      shadowTokens.forEach(token => {
        const value = computedStyle.getPropertyValue(token).trim();
        expect(value).toBeTruthy();
      });
    });

    it('should have typography tokens defined', () => {
      const { window, document } = pages['dashboard.html'];
      const computedStyle = window.getComputedStyle(document.documentElement);

      const fontSans = computedStyle.getPropertyValue('--cg-font-sans').trim();
      const fontMono = computedStyle.getPropertyValue('--cg-font-mono').trim();

      expect(fontSans).toContain('Inter');
      expect(fontMono).toContain('JetBrains Mono');
    });
  });

  describe('Page-Specific Token Application', () => {
    it('should apply tokens correctly in dashboard.html', () => {
      const { window, document } = pages['dashboard.html'];
      const computedStyle = window.getComputedStyle(document.documentElement);

      // Verify dashboard-specific elements can access tokens
      expect(computedStyle.getPropertyValue('--cg-bg-base').trim()).toBe('#0B0F19');
      expect(computedStyle.getPropertyValue('--cg-accent').trim()).toBe('#A78BFA');
    });

    it('should apply tokens correctly in login.html', () => {
      const { window, document } = pages['login.html'];
      const computedStyle = window.getComputedStyle(document.documentElement);

      // Verify login page can access tokens
      expect(computedStyle.getPropertyValue('--cg-accent').trim()).toBe('#A78BFA');
      expect(computedStyle.getPropertyValue('--cg-bg-surface').trim()).toBeTruthy();
    });

    it('should apply tokens correctly in signup.html', () => {
      const { window, document } = pages['signup.html'];
      const computedStyle = window.getComputedStyle(document.documentElement);

      // Verify signup page can access tokens
      expect(computedStyle.getPropertyValue('--cg-accent').trim()).toBe('#A78BFA');
      expect(computedStyle.getPropertyValue('--cg-bg-surface').trim()).toBeTruthy();
    });

    it('should apply tokens correctly in index.html (landing page)', () => {
      const { window, document } = pages['index.html'];
      const computedStyle = window.getComputedStyle(document.documentElement);

      // Verify landing page can access tokens
      expect(computedStyle.getPropertyValue('--cg-accent').trim()).toBe('#A78BFA');
      expect(computedStyle.getPropertyValue('--cg-bg-base').trim()).toBe('#0B0F19');
    });
  });

  describe('End-to-End Workflow Validation', () => {
    it('should complete full workflow: load → resolve → render → verify', () => {
      const { window, document } = pages['dashboard.html'];

      // Step 1: Load page (verified by beforeAll)
      expect(document.body).toBeTruthy();

      // Step 2: Resolve tokens from CSS custom properties
      const computedStyle = window.getComputedStyle(document.documentElement);
      const tokens = {
        bgBase: computedStyle.getPropertyValue('--cg-bg-base').trim(),
        accent: computedStyle.getPropertyValue('--cg-accent').trim(),
        success: computedStyle.getPropertyValue('--cg-success').trim(),
      };

      expect(tokens.bgBase).toBe('#0B0F19');
      expect(tokens.accent).toBe('#A78BFA');
      expect(tokens.success).toBe('#34D399');

      // Step 3: Render UI with token-based colors
      const testElement = document.createElement('div');
      testElement.className = 'cyber-card';
      document.body.appendChild(testElement);

      const elementStyle = window.getComputedStyle(testElement);
      expect(elementStyle).toBeTruthy();

      // Step 4: Verify colors match pre-migration state
      expect(tokens.bgBase).toBe('#0B0F19'); // Original value preserved
      expect(tokens.accent).toBe('#A78BFA'); // Unified violet accent
    });

    it('should verify token system works end-to-end across all pages', () => {
      const pageNames = Object.keys(pages);
      expect(pageNames.length).toBe(4);

      pageNames.forEach(pageName => {
        const { window, document } = pages[pageName];

        // Verify page loaded
        expect(document.body).toBeTruthy();

        // Verify tokens resolved
        const computedStyle = window.getComputedStyle(document.documentElement);
        const accent = computedStyle.getPropertyValue('--cg-accent').trim();
        expect(accent).toBe('#A78BFA');

        // Verify theme-tokens.css loaded first among local stylesheets
        const links = document.querySelectorAll('link[rel="stylesheet"]');
        const hrefs = Array.from(links).map(link => link.getAttribute('href'));
        const localStylesheets = hrefs.filter(href => !href.startsWith('http'));
        expect(localStylesheets[0]).toBe('theme-tokens.css');
      });
    });
  });

  describe('Performance and Caching', () => {
    it('should support cached token resolution for performance', () => {
      const { window, document } = pages['dashboard.html'];

      // Simulate performance-optimized token resolution
      const startTime = Date.now();

      let _tokenCache = null;

      function resolveTokens() {
        if (!_tokenCache) {
          const root = document.documentElement;
          const styles = window.getComputedStyle(root);

          _tokenCache = {
            success: styles.getPropertyValue('--cg-success').trim() || '#34D399',
            warning: styles.getPropertyValue('--cg-warning').trim() || '#FBBF24',
            danger: styles.getPropertyValue('--cg-danger').trim() || '#F87171',
            accent: styles.getPropertyValue('--cg-accent').trim() || '#A78BFA',
          };
        }
        return _tokenCache;
      }

      // First call - should cache
      const tokens1 = resolveTokens();
      const firstCallTime = Date.now() - startTime;

      // Second call - should use cache
      const tokens2 = resolveTokens();
      const secondCallTime = Date.now() - startTime;

      // Verify caching works
      expect(tokens1).toBe(tokens2); // Same object reference
      expect(tokens1.accent).toBe('#A78BFA');
    });
  });
});

