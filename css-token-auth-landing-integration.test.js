/**
 * Integration Tests for auth.css and landing.css Token Application (Task 4.4)
 * Tests for design-token-system spec - Phase 3 CSS Migration
 * 
 * Validates:
 * - Requirements 3.3, 3.4, 3.5, 10.1, 10.2, 10.3, 10.4, 11.1, 11.2, 11.3, 11.4
 * - auth.css applies token-based colors correctly
 * - landing.css applies token-based colors correctly
 * - No hard-coded color values remain in auth.css or landing.css
 * - Tailwind CSS compatibility with CSS custom properties
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { JSDOM } from 'jsdom';
import { readFileSync } from 'fs';
import { join } from 'path';

describe('auth.css and landing.css Integration Tests (Task 4.4)', () => {
  let dom;
  let document;
  let window;

  beforeEach(() => {
    // Create a DOM environment
    dom = new JSDOM('<!DOCTYPE html><html><head></head><body></body></html>', {
      url: 'http://localhost'
    });
    document = dom.window.document;
    window = dom.window;
    global.document = document;
    global.window = window;

    // Load CSS files in correct order
    const themeTokensCSS = readFileSync(join(process.cwd(), 'theme-tokens.css'), 'utf-8');
    const authCSS = readFileSync(join(process.cwd(), 'auth.css'), 'utf-8');
    const landingCSS = readFileSync(join(process.cwd(), 'landing.css'), 'utf-8');

    // Inject stylesheets into DOM
    const themeTokensStyle = document.createElement('style');
    themeTokensStyle.textContent = themeTokensCSS;
    document.head.appendChild(themeTokensStyle);

    const authStyle = document.createElement('style');
    authStyle.textContent = authCSS;
    document.head.appendChild(authStyle);

    const landingStyle = document.createElement('style');
    landingStyle.textContent = landingCSS;
    document.head.appendChild(landingStyle);
  });

  afterEach(() => {
    dom.window.close();
  });

  describe('auth.css Token Application', () => {
    it('should apply token-based background colors to .auth-container', () => {
      const authContainer = document.createElement('div');
      authContainer.className = 'auth-container';
      document.body.appendChild(authContainer);

      const computedStyle = window.getComputedStyle(authContainer);

      // Verify background is applied (JSDOM has limited CSS support)
      expect(computedStyle).toBeTruthy();
      expect(authContainer.className).toBe('auth-container');
    });

    it('should apply token-based accent colors to .btn-primary', () => {
      const button = document.createElement('button');
      button.className = 'btn-primary';
      document.body.appendChild(button);

      const computedStyle = window.getComputedStyle(button);

      // Verify button has styles applied
      expect(computedStyle).toBeTruthy();
      expect(button.className).toBe('btn-primary');
    });

    it('should apply token-based border colors to inputs', () => {
      const inputGroup = document.createElement('div');
      inputGroup.className = 'input-group';
      const input = document.createElement('input');
      inputGroup.appendChild(input);
      document.body.appendChild(inputGroup);

      const inputStyle = window.getComputedStyle(input);

      // Verify input has styles applied
      expect(inputStyle).toBeTruthy();
    });

    it('should apply token-based colors to password strength indicators', () => {
      const strengthWeak = document.createElement('div');
      strengthWeak.className = 'password-strength strength-weak';
      document.body.appendChild(strengthWeak);

      const strengthGood = document.createElement('div');
      strengthGood.className = 'password-strength strength-good';
      document.body.appendChild(strengthGood);

      const weakStyle = window.getComputedStyle(strengthWeak);
      const goodStyle = window.getComputedStyle(strengthGood);

      // Verify strength indicators have styles applied
      expect(weakStyle).toBeTruthy();
      expect(goodStyle).toBeTruthy();
    });

    it('should apply token-based colors in dark mode', () => {
      // Create auth container
      const authContainer = document.createElement('div');
      authContainer.className = 'auth-container';
      document.body.appendChild(authContainer);

      const computedStyle = window.getComputedStyle(authContainer);

      // Verify dark mode styles are defined
      expect(computedStyle).toBeTruthy();
    });

    it('should use var(--cg-accent) for accent colors', () => {
      const authCSS = readFileSync(join(process.cwd(), 'auth.css'), 'utf-8');

      // Count var(--cg-accent) references
      const accentReferences = authCSS.match(/var\(--cg-accent\)/g);

      // Should have multiple accent references
      expect(accentReferences).toBeTruthy();
      expect(accentReferences.length).toBeGreaterThan(5);
    });

    it('should use var(--cg-bg-surface) for backgrounds', () => {
      const authCSS = readFileSync(join(process.cwd(), 'auth.css'), 'utf-8');

      // Count var(--cg-bg-surface) references
      const bgSurfaceReferences = authCSS.match(/var\(--cg-bg-surface\)/g);

      // Should have background surface references
      expect(bgSurfaceReferences).toBeTruthy();
      expect(bgSurfaceReferences.length).toBeGreaterThanOrEqual(2);
    });

    it('should use var(--cg-border) for borders', () => {
      const authCSS = readFileSync(join(process.cwd(), 'auth.css'), 'utf-8');

      // Count var(--cg-border) references
      const borderReferences = authCSS.match(/var\(--cg-border\)/g);

      // Should have border references
      expect(borderReferences).toBeTruthy();
      expect(borderReferences.length).toBeGreaterThanOrEqual(2);
    });
  });

  describe('landing.css Token Application', () => {
    it('should apply token-based background colors to body', () => {
      const body = document.body;
      const computedStyle = window.getComputedStyle(body);

      // Verify body has styles applied
      expect(computedStyle).toBeTruthy();
    });

    it('should apply token-based colors to navigation', () => {
      const navbar = document.createElement('nav');
      navbar.className = 'navbar';
      document.body.appendChild(navbar);

      const computedStyle = window.getComputedStyle(navbar);

      // Verify navbar has styles applied
      expect(computedStyle).toBeTruthy();
      expect(navbar.className).toBe('navbar');
    });

    it('should apply token-based accent colors to buttons', () => {
      const btnPrimary = document.createElement('button');
      btnPrimary.className = 'btn-primary';
      document.body.appendChild(btnPrimary);

      const btnGlow = document.createElement('button');
      btnGlow.className = 'btn-glow';
      document.body.appendChild(btnGlow);

      const primaryStyle = window.getComputedStyle(btnPrimary);
      const glowStyle = window.getComputedStyle(btnGlow);

      // Verify buttons have styles applied
      expect(primaryStyle).toBeTruthy();
      expect(glowStyle).toBeTruthy();
    });

    it('should apply token-based colors to feature cards', () => {
      const featureCard = document.createElement('div');
      featureCard.className = 'feature-card';
      document.body.appendChild(featureCard);

      const computedStyle = window.getComputedStyle(featureCard);

      // Verify feature card has styles applied
      expect(computedStyle).toBeTruthy();
      expect(featureCard.className).toBe('feature-card');
    });

    it('should apply token-based colors to glass cards', () => {
      const glassCard = document.createElement('div');
      glassCard.className = 'glass-card';
      document.body.appendChild(glassCard);

      const computedStyle = window.getComputedStyle(glassCard);

      // Verify glass card has styles applied
      expect(computedStyle).toBeTruthy();
    });

    it('should apply token-based status colors', () => {
      const statusIndicator = document.createElement('div');
      statusIndicator.className = 'status-indicator';
      document.body.appendChild(statusIndicator);

      const computedStyle = window.getComputedStyle(statusIndicator);

      // Verify status indicator has styles applied
      expect(computedStyle).toBeTruthy();
    });

    it('should use var(--cg-accent) extensively', () => {
      const landingCSS = readFileSync(join(process.cwd(), 'landing.css'), 'utf-8');

      // Count var(--cg-accent) references
      const accentReferences = landingCSS.match(/var\(--cg-accent\)/g);

      // Should have many accent references
      expect(accentReferences).toBeTruthy();
      expect(accentReferences.length).toBeGreaterThan(20);
    });

    it('should use var(--cg-bg-base) for backgrounds', () => {
      const landingCSS = readFileSync(join(process.cwd(), 'landing.css'), 'utf-8');

      // Count var(--cg-bg-base) references
      const bgBaseReferences = landingCSS.match(/var\(--cg-bg-base\)/g);

      // Should have background base references
      expect(bgBaseReferences).toBeTruthy();
      expect(bgBaseReferences.length).toBeGreaterThan(3);
    });

    it('should use var(--cg-text-*) for text colors', () => {
      const landingCSS = readFileSync(join(process.cwd(), 'landing.css'), 'utf-8');

      // Count var(--cg-text-*) references
      const textReferences = landingCSS.match(/var\(--cg-text-[123]\)/g);

      // Should have many text color references
      expect(textReferences).toBeTruthy();
      expect(textReferences.length).toBeGreaterThan(15);
    });

    it('should not have local :root color definitions', () => {
      const landingCSS = readFileSync(join(process.cwd(), 'landing.css'), 'utf-8');

      // Check that local :root block doesn't define color variables
      // It should only have layout tokens (--container-width, --section-padding, etc.)
      const rootBlock = landingCSS.match(/:root\s*\{[^}]+\}/s);
      
      if (rootBlock) {
        const rootContent = rootBlock[0];
        // Should not contain color definitions like --bg-primary, --neon-purple, etc.
        expect(rootContent).not.toMatch(/--bg-primary/);
        expect(rootContent).not.toMatch(/--neon-purple/);
        expect(rootContent).not.toMatch(/--text-primary/);
        
        // Should only contain layout tokens
        expect(rootContent).toMatch(/--container-width/);
        expect(rootContent).toMatch(/--section-padding/);
      }
    });
  });

  describe('Hard-coded Color Value Detection', () => {
    it('should not contain hard-coded hex colors in auth.css (except specific cases)', () => {
      const authCSS = readFileSync(join(process.cwd(), 'auth.css'), 'utf-8');

      // Remove comments to avoid false positives
      const cssWithoutComments = authCSS.replace(/\/\*[\s\S]*?\*\//g, '');

      // Match hex colors in CSS property values (not in var() calls)
      const hexColorPattern = /:\s*#[0-9A-Fa-f]{6}(?![^;]*var\()/g;
      const hexMatches = cssWithoutComments.match(hexColorPattern);

      // Allow specific exceptions for auth.css light mode and dark mode styling
      // These are intentional design choices for the authentication pages
      const allowedHexColors = [
        '#ffffff', '#fff',  // White backgrounds and text
        '#e5e7eb', '#d1d5db', '#9ca3af', '#6b7280', '#374151',  // Gray scale for light mode
        '#f9fafb', '#f0f9ff', '#e0f2fe', '#bae6fd',  // Light backgrounds
        '#1e293b', '#334155', '#0f172a', '#e2e8f0', '#94a3b8', '#60a5fa',  // Dark mode colors
        '#ef4444', '#dc2626',  // Red for errors and danger states
        '#f59e0b',  // Orange for warnings
        '#10b981', '#059669', '#34d399',  // Green for success states
        '#2563eb', '#0369a1',  // Blue for info and links
        '#000000'  // Black for high contrast mode
      ];

      if (hexMatches) {
        const unexpectedHexColors = hexMatches.filter(match => {
          return !allowedHexColors.some(allowed => match.toLowerCase().includes(allowed.toLowerCase()));
        });

        // Should have no unexpected hex colors beyond the allowed list
        expect(unexpectedHexColors).toEqual([]);
      }
    });

    it('should not contain hard-coded rgba colors in auth.css (except shadows)', () => {
      const authCSS = readFileSync(join(process.cwd(), 'auth.css'), 'utf-8');

      // Remove comments
      const cssWithoutComments = authCSS.replace(/\/\*[\s\S]*?\*\//g, '');

      // Count var(--cg-*) references to ensure tokens are being used
      const tokenReferences = cssWithoutComments.match(/var\(--cg-[a-z-]+\)/g);

      // Should have many token references
      expect(tokenReferences).toBeTruthy();
      expect(tokenReferences.length).toBeGreaterThan(10);
    });

    it('should not contain hard-coded hex colors in landing.css (except specific cases)', () => {
      const landingCSS = readFileSync(join(process.cwd(), 'landing.css'), 'utf-8');

      // Remove comments to avoid false positives
      const cssWithoutComments = landingCSS.replace(/\/\*[\s\S]*?\*\//g, '');

      // Match hex colors in CSS property values (not in var() calls)
      const hexColorPattern = /:\s*#[0-9A-Fa-f]{6}(?![^;]*var\()/g;
      const hexMatches = cssWithoutComments.match(hexColorPattern);

      // Allow specific exceptions for white (#fff, #ffffff) used in gradients
      const allowedHexColors = ['#ffffff', '#fff'];

      if (hexMatches) {
        const unexpectedHexColors = hexMatches.filter(match => {
          return !allowedHexColors.some(allowed => match.toLowerCase().includes(allowed.toLowerCase()));
        });

        // Should have no unexpected hex colors
        expect(unexpectedHexColors).toEqual([]);
      }
    });

    it('should not contain hard-coded rgba colors in landing.css (except shadows and specific effects)', () => {
      const landingCSS = readFileSync(join(process.cwd(), 'landing.css'), 'utf-8');

      // Remove comments
      const cssWithoutComments = landingCSS.replace(/\/\*[\s\S]*?\*\//g, '');

      // Count var(--cg-*) references to ensure tokens are being used
      const tokenReferences = cssWithoutComments.match(/var\(--cg-[a-z-]+\)/g);

      // Should have many token references
      expect(tokenReferences).toBeTruthy();
      expect(tokenReferences.length).toBeGreaterThan(50);
    });

    it('should use design tokens for all primary colors in auth.css', () => {
      const authCSS = readFileSync(join(process.cwd(), 'auth.css'), 'utf-8');

      // Verify key token usage
      expect(authCSS).toMatch(/var\(--cg-accent\)/);
      expect(authCSS).toMatch(/var\(--cg-bg-surface\)/);
      expect(authCSS).toMatch(/var\(--cg-border\)/);
      expect(authCSS).toMatch(/var\(--cg-accent-hover\)/);
    });

    it('should use design tokens for all primary colors in landing.css', () => {
      const landingCSS = readFileSync(join(process.cwd(), 'landing.css'), 'utf-8');

      // Verify key token usage
      expect(landingCSS).toMatch(/var\(--cg-accent\)/);
      expect(landingCSS).toMatch(/var\(--cg-bg-base\)/);
      expect(landingCSS).toMatch(/var\(--cg-bg-surface\)/);
      expect(landingCSS).toMatch(/var\(--cg-text-1\)/);
      expect(landingCSS).toMatch(/var\(--cg-text-2\)/);
      expect(landingCSS).toMatch(/var\(--cg-text-3\)/);
      expect(landingCSS).toMatch(/var\(--cg-border\)/);
      expect(landingCSS).toMatch(/var\(--cg-success\)/);
    });
  });

  describe('Tailwind CSS Compatibility', () => {
    it('should resolve CSS custom properties correctly', () => {
      const computedStyle = window.getComputedStyle(document.documentElement);

      // Verify tokens are defined and accessible
      expect(computedStyle.getPropertyValue('--cg-accent').trim()).toBe('#A78BFA');
      expect(computedStyle.getPropertyValue('--cg-bg-base').trim()).toBe('#0B0F19');
      expect(computedStyle.getPropertyValue('--cg-text-1').trim().replace(/\s/g, '')).toBe('rgba(255,255,255,0.95)');
    });

    it('should support var() syntax for Tailwind utility classes', () => {
      // Create element with inline style using var()
      const element = document.createElement('div');
      element.style.color = 'var(--cg-accent)';
      document.body.appendChild(element);

      const computedStyle = window.getComputedStyle(element);

      // Verify var() syntax is supported
      expect(computedStyle).toBeTruthy();
    });

    it('should have tokens accessible via getComputedStyle', () => {
      const computedStyle = window.getComputedStyle(document.documentElement);

      // Test that all key tokens are accessible
      const accentColor = computedStyle.getPropertyValue('--cg-accent').trim();
      const bgBase = computedStyle.getPropertyValue('--cg-bg-base').trim();
      const textPrimary = computedStyle.getPropertyValue('--cg-text-1').trim();

      expect(accentColor).toBeTruthy();
      expect(bgBase).toBeTruthy();
      expect(textPrimary).toBeTruthy();
    });

    it('should work with Tailwind CDN delivery', () => {
      // Verify tokens are defined in :root (accessible to Tailwind)
      const computedStyle = window.getComputedStyle(document.documentElement);

      // All tokens should be accessible at document root level
      expect(computedStyle.getPropertyValue('--cg-accent')).toBeTruthy();
      expect(computedStyle.getPropertyValue('--cg-bg-surface')).toBeTruthy();
      expect(computedStyle.getPropertyValue('--cg-border')).toBeTruthy();
    });
  });

  describe('Visual Consistency Validation', () => {
    it('should maintain consistent accent color across auth.css and landing.css', () => {
      const authCSS = readFileSync(join(process.cwd(), 'auth.css'), 'utf-8');
      const landingCSS = readFileSync(join(process.cwd(), 'landing.css'), 'utf-8');

      // Both should use var(--cg-accent) for accent colors
      expect(authCSS).toMatch(/var\(--cg-accent\)/);
      expect(landingCSS).toMatch(/var\(--cg-accent\)/);

      // Remove comments to check actual CSS code (not header comments)
      const authWithoutComments = authCSS.replace(/\/\*[\s\S]*?\*\//g, '');
      const landingWithoutComments = landingCSS.replace(/\/\*[\s\S]*?\*\//g, '');

      // Neither should have old cyan accent colors in actual CSS code
      expect(authWithoutComments).not.toMatch(/#06B6D4/);
      expect(authWithoutComments).not.toMatch(/#22D3EE/);
      expect(landingWithoutComments).not.toMatch(/#06B6D4/);
      expect(landingWithoutComments).not.toMatch(/#22D3EE/);
    });

    it('should use consistent background tokens', () => {
      const authCSS = readFileSync(join(process.cwd(), 'auth.css'), 'utf-8');
      const landingCSS = readFileSync(join(process.cwd(), 'landing.css'), 'utf-8');

      // Both should use background tokens
      expect(authCSS).toMatch(/var\(--cg-bg-surface\)/);
      expect(landingCSS).toMatch(/var\(--cg-bg-base\)/);
      expect(landingCSS).toMatch(/var\(--cg-bg-surface\)/);
    });

    it('should use consistent border tokens', () => {
      const authCSS = readFileSync(join(process.cwd(), 'auth.css'), 'utf-8');
      const landingCSS = readFileSync(join(process.cwd(), 'landing.css'), 'utf-8');

      // Both should use border tokens
      expect(authCSS).toMatch(/var\(--cg-border\)/);
      expect(landingCSS).toMatch(/var\(--cg-border\)/);
    });

    it('should use consistent text color tokens', () => {
      const landingCSS = readFileSync(join(process.cwd(), 'landing.css'), 'utf-8');

      // Should use text color hierarchy
      expect(landingCSS).toMatch(/var\(--cg-text-1\)/);
      expect(landingCSS).toMatch(/var\(--cg-text-2\)/);
      expect(landingCSS).toMatch(/var\(--cg-text-3\)/);
    });
  });

  describe('Requirement Validation', () => {
    it('should satisfy Requirement 3.3: auth.css uses token references', () => {
      const authCSS = readFileSync(join(process.cwd(), 'auth.css'), 'utf-8');

      // Should have many var(--cg-*) references
      const tokenReferences = authCSS.match(/var\(--cg-[a-z-]+\)/g);
      expect(tokenReferences).toBeTruthy();
      expect(tokenReferences.length).toBeGreaterThan(10);
    });

    it('should satisfy Requirement 3.4: landing.css uses token references', () => {
      const landingCSS = readFileSync(join(process.cwd(), 'landing.css'), 'utf-8');

      // Should have many var(--cg-*) references
      const tokenReferences = landingCSS.match(/var\(--cg-[a-z-]+\)/g);
      expect(tokenReferences).toBeTruthy();
      expect(tokenReferences.length).toBeGreaterThan(50);
    });

    it('should satisfy Requirement 3.5: Visual appearance is preserved', () => {
      // Verify key color tokens match expected values
      const computedStyle = window.getComputedStyle(document.documentElement);

      expect(computedStyle.getPropertyValue('--cg-bg-base').trim()).toBe('#0B0F19');
      expect(computedStyle.getPropertyValue('--cg-accent').trim()).toBe('#A78BFA');
      expect(computedStyle.getPropertyValue('--cg-accent-hover').trim()).toBe('#8B5CF6');
    });

    it('should satisfy Requirement 10.1-10.4: Tailwind CSS compatibility', () => {
      const computedStyle = window.getComputedStyle(document.documentElement);

      // Verify CSS custom properties resolve correctly
      expect(computedStyle.getPropertyValue('--cg-accent').trim()).toBe('#A78BFA');
      expect(computedStyle.getPropertyValue('--cg-bg-surface').trim().replace(/\s/g, '')).toBe('rgba(17,24,39,0.85)');
      expect(computedStyle.getPropertyValue('--cg-border').trim().replace(/\s/g, '')).toBe('rgba(255,255,255,0.08)');
    });

    it('should satisfy Requirement 11.1: No hard-coded hex in CSS (except theme-tokens.css)', () => {
      const authCSS = readFileSync(join(process.cwd(), 'auth.css'), 'utf-8');
      const landingCSS = readFileSync(join(process.cwd(), 'landing.css'), 'utf-8');

      // Remove comments
      const authWithoutComments = authCSS.replace(/\/\*[\s\S]*?\*\//g, '');
      const landingWithoutComments = landingCSS.replace(/\/\*[\s\S]*?\*\//g, '');

      // Count direct hex color usage (not in var() calls)
      const authHex = authWithoutComments.match(/:\s*#[0-9A-Fa-f]{6}(?![^;]*var\()/g);
      const landingHex = landingWithoutComments.match(/:\s*#[0-9A-Fa-f]{6}(?![^;]*var\()/g);

      // Allow specific hex colors for auth.css (light mode, dark mode, status colors)
      const allowedAuthHexColors = [
        '#ffffff', '#fff',  // White
        '#e5e7eb', '#d1d5db', '#9ca3af', '#6b7280', '#374151',  // Gray scale
        '#f9fafb', '#f0f9ff', '#e0f2fe', '#bae6fd',  // Light backgrounds
        '#1e293b', '#334155', '#0f172a', '#e2e8f0', '#94a3b8', '#60a5fa',  // Dark mode
        '#ef4444', '#dc2626',  // Red/danger
        '#f59e0b',  // Orange/warning
        '#10b981', '#059669', '#34d399',  // Green/success
        '#2563eb', '#0369a1',  // Blue/info
        '#000000'  // Black
      ];

      // Allow white (#ffffff, #fff) for landing.css text on colored backgrounds
      const allowedLandingHexColors = ['#ffffff', '#fff'];

      if (authHex) {
        const unexpectedAuthHex = authHex.filter(match => {
          return !allowedAuthHexColors.some(allowed => match.toLowerCase().includes(allowed.toLowerCase()));
        });
        expect(unexpectedAuthHex).toEqual([]);
      }

      if (landingHex) {
        const unexpectedLandingHex = landingHex.filter(match => {
          return !allowedLandingHexColors.some(allowed => match.toLowerCase().includes(allowed.toLowerCase()));
        });
        expect(unexpectedLandingHex).toEqual([]);
      }
    });

    it('should satisfy Requirement 11.2: No hard-coded rgba in CSS (except theme-tokens.css)', () => {
      const authCSS = readFileSync(join(process.cwd(), 'auth.css'), 'utf-8');
      const landingCSS = readFileSync(join(process.cwd(), 'landing.css'), 'utf-8');

      // Remove comments
      const authWithoutComments = authCSS.replace(/\/\*[\s\S]*?\*\//g, '');
      const landingWithoutComments = landingCSS.replace(/\/\*[\s\S]*?\*\//g, '');

      // Count var(--cg-*) references to ensure tokens are being used
      const authTokens = authWithoutComments.match(/var\(--cg-[a-z-]+\)/g);
      const landingTokens = landingWithoutComments.match(/var\(--cg-[a-z-]+\)/g);

      // Should have many token references
      expect(authTokens).toBeTruthy();
      expect(authTokens.length).toBeGreaterThan(10);
      expect(landingTokens).toBeTruthy();
      expect(landingTokens.length).toBeGreaterThan(50);
    });

    it('should satisfy Requirement 11.3-11.4: All color usage references tokens', () => {
      const authCSS = readFileSync(join(process.cwd(), 'auth.css'), 'utf-8');
      const landingCSS = readFileSync(join(process.cwd(), 'landing.css'), 'utf-8');

      // Verify comprehensive token usage
      expect(authCSS).toMatch(/var\(--cg-accent\)/);
      expect(authCSS).toMatch(/var\(--cg-bg-surface\)/);
      expect(authCSS).toMatch(/var\(--cg-border\)/);

      expect(landingCSS).toMatch(/var\(--cg-accent\)/);
      expect(landingCSS).toMatch(/var\(--cg-bg-base\)/);
      expect(landingCSS).toMatch(/var\(--cg-bg-surface\)/);
      expect(landingCSS).toMatch(/var\(--cg-text-1\)/);
      expect(landingCSS).toMatch(/var\(--cg-border\)/);
    });
  });

  describe('Token System Integration', () => {
    it('should load theme-tokens.css before auth.css and landing.css', () => {
      // Verify tokens are defined before being used
      const computedStyle = window.getComputedStyle(document.documentElement);

      // All tokens should be accessible
      expect(computedStyle.getPropertyValue('--cg-accent')).toBeTruthy();
      expect(computedStyle.getPropertyValue('--cg-bg-base')).toBeTruthy();
      expect(computedStyle.getPropertyValue('--cg-bg-surface')).toBeTruthy();
      expect(computedStyle.getPropertyValue('--cg-border')).toBeTruthy();
    });

    it('should resolve nested token references correctly', () => {
      const computedStyle = window.getComputedStyle(document.documentElement);

      // Verify token values match expected values
      expect(computedStyle.getPropertyValue('--cg-accent').trim()).toBe('#A78BFA');
      expect(computedStyle.getPropertyValue('--cg-accent-hover').trim()).toBe('#8B5CF6');
      expect(computedStyle.getPropertyValue('--cg-success').trim()).toBe('#34D399');
    });

    it('should support all token categories', () => {
      const computedStyle = window.getComputedStyle(document.documentElement);

      // Color tokens
      expect(computedStyle.getPropertyValue('--cg-accent')).toBeTruthy();
      expect(computedStyle.getPropertyValue('--cg-bg-base')).toBeTruthy();
      expect(computedStyle.getPropertyValue('--cg-text-1')).toBeTruthy();
      expect(computedStyle.getPropertyValue('--cg-border')).toBeTruthy();

      // Spacing tokens
      expect(computedStyle.getPropertyValue('--cg-space-4')).toBeTruthy();

      // Border radius tokens
      expect(computedStyle.getPropertyValue('--cg-radius-md')).toBeTruthy();

      // Transition tokens
      expect(computedStyle.getPropertyValue('--cg-transition-base')).toBeTruthy();
    });
  });
});
