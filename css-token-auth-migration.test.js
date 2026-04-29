/**
 * Test: auth.css Design Token Migration (Task 4.1)
 * Validates that auth.css uses design tokens correctly
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';

describe('auth.css Design Token Migration', () => {
  const authCss = readFileSync('auth.css', 'utf-8');

  it('should not contain rgba(255, 255, 255, 0.95) - replaced with var(--cg-bg-surface)', () => {
    expect(authCss).not.toMatch(/rgba\(255,\s*255,\s*255,\s*0\.95\)/);
  });

  it('should not contain rgba(255, 255, 255, 0.2) - replaced with var(--cg-border)', () => {
    expect(authCss).not.toMatch(/rgba\(255,\s*255,\s*255,\s*0\.2\)/);
  });

  it('should not contain rgba(255, 255, 255, 0.1) in .shape - replaced with var(--cg-border-subtle)', () => {
    const shapeRule = authCss.match(/\.shape\s*\{[^}]+\}/s);
    if (shapeRule) {
      expect(shapeRule[0]).not.toMatch(/rgba\(255,\s*255,\s*255,\s*0\.1\)/);
    }
  });

  it('should use var(--cg-bg-surface) for .auth-container background', () => {
    expect(authCss).toMatch(/\.auth-container\s*\{[^}]*background:\s*var\(--cg-bg-surface\)/s);
  });

  it('should use var(--cg-border) for .auth-container border', () => {
    expect(authCss).toMatch(/\.auth-container\s*\{[^}]*border:\s*1px\s+solid\s+var\(--cg-border\)/s);
  });

  it('should use var(--cg-border-subtle) for .shape background', () => {
    expect(authCss).toMatch(/\.shape\s*\{[^}]*background:\s*var\(--cg-border-subtle\)/s);
  });

  it('should use design tokens in .btn-primary gradient', () => {
    expect(authCss).toMatch(/\.btn-primary\s*\{[^}]*background:\s*linear-gradient\([^)]*var\(--cg-accent\)[^)]*var\(--cg-accent-hover\)/s);
  });

  it('should use var(--cg-border) in .btn-primary::before gradient', () => {
    expect(authCss).toMatch(/\.btn-primary::before\s*\{[^}]*background:\s*linear-gradient\([^)]*var\(--cg-border\)/s);
  });

  it('should use var(--cg-bg-surface) in dark mode .auth-container', () => {
    const darkModeSection = authCss.match(/@media\s*\(prefers-color-scheme:\s*dark\)\s*\{[^}]+\.auth-container\s*\{[^}]+\}/s);
    if (darkModeSection) {
      expect(darkModeSection[0]).toMatch(/background:\s*var\(--cg-bg-surface\)/);
    }
  });

  it('should use var(--cg-border-subtle) in dark mode .auth-container border', () => {
    const darkModeSection = authCss.match(/@media\s*\(prefers-color-scheme:\s*dark\)\s*\{[^}]+\.auth-container\s*\{[^}]+\}/s);
    if (darkModeSection) {
      expect(darkModeSection[0]).toMatch(/border-color:\s*var\(--cg-border-subtle\)/);
    }
  });
});

describe('Visual Parity Validation', () => {
  const themeTokensCss = readFileSync('theme-tokens.css', 'utf-8');

  it('should have --cg-bg-surface defined in theme-tokens.css', () => {
    expect(themeTokensCss).toMatch(/--cg-bg-surface:\s*rgba\(17,\s*24,\s*39,\s*0\.85\)/);
  });

  it('should have --cg-border defined in theme-tokens.css', () => {
    expect(themeTokensCss).toMatch(/--cg-border:\s*rgba\(255,\s*255,\s*255,\s*0\.08\)/);
  });

  it('should have --cg-border-subtle defined in theme-tokens.css', () => {
    expect(themeTokensCss).toMatch(/--cg-border-subtle:\s*rgba\(255,\s*255,\s*255,\s*0\.06\)/);
  });

  it('should have --cg-accent defined in theme-tokens.css', () => {
    expect(themeTokensCss).toMatch(/--cg-accent:\s*#A78BFA/);
  });

  it('should have --cg-accent-hover defined in theme-tokens.css', () => {
    expect(themeTokensCss).toMatch(/--cg-accent-hover:\s*#8B5CF6/);
  });
});
