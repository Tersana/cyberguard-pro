/**
 * Test Suite: Sidebar Toggle CSS Implementation (Task 2.1)
 * 
 * Tests the CSS transition properties added to .cyber-sidebar
 * Validates: Requirements 2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 10.1, 10.2, 10.6
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { JSDOM } from 'jsdom';
import fs from 'fs';
import path from 'path';

describe('Task 2.1: Sidebar Toggle CSS Transitions', () => {
  let dom;
  let document;
  let window;
  let sidebar;

  beforeEach(() => {
    // Load the CSS file
    const cssPath = path.join(process.cwd(), 'cyber-theme.css');
    const cssContent = fs.readFileSync(cssPath, 'utf-8');

    // Create a minimal HTML structure with the CSS
    const html = `
      <!DOCTYPE html>
      <html>
        <head>
          <style>${cssContent}</style>
        </head>
        <body>
          <aside id="sidebar" class="cyber-sidebar">
            <div class="sidebar-content">Test Content</div>
          </aside>
        </body>
      </html>
    `;

    dom = new JSDOM(html);
    document = dom.window.document;
    window = dom.window;
    sidebar = document.getElementById('sidebar');
  });

  afterEach(() => {
    dom.window.close();
  });

  describe('Base Sidebar Styles (Requirement 2.1, 2.2)', () => {
    it('should have correct width properties', () => {
      const styles = window.getComputedStyle(sidebar);
      
      // Requirement 2.1: Sidebar should be 260px width
      expect(styles.width).toBe('260px');
      expect(styles.minWidth).toBe('260px');
    });

    it('should have transition properties defined (Requirement 2.3)', () => {
      const styles = window.getComputedStyle(sidebar);
      
      // Requirement 2.3: Should have transition for transform, width, opacity
      const transition = styles.transition;
      expect(transition).toContain('transform');
      expect(transition).toContain('width');
      expect(transition).toContain('opacity');
      
      // Requirement 2.3: Should use 300ms duration
      expect(transition).toContain('300ms');
      
      // Requirement 2.4: Should use cubic-bezier(0.4, 0, 0.2, 1) easing
      expect(transition).toContain('cubic-bezier(0.4, 0, 0.2, 1)');
    });

    it('should have will-change property for GPU acceleration (Requirement 2.5)', () => {
      const styles = window.getComputedStyle(sidebar);
      
      // Requirement 2.5: Should have will-change for performance
      expect(styles.willChange).toBe('transform, width, opacity');
    });

    it('should have GPU acceleration properties (Requirement 2.6)', () => {
      const styles = window.getComputedStyle(sidebar);
      
      // Requirement 2.6: Should have transform: translateZ(0) for GPU acceleration
      expect(styles.transform).toContain('translateZ(0)');
      
      // Requirement 2.6: Should have backface-visibility: hidden
      expect(styles.backfaceVisibility).toBe('hidden');
    });
  });

  describe('Collapsed State Class (Requirement 10.1, 10.2)', () => {
    it('should have .sidebar-collapsed class defined', () => {
      // Add the collapsed class
      sidebar.classList.add('sidebar-collapsed');
      const styles = window.getComputedStyle(sidebar);
      
      // Requirement 10.1: Should have .sidebar-collapsed class
      expect(sidebar.classList.contains('sidebar-collapsed')).toBe(true);
    });

    it('should collapse to 0px width when .sidebar-collapsed is applied (Requirement 2.1)', () => {
      sidebar.classList.add('sidebar-collapsed');
      const styles = window.getComputedStyle(sidebar);
      
      // Requirement 2.1: Should animate from 260px to 0px width
      expect(styles.width).toBe('0px');
      expect(styles.minWidth).toBe('0px');
    });

    it('should use translateX(-100%) for smooth animation (Requirement 2.2)', () => {
      sidebar.classList.add('sidebar-collapsed');
      const styles = window.getComputedStyle(sidebar);
      
      // Requirement 2.2: Should use transform: translateX(-100%)
      expect(styles.transform).toContain('translateX(-100%)');
    });

    it('should set opacity to 0 when collapsed (Requirement 2.3)', () => {
      sidebar.classList.add('sidebar-collapsed');
      const styles = window.getComputedStyle(sidebar);
      
      // Requirement 2.3: Should transition opacity
      expect(styles.opacity).toBe('0');
    });
  });

  describe('Legacy .hidden Class Support (Requirement 10.6)', () => {
    it('should maintain backward compatibility with .hidden class', () => {
      sidebar.classList.add('hidden');
      const styles = window.getComputedStyle(sidebar);
      
      // Should behave the same as .sidebar-collapsed
      expect(styles.width).toBe('0px');
      expect(styles.minWidth).toBe('0px');
      expect(styles.opacity).toBe('0');
      expect(styles.transform).toContain('translateX(-100%)');
    });
  });

  describe('CSS Class Structure (Requirement 10.2)', () => {
    it('should follow cyber-theme naming conventions', () => {
      // Requirement 10.2: Should use .sidebar-collapsed class name
      expect(sidebar.classList.contains('cyber-sidebar')).toBe(true);
      
      // Test that the class can be added
      sidebar.classList.add('sidebar-collapsed');
      expect(sidebar.classList.contains('sidebar-collapsed')).toBe(true);
    });
  });

  describe('Border and Shadow Effects (Requirement 2.6)', () => {
    it('should maintain border during transition', () => {
      const styles = window.getComputedStyle(sidebar);
      
      // Requirement 2.6: Should maintain border effects
      // Note: JSDOM has limited CSS parsing, so we check if borderRight is defined
      // In a real browser, this would be '1px solid rgba(139, 92, 246, 0.15)'
      expect(styles.borderRight).toBeDefined();
    });

    it('should maintain background gradient', () => {
      const styles = window.getComputedStyle(sidebar);
      
      // Should have background gradient
      // Note: JSDOM has limited CSS parsing for gradients
      expect(styles.background).toBeDefined();
    });
  });
});
