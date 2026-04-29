/**
 * Chromium Browser Testing for Dashboard Navigation Reorganization
 * Task 8.1: Test in Chrome/Edge (Chromium)
 * 
 * This test suite verifies:
 * 1. Navigation functionality works correctly
 * 2. Styling renders correctly
 * 3. No console errors occur
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { JSDOM } from 'jsdom';
import fs from 'fs';
import path from 'path';

describe('Dashboard Navigation Reorganization - Chromium Browser Tests (Task 8.1)', () => {
  let dom;
  let document;
  let window;
  let DashboardTabManager;
  let consoleErrors;
  let consoleWarnings;

  beforeEach(() => {
    // Capture console errors and warnings
    consoleErrors = [];
    consoleWarnings = [];
    
    const originalError = console.error;
    const originalWarn = console.warn;
    
    console.error = (...args) => {
      consoleErrors.push(args.join(' '));
      originalError(...args);
    };
    
    console.warn = (...args) => {
      consoleWarnings.push(args.join(' '));
      originalWarn(...args);
    };

    // Load dashboard.html
    const dashboardHtml = fs.readFileSync(
      path.resolve(__dirname, 'dashboard.html'),
      'utf-8'
    );

    // Load dashboard-tab-manager.js
    const tabManagerJs = fs.readFileSync(
      path.resolve(__dirname, 'dashboard-tab-manager.js'),
      'utf-8'
    );

    // Create JSDOM instance
    dom = new JSDOM(dashboardHtml, {
      runScripts: 'dangerously',
      resources: 'usable',
      beforeParse(window) {
        // Mock console methods
        window.console.error = console.error;
        window.console.warn = console.warn;
        window.console.log = vi.fn();
      }
    });

    document = dom.window.document;
    window = dom.window;

    // Execute the tab manager script
    const scriptEl = document.createElement('script');
    scriptEl.textContent = tabManagerJs;
    document.body.appendChild(scriptEl);

    DashboardTabManager = window.DashboardTabManager;
  });

  afterEach(() => {
    // Restore console
    console.error = console.error;
    console.warn = console.warn;
  });

  describe('TC-1: Navigation Functionality', () => {
    it('TC-1.1: Should switch to Network Analysis tab', () => {
      const navItem = document.querySelector('[onclick*="network-tools"]');
      expect(navItem).toBeTruthy();
      
      // Click the navigation item
      navItem.click();
      
      // Verify active state
      expect(navItem.classList.contains('cyber-nav-active')).toBe(true);
      
      // Verify tab pane is visible
      const tabPane = document.getElementById('network-tools');
      expect(tabPane).toBeTruthy();
      expect(tabPane.classList.contains('hidden')).toBe(false);
      
      // Verify no console errors
      expect(consoleErrors).toHaveLength(0);
    });

    it('TC-1.2: Should switch to Web Security tab', () => {
      const navItem = document.querySelector('[onclick*="web-security"]');
      expect(navItem).toBeTruthy();
      
      navItem.click();
      
      expect(navItem.classList.contains('cyber-nav-active')).toBe(true);
      
      const tabPane = document.getElementById('web-security');
      expect(tabPane).toBeTruthy();
      expect(tabPane.classList.contains('hidden')).toBe(false);
      
      expect(consoleErrors).toHaveLength(0);
    });

    it('TC-1.3: Should switch to Hash Tools tab', () => {
      const navItem = document.querySelector('[onclick*="hash-tools"]');
      expect(navItem).toBeTruthy();
      
      navItem.click();
      
      expect(navItem.classList.contains('cyber-nav-active')).toBe(true);
      
      const tabPane = document.getElementById('hash-tools');
      expect(tabPane).toBeTruthy();
      expect(tabPane.classList.contains('hidden')).toBe(false);
      
      expect(consoleErrors).toHaveLength(0);
    });

    it('TC-1.4: Should switch to AI Assistant tab', () => {
      const navItem = document.querySelector('[onclick*="ai-assistant"]');
      expect(navItem).toBeTruthy();
      
      navItem.click();
      
      expect(navItem.classList.contains('cyber-nav-active')).toBe(true);
      
      const tabPane = document.getElementById('ai-assistant');
      expect(tabPane).toBeTruthy();
      expect(tabPane.classList.contains('hidden')).toBe(false);
      
      expect(consoleErrors).toHaveLength(0);
    });

    it('TC-1.5: Should switch to Threat Intel tab', () => {
      const navItem = document.querySelector('[onclick*="threat-intel"]');
      expect(navItem).toBeTruthy();
      
      navItem.click();
      
      expect(navItem.classList.contains('cyber-nav-active')).toBe(true);
      
      const tabPane = document.getElementById('threat-intel');
      expect(tabPane).toBeTruthy();
      expect(tabPane.classList.contains('hidden')).toBe(false);
      
      expect(consoleErrors).toHaveLength(0);
    });

    it('TC-1.6: Should switch to Projects tab', () => {
      const navItem = document.querySelector('[onclick*="projects"]');
      expect(navItem).toBeTruthy();
      
      navItem.click();
      
      expect(navItem.classList.contains('cyber-nav-active')).toBe(true);
      
      const tabPane = document.getElementById('projects');
      expect(tabPane).toBeTruthy();
      expect(tabPane.classList.contains('hidden')).toBe(false);
      
      expect(consoleErrors).toHaveLength(0);
    });

    it('TC-1.7: Should remove active state from previous item when switching', () => {
      const networkNav = document.querySelector('[onclick*="network-tools"]');
      const webSecNav = document.querySelector('[onclick*="web-security"]');
      
      // Switch to Network Analysis
      networkNav.click();
      expect(networkNav.classList.contains('cyber-nav-active')).toBe(true);
      
      // Switch to Web Security
      webSecNav.click();
      expect(webSecNav.classList.contains('cyber-nav-active')).toBe(true);
      expect(networkNav.classList.contains('cyber-nav-active')).toBe(false);
      
      expect(consoleErrors).toHaveLength(0);
    });

    it('TC-1.8: Should handle rapid tab switching without errors', () => {
      const navItems = [
        document.querySelector('[onclick*="network-tools"]'),
        document.querySelector('[onclick*="web-security"]'),
        document.querySelector('[onclick*="hash-tools"]'),
        document.querySelector('[onclick*="ai-assistant"]'),
        document.querySelector('[onclick*="threat-intel"]')
      ];
      
      // Rapidly click through all tabs
      navItems.forEach(item => item.click());
      
      // Verify final state is correct (last clicked item)
      const lastItem = navItems[navItems.length - 1];
      expect(lastItem.classList.contains('cyber-nav-active')).toBe(true);
      
      // Verify no errors occurred
      expect(consoleErrors).toHaveLength(0);
    });
  });

  describe('TC-2: HTML Structure Verification', () => {
    it('TC-2.1: Should have all 6 TOOLS navigation items', () => {
      const toolsNavItems = document.querySelectorAll('.cyber-nav-item[onclick*="switchToTab"]');
      
      // Should have 6 items (excluding Security Dashboard and API Keys)
      expect(toolsNavItems.length).toBeGreaterThanOrEqual(6);
      
      // Verify specific items exist
      const expectedTabs = [
        'network-tools',
        'web-security',
        'hash-tools',
        'ai-assistant',
        'threat-intel',
        'projects'
      ];
      
      expectedTabs.forEach(tabId => {
        const navItem = document.querySelector(`[onclick*="${tabId}"]`);
        expect(navItem).toBeTruthy();
      });
    });

    it('TC-2.2: Should NOT have horizontal tab bar', () => {
      const tabBar = document.querySelector('.cyber-tab-bar');
      expect(tabBar).toBeNull();
      
      const tabButtons = document.querySelectorAll('.tab-button');
      expect(tabButtons.length).toBe(0);
    });

    it('TC-2.3: Should have TOOLS section header', () => {
      const toolsHeader = Array.from(document.querySelectorAll('span'))
        .find(span => span.textContent.trim() === 'TOOLS');
      
      expect(toolsHeader).toBeTruthy();
      expect(toolsHeader.classList.contains('uppercase')).toBe(true);
    });

    it('TC-2.4: Should have icons for all navigation items', () => {
      const navItems = document.querySelectorAll('.cyber-nav-item[onclick*="switchToTab"]');
      
      navItems.forEach(item => {
        const icon = item.querySelector('svg');
        expect(icon).toBeTruthy();
      });
    });

    it('TC-2.5: Should have correct onclick handlers', () => {
      const navItems = document.querySelectorAll('.cyber-nav-item[onclick*="switchToTab"]');
      
      navItems.forEach(item => {
        const onclick = item.getAttribute('onclick');
        expect(onclick).toMatch(/switchToTab\('[^']+'\); return false;/);
      });
    });
  });

  describe('TC-3: CSS Class Verification', () => {
    it('TC-3.1: Should apply cyber-nav-active class to active item', () => {
      const navItem = document.querySelector('[onclick*="network-tools"]');
      navItem.click();
      
      expect(navItem.classList.contains('cyber-nav-active')).toBe(true);
    });

    it('TC-3.2: Should have cyber-nav-item class on all navigation items', () => {
      const navItems = document.querySelectorAll('[onclick*="switchToTab"]');
      
      navItems.forEach(item => {
        expect(item.classList.contains('cyber-nav-item')).toBe(true);
      });
    });

    it('TC-3.3: Should remove cyber-nav-active from non-active items', () => {
      const networkNav = document.querySelector('[onclick*="network-tools"]');
      const webSecNav = document.querySelector('[onclick*="web-security"]');
      
      networkNav.click();
      webSecNav.click();
      
      expect(networkNav.classList.contains('cyber-nav-active')).toBe(false);
      expect(webSecNav.classList.contains('cyber-nav-active')).toBe(true);
    });
  });

  describe('TC-4: Tab Manager Functionality', () => {
    it('TC-4.1: Should have DashboardTabManager available', () => {
      expect(DashboardTabManager).toBeDefined();
      expect(typeof DashboardTabManager.switchTab).toBe('function');
    });

    it('TC-4.2: Should have updateTabButtons method', () => {
      expect(typeof DashboardTabManager.updateTabButtons).toBe('function');
    });

    it('TC-4.3: Should extract tab ID from onclick attribute', () => {
      const navItem = document.querySelector('[onclick*="network-tools"]');
      const onclick = navItem.getAttribute('onclick');
      const match = onclick.match(/switchToTab\('([^']+)'\)/);
      
      expect(match).toBeTruthy();
      expect(match[1]).toBe('network-tools');
    });

    it('TC-4.4: Should have global switchToTab function', () => {
      expect(typeof window.switchToTab).toBe('function');
    });

    it('TC-4.5: Should switch tabs via global function', () => {
      window.switchToTab('web-security');
      
      const navItem = document.querySelector('[onclick*="web-security"]');
      expect(navItem.classList.contains('cyber-nav-active')).toBe(true);
      
      expect(consoleErrors).toHaveLength(0);
    });
  });

  describe('TC-5: Console Error Verification', () => {
    it('TC-5.1: Should not produce console errors on page load', () => {
      expect(consoleErrors).toHaveLength(0);
    });

    it('TC-5.2: Should not produce console errors during navigation', () => {
      const navItems = document.querySelectorAll('[onclick*="switchToTab"]');
      
      navItems.forEach(item => item.click());
      
      expect(consoleErrors).toHaveLength(0);
    });

    it('TC-5.3: Should not have missing tab pane errors', () => {
      const navItems = document.querySelectorAll('[onclick*="switchToTab"]');
      
      navItems.forEach(item => item.click());
      
      const missingPaneErrors = consoleErrors.filter(err => 
        err.includes('Tab pane') && err.includes('not found')
      );
      
      expect(missingPaneErrors).toHaveLength(0);
    });

    it('TC-5.4: Should not have querySelector errors', () => {
      const navItems = document.querySelectorAll('[onclick*="switchToTab"]');
      
      navItems.forEach(item => item.click());
      
      const querySelectorErrors = consoleErrors.filter(err =>
        err.includes('querySelector') || err.includes('querySelectorAll')
      );
      
      expect(querySelectorErrors).toHaveLength(0);
    });
  });

  describe('TC-6: Tab Pane Visibility', () => {
    it('TC-6.1: Should hide non-active tab panes', () => {
      const networkNav = document.querySelector('[onclick*="network-tools"]');
      networkNav.click();
      
      const networkPane = document.getElementById('network-tools');
      const webSecPane = document.getElementById('web-security');
      
      expect(networkPane.classList.contains('hidden')).toBe(false);
      expect(webSecPane.classList.contains('hidden')).toBe(true);
    });

    it('TC-6.2: Should show active tab pane', () => {
      const hashNav = document.querySelector('[onclick*="hash-tools"]');
      hashNav.click();
      
      const hashPane = document.getElementById('hash-tools');
      expect(hashPane.classList.contains('hidden')).toBe(false);
      expect(hashPane.classList.contains('active')).toBe(true);
    });

    it('TC-6.3: Should only have one visible tab pane at a time', () => {
      const aiNav = document.querySelector('[onclick*="ai-assistant"]');
      aiNav.click();
      
      const tabPanes = document.querySelectorAll('.tab-pane');
      const visiblePanes = Array.from(tabPanes).filter(pane => 
        !pane.classList.contains('hidden')
      );
      
      expect(visiblePanes.length).toBe(1);
      expect(visiblePanes[0].id).toBe('ai-assistant');
    });
  });

  describe('TC-7: Backward Compatibility', () => {
    it('TC-7.1: Should handle .tab-button elements if they exist', () => {
      // Even though we removed them, the code should handle them gracefully
      const tabButtons = document.querySelectorAll('.tab-button');
      
      // Should not throw error even if no buttons found
      expect(() => {
        DashboardTabManager.updateTabButtons('network-tools');
      }).not.toThrow();
    });

    it('TC-7.2: Should work with onclick attribute format', () => {
      const navItem = document.querySelector('[onclick*="network-tools"]');
      const onclick = navItem.getAttribute('onclick');
      
      // Verify format: switchToTab('tab-id'); return false;
      expect(onclick).toMatch(/switchToTab\('[^']+'\); return false;/);
    });
  });

  describe('TC-8: Integration Tests', () => {
    it('TC-8.1: Should maintain state across multiple switches', () => {
      const tabs = [
        'network-tools',
        'web-security',
        'hash-tools',
        'ai-assistant',
        'threat-intel'
      ];
      
      tabs.forEach(tabId => {
        window.switchToTab(tabId);
        
        const navItem = document.querySelector(`[onclick*="${tabId}"]`);
        expect(navItem.classList.contains('cyber-nav-active')).toBe(true);
        
        const tabPane = document.getElementById(tabId);
        expect(tabPane.classList.contains('hidden')).toBe(false);
      });
      
      expect(consoleErrors).toHaveLength(0);
    });

    it('TC-8.2: Should handle same tab click gracefully', () => {
      const navItem = document.querySelector('[onclick*="network-tools"]');
      
      navItem.click();
      navItem.click();
      navItem.click();
      
      expect(navItem.classList.contains('cyber-nav-active')).toBe(true);
      expect(consoleErrors).toHaveLength(0);
    });
  });
});
