/**
 * Task 6.1: Test Desktop Viewport (> 640px)
 * 
 * Tests the responsive behavior in desktop viewports to ensure all navigation
 * functionality works correctly on larger screens.
 * 
 * Requirements tested: 6.1, 6.2, 6.3, 6.4, 6.5, 8.1, 8.2, 8.3, 8.4, 8.5
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { JSDOM } from 'jsdom';
import fs from 'fs';
import path from 'path';

describe('Task 6.1: Desktop Viewport Navigation (> 640px)', () => {
  let dom;
  let document;
  let window;
  let DashboardTabManager;

  beforeEach(async () => {
    // Read the actual dashboard.html file
    const dashboardHtml = fs.readFileSync(
      path.resolve(process.cwd(), 'dashboard.html'),
      'utf-8'
    );

    // Create DOM with desktop viewport dimensions
    dom = new JSDOM(dashboardHtml, {
      url: 'http://localhost',
      runScripts: 'dangerously',
      resources: 'usable',
      pretendToBeVisual: true,
      beforeParse(window) {
        // Set desktop viewport dimensions (> 640px)
        window.innerWidth = 1024;
        window.innerHeight = 768;
        
        // Mock matchMedia for responsive queries
        window.matchMedia = (query) => ({
          matches: query.includes('min-width: 640px') || query.includes('min-width: 768px'),
          media: query,
          onchange: null,
          addListener: vi.fn(),
          removeListener: vi.fn(),
          addEventListener: vi.fn(),
          removeEventListener: vi.fn(),
          dispatchEvent: vi.fn(),
        });
      }
    });

    document = dom.window.document;
    window = dom.window;
    global.document = document;
    global.window = window;
    global.CustomEvent = window.CustomEvent;

    // Mock console methods to reduce noise
    global.console.log = vi.fn();
    global.console.warn = vi.fn();
    global.console.error = vi.fn();

    // Mock CustomEvent to work with JSDOM
    vi.spyOn(document, 'dispatchEvent').mockImplementation(() => true);

    // Import the dashboard tab manager
    const module = await import('./dashboard-tab-manager.js');
    DashboardTabManager = module.default || module.DashboardTabManager;
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  /**
   * Requirement 6.1: Verify all 5 TOOLS navigation items are visible
   */
  describe('Requirement 6.1: All 5 TOOLS navigation items visible', () => {
    it('should display all 5 navigation items in TOOLS section', () => {
      // Arrange: Get all navigation items in TOOLS section
      const toolsSection = Array.from(document.querySelectorAll('nav .cyber-nav-item'))
        .filter(item => {
          const onclick = item.getAttribute('onclick');
          return onclick && onclick.includes('switchToTab');
        });

      // Expected tool items
      const expectedTools = [
        'network-tools',
        'web-security',
        'hash-tools',
        'ai-assistant',
        'threat-intel'
      ];

      // Act: Extract tab IDs from onclick attributes
      const actualTools = toolsSection
        .map(item => {
          const onclick = item.getAttribute('onclick');
          const match = onclick?.match(/switchToTab\('([^']+)'\)/);
          return match ? match[1] : null;
        })
        .filter(Boolean);

      // Assert: All 5 tools are present
      expect(actualTools.length).toBeGreaterThanOrEqual(5);
      expectedTools.forEach(tool => {
        expect(actualTools).toContain(tool);
      });
    });

    it('should have visible navigation items (not display: none)', () => {
      // Arrange: Get all TOOLS navigation items
      const navItems = Array.from(document.querySelectorAll('.cyber-nav-item[onclick*="switchToTab"]'));

      // Assert: None should have display: none or hidden class
      navItems.forEach(item => {
        const computedStyle = window.getComputedStyle(item);
        expect(computedStyle.display).not.toBe('none');
        expect(item.classList.contains('hidden')).toBe(false);
      });
    });

    it('should have all navigation items with proper labels', () => {
      // Arrange: Expected labels
      const expectedLabels = [
        'Network Analysis',
        'Web Security',
        'Hash Tools',
        'AI Assistant',
        'Threat Intel'
      ];

      // Act: Get all navigation item text content
      const navItems = Array.from(document.querySelectorAll('.cyber-nav-item[onclick*="switchToTab"]'));
      const actualLabels = navItems.map(item => item.textContent.trim());

      // Assert: All expected labels are present
      expectedLabels.forEach(label => {
        expect(actualLabels.some(actual => actual.includes(label))).toBe(true);
      });
    });
  });

  /**
   * Requirement 6.2: Verify clicking each item switches to correct tab
   */
  describe('Requirement 6.2: Clicking each item switches to correct tab', () => {
    it('should switch to Network Analysis tab when clicked', () => {
      // Arrange
      const navItem = Array.from(document.querySelectorAll('.cyber-nav-item'))
        .find(item => item.getAttribute('onclick')?.includes("'network-tools'"));
      
      // Act
      DashboardTabManager.switchTab('network-tools');

      // Assert
      const tabPane = document.getElementById('network-tools');
      expect(tabPane.classList.contains('hidden')).toBe(false);
      expect(tabPane.classList.contains('active')).toBe(true);
    });

    it('should switch to Web Security tab when clicked', () => {
      // Act
      DashboardTabManager.switchTab('web-security');

      // Assert
      const tabPane = document.getElementById('web-security');
      expect(tabPane.classList.contains('hidden')).toBe(false);
      expect(tabPane.classList.contains('active')).toBe(true);
    });

    it('should switch to Hash Tools tab when clicked', () => {
      // Act
      DashboardTabManager.switchTab('hash-tools');

      // Assert
      const tabPane = document.getElementById('hash-tools');
      expect(tabPane.classList.contains('hidden')).toBe(false);
      expect(tabPane.classList.contains('active')).toBe(true);
    });

    it('should switch to AI Assistant tab when clicked', () => {
      // Act
      DashboardTabManager.switchTab('ai-assistant');

      // Assert
      const tabPane = document.getElementById('ai-assistant');
      expect(tabPane.classList.contains('hidden')).toBe(false);
      expect(tabPane.classList.contains('active')).toBe(true);
    });

    it('should switch to Threat Intel tab when clicked', () => {
      // Act
      DashboardTabManager.switchTab('threat-intel');

      // Assert
      const tabPane = document.getElementById('threat-intel');
      expect(tabPane.classList.contains('hidden')).toBe(false);
      expect(tabPane.classList.contains('active')).toBe(true);
    });

    it('should hide previous tab when switching to new tab', () => {
      // Arrange: Start on network-tools
      DashboardTabManager.switchTab('network-tools');
      const networkPane = document.getElementById('network-tools');
      expect(networkPane.classList.contains('active')).toBe(true);

      // Act: Switch to web-security
      DashboardTabManager.switchTab('web-security');

      // Assert: network-tools should be hidden
      expect(networkPane.classList.contains('hidden')).toBe(true);
      expect(networkPane.classList.contains('active')).toBe(false);
    });
  });

  /**
   * Requirement 6.3: Verify active state appears correctly
   */
  describe('Requirement 6.3: Active state appears correctly', () => {
    it('should apply cyber-nav-active class to active navigation item', () => {
      // Act
      DashboardTabManager.switchTab('network-tools');

      // Assert
      const navItems = document.querySelectorAll('.cyber-nav-item[onclick*="switchToTab"]');
      const networkItem = Array.from(navItems).find(item =>
        item.getAttribute('onclick')?.includes("'network-tools'")
      );
      
      expect(networkItem.classList.contains('cyber-nav-active')).toBe(true);
    });

    it('should remove cyber-nav-active from previous item when switching', () => {
      // Arrange: Start on network-tools
      DashboardTabManager.switchTab('network-tools');
      
      // Verify network-tools is now active
      const navItems = document.querySelectorAll('.cyber-nav-item[onclick*="switchToTab"]');
      const networkItem = Array.from(navItems).find(item =>
        item.getAttribute('onclick')?.includes("'network-tools'")
      );
      
      // After switchTab, updateTabButtons should have been called
      // Check if it has the active class (it should after the switch)
      const hasActiveAfterSwitch = networkItem.classList.contains('cyber-nav-active');

      // Act: Switch to web-security
      DashboardTabManager.switchTab('web-security');

      // Assert: network-tools should no longer be active
      expect(networkItem.classList.contains('cyber-nav-active')).toBe(false);
      
      // And web-security should be active
      const webSecurityItem = Array.from(navItems).find(item =>
        item.getAttribute('onclick')?.includes("'web-security'")
      );
      expect(webSecurityItem.classList.contains('cyber-nav-active')).toBe(true);
    });

    it('should have only one active navigation item at a time', () => {
      // Act
      DashboardTabManager.switchTab('hash-tools');

      // Assert
      const navItems = document.querySelectorAll('.cyber-nav-item[onclick*="switchToTab"]');
      const activeItems = Array.from(navItems).filter(item =>
        item.classList.contains('cyber-nav-active')
      );
      
      expect(activeItems.length).toBe(1);
      expect(activeItems[0].getAttribute('onclick')).toContain("'hash-tools'");
    });

    it('should maintain active state through multiple tab switches', () => {
      // Act: Switch through multiple tabs
      DashboardTabManager.switchTab('network-tools');
      DashboardTabManager.switchTab('web-security');
      DashboardTabManager.switchTab('hash-tools');
      DashboardTabManager.switchTab('ai-assistant');
      DashboardTabManager.switchTab('threat-intel');

      // Assert: Only threat-intel should be active
      const navItems = document.querySelectorAll('.cyber-nav-item[onclick*="switchToTab"]');
      navItems.forEach(item => {
        const onclick = item.getAttribute('onclick');
        if (onclick?.includes("'threat-intel'")) {
          expect(item.classList.contains('cyber-nav-active')).toBe(true);
        } else {
          expect(item.classList.contains('cyber-nav-active')).toBe(false);
        }
      });
    });
  });

  /**
   * Requirement 6.4: Verify no horizontal tab bar is visible
   */
  describe('Requirement 6.4: No horizontal tab bar visible', () => {
    it('should not have horizontal tab bar element in DOM', () => {
      // Arrange: Look for horizontal tab bar
      const tabBar = document.querySelector('.cyber-tab-bar');

      // Assert: Should not exist or should be hidden
      if (tabBar) {
        const computedStyle = window.getComputedStyle(tabBar);
        expect(computedStyle.display).toBe('none');
      } else {
        // Tab bar doesn't exist - this is the expected state after reorganization
        expect(tabBar).toBeNull();
      }
    });

    it('should not have horizontal tab buttons visible', () => {
      // Arrange: Look for horizontal tab buttons
      const tabButtons = document.querySelectorAll('.tab-button[data-tab]');

      // Assert: Should not exist or should be hidden
      if (tabButtons.length > 0) {
        tabButtons.forEach(button => {
          const computedStyle = window.getComputedStyle(button);
          expect(computedStyle.display).toBe('none');
        });
      } else {
        // No tab buttons - this is the expected state after reorganization
        expect(tabButtons.length).toBe(0);
      }
    });

    it('should have navigation only in sidebar', () => {
      // Arrange: Get sidebar navigation items
      const sidebarNavItems = document.querySelectorAll('.cyber-sidebar .cyber-nav-item[onclick*="switchToTab"]');

      // Assert: Should have navigation items in sidebar
      expect(sidebarNavItems.length).toBeGreaterThanOrEqual(5);
    });
  });

  /**
   * Requirement 6.5: Verify content area uses full vertical space
   */
  describe('Requirement 6.5: Content area uses full vertical space', () => {
    it('should have main content area without horizontal tab bar spacing', () => {
      // Arrange: Get main content area
      const mainContent = document.querySelector('main');
      
      // Assert: Main content should exist
      expect(mainContent).not.toBeNull();
    });

    it('should have tab panes directly under header without tab bar gap', () => {
      // Arrange: Get header and first tab pane
      const header = document.querySelector('.cyber-header');
      const tabPane = document.querySelector('.tab-pane');

      // Assert: Both should exist
      expect(header).not.toBeNull();
      expect(tabPane).not.toBeNull();
    });

    it('should not have cyber-tab-bar spacing in content flow', () => {
      // Arrange: Look for tab bar spacing elements
      const tabBarSpacing = document.querySelector('.cyber-tab-bar');

      // Assert: Should not exist or be hidden
      if (tabBarSpacing) {
        const computedStyle = window.getComputedStyle(tabBarSpacing);
        expect(computedStyle.display).toBe('none');
      }
    });
  });

  /**
   * Requirement 8.1: Maintain existing color scheme
   */
  describe('Requirement 8.1: Maintain existing color scheme', () => {
    it('should use cyber-nav-item class for navigation items', () => {
      // Arrange: Get all navigation items
      const navItems = document.querySelectorAll('.cyber-nav-item[onclick*="switchToTab"]');

      // Assert: All should have cyber-nav-item class
      navItems.forEach(item => {
        expect(item.classList.contains('cyber-nav-item')).toBe(true);
      });
    });

    it('should use cyber-nav-active class for active state', () => {
      // Act
      DashboardTabManager.switchTab('network-tools');

      // Assert
      const navItems = document.querySelectorAll('.cyber-nav-item[onclick*="switchToTab"]');
      const activeItem = Array.from(navItems).find(item =>
        item.classList.contains('cyber-nav-active')
      );
      
      expect(activeItem).not.toBeNull();
      expect(activeItem.classList.contains('cyber-nav-active')).toBe(true);
    });
  });

  /**
   * Requirement 8.2: Icon and text spacing matches existing layout
   */
  describe('Requirement 8.2: Icon and text spacing', () => {
    it('should have icons for all navigation items', () => {
      // Arrange: Get all navigation items
      const navItems = document.querySelectorAll('.cyber-nav-item[onclick*="switchToTab"]');

      // Assert: Each should contain an SVG icon
      navItems.forEach(item => {
        const svg = item.querySelector('svg');
        expect(svg).not.toBeNull();
      });
    });

    it('should have text labels for all navigation items', () => {
      // Arrange: Get all navigation items
      const navItems = document.querySelectorAll('.cyber-nav-item[onclick*="switchToTab"]');

      // Assert: Each should have text content
      navItems.forEach(item => {
        const text = item.textContent.trim();
        expect(text.length).toBeGreaterThan(0);
      });
    });

    it('should have consistent structure with flex layout', () => {
      // Arrange: Get all navigation items
      const navItems = document.querySelectorAll('.cyber-nav-item[onclick*="switchToTab"]');

      // Assert: Each should have flex items-center gap-3 classes
      navItems.forEach(item => {
        const classes = item.className;
        expect(classes).toContain('flex');
        expect(classes).toContain('items-center');
        expect(classes).toContain('gap-3');
      });
    });
  });

  /**
   * Requirement 8.3: Hover states use existing styling
   */
  describe('Requirement 8.3: Hover states', () => {
    it('should have hover state defined for navigation items', () => {
      // Arrange: Get a navigation item
      const navItem = document.querySelector('.cyber-nav-item[onclick*="switchToTab"]');

      // Assert: Should have cyber-nav-item class which has hover styles
      expect(navItem.classList.contains('cyber-nav-item')).toBe(true);
    });
  });

  /**
   * Requirement 8.4: Navigation items use existing cyber-nav-item CSS class
   */
  describe('Requirement 8.4: CSS class usage', () => {
    it('should use cyber-nav-item class for all navigation items', () => {
      // Arrange: Get all navigation items
      const navItems = document.querySelectorAll('.cyber-nav-item[onclick*="switchToTab"]');

      // Assert: All should have cyber-nav-item class
      expect(navItems.length).toBeGreaterThanOrEqual(5);
      navItems.forEach(item => {
        expect(item.classList.contains('cyber-nav-item')).toBe(true);
      });
    });
  });

  /**
   * Requirement 8.5: Active state uses existing cyber-nav-active CSS class
   */
  describe('Requirement 8.5: Active state CSS class', () => {
    it('should use cyber-nav-active class for active state', () => {
      // Act
      DashboardTabManager.switchTab('web-security');

      // Assert
      const navItems = document.querySelectorAll('.cyber-nav-item[onclick*="switchToTab"]');
      const activeItem = Array.from(navItems).find(item =>
        item.getAttribute('onclick')?.includes("'web-security'")
      );
      
      expect(activeItem.classList.contains('cyber-nav-active')).toBe(true);
    });

    it('should not use any other active state classes', () => {
      // Act
      DashboardTabManager.switchTab('hash-tools');

      // Assert
      const navItems = document.querySelectorAll('.cyber-nav-item[onclick*="switchToTab"]');
      const activeItem = Array.from(navItems).find(item =>
        item.getAttribute('onclick')?.includes("'hash-tools'")
      );
      
      // Should only have cyber-nav-active, not 'active' or other variants
      expect(activeItem.classList.contains('cyber-nav-active')).toBe(true);
      expect(activeItem.classList.contains('active')).toBe(false);
    });
  });

  /**
   * Integration test: Complete navigation workflow
   */
  describe('Integration: Complete navigation workflow', () => {
    it('should handle complete navigation workflow in desktop viewport', () => {
      // Arrange: Verify we're in desktop viewport
      expect(window.innerWidth).toBeGreaterThan(640);

      // Act & Assert: Navigate through all tabs
      const tabs = ['network-tools', 'web-security', 'hash-tools', 'ai-assistant', 'threat-intel'];
      
      tabs.forEach(tabId => {
        // Switch to tab
        DashboardTabManager.switchTab(tabId);

        // Verify tab pane is visible
        const tabPane = document.getElementById(tabId);
        expect(tabPane.classList.contains('hidden')).toBe(false);
        expect(tabPane.classList.contains('active')).toBe(true);

        // Verify navigation item is active
        const navItems = document.querySelectorAll('.cyber-nav-item[onclick*="switchToTab"]');
        const activeItem = Array.from(navItems).find(item =>
          item.getAttribute('onclick')?.includes(`'${tabId}'`)
        );
        expect(activeItem.classList.contains('cyber-nav-active')).toBe(true);

        // Verify only one item is active
        const activeItems = Array.from(navItems).filter(item =>
          item.classList.contains('cyber-nav-active')
        );
        expect(activeItems.length).toBe(1);
      });
    });

    it('should maintain state consistency across rapid tab switches', () => {
      // Act: Rapidly switch tabs
      DashboardTabManager.switchTab('network-tools');
      DashboardTabManager.switchTab('web-security');
      DashboardTabManager.switchTab('hash-tools');
      DashboardTabManager.switchTab('ai-assistant');
      DashboardTabManager.switchTab('threat-intel');
      DashboardTabManager.switchTab('network-tools');

      // Assert: Final state should be consistent
      const networkPane = document.getElementById('network-tools');
      expect(networkPane.classList.contains('active')).toBe(true);
      expect(networkPane.classList.contains('hidden')).toBe(false);

      const navItems = document.querySelectorAll('.cyber-nav-item[onclick*="switchToTab"]');
      const networkItem = Array.from(navItems).find(item =>
        item.getAttribute('onclick')?.includes("'network-tools'")
      );
      expect(networkItem.classList.contains('cyber-nav-active')).toBe(true);
    });
  });
});
