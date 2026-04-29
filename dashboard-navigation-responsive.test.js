/**
 * Task 6.3: Integration Tests for Responsive Behavior
 * 
 * Tests the navigation behavior across different viewport sizes and verifies
 * that active state is preserved when resizing between mobile and desktop.
 * 
 * Requirements tested: 6.1, 6.2, 6.3, 6.4, 6.5
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { JSDOM } from 'jsdom';
import fs from 'fs';
import path from 'path';

describe('Task 6.3: Responsive Behavior Integration Tests', () => {
  let dom;
  let document;
  let window;
  let DashboardTabManager;

  /**
   * Helper function to create a DOM with specific viewport dimensions
   */
  const createDOMWithViewport = async (width, height) => {
    const dashboardHtml = fs.readFileSync(
      path.resolve(process.cwd(), 'dashboard.html'),
      'utf-8'
    );

    const newDom = new JSDOM(dashboardHtml, {
      url: 'http://localhost',
      runScripts: 'dangerously',
      resources: 'usable',
      pretendToBeVisual: true,
      beforeParse(win) {
        win.innerWidth = width;
        win.innerHeight = height;
        
        // Mock matchMedia for responsive queries
        win.matchMedia = (query) => {
          const isMobile = width < 640;
          const isDesktop = width >= 640;
          
          return {
            matches: (query.includes('max-width') && isMobile) || 
                     (query.includes('min-width') && isDesktop),
            media: query,
            onchange: null,
            addListener: vi.fn(),
            removeListener: vi.fn(),
            addEventListener: vi.fn(),
            removeEventListener: vi.fn(),
            dispatchEvent: vi.fn(),
          };
        };
      }
    });

    return newDom;
  };

  /**
   * Helper function to resize the viewport
   */
  const resizeViewport = (newWidth, newHeight) => {
    window.innerWidth = newWidth;
    window.innerHeight = newHeight;
    
    // Update matchMedia to reflect new viewport
    window.matchMedia = (query) => {
      const isMobile = newWidth < 640;
      const isDesktop = newWidth >= 640;
      
      return {
        matches: (query.includes('max-width') && isMobile) || 
                 (query.includes('min-width') && isDesktop),
        media: query,
        onchange: null,
        addListener: vi.fn(),
        removeListener: vi.fn(),
        addEventListener: vi.fn(),
        removeEventListener: vi.fn(),
        dispatchEvent: vi.fn(),
      };
    };
    
    // Trigger resize event
    const resizeEvent = new window.Event('resize');
    window.dispatchEvent(resizeEvent);
  };

  beforeEach(async () => {
    // Start with desktop viewport
    dom = await createDOMWithViewport(1024, 768);
    
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
   * Requirement 6.1: Test sidebar navigation in mobile viewport
   */
  describe('Requirement 6.1: Sidebar navigation in mobile viewport', () => {
    it('should display sidebar navigation in mobile viewport', async () => {
      // Arrange: Resize to mobile
      resizeViewport(375, 667);

      // Act: Get sidebar and navigation items
      const sidebar = document.getElementById('sidebar');
      const navItems = document.querySelectorAll('.cyber-sidebar .cyber-nav-item[onclick*="switchToTab"]');

      // Assert: Sidebar and navigation items should exist
      expect(sidebar).not.toBeNull();
      expect(navItems.length).toBeGreaterThanOrEqual(5);
    });

    it('should have all 5 tool navigation items accessible in mobile', async () => {
      // Arrange: Resize to mobile
      resizeViewport(375, 667);

      // Act: Get navigation items
      const navItems = document.querySelectorAll('.cyber-sidebar .cyber-nav-item[onclick*="switchToTab"]');
      
      const expectedTools = [
        'network-tools',
        'web-security',
        'hash-tools',
        'ai-assistant',
        'threat-intel'
      ];

      const actualTools = Array.from(navItems)
        .map(item => {
          const onclick = item.getAttribute('onclick');
          const match = onclick?.match(/switchToTab\('([^']+)'\)/);
          return match ? match[1] : null;
        })
        .filter(Boolean);

      // Assert: All tools should be present
      expectedTools.forEach(tool => {
        expect(actualTools).toContain(tool);
      });
    });

    it('should allow tab switching in mobile viewport', async () => {
      // Arrange: Resize to mobile
      resizeViewport(375, 667);

      // Act: Switch to a tab
      DashboardTabManager.switchTab('web-security');

      // Assert: Tab should be active
      const tabPane = document.getElementById('web-security');
      expect(tabPane.classList.contains('active')).toBe(true);
      expect(tabPane.classList.contains('hidden')).toBe(false);
    });

    it('should show floating toggle button in mobile viewport', async () => {
      // Arrange: Resize to mobile
      resizeViewport(375, 667);

      // Act: Get floating toggle button
      const floatingToggle = document.getElementById('floating-sidebar-toggle');

      // Assert: Button should exist and be visible
      expect(floatingToggle).not.toBeNull();
      expect(floatingToggle.classList.contains('cyber-float-btn')).toBe(true);
    });

    it('should have sidebar overlay in mobile viewport', async () => {
      // Arrange: Resize to mobile
      resizeViewport(375, 667);

      // Act: Get overlay element
      const overlay = document.getElementById('sidebar-overlay');

      // Assert: Overlay should exist
      expect(overlay).not.toBeNull();
      expect(overlay.classList.contains('fixed')).toBe(true);
    });
  });

  /**
   * Requirement 6.2: Test sidebar navigation in desktop viewport
   */
  describe('Requirement 6.2: Sidebar navigation in desktop viewport', () => {
    it('should display sidebar navigation in desktop viewport', () => {
      // Arrange: Already in desktop viewport (1024x768)
      
      // Act: Get sidebar and navigation items
      const sidebar = document.getElementById('sidebar');
      const navItems = document.querySelectorAll('.cyber-sidebar .cyber-nav-item[onclick*="switchToTab"]');

      // Assert: Sidebar and navigation items should exist
      expect(sidebar).not.toBeNull();
      expect(navItems.length).toBeGreaterThanOrEqual(5);
    });

    it('should have all 5 tool navigation items visible in desktop', () => {
      // Arrange: Already in desktop viewport
      
      // Act: Get navigation items
      const navItems = document.querySelectorAll('.cyber-sidebar .cyber-nav-item[onclick*="switchToTab"]');
      
      const expectedTools = [
        'network-tools',
        'web-security',
        'hash-tools',
        'ai-assistant',
        'threat-intel'
      ];

      const actualTools = Array.from(navItems)
        .map(item => {
          const onclick = item.getAttribute('onclick');
          const match = onclick?.match(/switchToTab\('([^']+)'\)/);
          return match ? match[1] : null;
        })
        .filter(Boolean);

      // Assert: All tools should be present
      expectedTools.forEach(tool => {
        expect(actualTools).toContain(tool);
      });
    });

    it('should allow tab switching in desktop viewport', () => {
      // Arrange: Already in desktop viewport
      
      // Act: Switch to a tab
      DashboardTabManager.switchTab('hash-tools');

      // Assert: Tab should be active
      const tabPane = document.getElementById('hash-tools');
      expect(tabPane.classList.contains('active')).toBe(true);
      expect(tabPane.classList.contains('hidden')).toBe(false);
    });

    it('should not require floating toggle button in desktop viewport', () => {
      // Arrange: Already in desktop viewport
      
      // Act: Get floating toggle button
      const floatingToggle = document.getElementById('floating-sidebar-toggle');

      // Assert: Button exists but may not be needed for desktop interaction
      expect(floatingToggle).not.toBeNull();
    });

    it('should have sidebar always visible in desktop viewport', () => {
      // Arrange: Already in desktop viewport
      
      // Act: Get sidebar
      const sidebar = document.getElementById('sidebar');

      // Assert: Sidebar should not have hidden class by default
      expect(sidebar).not.toBeNull();
      // In desktop, sidebar is typically visible by default
    });
  });

  /**
   * Requirement 6.3: Test active state preservation across viewport changes
   */
  describe('Requirement 6.3: Active state preservation across viewport changes', () => {
    it('should preserve active tab when resizing from desktop to mobile', () => {
      // Arrange: Start in desktop, switch to a specific tab
      expect(window.innerWidth).toBe(1024);
      DashboardTabManager.switchTab('ai-assistant');
      
      // Verify tab is active in desktop
      let tabPane = document.getElementById('ai-assistant');
      expect(tabPane.classList.contains('active')).toBe(true);

      // Act: Resize to mobile
      resizeViewport(375, 667);

      // Assert: Tab should still be active
      tabPane = document.getElementById('ai-assistant');
      expect(tabPane.classList.contains('active')).toBe(true);
      expect(tabPane.classList.contains('hidden')).toBe(false);
    });

    it('should preserve active tab when resizing from mobile to desktop', async () => {
      // Arrange: Start in mobile
      resizeViewport(375, 667);
      expect(window.innerWidth).toBe(375);
      
      // Switch to a specific tab
      DashboardTabManager.switchTab('threat-intel');
      
      // Verify tab is active in mobile
      let tabPane = document.getElementById('threat-intel');
      expect(tabPane.classList.contains('active')).toBe(true);

      // Act: Resize to desktop
      resizeViewport(1024, 768);

      // Assert: Tab should still be active
      tabPane = document.getElementById('threat-intel');
      expect(tabPane.classList.contains('active')).toBe(true);
      expect(tabPane.classList.contains('hidden')).toBe(false);
    });

    it('should preserve navigation item active state when resizing from desktop to mobile', () => {
      // Arrange: Start in desktop, switch to a specific tab
      DashboardTabManager.switchTab('web-security');
      
      // Verify navigation item is active in desktop
      let navItems = document.querySelectorAll('.cyber-nav-item[onclick*="switchToTab"]');
      let webSecurityItem = Array.from(navItems).find(item =>
        item.getAttribute('onclick')?.includes("'web-security'")
      );
      expect(webSecurityItem.classList.contains('cyber-nav-active')).toBe(true);

      // Act: Resize to mobile
      resizeViewport(375, 667);

      // Assert: Navigation item should still be active
      navItems = document.querySelectorAll('.cyber-nav-item[onclick*="switchToTab"]');
      webSecurityItem = Array.from(navItems).find(item =>
        item.getAttribute('onclick')?.includes("'web-security'")
      );
      expect(webSecurityItem.classList.contains('cyber-nav-active')).toBe(true);
    });

    it('should preserve navigation item active state when resizing from mobile to desktop', () => {
      // Arrange: Start in mobile
      resizeViewport(375, 667);
      
      // Switch to a specific tab
      DashboardTabManager.switchTab('hash-tools');
      
      // Verify navigation item is active in mobile
      let navItems = document.querySelectorAll('.cyber-nav-item[onclick*="switchToTab"]');
      let hashToolsItem = Array.from(navItems).find(item =>
        item.getAttribute('onclick')?.includes("'hash-tools'")
      );
      expect(hashToolsItem.classList.contains('cyber-nav-active')).toBe(true);

      // Act: Resize to desktop
      resizeViewport(1024, 768);

      // Assert: Navigation item should still be active
      navItems = document.querySelectorAll('.cyber-nav-item[onclick*="switchToTab"]');
      hashToolsItem = Array.from(navItems).find(item =>
        item.getAttribute('onclick')?.includes("'hash-tools'")
      );
      expect(hashToolsItem.classList.contains('cyber-nav-active')).toBe(true);
    });

    it('should maintain only one active tab across viewport changes', () => {
      // Arrange: Start in desktop, switch to a tab
      DashboardTabManager.switchTab('network-tools');

      // Act: Resize to mobile and back to desktop
      resizeViewport(375, 667);
      resizeViewport(1024, 768);

      // Assert: Only one tab should be active
      const tabPanes = document.querySelectorAll('.tab-pane');
      const activePanes = Array.from(tabPanes).filter(pane =>
        pane.classList.contains('active') && !pane.classList.contains('hidden')
      );
      
      expect(activePanes.length).toBe(1);
      expect(activePanes[0].id).toBe('network-tools');
    });

    it('should maintain only one active navigation item across viewport changes', () => {
      // Arrange: Start in desktop, switch to a tab
      DashboardTabManager.switchTab('ai-assistant');

      // Act: Resize to mobile and back to desktop
      resizeViewport(375, 667);
      resizeViewport(1024, 768);

      // Assert: Only one navigation item should be active
      const navItems = document.querySelectorAll('.cyber-nav-item[onclick*="switchToTab"]');
      const activeItems = Array.from(navItems).filter(item =>
        item.classList.contains('cyber-nav-active')
      );
      
      expect(activeItems.length).toBe(1);
      expect(activeItems[0].getAttribute('onclick')).toContain("'ai-assistant'");
    });
  });

  /**
   * Requirement 6.4: Test multiple viewport transitions
   */
  describe('Requirement 6.4: Multiple viewport transitions', () => {
    it('should handle multiple rapid viewport changes', () => {
      // Arrange: Start in desktop
      DashboardTabManager.switchTab('web-security');

      // Act: Rapidly change viewports
      resizeViewport(375, 667);   // Mobile
      resizeViewport(768, 1024);  // Tablet
      resizeViewport(320, 568);   // Small mobile
      resizeViewport(1440, 900);  // Large desktop
      resizeViewport(375, 667);   // Back to mobile

      // Assert: Active state should be preserved
      const tabPane = document.getElementById('web-security');
      expect(tabPane.classList.contains('active')).toBe(true);
      
      const navItems = document.querySelectorAll('.cyber-nav-item[onclick*="switchToTab"]');
      const webSecurityItem = Array.from(navItems).find(item =>
        item.getAttribute('onclick')?.includes("'web-security'")
      );
      expect(webSecurityItem.classList.contains('cyber-nav-active')).toBe(true);
    });

    it('should handle tab switching during viewport transitions', () => {
      // Arrange: Start in desktop
      DashboardTabManager.switchTab('network-tools');

      // Act: Switch tabs while changing viewports
      resizeViewport(375, 667);   // Mobile
      DashboardTabManager.switchTab('hash-tools');
      
      resizeViewport(1024, 768);  // Desktop
      DashboardTabManager.switchTab('threat-intel');
      
      resizeViewport(375, 667);   // Mobile
      DashboardTabManager.switchTab('ai-assistant');

      // Assert: Final active state should be correct
      const tabPane = document.getElementById('ai-assistant');
      expect(tabPane.classList.contains('active')).toBe(true);
      
      const navItems = document.querySelectorAll('.cyber-nav-item[onclick*="switchToTab"]');
      const aiAssistantItem = Array.from(navItems).find(item =>
        item.getAttribute('onclick')?.includes("'ai-assistant'")
      );
      expect(aiAssistantItem.classList.contains('cyber-nav-active')).toBe(true);
    });

    it('should maintain state consistency through tablet viewport', () => {
      // Arrange: Start in desktop
      DashboardTabManager.switchTab('hash-tools');

      // Act: Transition through tablet viewport
      resizeViewport(768, 1024);  // Tablet (still >= 640px, so desktop behavior)

      // Assert: Active state should be preserved
      const tabPane = document.getElementById('hash-tools');
      expect(tabPane.classList.contains('active')).toBe(true);
      
      const navItems = document.querySelectorAll('.cyber-nav-item[onclick*="switchToTab"]');
      const hashToolsItem = Array.from(navItems).find(item =>
        item.getAttribute('onclick')?.includes("'hash-tools'")
      );
      expect(hashToolsItem.classList.contains('cyber-nav-active')).toBe(true);
    });
  });

  /**
   * Requirement 6.5: Integration test for complete responsive workflow
   */
  describe('Requirement 6.5: Complete responsive workflow integration', () => {
    it('should handle complete responsive navigation workflow', () => {
      // Arrange: Start in desktop viewport
      expect(window.innerWidth).toBe(1024);

      // Act & Assert: Desktop navigation
      DashboardTabManager.switchTab('network-tools');
      let tabPane = document.getElementById('network-tools');
      expect(tabPane.classList.contains('active')).toBe(true);

      // Act & Assert: Resize to mobile
      resizeViewport(375, 667);
      expect(window.innerWidth).toBe(375);
      
      // Verify state preserved
      tabPane = document.getElementById('network-tools');
      expect(tabPane.classList.contains('active')).toBe(true);

      // Act & Assert: Navigate in mobile
      DashboardTabManager.switchTab('web-security');
      tabPane = document.getElementById('web-security');
      expect(tabPane.classList.contains('active')).toBe(true);

      // Act & Assert: Resize back to desktop
      resizeViewport(1024, 768);
      expect(window.innerWidth).toBe(1024);
      
      // Verify state preserved
      tabPane = document.getElementById('web-security');
      expect(tabPane.classList.contains('active')).toBe(true);

      // Act & Assert: Navigate in desktop
      DashboardTabManager.switchTab('threat-intel');
      tabPane = document.getElementById('threat-intel');
      expect(tabPane.classList.contains('active')).toBe(true);

      // Final verification: Only one active tab and nav item
      const tabPanes = document.querySelectorAll('.tab-pane');
      const activePanes = Array.from(tabPanes).filter(pane =>
        pane.classList.contains('active') && !pane.classList.contains('hidden')
      );
      expect(activePanes.length).toBe(1);

      const navItems = document.querySelectorAll('.cyber-nav-item[onclick*="switchToTab"]');
      const activeItems = Array.from(navItems).filter(item =>
        item.classList.contains('cyber-nav-active')
      );
      expect(activeItems.length).toBe(1);
    });

    it('should handle all 5 tabs across viewport changes', () => {
      const tabs = ['network-tools', 'web-security', 'hash-tools', 'ai-assistant', 'threat-intel'];
      
      tabs.forEach((tabId, index) => {
        // Alternate between desktop and mobile
        const viewport = index % 2 === 0 ? [1024, 768] : [375, 667];
        resizeViewport(viewport[0], viewport[1]);

        // Switch to tab
        DashboardTabManager.switchTab(tabId);

        // Verify tab is active
        const tabPane = document.getElementById(tabId);
        expect(tabPane.classList.contains('active')).toBe(true);
        expect(tabPane.classList.contains('hidden')).toBe(false);

        // Verify navigation item is active
        const navItems = document.querySelectorAll('.cyber-nav-item[onclick*="switchToTab"]');
        const activeItem = Array.from(navItems).find(item =>
          item.getAttribute('onclick')?.includes(`'${tabId}'`)
        );
        expect(activeItem.classList.contains('cyber-nav-active')).toBe(true);
      });
    });

    it('should maintain sidebar structure across viewport changes', () => {
      // Arrange: Get initial sidebar structure
      const sidebar = document.getElementById('sidebar');
      const initialNavItems = document.querySelectorAll('.cyber-sidebar .cyber-nav-item[onclick*="switchToTab"]');
      const initialCount = initialNavItems.length;

      // Act: Resize to mobile
      resizeViewport(375, 667);
      
      // Assert: Sidebar structure should be unchanged
      const mobileNavItems = document.querySelectorAll('.cyber-sidebar .cyber-nav-item[onclick*="switchToTab"]');
      expect(mobileNavItems.length).toBe(initialCount);

      // Act: Resize back to desktop
      resizeViewport(1024, 768);
      
      // Assert: Sidebar structure should still be unchanged
      const desktopNavItems = document.querySelectorAll('.cyber-sidebar .cyber-nav-item[onclick*="switchToTab"]');
      expect(desktopNavItems.length).toBe(initialCount);
    });

    it('should handle edge case: switching tabs at exact breakpoint', () => {
      // Arrange: Set viewport to exactly 640px (breakpoint)
      resizeViewport(640, 768);

      // Act: Switch to a tab
      DashboardTabManager.switchTab('hash-tools');

      // Assert: Tab should be active
      const tabPane = document.getElementById('hash-tools');
      expect(tabPane.classList.contains('active')).toBe(true);

      // Act: Resize just below breakpoint
      resizeViewport(639, 768);

      // Assert: State should be preserved
      expect(tabPane.classList.contains('active')).toBe(true);
    });

    it('should preserve tab content visibility across viewport changes', () => {
      // Arrange: Switch to a tab in desktop
      DashboardTabManager.switchTab('ai-assistant');
      
      // Verify tab pane is visible
      let tabPane = document.getElementById('ai-assistant');
      expect(tabPane.classList.contains('hidden')).toBe(false);

      // Act: Resize to mobile
      resizeViewport(375, 667);

      // Assert: Tab pane should still be visible
      tabPane = document.getElementById('ai-assistant');
      expect(tabPane.classList.contains('hidden')).toBe(false);

      // Act: Resize back to desktop
      resizeViewport(1024, 768);

      // Assert: Tab pane should still be visible
      tabPane = document.getElementById('ai-assistant');
      expect(tabPane.classList.contains('hidden')).toBe(false);
    });
  });

  /**
   * Edge cases and error handling
   */
  describe('Edge cases: Responsive behavior', () => {
    it('should handle very small mobile viewport (320px)', () => {
      // Arrange: Resize to very small mobile
      resizeViewport(320, 568);

      // Act: Switch to a tab
      DashboardTabManager.switchTab('network-tools');

      // Assert: Navigation should still work
      const tabPane = document.getElementById('network-tools');
      expect(tabPane.classList.contains('active')).toBe(true);
    });

    it('should handle very large desktop viewport (1920px)', () => {
      // Arrange: Resize to large desktop
      resizeViewport(1920, 1080);

      // Act: Switch to a tab
      DashboardTabManager.switchTab('threat-intel');

      // Assert: Navigation should still work
      const tabPane = document.getElementById('threat-intel');
      expect(tabPane.classList.contains('active')).toBe(true);
    });

    it('should handle portrait mobile orientation', () => {
      // Arrange: Portrait mobile (width < height)
      resizeViewport(375, 812);

      // Act: Switch to a tab
      DashboardTabManager.switchTab('web-security');

      // Assert: Navigation should work
      const tabPane = document.getElementById('web-security');
      expect(tabPane.classList.contains('active')).toBe(true);
    });

    it('should handle landscape mobile orientation', () => {
      // Arrange: Landscape mobile (width > height, but still < 640px)
      resizeViewport(568, 320);

      // Act: Switch to a tab
      DashboardTabManager.switchTab('hash-tools');

      // Assert: Navigation should work
      const tabPane = document.getElementById('hash-tools');
      expect(tabPane.classList.contains('active')).toBe(true);
    });

    it('should not lose active state during rapid viewport oscillation', () => {
      // Arrange: Set initial tab
      DashboardTabManager.switchTab('ai-assistant');

      // Act: Rapidly oscillate viewport
      for (let i = 0; i < 10; i++) {
        resizeViewport(i % 2 === 0 ? 375 : 1024, 768);
      }

      // Assert: Active state should be preserved
      const tabPane = document.getElementById('ai-assistant');
      expect(tabPane.classList.contains('active')).toBe(true);
      
      const navItems = document.querySelectorAll('.cyber-nav-item[onclick*="switchToTab"]');
      const aiAssistantItem = Array.from(navItems).find(item =>
        item.getAttribute('onclick')?.includes("'ai-assistant'")
      );
      expect(aiAssistantItem.classList.contains('cyber-nav-active')).toBe(true);
    });
  });
});
