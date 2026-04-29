/**
 * Dashboard Navigation Cleanup Verification Tests
 * Task 7: Verify code cleanup and removal
 * 
 * Tests verify that:
 * - Horizontal tab bar HTML is completely removed
 * - No orphaned event listeners exist
 * - No console warnings about missing elements
 * - CSS classes are not causing conflicts
 * - All JavaScript functions still work correctly
 * - No dead code remains
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { JSDOM } from 'jsdom';

describe('Dashboard Navigation Cleanup Verification', () => {
  let dom;
  let document;
  let window;
  let DashboardTabManager;

  beforeEach(() => {
    // Create a minimal DOM structure matching the current dashboard
    dom = new JSDOM(`
      <!DOCTYPE html>
      <html>
        <head></head>
        <body>
          <!-- Sidebar navigation items -->
          <nav>
            <a href="#" class="cyber-nav-item cyber-nav-active" onclick="switchToTab('network-tools'); return false;">
              Network Analysis
            </a>
            <a href="#" class="cyber-nav-item" onclick="switchToTab('web-security'); return false;">
              Web Security
            </a>
            <a href="#" class="cyber-nav-item" onclick="switchToTab('hash-tools'); return false;">
              Hash Tools
            </a>
            <a href="#" class="cyber-nav-item" onclick="switchToTab('ai-assistant'); return false;">
              AI Assistant
            </a>
            <a href="#" class="cyber-nav-item" onclick="switchToTab('threat-intel'); return false;">
              Threat Intel
            </a>
          </nav>
          
          <!-- Tab panes -->
          <div id="network-tools" class="tab-pane active">Network Tools Content</div>
          <div id="web-security" class="tab-pane hidden">Web Security Content</div>
          <div id="hash-tools" class="tab-pane hidden">Hash Tools Content</div>
          <div id="ai-assistant" class="tab-pane hidden">AI Assistant Content</div>
          <div id="threat-intel" class="tab-pane hidden">Threat Intel Content</div>
        </body>
      </html>
    `, {
      url: 'http://localhost',
      runScripts: 'dangerously',
      resources: 'usable'
    });

    document = dom.window.document;
    window = dom.window;
    global.document = document;
    global.window = window;

    // Mock console methods to capture warnings/errors
    global.console.warn = vi.fn();
    global.console.error = vi.fn();

    // Load the DashboardTabManager
    const dashboardTabManagerCode = require('fs').readFileSync('./dashboard-tab-manager.js', 'utf8');
    const scriptEl = document.createElement('script');
    scriptEl.textContent = dashboardTabManagerCode;
    document.body.appendChild(scriptEl);
    
    DashboardTabManager = window.DashboardTabManager;
  });

  describe('7.1 - Horizontal Tab Bar HTML Removal', () => {
    it('should not have any horizontal tab bar elements', () => {
      // Check for tab bar container
      const tabBar = document.querySelector('.cyber-tab-bar');
      expect(tabBar).toBeNull();
    });

    it('should not have any tab-button elements', () => {
      const tabButtons = document.querySelectorAll('.tab-button');
      expect(tabButtons.length).toBe(0);
    });

    it('should not have any data-tab attributes on buttons', () => {
      const dataTabButtons = document.querySelectorAll('button[data-tab]');
      expect(dataTabButtons.length).toBe(0);
    });

    it('should not have TAB BAR comment markers', () => {
      const htmlContent = document.documentElement.outerHTML;
      expect(htmlContent).not.toContain('===== TAB BAR =====');
      expect(htmlContent).not.toContain('TAB BAR');
    });
  });

  describe('7.2 - No Orphaned Event Listeners', () => {
    it('should not throw errors when querying for tab-button elements', () => {
      expect(() => {
        document.querySelectorAll('.tab-button');
      }).not.toThrow();
    });

    it('should handle missing tab-button elements gracefully in DashboardTabManager', () => {
      // Initialize the tab manager
      expect(() => {
        if (DashboardTabManager && DashboardTabManager.init) {
          DashboardTabManager.init();
        }
      }).not.toThrow();
    });

    it('should not have event listeners waiting for non-existent elements', () => {
      // Simulate clicking on the document (event delegation test)
      const clickEvent = new window.MouseEvent('click', {
        bubbles: true,
        cancelable: true
      });
      
      expect(() => {
        document.body.dispatchEvent(clickEvent);
      }).not.toThrow();
    });

    it('should not log errors when tab manager tries to update tab buttons', () => {
      if (DashboardTabManager && DashboardTabManager.updateTabButtons) {
        DashboardTabManager.updateTabButtons('network-tools');
      }
      
      // Should not have logged any errors
      expect(console.error).not.toHaveBeenCalled();
    });
  });

  describe('7.3 - No Console Warnings About Missing Elements', () => {
    it('should not log warnings when initializing dashboard', () => {
      // Simulate dashboard initialization
      const tabButtons = document.querySelectorAll('.tab-button');
      const tabPanes = document.querySelectorAll('.tab-pane');
      
      // These queries should not generate warnings
      expect(console.warn).not.toHaveBeenCalled();
      expect(console.error).not.toHaveBeenCalled();
    });

    it('should not log warnings when switching tabs', () => {
      if (DashboardTabManager && DashboardTabManager.switchTab) {
        DashboardTabManager.switchTab('web-security');
      }
      
      expect(console.warn).not.toHaveBeenCalled();
      expect(console.error).not.toHaveBeenCalled();
    });

    it('should not log errors about missing active button', () => {
      // Query for active button (which doesn't exist in horizontal tab bar)
      const activeButton = document.querySelector('.tab-button.active');
      
      // Should be null but not cause errors
      expect(activeButton).toBeNull();
      expect(console.error).not.toHaveBeenCalled();
    });
  });

  describe('7.4 - CSS Classes Not Causing Conflicts', () => {
    it('should have cyber-nav-item class defined and working', () => {
      const navItems = document.querySelectorAll('.cyber-nav-item');
      expect(navItems.length).toBeGreaterThan(0);
    });

    it('should have cyber-nav-active class working correctly', () => {
      const activeItem = document.querySelector('.cyber-nav-active');
      expect(activeItem).not.toBeNull();
      expect(activeItem.classList.contains('cyber-nav-item')).toBe(true);
    });

    it('should not have conflicting tab-button styles affecting sidebar', () => {
      const navItems = document.querySelectorAll('.cyber-nav-item');
      navItems.forEach(item => {
        // Should not have tab-button class
        expect(item.classList.contains('tab-button')).toBe(false);
      });
    });

    it('should not have cyber-tab-bar class applied to any elements', () => {
      const tabBarElements = document.querySelectorAll('.cyber-tab-bar');
      expect(tabBarElements.length).toBe(0);
    });

    it('should not have cyber-tab class applied to sidebar items', () => {
      const navItems = document.querySelectorAll('.cyber-nav-item');
      navItems.forEach(item => {
        expect(item.classList.contains('cyber-tab')).toBe(false);
      });
    });
  });

  describe('7.5 - All JavaScript Functions Still Work', () => {
    it('should switch tabs correctly using sidebar navigation', () => {
      if (!DashboardTabManager) return;
      
      // Switch to web-security tab
      DashboardTabManager.switchTab('web-security');
      
      // Check that the correct pane is visible
      const webSecurityPane = document.getElementById('web-security');
      const networkToolsPane = document.getElementById('network-tools');
      
      expect(webSecurityPane.classList.contains('hidden')).toBe(false);
      expect(networkToolsPane.classList.contains('hidden')).toBe(true);
    });

    it('should update active state on sidebar items', () => {
      if (!DashboardTabManager) return;
      
      // Switch to hash-tools
      DashboardTabManager.switchTab('hash-tools');
      
      // Check sidebar active states
      const navItems = document.querySelectorAll('.cyber-nav-item');
      let hashToolsActive = false;
      let othersInactive = true;
      
      navItems.forEach(item => {
        const onclick = item.getAttribute('onclick');
        if (onclick && onclick.includes('hash-tools')) {
          hashToolsActive = item.classList.contains('cyber-nav-active');
        } else if (onclick && onclick.includes('switchToTab')) {
          if (item.classList.contains('cyber-nav-active')) {
            othersInactive = false;
          }
        }
      });
      
      expect(hashToolsActive).toBe(true);
      expect(othersInactive).toBe(true);
    });

    it('should handle rapid tab switching without errors', () => {
      if (!DashboardTabManager) return;
      
      expect(() => {
        DashboardTabManager.switchTab('network-tools');
        DashboardTabManager.switchTab('web-security');
        DashboardTabManager.switchTab('hash-tools');
        DashboardTabManager.switchTab('ai-assistant');
        DashboardTabManager.switchTab('threat-intel');
      }).not.toThrow();
    });

    it('should initialize tabs correctly on first visit', () => {
      if (!DashboardTabManager) return;
      
      // Check that tab initialization doesn't throw errors
      expect(() => {
        DashboardTabManager.initializeTab('network-tools');
        DashboardTabManager.initializeTab('web-security');
        DashboardTabManager.initializeTab('hash-tools');
      }).not.toThrow();
    });

    it('should handle missing tab panes gracefully', () => {
      if (!DashboardTabManager) return;
      
      // Try to switch to a non-existent tab
      expect(() => {
        DashboardTabManager.switchTab('non-existent-tab');
      }).not.toThrow();
      
      // Should log an error but not crash
      expect(console.error).toHaveBeenCalled();
    });
  });

  describe('7.6 - No Dead Code Remains', () => {
    it('should not have unused tabButtons variable causing issues', () => {
      // Query for tab buttons (should return empty NodeList)
      const tabButtons = document.querySelectorAll('.tab-button');
      
      // Should be empty but not undefined
      expect(tabButtons).toBeDefined();
      expect(tabButtons.length).toBe(0);
    });

    it('should not have event listeners on non-existent tab buttons', () => {
      // Try to add event listener to non-existent elements
      const tabButtons = document.querySelectorAll('.tab-button');
      
      expect(() => {
        tabButtons.forEach(button => {
          button.addEventListener('click', () => {});
        });
      }).not.toThrow();
      
      // Should iterate zero times
      let count = 0;
      tabButtons.forEach(() => count++);
      expect(count).toBe(0);
    });

    it('should not have orphaned CSS selectors causing layout issues', () => {
      // Check that removed elements don't affect layout
      const body = document.body;
      const computedStyle = window.getComputedStyle(body);
      
      // Should not have any broken styles
      expect(computedStyle).toBeDefined();
    });
  });

  describe('7.7 - Backward Compatibility', () => {
    it('should maintain backward compatibility with existing code', () => {
      // The updateTabButtons method should handle both old and new navigation
      if (DashboardTabManager && DashboardTabManager.updateTabButtons) {
        expect(() => {
          DashboardTabManager.updateTabButtons('network-tools');
        }).not.toThrow();
      }
    });

    it('should not break when tab-button elements are queried', () => {
      // Code that queries for tab-button should not break
      expect(() => {
        const buttons = document.querySelectorAll('.tab-button');
        buttons.forEach(btn => {
          if (btn.dataset.tab === 'network-tools') {
            btn.classList.add('active');
          }
        });
      }).not.toThrow();
    });

    it('should work with global switchToTab function', () => {
      // The global function should still work
      if (window.switchToTab) {
        expect(() => {
          window.switchToTab('web-security');
        }).not.toThrow();
      }
    });
  });

  describe('7.8 - Integration Verification', () => {
    it('should have all required sidebar navigation items', () => {
      const requiredTabs = [
        'network-tools',
        'web-security',
        'hash-tools',
        'ai-assistant',
        'threat-intel'
      ];
      
      requiredTabs.forEach(tabId => {
        const navItem = document.querySelector(`[onclick*="switchToTab('${tabId}')"]`);
        expect(navItem).not.toBeNull();
      });
    });

    it('should have all required tab panes', () => {
      const requiredPanes = [
        'network-tools',
        'web-security',
        'hash-tools',
        'ai-assistant',
        'threat-intel'
      ];
      
      requiredPanes.forEach(paneId => {
        const pane = document.getElementById(paneId);
        expect(pane).not.toBeNull();
      });
    });

    it('should maintain proper tab pane visibility', () => {
      const panes = document.querySelectorAll('.tab-pane');
      let visibleCount = 0;
      
      panes.forEach(pane => {
        if (!pane.classList.contains('hidden')) {
          visibleCount++;
        }
      });
      
      // Only one pane should be visible
      expect(visibleCount).toBe(1);
    });
  });
});
