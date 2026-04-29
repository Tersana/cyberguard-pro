/**
 * Tests for Dashboard Tab Manager - updateTabButtons method
 * Validates sidebar navigation active state management
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { JSDOM } from 'jsdom';

describe('DashboardTabManager - updateTabButtons', () => {
  let dom;
  let document;
  let DashboardTabManager;

  beforeEach(async () => {
    // Create a fresh DOM for each test
    dom = new JSDOM(`
      <!DOCTYPE html>
      <html>
        <body>
          <!-- Horizontal tab buttons (legacy) -->
          <button class="tab-button" data-tab="network-tools">Network</button>
          <button class="tab-button active" data-tab="web-security">Web Security</button>
          <button class="tab-button" data-tab="hash-tools">Hash Tools</button>
          
          <!-- Sidebar navigation items -->
          <nav>
            <a href="#" class="cyber-nav-item" onclick="switchToTab('network-tools'); return false;">
              Network Analysis
            </a>
            <a href="#" class="cyber-nav-item cyber-nav-active" onclick="switchToTab('web-security'); return false;">
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
          <div id="network-tools" class="tab-pane hidden"></div>
          <div id="web-security" class="tab-pane active"></div>
          <div id="hash-tools" class="tab-pane hidden"></div>
          <div id="ai-assistant" class="tab-pane hidden"></div>
          <div id="threat-intel" class="tab-pane hidden"></div>
        </body>
      </html>
    `, {
      url: 'http://localhost',
      runScripts: 'dangerously',
      resources: 'usable'
    });

    document = dom.window.document;
    global.document = document;
    global.window = dom.window;

    // Import the module
    const module = await import('./dashboard-tab-manager.js');
    DashboardTabManager = module.default || module.DashboardTabManager;
  });

  describe('Sidebar Navigation Active State', () => {
    it('should add cyber-nav-active class to matching sidebar nav item', () => {
      // Act
      DashboardTabManager.updateTabButtons('network-tools');

      // Assert
      const navItems = document.querySelectorAll('.cyber-nav-item');
      const networkItem = Array.from(navItems).find(item => 
        item.getAttribute('onclick')?.includes("'network-tools'")
      );
      
      expect(networkItem.classList.contains('cyber-nav-active')).toBe(true);
    });

    it('should remove cyber-nav-active class from non-matching items', () => {
      // Arrange: web-security is initially active
      const webSecurityItem = Array.from(document.querySelectorAll('.cyber-nav-item')).find(item =>
        item.getAttribute('onclick')?.includes("'web-security'")
      );
      expect(webSecurityItem.classList.contains('cyber-nav-active')).toBe(true);

      // Act: Switch to network-tools
      DashboardTabManager.updateTabButtons('network-tools');

      // Assert: web-security should no longer be active
      expect(webSecurityItem.classList.contains('cyber-nav-active')).toBe(false);
    });

    it('should handle all sidebar navigation items correctly', () => {
      // Act
      DashboardTabManager.updateTabButtons('threat-intel');

      // Assert
      const navItems = document.querySelectorAll('.cyber-nav-item');
      navItems.forEach(item => {
        const onclick = item.getAttribute('onclick');
        if (onclick?.includes("'threat-intel'")) {
          expect(item.classList.contains('cyber-nav-active')).toBe(true);
        } else {
          expect(item.classList.contains('cyber-nav-active')).toBe(false);
        }
      });
    });

    it('should extract tab ID from onclick attribute using regex', () => {
      // Arrange
      const testCases = [
        { onclick: "switchToTab('network-tools'); return false;", expected: 'network-tools' },
        { onclick: "switchToTab('web-security'); return false;", expected: 'web-security' },
        { onclick: "switchToTab('hash-tools'); return false;", expected: 'hash-tools' },
        { onclick: "switchToTab('ai-assistant'); return false;", expected: 'ai-assistant' },
        { onclick: "switchToTab('threat-intel'); return false;", expected: 'threat-intel' }
      ];

      testCases.forEach(({ onclick, expected }) => {
        // Act
        const match = onclick.match(/switchToTab\('([^']+)'\)/);
        
        // Assert
        expect(match).not.toBeNull();
        expect(match[1]).toBe(expected);
      });
    });

    it('should handle items without onclick attribute gracefully', () => {
      // Arrange: Add a nav item without onclick
      const navItem = document.createElement('a');
      navItem.className = 'cyber-nav-item';
      navItem.textContent = 'No onclick';
      document.querySelector('nav').appendChild(navItem);

      // Act & Assert: Should not throw error
      expect(() => {
        DashboardTabManager.updateTabButtons('network-tools');
      }).not.toThrow();
    });

    it('should handle malformed onclick attribute gracefully', () => {
      // Arrange: Add a nav item with malformed onclick
      const navItem = document.createElement('a');
      navItem.className = 'cyber-nav-item';
      navItem.setAttribute('onclick', 'switchToTab(network-tools)'); // Missing quotes
      document.querySelector('nav').appendChild(navItem);

      // Act & Assert: Should not throw error
      expect(() => {
        DashboardTabManager.updateTabButtons('network-tools');
      }).not.toThrow();
      
      // Malformed item should not get active class
      expect(navItem.classList.contains('cyber-nav-active')).toBe(false);
    });
  });

  describe('Backward Compatibility - Horizontal Tab Buttons', () => {
    it('should still update horizontal tab buttons with active class', () => {
      // Act
      DashboardTabManager.updateTabButtons('network-tools');

      // Assert
      const tabButtons = document.querySelectorAll('.tab-button');
      tabButtons.forEach(button => {
        if (button.dataset.tab === 'network-tools') {
          expect(button.classList.contains('active')).toBe(true);
        } else {
          expect(button.classList.contains('active')).toBe(false);
        }
      });
    });

    it('should handle both horizontal buttons and sidebar nav items simultaneously', () => {
      // Act
      DashboardTabManager.updateTabButtons('hash-tools');

      // Assert horizontal buttons
      const hashButton = document.querySelector('.tab-button[data-tab="hash-tools"]');
      expect(hashButton.classList.contains('active')).toBe(true);

      // Assert sidebar nav items
      const navItems = document.querySelectorAll('.cyber-nav-item');
      const hashNavItem = Array.from(navItems).find(item =>
        item.getAttribute('onclick')?.includes("'hash-tools'")
      );
      expect(hashNavItem.classList.contains('cyber-nav-active')).toBe(true);
    });

    it('should work when no horizontal tab buttons exist', () => {
      // Arrange: Remove all horizontal tab buttons
      document.querySelectorAll('.tab-button').forEach(btn => btn.remove());

      // Act & Assert: Should not throw error
      expect(() => {
        DashboardTabManager.updateTabButtons('network-tools');
      }).not.toThrow();

      // Sidebar nav should still work
      const navItems = document.querySelectorAll('.cyber-nav-item');
      const networkItem = Array.from(navItems).find(item =>
        item.getAttribute('onclick')?.includes("'network-tools'")
      );
      expect(networkItem.classList.contains('cyber-nav-active')).toBe(true);
    });
  });

  describe('Edge Cases', () => {
    it('should handle switching to same tab multiple times', () => {
      // Act
      DashboardTabManager.updateTabButtons('network-tools');
      DashboardTabManager.updateTabButtons('network-tools');
      DashboardTabManager.updateTabButtons('network-tools');

      // Assert: Should still have correct active state
      const navItems = document.querySelectorAll('.cyber-nav-item');
      const networkItem = Array.from(navItems).find(item =>
        item.getAttribute('onclick')?.includes("'network-tools'")
      );
      expect(networkItem.classList.contains('cyber-nav-active')).toBe(true);
    });

    it('should handle rapid tab switching', () => {
      // Act: Switch between tabs rapidly
      DashboardTabManager.updateTabButtons('network-tools');
      DashboardTabManager.updateTabButtons('web-security');
      DashboardTabManager.updateTabButtons('hash-tools');
      DashboardTabManager.updateTabButtons('ai-assistant');
      DashboardTabManager.updateTabButtons('threat-intel');

      // Assert: Final state should be correct
      const navItems = document.querySelectorAll('.cyber-nav-item');
      navItems.forEach(item => {
        const onclick = item.getAttribute('onclick');
        if (onclick?.includes("'threat-intel'")) {
          expect(item.classList.contains('cyber-nav-active')).toBe(true);
        } else {
          expect(item.classList.contains('cyber-nav-active')).toBe(false);
        }
      });
    });

    it('should handle non-existent tab ID', () => {
      // Act & Assert: Should not throw error
      expect(() => {
        DashboardTabManager.updateTabButtons('non-existent-tab');
      }).not.toThrow();

      // No items should have active class
      const navItems = document.querySelectorAll('.cyber-nav-item');
      navItems.forEach(item => {
        expect(item.classList.contains('cyber-nav-active')).toBe(false);
      });
    });
  });
});
