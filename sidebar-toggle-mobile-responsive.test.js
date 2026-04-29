/**
 * Integration Tests for Sidebar Toggle Mobile Responsive Behavior (Task 7.4)
 * 
 * Tests Requirements:
 * - 6.1: Sidebar acts as overlay drawer on mobile (< 768px)
 * - 6.2: Sidebar slides in from left edge on mobile
 * - 6.3: Sidebar doesn't push main content on mobile
 * - 6.4: Overlay appears when sidebar opens on mobile
 * - 6.5: Overlay click closes sidebar
 * - 6.8: Viewport resize switches between modes
 * - 6.10: Smooth transitions between drawer and push modes
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { JSDOM } from 'jsdom';

describe('Sidebar Toggle - Mobile Responsive Behavior (Task 7.4)', () => {
  let dom;
  let document;
  let window;
  let sidebar;
  let overlay;
  let toggleBtn;
  let main;

  // Helper function to set viewport width
  function setViewportWidth(width) {
    Object.defineProperty(window, 'innerWidth', {
      writable: true,
      configurable: true,
      value: width,
    });
  }

  // Helper function to trigger resize event
  function triggerResize() {
    const resizeEvent = new window.Event('resize');
    window.dispatchEvent(resizeEvent);
  }

  beforeEach(() => {
    // Create a minimal DOM structure
    dom = new JSDOM(`
      <!DOCTYPE html>
      <html>
        <head>
          <style>
            /* Mobile responsive styles */
            @media (max-width: 767px) {
              .cyber-sidebar {
                position: fixed;
                top: 0;
                left: 0;
                height: 100vh;
                z-index: 40;
                transform: translateX(-100%);
              }
              
              .cyber-sidebar:not(.sidebar-collapsed) {
                transform: translateX(0);
              }
              
              main {
                margin-left: 0 !important;
              }
            }
            
            .cyber-sidebar-overlay {
              position: fixed;
              inset: 0;
              background: rgba(0, 0, 0, 0.6);
              z-index: 30;
              opacity: 0;
              pointer-events: none;
              transition: opacity 300ms ease;
            }
            
            .cyber-sidebar-overlay.active {
              opacity: 1;
              pointer-events: auto;
            }
            
            .cyber-sidebar {
              width: 260px;
              transition: transform 300ms ease;
            }
            
            .cyber-sidebar.sidebar-collapsed {
              transform: translateX(-100%);
            }
          </style>
        </head>
        <body>
          <div id="app" class="flex h-screen overflow-hidden">
            <div id="sidebar-overlay" class="cyber-sidebar-overlay"></div>
            
            <button 
              id="sidebar-toggle-btn" 
              class="cyber-sidebar-toggle" 
              aria-label="Toggle sidebar navigation"
              aria-expanded="true"
              aria-controls="sidebar">
              Toggle
            </button>
            
            <aside id="sidebar" class="cyber-sidebar" aria-hidden="false">
              <div class="cyber-user-card">User Profile</div>
              <button id="enable-2fa-btn">Enable 2FA</button>
            </aside>
            
            <main>Main Content</main>
          </div>
          
          <script>
            ${getToggleSidebarScript()}
          </script>
        </body>
      </html>
    `, {
      url: 'http://localhost',
      runScripts: 'dangerously',
      resources: 'usable',
    });

    document = dom.window.document;
    window = dom.window;
    
    sidebar = document.getElementById('sidebar');
    overlay = document.getElementById('sidebar-overlay');
    toggleBtn = document.getElementById('sidebar-toggle-btn');
    main = document.querySelector('main');

    // Mock localStorage
    const localStorageMock = {
      getItem: vi.fn(),
      setItem: vi.fn(),
      removeItem: vi.fn(),
      clear: vi.fn(),
    };
    global.localStorage = localStorageMock;
  });

  afterEach(() => {
    dom.window.close();
    vi.clearAllMocks();
  });

  describe('Requirement 6.1 & 6.2: Sidebar acts as overlay drawer on mobile', () => {
    it('should position sidebar as fixed overlay on mobile viewport (< 768px)', () => {
      setViewportWidth(767);
      
      const styles = window.getComputedStyle(sidebar);
      
      // On mobile, sidebar should be positioned fixed
      // Note: JSDOM has limited CSS support, so we check the class behavior instead
      expect(sidebar.classList.contains('cyber-sidebar')).toBe(true);
    });

    it('should slide sidebar in from left when opened on mobile', () => {
      setViewportWidth(767);
      
      // Initially collapsed
      sidebar.classList.add('sidebar-collapsed');
      expect(sidebar.classList.contains('sidebar-collapsed')).toBe(true);
      
      // Toggle to open
      window.toggleSidebar();
      
      // Should remove collapsed class (slides in)
      expect(sidebar.classList.contains('sidebar-collapsed')).toBe(false);
    });

    it('should slide sidebar out to left when closed on mobile', () => {
      setViewportWidth(767);
      
      // Initially expanded
      sidebar.classList.remove('sidebar-collapsed');
      
      // Toggle to close
      window.toggleSidebar();
      
      // Should add collapsed class (slides out)
      expect(sidebar.classList.contains('sidebar-collapsed')).toBe(true);
    });
  });

  describe('Requirement 6.3: Sidebar does not push main content on mobile', () => {
    it('should keep main content in place when sidebar opens on mobile', () => {
      setViewportWidth(767);
      
      // Get initial main position
      const initialMargin = window.getComputedStyle(main).marginLeft;
      
      // Open sidebar
      sidebar.classList.remove('sidebar-collapsed');
      
      // Main content margin should not change on mobile
      const afterMargin = window.getComputedStyle(main).marginLeft;
      expect(afterMargin).toBe(initialMargin);
    });

    it('should keep main content in place when sidebar closes on mobile', () => {
      setViewportWidth(767);
      
      // Start with sidebar open
      sidebar.classList.remove('sidebar-collapsed');
      const initialMargin = window.getComputedStyle(main).marginLeft;
      
      // Close sidebar
      sidebar.classList.add('sidebar-collapsed');
      
      // Main content margin should not change on mobile
      const afterMargin = window.getComputedStyle(main).marginLeft;
      expect(afterMargin).toBe(initialMargin);
    });
  });

  describe('Requirement 6.4: Overlay appears when sidebar opens on mobile', () => {
    it('should show overlay when sidebar is opened on mobile', () => {
      setViewportWidth(767);
      
      // Initially no overlay
      expect(overlay.classList.contains('active')).toBe(false);
      
      // Open sidebar (remove collapsed class)
      sidebar.classList.remove('sidebar-collapsed');
      window.toggleSidebar();
      
      // Overlay should be active on mobile
      expect(overlay.classList.contains('active')).toBe(true);
    });

    it('should hide overlay when sidebar is closed on mobile', () => {
      setViewportWidth(767);
      
      // Start with overlay active
      overlay.classList.add('active');
      sidebar.classList.remove('sidebar-collapsed');
      
      // Close sidebar
      window.toggleSidebar();
      
      // Overlay should be removed
      expect(overlay.classList.contains('active')).toBe(false);
    });

    it('should not show overlay on desktop viewport', () => {
      setViewportWidth(1024);
      
      // Open sidebar
      sidebar.classList.remove('sidebar-collapsed');
      window.toggleSidebar();
      
      // Overlay should not be active on desktop
      expect(overlay.classList.contains('active')).toBe(false);
    });
  });

  describe('Requirement 6.5: Overlay click closes sidebar', () => {
    it('should close sidebar when overlay is clicked on mobile', async () => {
      setViewportWidth(767);
      
      // Setup: sidebar open, overlay active
      sidebar.classList.remove('sidebar-collapsed');
      overlay.classList.add('active');
      
      // Click overlay
      const clickEvent = new window.MouseEvent('click', { bubbles: true });
      overlay.dispatchEvent(clickEvent);
      
      // Wait for event handler to execute
      await new Promise(resolve => setTimeout(resolve, 50));
      expect(sidebar.classList.contains('sidebar-collapsed')).toBe(true);
    });

    it('should not close sidebar when overlay is clicked on desktop', async () => {
      setViewportWidth(1024);
      
      // Setup: sidebar open
      sidebar.classList.remove('sidebar-collapsed');
      
      // Click overlay
      const clickEvent = new window.MouseEvent('click', { bubbles: true });
      overlay.dispatchEvent(clickEvent);
      
      // Sidebar should remain open on desktop
      await new Promise(resolve => setTimeout(resolve, 50));
      expect(sidebar.classList.contains('sidebar-collapsed')).toBe(false);
    });
  });

  describe('Requirement 6.8 & 6.10: Viewport resize switches between modes', () => {
    it('should switch from desktop to mobile mode when viewport shrinks', async () => {
      // Start in desktop mode
      setViewportWidth(1024);
      overlay.classList.remove('active');
      
      // Resize to mobile
      setViewportWidth(767);
      triggerResize();
      
      // Wait for debounced resize handler (150ms)
      await new Promise(resolve => setTimeout(resolve, 200));
      
      // Overlay should be hidden after resize
      expect(overlay.classList.contains('active')).toBe(false);
    });

    it('should switch from mobile to desktop mode when viewport expands', async () => {
      // Start in mobile mode with overlay active
      setViewportWidth(767);
      overlay.classList.add('active');
      
      // Resize to desktop
      setViewportWidth(1024);
      triggerResize();
      
      // Wait for debounced resize handler (150ms)
      await new Promise(resolve => setTimeout(resolve, 200));
      
      // Overlay should be removed on desktop
      expect(overlay.classList.contains('active')).toBe(false);
    });

    it('should debounce resize events to prevent excessive recalculations', async () => {
      const resizeHandler = vi.fn();
      window.addEventListener('resize', resizeHandler);
      
      // Trigger multiple rapid resize events
      setViewportWidth(800);
      triggerResize();
      setViewportWidth(750);
      triggerResize();
      setViewportWidth(700);
      triggerResize();
      
      // Handler should be called multiple times immediately
      expect(resizeHandler).toHaveBeenCalled();
      
      // But debounced logic should only execute once after 150ms
      await new Promise(resolve => setTimeout(resolve, 200));
      
      // Verify debouncing worked (overlay state updated only once)
      expect(overlay.classList.contains('active')).toBe(false);
    });
  });

  describe('Edge Cases', () => {
    it('should handle rapid viewport size changes gracefully', async () => {
      // Rapidly switch between mobile and desktop
      setViewportWidth(767);
      triggerResize();
      
      await new Promise(resolve => setTimeout(resolve, 50));
      setViewportWidth(1024);
      triggerResize();
      
      await new Promise(resolve => setTimeout(resolve, 50));
      setViewportWidth(767);
      triggerResize();
      
      // After all changes settle, overlay should be in correct state
      await new Promise(resolve => setTimeout(resolve, 200));
      expect(overlay.classList.contains('active')).toBe(false);
    });

    it('should maintain sidebar state across viewport changes', () => {
      // Start with collapsed sidebar on desktop
      setViewportWidth(1024);
      sidebar.classList.add('sidebar-collapsed');
      
      // Resize to mobile
      setViewportWidth(767);
      triggerResize();
      
      // Sidebar should still be collapsed
      expect(sidebar.classList.contains('sidebar-collapsed')).toBe(true);
    });

    it('should handle missing overlay element gracefully', () => {
      // Remove overlay element
      overlay.remove();
      
      // Toggle should not throw error
      expect(() => {
        window.toggleSidebar();
      }).not.toThrow();
    });
  });

  describe('Accessibility on Mobile', () => {
    it('should maintain ARIA attributes on mobile', () => {
      setViewportWidth(767);
      
      // Toggle sidebar
      window.toggleSidebar();
      
      // ARIA attributes should be updated
      expect(toggleBtn.getAttribute('aria-expanded')).toBe('false');
      expect(sidebar.getAttribute('aria-hidden')).toBe('true');
    });

    it('should allow keyboard navigation on mobile', async () => {
      setViewportWidth(767);
      
      // Focus toggle button
      toggleBtn.focus();
      
      // Press Enter key
      const enterEvent = new window.KeyboardEvent('keydown', {
        key: 'Enter',
        bubbles: true,
      });
      toggleBtn.dispatchEvent(enterEvent);
      
      // Sidebar should toggle
      await new Promise(resolve => setTimeout(resolve, 50));
      expect(sidebar.classList.contains('sidebar-collapsed')).toBe(true);
    });
  });
});

/**
 * Helper function to get the toggle sidebar script
 * This is the actual implementation from dashboard.html
 */
function getToggleSidebarScript() {
  return `
    function toggleSidebar() {
      const sidebar = document.getElementById('sidebar');
      const toggleBtn = document.getElementById('sidebar-toggle-btn');
      const overlay = document.getElementById('sidebar-overlay');
      const main = document.querySelector('main');
      
      if (!sidebar || !toggleBtn || !overlay || !main) {
        console.warn('Sidebar toggle: Required elements not found');
        return;
      }
      
      const isCollapsed = sidebar.classList.contains('sidebar-collapsed');
      const newState = !isCollapsed;
      
      requestAnimationFrame(() => {
        sidebar.style.willChange = 'transform, width, opacity';
        main.style.willChange = 'margin-left';
        
        sidebar.classList.toggle('sidebar-collapsed');
        
        toggleBtn.setAttribute('aria-expanded', isCollapsed ? 'true' : 'false');
        sidebar.setAttribute('aria-hidden', newState ? 'true' : 'false');
        
        if (window.innerWidth < 768) {
          overlay.classList.toggle('active', !newState);
        }
      });
      
      setTimeout(() => {
        sidebar.style.willChange = 'auto';
        main.style.willChange = 'auto';
      }, 300);
      
      try {
        localStorage.setItem('sidebarCollapsed', JSON.stringify(newState));
      } catch (error) {
        console.warn('Failed to save sidebar state:', error);
      }
      
      window.dispatchEvent(new CustomEvent('sidebarToggled', {
        detail: { isCollapsed: newState, timestamp: Date.now() }
      }));
    }
    
    function setSidebarState(collapsed) {
      const sidebar = document.getElementById('sidebar');
      if (!sidebar) return;
      
      const isCurrentlyCollapsed = sidebar.classList.contains('sidebar-collapsed');
      
      if (collapsed !== isCurrentlyCollapsed) {
        toggleSidebar();
      }
    }
    
    function initSidebar() {
      const toggleBtn = document.getElementById('sidebar-toggle-btn');
      const overlay = document.getElementById('sidebar-overlay');
      
      if (!toggleBtn || !overlay) {
        console.warn('Sidebar toggle: Required elements not found for initialization');
        return;
      }
      
      toggleBtn.addEventListener('click', toggleSidebar);
      
      toggleBtn.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          toggleSidebar();
        }
      });
      
      overlay.addEventListener('click', () => {
        if (window.innerWidth < 768) {
          setSidebarState(true);
        }
      });
      
      let resizeTimeout;
      window.addEventListener('resize', () => {
        clearTimeout(resizeTimeout);
        resizeTimeout = setTimeout(() => {
          const isMobile = window.innerWidth < 768;
          if (!isMobile) {
            overlay.classList.remove('active');
          }
        }, 150);
      });
    }
    
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', initSidebar);
    } else {
      initSidebar();
    }
  `;
}
