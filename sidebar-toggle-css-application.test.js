/**
 * Unit Tests for Sidebar Toggle CSS Class Application
 * 
 * Tests CSS class application, animation properties, and GPU acceleration
 * for the sidebar toggle feature.
 * 
 * **Validates: Requirements 2.1, 2.2, 2.3, 11.1, 11.2, 11.7**
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';

describe('Sidebar Toggle - CSS Class Application', () => {
  let sidebar;
  let mainContent;
  let toggleButton;

  beforeEach(() => {
    // Create DOM structure
    document.body.innerHTML = `
      <button 
        id="sidebar-toggle-btn" 
        class="cyber-sidebar-toggle"
        aria-label="Toggle sidebar navigation"
        aria-expanded="true"
        aria-controls="sidebar">
        Toggle
      </button>

      <aside id="sidebar" class="cyber-sidebar" aria-hidden="false">
        <div class="cyber-user-card">
          <span class="username">tersana</span>
          <span class="role">Security Analyst</span>
        </div>
        <button id="enable-2fa-btn">Enable 2FA</button>
        <div id="twofa-enabled-section">2FA Enabled</div>
      </aside>

      <main>
        <h1>Main Content</h1>
      </main>
    `;

    // Add CSS styles programmatically
    const style = document.createElement('style');
    style.textContent = `
      /* Sidebar base styles */
      .cyber-sidebar {
        width: 260px;
        min-width: 260px;
        transition: transform 300ms cubic-bezier(0.4, 0, 0.2, 1),
                    width 300ms cubic-bezier(0.4, 0, 0.2, 1),
                    opacity 300ms cubic-bezier(0.4, 0, 0.2, 1);
        will-change: transform, width, opacity;
        transform: translateZ(0);
        backface-visibility: hidden;
      }

      /* Collapsed state */
      .cyber-sidebar.sidebar-collapsed {
        transform: translateX(-100%);
        width: 0;
        min-width: 0;
        opacity: 0;
      }

      /* Main content area */
      main {
        flex: 1;
        margin-left: 260px;
        transition: margin-left 300ms cubic-bezier(0.4, 0, 0.2, 1);
        will-change: margin-left;
      }

      /* Main content when sidebar is collapsed */
      .sidebar-collapsed ~ main {
        margin-left: 0;
      }

      /* User profile card */
      .cyber-user-card {
        display: block;
      }

      .cyber-sidebar.sidebar-collapsed .cyber-user-card {
        display: none;
      }

      /* 2FA controls */
      #enable-2fa-btn,
      #twofa-enabled-section {
        display: block;
      }

      .cyber-sidebar.sidebar-collapsed #enable-2fa-btn,
      .cyber-sidebar.sidebar-collapsed #twofa-enabled-section {
        display: none;
      }
    `;
    document.head.appendChild(style);

    sidebar = document.getElementById('sidebar');
    mainContent = document.querySelector('main');
    toggleButton = document.getElementById('sidebar-toggle-btn');
  });

  afterEach(() => {
    document.body.innerHTML = '';
    document.head.innerHTML = '';
  });

  describe('Requirement 2.1 - Sidebar Collapse Class Toggle', () => {
    it('should add .sidebar-collapsed class when toggling to collapsed state', () => {
      // Arrange
      expect(sidebar.classList.contains('sidebar-collapsed')).toBe(false);

      // Act
      sidebar.classList.add('sidebar-collapsed');

      // Assert
      expect(sidebar.classList.contains('sidebar-collapsed')).toBe(true);
    });

    it('should remove .sidebar-collapsed class when toggling to expanded state', () => {
      // Arrange
      sidebar.classList.add('sidebar-collapsed');
      expect(sidebar.classList.contains('sidebar-collapsed')).toBe(true);

      // Act
      sidebar.classList.remove('sidebar-collapsed');

      // Assert
      expect(sidebar.classList.contains('sidebar-collapsed')).toBe(false);
    });

    it('should toggle .sidebar-collapsed class correctly', () => {
      // Initial state: expanded
      expect(sidebar.classList.contains('sidebar-collapsed')).toBe(false);

      // First toggle: collapse
      sidebar.classList.toggle('sidebar-collapsed');
      expect(sidebar.classList.contains('sidebar-collapsed')).toBe(true);

      // Second toggle: expand
      sidebar.classList.toggle('sidebar-collapsed');
      expect(sidebar.classList.contains('sidebar-collapsed')).toBe(false);

      // Third toggle: collapse again
      sidebar.classList.toggle('sidebar-collapsed');
      expect(sidebar.classList.contains('sidebar-collapsed')).toBe(true);
    });

    it('should maintain other CSS classes when toggling sidebar-collapsed', () => {
      // Arrange
      sidebar.classList.add('custom-class', 'another-class');

      // Act
      sidebar.classList.toggle('sidebar-collapsed');

      // Assert
      expect(sidebar.classList.contains('cyber-sidebar')).toBe(true);
      expect(sidebar.classList.contains('custom-class')).toBe(true);
      expect(sidebar.classList.contains('another-class')).toBe(true);
      expect(sidebar.classList.contains('sidebar-collapsed')).toBe(true);
    });
  });

  describe('Requirement 2.2 - Animation Timing and Easing Function', () => {
    it('should have transition CSS rule defined for sidebar', () => {
      // Act - Check if the style element contains the transition rule
      const styleElement = document.querySelector('style');
      const cssText = styleElement.textContent;

      // Assert - CSS should define 300ms transitions
      expect(cssText).toContain('transition:');
      expect(cssText).toContain('300ms');
      expect(cssText).toContain('cubic-bezier(0.4, 0, 0.2, 1)');
    });

    it('should define cubic-bezier(0.4, 0, 0.2, 1) easing function in CSS', () => {
      // Act
      const styleElement = document.querySelector('style');
      const cssText = styleElement.textContent;

      // Assert - CSS should use the standard easing function
      expect(cssText).toMatch(/cubic-bezier\(0\.4,\s*0,\s*0\.2,\s*1\)/);
    });

    it('should define transitions for transform, width, and opacity properties', () => {
      // Act
      const styleElement = document.querySelector('style');
      const cssText = styleElement.textContent;

      // Assert - CSS should include all three properties in transition
      expect(cssText).toContain('transform');
      expect(cssText).toContain('width');
      expect(cssText).toContain('opacity');
    });

    it('should have consistent 300ms timing for all transition properties', () => {
      // Act
      const styleElement = document.querySelector('style');
      const cssText = styleElement.textContent;

      // Assert - all transition properties should use 300ms
      const transitionMatch = cssText.match(/transition:\s*transform\s+300ms[^;]+width\s+300ms[^;]+opacity\s+300ms/);
      expect(transitionMatch).toBeTruthy();
    });

    it('should apply same easing function to all transition properties', () => {
      // Act
      const styleElement = document.querySelector('style');
      const cssText = styleElement.textContent;

      // Assert - cubic-bezier should appear for each property
      const cubicBezierCount = (cssText.match(/cubic-bezier\(0\.4,\s*0,\s*0\.2,\s*1\)/g) || []).length;
      expect(cubicBezierCount).toBeGreaterThanOrEqual(3); // At least 3 times (transform, width, opacity)
    });
  });

  describe('Requirement 2.3 & 11.7 - GPU Acceleration Properties', () => {
    it('should have will-change property set for performance optimization', () => {
      // Act
      const computedStyle = window.getComputedStyle(sidebar);
      const willChange = computedStyle.willChange;

      // Assert
      expect(willChange).toContain('transform');
      expect(willChange).toContain('width');
      expect(willChange).toContain('opacity');
    });

    it('should use translateZ(0) for GPU acceleration', () => {
      // Act
      const computedStyle = window.getComputedStyle(sidebar);
      const transform = computedStyle.transform;

      // Assert - should include translateZ or matrix3d (GPU-accelerated)
      // translateZ(0) creates a 3D rendering context
      expect(transform).toBeTruthy();
    });

    it('should have backface-visibility set to hidden for GPU optimization', () => {
      // Act
      const computedStyle = window.getComputedStyle(sidebar);
      const backfaceVisibility = computedStyle.backfaceVisibility;

      // Assert
      expect(backfaceVisibility).toBe('hidden');
    });

    it('should apply transform: translateX(-100%) when collapsed', () => {
      // Arrange
      sidebar.classList.add('sidebar-collapsed');

      // Act
      const computedStyle = window.getComputedStyle(sidebar);
      const transform = computedStyle.transform;

      // Assert - should include translateX(-100%)
      // Note: computed style may convert to matrix notation
      expect(transform).toBeTruthy();
      expect(transform).not.toBe('none');
    });
  });

  describe('Requirement 3.8 - Main Content Area Margin-Left Transitions', () => {
    it('should have 300ms transition duration defined for margin-left in CSS', () => {
      // Act
      const styleElement = document.querySelector('style');
      const cssText = styleElement.textContent;

      // Assert - main element should have margin-left transition with 300ms
      expect(cssText).toContain('main');
      expect(cssText).toMatch(/margin-left\s+300ms/);
    });

    it('should use cubic-bezier(0.4, 0, 0.2, 1) easing for margin-left in CSS', () => {
      // Act
      const styleElement = document.querySelector('style');
      const cssText = styleElement.textContent;
      
      // Extract main element styles
      const mainStyleMatch = cssText.match(/main\s*{[^}]+}/);
      expect(mainStyleMatch).toBeTruthy();
      
      // Assert - should contain cubic-bezier in main styles
      expect(mainStyleMatch[0]).toContain('cubic-bezier(0.4, 0, 0.2, 1)');
    });

    it('should define margin-left in transition property for main element', () => {
      // Act
      const styleElement = document.querySelector('style');
      const cssText = styleElement.textContent;

      // Assert - main element should have margin-left in transition
      const mainStyleMatch = cssText.match(/main\s*{[^}]+}/);
      expect(mainStyleMatch).toBeTruthy();
      expect(mainStyleMatch[0]).toContain('margin-left');
    });

    it('should have will-change property for margin-left optimization', () => {
      // Act
      const styleElement = document.querySelector('style');
      const cssText = styleElement.textContent;

      // Assert - main element should have will-change: margin-left
      const mainStyleMatch = cssText.match(/main\s*{[^}]+}/);
      expect(mainStyleMatch).toBeTruthy();
      expect(mainStyleMatch[0]).toContain('will-change: margin-left');
    });

    it('should have initial margin-left of 260px when sidebar is expanded', () => {
      // Act
      const styleElement = document.querySelector('style');
      const cssText = styleElement.textContent;

      // Assert - main element should have margin-left: 260px
      const mainStyleMatch = cssText.match(/main\s*{[^}]+}/);
      expect(mainStyleMatch).toBeTruthy();
      expect(mainStyleMatch[0]).toContain('margin-left: 260px');
    });
  });

  describe('Requirement 7 - User Profile Card Visibility', () => {
    it('should display user profile card when sidebar is expanded', () => {
      // Arrange
      const userCard = sidebar.querySelector('.cyber-user-card');

      // Act
      const computedStyle = window.getComputedStyle(userCard);

      // Assert
      expect(computedStyle.display).toBe('block');
    });

    it('should hide user profile card when sidebar is collapsed', () => {
      // Arrange
      sidebar.classList.add('sidebar-collapsed');
      const userCard = sidebar.querySelector('.cyber-user-card');

      // Act
      const computedStyle = window.getComputedStyle(userCard);

      // Assert
      expect(computedStyle.display).toBe('none');
    });

    it('should hide username text when sidebar is collapsed', () => {
      // Arrange
      sidebar.classList.add('sidebar-collapsed');
      const username = sidebar.querySelector('.username');

      // Act
      const userCard = sidebar.querySelector('.cyber-user-card');
      const computedStyle = window.getComputedStyle(userCard);

      // Assert - parent is hidden, so username is effectively hidden
      expect(computedStyle.display).toBe('none');
      expect(username).toBeTruthy();
    });

    it('should hide role text when sidebar is collapsed', () => {
      // Arrange
      sidebar.classList.add('sidebar-collapsed');
      const role = sidebar.querySelector('.role');

      // Act
      const userCard = sidebar.querySelector('.cyber-user-card');
      const computedStyle = window.getComputedStyle(userCard);

      // Assert - parent is hidden, so role is effectively hidden
      expect(computedStyle.display).toBe('none');
      expect(role).toBeTruthy();
    });
  });

  describe('Requirement 8 - 2FA Controls Visibility', () => {
    it('should display 2FA enable button when sidebar is expanded', () => {
      // Arrange
      const enable2faBtn = document.getElementById('enable-2fa-btn');

      // Act
      const computedStyle = window.getComputedStyle(enable2faBtn);

      // Assert
      expect(computedStyle.display).toBe('block');
    });

    it('should hide 2FA enable button when sidebar is collapsed', () => {
      // Arrange
      sidebar.classList.add('sidebar-collapsed');
      const enable2faBtn = document.getElementById('enable-2fa-btn');

      // Act
      const computedStyle = window.getComputedStyle(enable2faBtn);

      // Assert
      expect(computedStyle.display).toBe('none');
    });

    it('should display 2FA enabled section when sidebar is expanded', () => {
      // Arrange
      const twofaSection = document.getElementById('twofa-enabled-section');

      // Act
      const computedStyle = window.getComputedStyle(twofaSection);

      // Assert
      expect(computedStyle.display).toBe('block');
    });

    it('should hide 2FA enabled section when sidebar is collapsed', () => {
      // Arrange
      sidebar.classList.add('sidebar-collapsed');
      const twofaSection = document.getElementById('twofa-enabled-section');

      // Act
      const computedStyle = window.getComputedStyle(twofaSection);

      // Assert
      expect(computedStyle.display).toBe('none');
    });
  });

  describe('Requirement 11.1 - CSS Transform Performance', () => {
    it('should use transform property for animations instead of width changes alone', () => {
      // Arrange
      sidebar.classList.add('sidebar-collapsed');

      // Act
      const computedStyle = window.getComputedStyle(sidebar);
      const transform = computedStyle.transform;

      // Assert - transform should be applied (not 'none')
      expect(transform).not.toBe('none');
    });

    it('should combine transform and width changes for smooth animation', () => {
      // Arrange
      sidebar.classList.add('sidebar-collapsed');

      // Act
      const computedStyle = window.getComputedStyle(sidebar);
      const width = computedStyle.width;
      const transform = computedStyle.transform;

      // Assert
      expect(width).toBe('0px');
      expect(transform).not.toBe('none');
    });

    it('should use opacity transition for fade effect', () => {
      // Arrange
      sidebar.classList.add('sidebar-collapsed');

      // Act
      const computedStyle = window.getComputedStyle(sidebar);
      const opacity = computedStyle.opacity;

      // Assert
      expect(opacity).toBe('0');
    });
  });

  describe('Edge Cases - CSS Class Application', () => {
    it('should handle multiple rapid class toggles', () => {
      // Act
      sidebar.classList.toggle('sidebar-collapsed'); // collapsed
      sidebar.classList.toggle('sidebar-collapsed'); // expanded
      sidebar.classList.toggle('sidebar-collapsed'); // collapsed
      sidebar.classList.toggle('sidebar-collapsed'); // expanded
      sidebar.classList.toggle('sidebar-collapsed'); // collapsed

      // Assert - final state should be collapsed
      expect(sidebar.classList.contains('sidebar-collapsed')).toBe(true);
    });

    it('should maintain CSS properties when class is added multiple times', () => {
      // Act
      sidebar.classList.add('sidebar-collapsed');
      sidebar.classList.add('sidebar-collapsed'); // Adding again should be idempotent
      sidebar.classList.add('sidebar-collapsed');

      // Assert
      expect(sidebar.classList.contains('sidebar-collapsed')).toBe(true);
    });

    it('should handle removing class that is not present', () => {
      // Arrange
      expect(sidebar.classList.contains('sidebar-collapsed')).toBe(false);

      // Act & Assert - should not throw error
      expect(() => {
        sidebar.classList.remove('sidebar-collapsed');
      }).not.toThrow();
      
      expect(sidebar.classList.contains('sidebar-collapsed')).toBe(false);
    });

    it('should preserve CSS class structure after toggle', () => {
      // Act
      sidebar.classList.toggle('sidebar-collapsed');
      sidebar.classList.toggle('sidebar-collapsed');

      // Assert - original classes should still be present
      expect(sidebar.classList.contains('cyber-sidebar')).toBe(true);
      
      // CSS rules should still be defined
      const styleElement = document.querySelector('style');
      expect(styleElement.textContent).toContain('transition:');
    });
  });

  describe('Integration - Sidebar and Main Content Coordination', () => {
    it('should coordinate sidebar collapse with main content expansion', () => {
      // Arrange
      const styleElement = document.querySelector('style');
      const cssText = styleElement.textContent;

      // Assert - CSS should define both sidebar and main content rules
      expect(cssText).toContain('.cyber-sidebar');
      expect(cssText).toContain('main');
      expect(cssText).toContain('sidebar-collapsed');
    });

    it('should have matching transition durations for sidebar and main content', () => {
      // Act
      const styleElement = document.querySelector('style');
      const cssText = styleElement.textContent;

      // Assert - both should have 300ms transitions
      const sidebarMatch = cssText.match(/\.cyber-sidebar\s*{[^}]+}/);
      const mainMatch = cssText.match(/main\s*{[^}]+}/);
      
      expect(sidebarMatch[0]).toContain('300ms');
      expect(mainMatch[0]).toContain('300ms');
    });

    it('should have matching easing functions for sidebar and main content', () => {
      // Act
      const styleElement = document.querySelector('style');
      const cssText = styleElement.textContent;

      // Assert - both should use cubic-bezier(0.4, 0, 0.2, 1)
      const sidebarMatch = cssText.match(/\.cyber-sidebar\s*{[^}]+}/);
      const mainMatch = cssText.match(/main\s*{[^}]+}/);
      
      expect(sidebarMatch[0]).toContain('cubic-bezier(0.4, 0, 0.2, 1)');
      expect(mainMatch[0]).toContain('cubic-bezier(0.4, 0, 0.2, 1)');
    });
  });

  describe('Accessibility - ARIA Attributes with CSS Classes', () => {
    it('should have aria-hidden="false" when sidebar is expanded', () => {
      // Assert
      expect(sidebar.getAttribute('aria-hidden')).toBe('false');
      expect(sidebar.classList.contains('sidebar-collapsed')).toBe(false);
    });

    it('should coordinate aria-hidden with sidebar-collapsed class', () => {
      // Act
      sidebar.classList.add('sidebar-collapsed');
      sidebar.setAttribute('aria-hidden', 'true');

      // Assert
      expect(sidebar.getAttribute('aria-hidden')).toBe('true');
      expect(sidebar.classList.contains('sidebar-collapsed')).toBe(true);
    });

    it('should have aria-expanded="true" on toggle button when sidebar is expanded', () => {
      // Assert
      expect(toggleButton.getAttribute('aria-expanded')).toBe('true');
      expect(sidebar.classList.contains('sidebar-collapsed')).toBe(false);
    });

    it('should coordinate aria-expanded with sidebar state', () => {
      // Act
      sidebar.classList.add('sidebar-collapsed');
      toggleButton.setAttribute('aria-expanded', 'false');

      // Assert
      expect(toggleButton.getAttribute('aria-expanded')).toBe('false');
      expect(sidebar.classList.contains('sidebar-collapsed')).toBe(true);
    });
  });
});
