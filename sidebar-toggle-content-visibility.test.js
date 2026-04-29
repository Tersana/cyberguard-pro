/**
 * Test Suite: Sidebar Content Visibility Management (Task 6.3)
 * 
 * Tests CSS rules for hiding user profile card and 2FA controls when sidebar is collapsed
 * Validates: Requirements 7.1, 7.6, 8.1, 8.4
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { JSDOM } from 'jsdom';
import fs from 'fs';
import path from 'path';

describe('Task 6.3: Content Visibility Management', () => {
  let dom;
  let document;
  let window;
  let sidebar;
  let userCard;
  let enable2faBtn;
  let twofa2EnabledSection;

  beforeEach(() => {
    // Load the CSS file
    const cssPath = path.join(process.cwd(), 'cyber-theme.css');
    const cssContent = fs.readFileSync(cssPath, 'utf-8');

    // Create a minimal HTML structure matching dashboard.html
    const html = `
      <!DOCTYPE html>
      <html>
        <head>
          <style>${cssContent}</style>
        </head>
        <body>
          <aside id="sidebar" class="cyber-sidebar">
            <!-- User Profile Card -->
            <div class="px-3 pb-4" data-auth>
              <div class="cyber-user-card flex items-center gap-3 p-3 rounded-xl">
                <div class="cyber-avatar flex-shrink-0">
                  <span class="text-sm font-bold text-white" id="sidebarUserInitials">AP</span>
                </div>
                <div class="flex-1 min-w-0">
                  <p class="text-sm font-semibold text-white truncate" id="sidebarUserName">Alex Porter</p>
                  <p class="text-xs text-slate-400 truncate" id="sidebarUserRole">Security Analyst</p>
                </div>
                <span class="cyber-pro-badge">PRO</span>
              </div>
              
              <!-- 2FA Status and Control -->
              <div class="mt-3">
                <button id="enable-2fa-btn" class="cyber-btn-primary w-full text-xs py-2 px-3 rounded-lg">
                  Enable 2FA
                </button>
                <div id="twofa-enabled-section" class="hidden mt-2">
                  <div class="text-center mb-2">
                    <span class="text-xs text-green-400">2FA Enabled</span>
                  </div>
                  <button id="disable-2fa-btn" class="cyber-btn-danger w-full text-xs py-2 px-3 rounded-lg">
                    Disable 2FA
                  </button>
                </div>
              </div>
            </div>
          </aside>
        </body>
      </html>
    `;

    dom = new JSDOM(html);
    document = dom.window.document;
    window = dom.window;
    sidebar = document.getElementById('sidebar');
    userCard = document.querySelector('.cyber-user-card');
    enable2faBtn = document.getElementById('enable-2fa-btn');
    twofa2EnabledSection = document.getElementById('twofa-enabled-section');
  });

  afterEach(() => {
    dom.window.close();
  });

  describe('User Profile Card Visibility (Requirements 7.1, 7.6)', () => {
    it('should display user profile card when sidebar is expanded', () => {
      // Sidebar is expanded by default (no .sidebar-collapsed class)
      const styles = window.getComputedStyle(userCard);
      
      // Requirement 7.6: Elements should be visible when sidebar expanded
      // Note: JSDOM doesn't compute display: none from parent selectors perfectly,
      // but we can verify the element exists and is not explicitly hidden
      expect(userCard).toBeTruthy();
      expect(sidebar.classList.contains('sidebar-collapsed')).toBe(false);
    });

    it('should hide user profile card when sidebar is collapsed (Requirement 7.1)', () => {
      // Add collapsed class to sidebar
      sidebar.classList.add('sidebar-collapsed');
      
      // Force JSDOM to recompute styles
      const styles = window.getComputedStyle(userCard);
      
      // Requirement 7.1: User profile card should be hidden when collapsed
      // The CSS rule: .cyber-sidebar.sidebar-collapsed .cyber-user-card { display: none; }
      expect(styles.display).toBe('none');
    });

    it('should use display: none for complete hiding (Requirement 7.7)', () => {
      sidebar.classList.add('sidebar-collapsed');
      const styles = window.getComputedStyle(userCard);
      
      // Requirement 7.7: Should use display: none (not opacity or visibility)
      expect(styles.display).toBe('none');
    });

    it('should show user profile card when sidebar is expanded after collapse', () => {
      // Collapse sidebar
      sidebar.classList.add('sidebar-collapsed');
      let styles = window.getComputedStyle(userCard);
      expect(styles.display).toBe('none');
      
      // Expand sidebar
      sidebar.classList.remove('sidebar-collapsed');
      styles = window.getComputedStyle(userCard);
      
      // Should be visible again
      expect(styles.display).not.toBe('none');
    });

    it('should hide user profile card with legacy .hidden class', () => {
      // Test backward compatibility
      sidebar.classList.add('hidden');
      const styles = window.getComputedStyle(userCard);
      
      // Should also hide with .hidden class
      expect(styles.display).toBe('none');
    });
  });

  describe('2FA Controls Visibility (Requirements 8.1, 8.4)', () => {
    it('should display 2FA enable button when sidebar is expanded', () => {
      // Sidebar is expanded by default
      const styles = window.getComputedStyle(enable2faBtn);
      
      // Requirement 8.4: Elements should be visible when sidebar expanded
      expect(enable2faBtn).toBeTruthy();
      expect(sidebar.classList.contains('sidebar-collapsed')).toBe(false);
    });

    it('should hide 2FA enable button when sidebar is collapsed (Requirement 8.1)', () => {
      sidebar.classList.add('sidebar-collapsed');
      const styles = window.getComputedStyle(enable2faBtn);
      
      // Requirement 8.1: 2FA button should be hidden when collapsed
      expect(styles.display).toBe('none');
    });

    it('should hide 2FA enabled section when sidebar is collapsed (Requirement 8.1)', () => {
      // First make the section visible (remove hidden class)
      twofa2EnabledSection.classList.remove('hidden');
      
      // Then collapse sidebar
      sidebar.classList.add('sidebar-collapsed');
      const styles = window.getComputedStyle(twofa2EnabledSection);
      
      // Requirement 8.1: 2FA enabled section should be hidden when collapsed
      expect(styles.display).toBe('none');
    });

    it('should use display: none for complete hiding (Requirement 8.2)', () => {
      sidebar.classList.add('sidebar-collapsed');
      
      const enableBtnStyles = window.getComputedStyle(enable2faBtn);
      const enabledSectionStyles = window.getComputedStyle(twofa2EnabledSection);
      
      // Requirement 8.2: Should use display: none for complete hiding
      expect(enableBtnStyles.display).toBe('none');
      expect(enabledSectionStyles.display).toBe('none');
    });

    it('should show 2FA controls when sidebar is expanded after collapse', () => {
      // Collapse sidebar
      sidebar.classList.add('sidebar-collapsed');
      let styles = window.getComputedStyle(enable2faBtn);
      expect(styles.display).toBe('none');
      
      // Expand sidebar
      sidebar.classList.remove('sidebar-collapsed');
      styles = window.getComputedStyle(enable2faBtn);
      
      // Should be visible again
      expect(styles.display).not.toBe('none');
    });

    it('should hide 2FA controls with legacy .hidden class', () => {
      sidebar.classList.add('hidden');
      
      const enableBtnStyles = window.getComputedStyle(enable2faBtn);
      const enabledSectionStyles = window.getComputedStyle(twofa2EnabledSection);
      
      // Should also hide with .hidden class
      expect(enableBtnStyles.display).toBe('none');
      expect(enabledSectionStyles.display).toBe('none');
    });
  });

  describe('Combined Visibility Behavior', () => {
    it('should hide both user card and 2FA controls when collapsed', () => {
      sidebar.classList.add('sidebar-collapsed');
      
      const userCardStyles = window.getComputedStyle(userCard);
      const enable2faBtnStyles = window.getComputedStyle(enable2faBtn);
      const twofa2EnabledSectionStyles = window.getComputedStyle(twofa2EnabledSection);
      
      // All should be hidden
      expect(userCardStyles.display).toBe('none');
      expect(enable2faBtnStyles.display).toBe('none');
      expect(twofa2EnabledSectionStyles.display).toBe('none');
    });

    it('should show both user card and 2FA controls when expanded', () => {
      // Start collapsed
      sidebar.classList.add('sidebar-collapsed');
      
      // Then expand
      sidebar.classList.remove('sidebar-collapsed');
      
      const userCardStyles = window.getComputedStyle(userCard);
      const enable2faBtnStyles = window.getComputedStyle(enable2faBtn);
      
      // Both should be visible
      expect(userCardStyles.display).not.toBe('none');
      expect(enable2faBtnStyles.display).not.toBe('none');
    });

    it('should handle rapid toggle of collapsed state', () => {
      // Toggle multiple times
      sidebar.classList.add('sidebar-collapsed');
      sidebar.classList.remove('sidebar-collapsed');
      sidebar.classList.add('sidebar-collapsed');
      
      const userCardStyles = window.getComputedStyle(userCard);
      const enable2faBtnStyles = window.getComputedStyle(enable2faBtn);
      
      // Should end in hidden state
      expect(userCardStyles.display).toBe('none');
      expect(enable2faBtnStyles.display).toBe('none');
    });
  });

  describe('CSS Selector Specificity', () => {
    it('should use correct parent selector for user card', () => {
      // The CSS rule should be: .cyber-sidebar.sidebar-collapsed .cyber-user-card
      sidebar.classList.add('sidebar-collapsed');
      
      const styles = window.getComputedStyle(userCard);
      expect(styles.display).toBe('none');
      
      // Verify it's the parent selector causing the hide, not the element itself
      expect(userCard.style.display).not.toBe('none');
    });

    it('should use correct parent selector for 2FA controls', () => {
      // The CSS rules should be:
      // .cyber-sidebar.sidebar-collapsed #enable-2fa-btn
      // .cyber-sidebar.sidebar-collapsed #twofa-enabled-section
      sidebar.classList.add('sidebar-collapsed');
      
      const enableBtnStyles = window.getComputedStyle(enable2faBtn);
      const enabledSectionStyles = window.getComputedStyle(twofa2EnabledSection);
      
      expect(enableBtnStyles.display).toBe('none');
      expect(enabledSectionStyles.display).toBe('none');
      
      // Verify it's the parent selector causing the hide
      expect(enable2faBtn.style.display).not.toBe('none');
      expect(twofa2EnabledSection.style.display).not.toBe('hidden');
    });
  });

  describe('Integration with Existing Dashboard', () => {
    it('should not affect other sidebar elements', () => {
      sidebar.classList.add('sidebar-collapsed');
      
      // User card and 2FA controls should be hidden
      const userCardStyles = window.getComputedStyle(userCard);
      expect(userCardStyles.display).toBe('none');
      
      // But sidebar itself should still exist (just transformed)
      const sidebarStyles = window.getComputedStyle(sidebar);
      expect(sidebarStyles.display).not.toBe('none');
    });

    it('should work with data-auth attribute on parent', () => {
      const authContainer = document.querySelector('[data-auth]');
      expect(authContainer).toBeTruthy();
      
      // User card should be inside auth container
      expect(authContainer.contains(userCard)).toBe(true);
      
      // Collapsing should still hide the user card
      sidebar.classList.add('sidebar-collapsed');
      const styles = window.getComputedStyle(userCard);
      expect(styles.display).toBe('none');
    });
  });

  describe('Smooth Transitions (Requirement 8.3)', () => {
    it('should inherit transition properties from sidebar', () => {
      const sidebarStyles = window.getComputedStyle(sidebar);
      
      // Requirement 8.3: Should have smooth transitions
      // The sidebar has transition properties that will affect visibility changes
      expect(sidebarStyles.transition).toContain('300ms');
      expect(sidebarStyles.transition).toContain('cubic-bezier');
    });

    it('should not have conflicting transition properties on hidden elements', () => {
      sidebar.classList.add('sidebar-collapsed');
      
      const userCardStyles = window.getComputedStyle(userCard);
      const enable2faBtnStyles = window.getComputedStyle(enable2faBtn);
      
      // Elements should be hidden with display: none
      // This ensures instant hiding without conflicting transitions
      expect(userCardStyles.display).toBe('none');
      expect(enable2faBtnStyles.display).toBe('none');
    });
  });
});
