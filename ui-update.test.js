/**
 * Unit Tests for Task 9.3: Update UI with session data
 * Tests the updateUI method with full_name and job_title
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { JSDOM } from 'jsdom';

describe('AuthManager - UI Update with Session Data (Task 9.3)', () => {
  let authManager;
  let apiClientMock;
  let dom;

  beforeEach(() => {
    // Setup DOM environment with all required elements
    dom = new JSDOM(`
      <!DOCTYPE html>
      <html>
        <body>
          <!-- Header user info -->
          <div id="user-info" data-auth class="hidden">
            <div id="userName">User Name</div>
            <div id="userEmail">user@example.com</div>
          </div>
          <div id="guest-actions" data-guest>Guest Actions</div>
          
          <!-- Sidebar profile card -->
          <div data-auth class="hidden">
            <div id="sidebarUserName">Alex Porter</div>
            <div id="sidebarUserRole">Security Analyst</div>
            <div id="sidebarUserInitials">AP</div>
          </div>
          
          <!-- Guest notice -->
          <div id="guest-notice" data-guest>Guest Notice</div>
        </body>
      </html>
    `, {
      url: 'http://localhost'
    });
    
    global.document = dom.window.document;
    global.window = dom.window;
    global.localStorage = dom.window.localStorage;

    // Clear localStorage
    localStorage.clear();

    // Mock APIClient
    apiClientMock = {
      post: vi.fn(),
      get: vi.fn(),
      setToken: vi.fn(),
      getToken: vi.fn(),
      clearToken: vi.fn()
    };

    // Create AuthManager mock with actual updateUI method
    authManager = {
      apiClient: apiClientMock,
      currentUser: null,
      sessionTimeout: 30 * 60 * 1000,
      
      isAuthenticated() {
        return this.currentUser !== null;
      },
      
      normalizeUserData(userData) {
        return {
          id: userData.id,
          email: userData.email,
          name: userData.full_name || userData.name,
          fullName: userData.full_name || userData.name,
          jobTitle: userData.job_title || userData.job_tittle || '',
          emailVerified: userData.email_verified || false,
          twoFactorEnabled: userData.two_factor_enabled || false,
          role: userData.role || 'user',
          createdAt: userData.created_at || new Date().toISOString(),
          lastLogin: userData.last_login || new Date().toISOString(),
          preferences: userData.preferences || {}
        };
      },
      
      saveUserSession(user) {
        try {
          const sessionData = {
            timestamp: Date.now(),
            userAgent: navigator.userAgent,
            ip: "127.0.0.1",
          };

          localStorage.setItem("cyberguard_user", JSON.stringify(user));
          localStorage.setItem("cyberguard_session", JSON.stringify(sessionData));
          this.currentUser = user;
          this.updateUI();
          return true;
        } catch (error) {
          console.error("Error saving user session:", error);
          return false;
        }
      },
      
      // Actual updateUI method from auth.js
      updateUI() {
        const authElements = document.querySelectorAll("[data-auth]");
        const guestElements = document.querySelectorAll("[data-guest]");
        const authRequiredElements = document.querySelectorAll("[data-auth-required]");

        if (this.isAuthenticated()) {
          document.body.classList.add("authenticated");
          document.body.classList.remove("guest");
          
          authElements.forEach((el) => {
            el.classList.remove("hidden");
            el.style.removeProperty("display");
          });
          
          guestElements.forEach((el) => {
            el.classList.add("hidden");
            el.style.removeProperty("display");
          });
          
          const guestNotice = document.getElementById("guest-notice");
          if (guestNotice) {
            guestNotice.classList.add("hidden");
            guestNotice.style.display = "none";
          }

          authRequiredElements.forEach((el) => {
            el.disabled = false;
            el.classList.remove("disabled");
          });

          // Update header user info section
          const userNameEl = document.getElementById("userName");
          const userEmailEl = document.getElementById("userEmail");
          const userInfoEl = document.getElementById("user-info");

          if (userNameEl) userNameEl.textContent = this.currentUser.fullName || this.currentUser.name;
          if (userEmailEl) userEmailEl.textContent = this.currentUser.email;
          
          if (userInfoEl) {
            userInfoEl.classList.remove("hidden");
          }

          // Update sidebar profile card with full_name and job_title
          const sidebarName = document.getElementById("sidebarUserName");
          const sidebarRole = document.getElementById("sidebarUserRole");
          const sidebarInitials = document.getElementById("sidebarUserInitials");
          
          if (sidebarName) {
            sidebarName.textContent = this.currentUser.fullName || this.currentUser.name;
          }
          
          if (sidebarRole) {
            sidebarRole.textContent = this.currentUser.jobTitle || this.currentUser.role || "Security Analyst";
          }
          
          // Calculate and display user initials from full_name
          if (sidebarInitials) {
            const fullName = this.currentUser.fullName || this.currentUser.name || '';
            const parts = fullName.trim().split(/\s+/);
            
            if (parts.length >= 2) {
              sidebarInitials.textContent = (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
            } else if (parts.length === 1 && parts[0].length >= 2) {
              sidebarInitials.textContent = parts[0].substring(0, 2).toUpperCase();
            } else {
              sidebarInitials.textContent = fullName.substring(0, 2).toUpperCase() || 'U';
            }
          }
        } else {
          document.body.classList.remove("authenticated");
          document.body.classList.add("guest");
          
          authElements.forEach((el) => {
            el.classList.add("hidden");
            el.style.removeProperty("display");
          });
          
          guestElements.forEach((el) => {
            el.classList.remove("hidden");
            el.style.removeProperty("display");
          });
          
          const guestNotice = document.getElementById("guest-notice");
          if (guestNotice) {
            guestNotice.classList.remove("hidden");
            guestNotice.style.display = "";
          }
        }
      }
    };
  });

  afterEach(() => {
    localStorage.clear();
  });

  describe('Authenticated User UI Updates', () => {
    it('should update header with full_name from session data', () => {
      // Arrange
      const userData = {
        id: 1,
        email: 'john.doe@example.com',
        full_name: 'John Doe',
        job_title: 'Senior Security Analyst'
      };
      const normalizedUser = authManager.normalizeUserData(userData);
      authManager.currentUser = normalizedUser;

      // Act
      authManager.updateUI();

      // Assert
      const userNameEl = document.getElementById('userName');
      expect(userNameEl.textContent).toBe('John Doe');
    });

    it('should update header with email from session data', () => {
      // Arrange
      const userData = {
        id: 1,
        email: 'john.doe@example.com',
        full_name: 'John Doe',
        job_title: 'Security Analyst'
      };
      const normalizedUser = authManager.normalizeUserData(userData);
      authManager.currentUser = normalizedUser;

      // Act
      authManager.updateUI();

      // Assert
      const userEmailEl = document.getElementById('userEmail');
      expect(userEmailEl.textContent).toBe('john.doe@example.com');
    });

    it('should show user-info section when authenticated', () => {
      // Arrange
      const userData = {
        id: 1,
        email: 'test@example.com',
        full_name: 'Test User',
        job_title: 'Analyst'
      };
      const normalizedUser = authManager.normalizeUserData(userData);
      authManager.currentUser = normalizedUser;

      // Act
      authManager.updateUI();

      // Assert
      const userInfoEl = document.getElementById('user-info');
      expect(userInfoEl.classList.contains('hidden')).toBe(false);
    });

    it('should update sidebar name with full_name', () => {
      // Arrange
      const userData = {
        id: 1,
        email: 'jane.smith@example.com',
        full_name: 'Jane Smith',
        job_title: 'Security Engineer'
      };
      const normalizedUser = authManager.normalizeUserData(userData);
      authManager.currentUser = normalizedUser;

      // Act
      authManager.updateUI();

      // Assert
      const sidebarName = document.getElementById('sidebarUserName');
      expect(sidebarName.textContent).toBe('Jane Smith');
    });

    it('should update sidebar role with job_title', () => {
      // Arrange
      const userData = {
        id: 1,
        email: 'test@example.com',
        full_name: 'Test User',
        job_title: 'Senior Penetration Tester'
      };
      const normalizedUser = authManager.normalizeUserData(userData);
      authManager.currentUser = normalizedUser;

      // Act
      authManager.updateUI();

      // Assert
      const sidebarRole = document.getElementById('sidebarUserRole');
      expect(sidebarRole.textContent).toBe('Senior Penetration Tester');
    });

    it('should calculate initials correctly for two-word names', () => {
      // Arrange
      const userData = {
        id: 1,
        email: 'john.doe@example.com',
        full_name: 'John Doe',
        job_title: 'Analyst'
      };
      const normalizedUser = authManager.normalizeUserData(userData);
      authManager.currentUser = normalizedUser;

      // Act
      authManager.updateUI();

      // Assert
      const sidebarInitials = document.getElementById('sidebarUserInitials');
      expect(sidebarInitials.textContent).toBe('JD');
    });

    it('should calculate initials correctly for three-word names', () => {
      // Arrange
      const userData = {
        id: 1,
        email: 'test@example.com',
        full_name: 'John Michael Doe',
        job_title: 'Analyst'
      };
      const normalizedUser = authManager.normalizeUserData(userData);
      authManager.currentUser = normalizedUser;

      // Act
      authManager.updateUI();

      // Assert
      const sidebarInitials = document.getElementById('sidebarUserInitials');
      expect(sidebarInitials.textContent).toBe('JD'); // First and last
    });

    it('should calculate initials correctly for single-word names', () => {
      // Arrange
      const userData = {
        id: 1,
        email: 'test@example.com',
        full_name: 'Madonna',
        job_title: 'Analyst'
      };
      const normalizedUser = authManager.normalizeUserData(userData);
      authManager.currentUser = normalizedUser;

      // Act
      authManager.updateUI();

      // Assert
      const sidebarInitials = document.getElementById('sidebarUserInitials');
      expect(sidebarInitials.textContent).toBe('MA'); // First two characters
    });

    it('should handle job_tittle typo from backend', () => {
      // Arrange
      const userData = {
        id: 1,
        email: 'test@example.com',
        full_name: 'Test User',
        job_tittle: 'Security Specialist' // Note the typo
      };
      const normalizedUser = authManager.normalizeUserData(userData);
      authManager.currentUser = normalizedUser;

      // Act
      authManager.updateUI();

      // Assert
      const sidebarRole = document.getElementById('sidebarUserRole');
      expect(sidebarRole.textContent).toBe('Security Specialist');
    });

    it('should fallback to role when job_title is missing', () => {
      // Arrange
      const userData = {
        id: 1,
        email: 'test@example.com',
        full_name: 'Test User',
        role: 'admin'
      };
      const normalizedUser = authManager.normalizeUserData(userData);
      authManager.currentUser = normalizedUser;

      // Act
      authManager.updateUI();

      // Assert
      const sidebarRole = document.getElementById('sidebarUserRole');
      expect(sidebarRole.textContent).toBe('admin');
    });

    it('should use default when both job_title and role are missing', () => {
      // Arrange
      const userData = {
        id: 1,
        email: 'test@example.com',
        full_name: 'Test User'
      };
      const normalizedUser = authManager.normalizeUserData(userData);
      authManager.currentUser = normalizedUser;

      // Act
      authManager.updateUI();

      // Assert
      const sidebarRole = document.getElementById('sidebarUserRole');
      // When jobTitle is empty string, it falls back to role ('user'), then to default
      expect(sidebarRole.textContent).toBe('user');
    });

    it('should hide guest elements when authenticated', () => {
      // Arrange
      const userData = {
        id: 1,
        email: 'test@example.com',
        full_name: 'Test User',
        job_title: 'Analyst'
      };
      const normalizedUser = authManager.normalizeUserData(userData);
      authManager.currentUser = normalizedUser;

      // Act
      authManager.updateUI();

      // Assert
      const guestActions = document.getElementById('guest-actions');
      const guestNotice = document.getElementById('guest-notice');
      expect(guestActions.classList.contains('hidden')).toBe(true);
      expect(guestNotice.classList.contains('hidden')).toBe(true);
    });
  });

  describe('Guest User UI Updates', () => {
    it('should hide user-info section when not authenticated', () => {
      // Arrange
      authManager.currentUser = null;

      // Act
      authManager.updateUI();

      // Assert
      const userInfoEl = document.getElementById('user-info');
      expect(userInfoEl.classList.contains('hidden')).toBe(true);
    });

    it('should show guest elements when not authenticated', () => {
      // Arrange
      authManager.currentUser = null;

      // Act
      authManager.updateUI();

      // Assert
      const guestActions = document.getElementById('guest-actions');
      const guestNotice = document.getElementById('guest-notice');
      expect(guestActions.classList.contains('hidden')).toBe(false);
      expect(guestNotice.classList.contains('hidden')).toBe(false);
    });
  });
});
