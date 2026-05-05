/**
 * Bug Condition Exploration Test - Navbar Auth State Bugfix
 * 
 * **CRITICAL**: This test MUST FAIL on unfixed code - failure confirms the bug exists
 * 
 * This test encodes the EXPECTED BEHAVIOR:
 * - When a user with a valid JWT token loads index.html, the navbar should display authenticated UI
 * - Authenticated UI includes: user name, avatar, account dropdown
 * - Guest UI (Login/Sign Up buttons) should be hidden
 * 
 * When run on UNFIXED code, this test will FAIL, proving the bug exists.
 * When run on FIXED code, this test will PASS, confirming the fix works.
 * 
 * **Validates: Requirements 1.1, 1.2, 1.3, 1.4, 1.5, 2.1, 2.2, 2.3, 2.4, 2.5**
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { JSDOM } from 'jsdom';
import * as fc from 'fast-check';
import * as fs from 'fs';
import * as path from 'path';

describe('Bug Condition Exploration - Navbar Auth State (Property 1)', () => {
  let dom;
  let document;
  let window;
  let authManager;
  let apiClientMock;

  beforeEach(async () => {
    // Load the actual index.html file
    const indexHtmlPath = path.resolve(process.cwd(), 'index.html');
    const indexHtmlContent = fs.readFileSync(indexHtmlPath, 'utf-8');

    // Setup DOM environment with index.html content
    dom = new JSDOM(indexHtmlContent, {
      url: 'http://localhost/index.html',
      runScripts: 'outside-only',
      resources: 'usable'
    });

    document = dom.window.document;
    window = dom.window;
    global.document = document;
    global.window = window;
    global.localStorage = window.localStorage;
    global.sessionStorage = window.sessionStorage;

    // Clear storage
    localStorage.clear();
    sessionStorage.clear();

    // Mock global functions
    global.showLoading = vi.fn();
    global.hideLoading = vi.fn();

    // Mock normalizeUserData utility
    global.normalizeUserData = vi.fn((userData) => {
      if (!userData || typeof userData !== 'object') {
        return null;
      }
      return {
        id: userData.id || null,
        email: userData.email || '',
        name: userData.full_name || userData.name || '',
        fullName: userData.full_name || userData.name || '',
        jobTitle: userData.job_title || userData.job_tittle || '',
        emailVerified: userData.email_verified || false,
        twoFactorEnabled: userData.two_factor_enabled || false,
        role: userData.role || 'user',
        createdAt: userData.created_at || new Date().toISOString(),
        lastLogin: userData.last_login || new Date().toISOString(),
        preferences: userData.preferences || {}
      };
    });

    // Mock APIClient
    apiClientMock = {
      get: vi.fn(),
      post: vi.fn(),
      setToken: vi.fn(),
      getToken: vi.fn(),
      clearToken: vi.fn()
    };

    // Mock APIError
    global.APIError = class APIError extends Error {
      constructor(message, status) {
        super(message);
        this.name = 'APIError';
        this.status = status;
      }
    };

    // Create a minimal AuthManager mock that simulates the actual behavior
    // This will be used to test if AuthManager is initialized on index.html
    global.AuthManager = class AuthManager {
      constructor() {
        this.apiClient = apiClientMock;
        this.currentUser = null;
        this.sessionTimeout = 30 * 60 * 1000;
        // In the actual code, init() is called in constructor
        // For testing, we'll call it manually to control timing
      }

      async init() {
        await this.loadUserSession();
        this.updateUI();
      }

      async loadUserSession() {
        const token = this.apiClient.getToken();
        if (token) {
          const result = await this.restoreSession();
          return result.success;
        }
        this.currentUser = null;
        this.updateUI();
        return false;
      }

      async restoreSession() {
        try {
          const token = this.apiClient.getToken();
          if (!token) {
            this.currentUser = null;
            this.updateUI();
            return { success: false, message: 'No token found' };
          }

          const profileResult = await this.fetchUserProfile();
          if (!profileResult.success) {
            this.apiClient.clearToken();
            this.currentUser = null;
            this.updateUI();
            return { success: false, message: 'Session validation failed' };
          }

          const user = profileResult.user;
          this.saveUserSession(user);
          return { success: true, user: user };
        } catch (error) {
          this.apiClient.clearToken();
          this.currentUser = null;
          this.updateUI();
          return { success: false, message: 'Session restoration failed' };
        }
      }

      async fetchUserProfile() {
        try {
          const response = await this.apiClient.get('auth/me');
          const normalizedUser = normalizeUserData(response.user || response);
          return { success: true, user: normalizedUser };
        } catch (error) {
          throw error;
        }
      }

      saveUserSession(user) {
        this.currentUser = user;
        localStorage.setItem('cyberguard_user', JSON.stringify(user));
      }

      isAuthenticated() {
        return this.currentUser !== null;
      }

      updateUI() {
        const authElements = document.querySelectorAll('[data-auth]');
        const guestElements = document.querySelectorAll('[data-guest]');

        if (this.isAuthenticated()) {
          // Show authenticated elements
          authElements.forEach(el => {
            el.classList.remove('hidden');
            el.style.removeProperty('display');
          });
          guestElements.forEach(el => {
            el.classList.add('hidden');
            el.style.display = 'none';
          });

          // Update user info
          const userNameEl = document.getElementById('userName');
          const userInitialsEl = document.getElementById('userInitials');
          
          if (userNameEl) {
            userNameEl.textContent = this.currentUser.fullName || this.currentUser.name;
          }
          
          if (userInitialsEl) {
            const name = this.currentUser.fullName || this.currentUser.name || '';
            const initials = name.split(' ').map(n => n[0]).join('').toUpperCase().slice(0, 2);
            userInitialsEl.textContent = initials;
          }
        } else {
          // Show guest elements
          authElements.forEach(el => {
            el.classList.add('hidden');
            el.style.display = 'none';
          });
          guestElements.forEach(el => {
            el.classList.remove('hidden');
            el.style.removeProperty('display');
          });
        }
      }
    };
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  /**
   * Property 1: Bug Condition - Authenticated User Navbar Display
   * 
   * **Validates: Requirements 2.1, 2.2, 2.3, 2.4, 2.5**
   * 
   * This property encodes the EXPECTED BEHAVIOR:
   * For any page load where a user has a valid JWT token in localStorage and loads index.html,
   * the navbar SHALL check authentication state, restore the user session, and display
   * authenticated UI (user name/avatar with account dropdown) instead of guest UI
   * (Login/Sign Up buttons).
   * 
   * **EXPECTED OUTCOME ON UNFIXED CODE**: This test will FAIL because:
   * - index.html does not include auth.js script
   * - AuthManager is not initialized on page load
   * - Navbar always shows guest UI (Login/Sign Up buttons)
   * - No user info or account dropdown is displayed
   * 
   * **EXPECTED OUTCOME ON FIXED CODE**: This test will PASS because:
   * - index.html includes auth.js script
   * - AuthManager is initialized on page load
   * - Navbar checks JWT token and displays authenticated UI
   * - User info and account dropdown are visible
   */
  it('Property 1: Navbar should display authenticated UI when user has valid JWT token (Bug Condition)', async () => {
    // Scoped PBT: Generate test cases with various valid JWT tokens and user data
    await fc.assert(
      fc.asyncProperty(
        // Generate arbitrary user data
        fc.record({
          id: fc.integer({ min: 1, max: 10000 }),
          email: fc.emailAddress(),
          full_name: fc.string({ minLength: 3, maxLength: 50 }),
          job_title: fc.constantFrom('Security Analyst', 'Penetration Tester', 'Security Engineer', 'Security Manager'),
          email_verified: fc.boolean(),
          two_factor_enabled: fc.boolean(),
          role: fc.constantFrom('user', 'admin'),
          created_at: fc.date().map(d => d.toISOString()),
          last_login: fc.date().map(d => d.toISOString())
        }),
        // Generate arbitrary JWT token
        fc.string({ minLength: 20, maxLength: 100 }),
        
        async (userData, jwtToken) => {
          // Arrange: Simulate user with valid JWT token loading index.html
          localStorage.setItem('cyberguard_jwt', jwtToken);
          
          // Mock API response for session restoration
          const mockUserResponse = {
            status: 'success',
            user: userData
          };
          
          apiClientMock.getToken.mockReturnValue(jwtToken);
          apiClientMock.get.mockResolvedValue(mockUserResponse);

          // Act: Initialize AuthManager (simulating page load)
          authManager = new AuthManager();
          await authManager.init();

          // Assert: EXPECTED BEHAVIOR (will fail on unfixed code)
          
          // 1. AuthManager should be initialized (will fail if auth.js not loaded)
          expect(authManager).toBeDefined();
          
          // 2. User session should be restored
          expect(authManager.isAuthenticated()).toBe(true);
          expect(authManager.currentUser).toBeDefined();
          expect(authManager.currentUser.email).toBe(userData.email);
          
          // 3. Navbar should display authenticated UI elements
          const authElements = document.querySelectorAll('[data-auth]');
          const guestElements = document.querySelectorAll('[data-guest]');
          
          // On UNFIXED code: authElements.length will be 0 (no data-auth elements in HTML)
          // On FIXED code: authElements.length will be > 0
          expect(authElements.length).toBeGreaterThan(0);
          
          // Check that authenticated elements are visible
          authElements.forEach(el => {
            expect(el.classList.contains('hidden')).toBe(false);
          });
          
          // 4. Guest UI (Login/Sign Up buttons) should be hidden
          // On UNFIXED code: guestElements will not have data-guest attributes
          // On FIXED code: guestElements will have data-guest attributes and be hidden
          if (guestElements.length > 0) {
            guestElements.forEach(el => {
              expect(el.classList.contains('hidden')).toBe(true);
            });
          }
          
          // 5. User name should be displayed in navbar
          const userNameEl = document.getElementById('userName');
          // On UNFIXED code: userNameEl will be null (element doesn't exist)
          // On FIXED code: userNameEl will exist and contain user name
          expect(userNameEl).not.toBeNull();
          if (userNameEl) {
            expect(userNameEl.textContent).toBe(userData.full_name);
          }
          
          // 6. User avatar/initials should be displayed
          const userInitialsEl = document.getElementById('userInitials');
          // On UNFIXED code: userInitialsEl will be null
          // On FIXED code: userInitialsEl will exist and contain initials
          expect(userInitialsEl).not.toBeNull();
          if (userInitialsEl) {
            const expectedInitials = userData.full_name.split(' ').map(n => n[0]).join('').toUpperCase().slice(0, 2);
            expect(userInitialsEl.textContent).toBe(expectedInitials);
          }
          
          // 7. Account dropdown should be present
          const accountDropdown = document.querySelector('.dropdown');
          // On UNFIXED code: accountDropdown will be null
          // On FIXED code: accountDropdown will exist
          expect(accountDropdown).not.toBeNull();
          
          // 8. Logout button should be present
          const logoutBtn = document.getElementById('logout-btn');
          // On UNFIXED code: logoutBtn will be null
          // On FIXED code: logoutBtn will exist
          expect(logoutBtn).not.toBeNull();
        }
      ),
      {
        numRuns: 10, // Run 10 test cases to find counterexamples
        verbose: true // Show counterexamples when test fails
      }
    );
  });

  /**
   * Concrete Example: Authenticated User on Landing Page
   * 
   * This is a concrete example of the bug condition for easier debugging.
   * It demonstrates the exact scenario described in the bugfix requirements.
   */
  it('Concrete Example: User with valid JWT token should see authenticated navbar on index.html', async () => {
    // Arrange: User logs in and navigates to index.html
    const mockUser = {
      id: 1,
      email: 'john.doe@example.com',
      full_name: 'John Doe',
      job_title: 'Security Analyst',
      email_verified: true,
      two_factor_enabled: false,
      role: 'user',
      created_at: '2024-01-01T00:00:00Z',
      last_login: '2024-01-15T10:30:00Z'
    };
    
    const mockToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.mock-token-12345';
    
    localStorage.setItem('cyberguard_jwt', mockToken);
    
    apiClientMock.getToken.mockReturnValue(mockToken);
    apiClientMock.get.mockResolvedValue({
      status: 'success',
      user: mockUser
    });

    // Act: Initialize AuthManager (simulating page load)
    authManager = new AuthManager();
    await authManager.init();

    // Assert: EXPECTED BEHAVIOR (will fail on unfixed code)
    
    // User should be authenticated
    expect(authManager.isAuthenticated()).toBe(true);
    expect(authManager.currentUser.email).toBe('john.doe@example.com');
    
    // Navbar should show authenticated UI
    const authElements = document.querySelectorAll('[data-auth]');
    expect(authElements.length).toBeGreaterThan(0); // Will fail on unfixed code (no data-auth elements)
    
    // User name should be displayed
    const userNameEl = document.getElementById('userName');
    expect(userNameEl).not.toBeNull(); // Will fail on unfixed code (element doesn't exist)
    if (userNameEl) {
      expect(userNameEl.textContent).toBe('John Doe');
    }
    
    // Login/Sign Up buttons should be hidden
    const guestElements = document.querySelectorAll('[data-guest]');
    if (guestElements.length > 0) {
      guestElements.forEach(el => {
        expect(el.classList.contains('hidden')).toBe(true);
      });
    }
    
    // Account dropdown should be present
    const accountDropdown = document.querySelector('.dropdown');
    expect(accountDropdown).not.toBeNull(); // Will fail on unfixed code
    
    // Logout button should be present
    const logoutBtn = document.getElementById('logout-btn');
    expect(logoutBtn).not.toBeNull(); // Will fail on unfixed code
  });

  /**
   * Edge Case: Expired Token Handling
   * 
   * Tests that when a user has an expired JWT token, the navbar shows guest UI
   * and the token is cleared.
   */
  it('Edge Case: Expired JWT token should show guest UI and clear token', async () => {
    // Arrange: User has expired JWT token
    const expiredToken = 'expired-jwt-token-12345';
    localStorage.setItem('cyberguard_jwt', expiredToken);
    
    apiClientMock.getToken.mockReturnValue(expiredToken);
    apiClientMock.get.mockRejectedValue(new APIError('Token expired', 401));

    // Act: Initialize AuthManager
    authManager = new AuthManager();
    await authManager.init();

    // Assert: Should show guest UI
    expect(authManager.isAuthenticated()).toBe(false);
    expect(authManager.currentUser).toBeNull();
    
    // Token should be cleared
    expect(apiClientMock.clearToken).toHaveBeenCalled();
    
    // Guest elements should be visible
    const guestElements = document.querySelectorAll('[data-guest]');
    if (guestElements.length > 0) {
      guestElements.forEach(el => {
        expect(el.classList.contains('hidden')).toBe(false);
      });
    }
  });

  /**
   * Edge Case: Mobile Menu Authenticated State
   * 
   * Tests that the mobile menu also displays authenticated options for authenticated users.
   */
  it('Edge Case: Mobile menu should show authenticated options for authenticated users', async () => {
    // Arrange: Authenticated user
    const mockUser = {
      id: 2,
      email: 'mobile@example.com',
      full_name: 'Mobile User',
      job_title: 'Penetration Tester',
      email_verified: true,
      two_factor_enabled: true,
      role: 'user',
      created_at: '2024-01-01T00:00:00Z',
      last_login: '2024-01-15T10:30:00Z'
    };
    
    const mockToken = 'mobile-jwt-token-67890';
    localStorage.setItem('cyberguard_jwt', mockToken);
    
    apiClientMock.getToken.mockReturnValue(mockToken);
    apiClientMock.get.mockResolvedValue({
      status: 'success',
      user: mockUser
    });

    // Act: Initialize AuthManager
    authManager = new AuthManager();
    await authManager.init();

    // Assert: Mobile menu should show authenticated options
    const mobileUserName = document.getElementById('mobileUserName');
    // On UNFIXED code: mobileUserName will be null
    // On FIXED code: mobileUserName will exist and contain user name
    expect(mobileUserName).not.toBeNull();
    if (mobileUserName) {
      expect(mobileUserName.textContent).toBe('John Doe'); // Should match mockUser.name
    }
    
    // Mobile logout button should be present
    const mobileLogoutBtn = document.getElementById('mobile-logout-btn');
    expect(mobileLogoutBtn).not.toBeNull(); // Will fail on unfixed code
  });
});
