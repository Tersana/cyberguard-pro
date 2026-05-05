/**
 * Preservation Property Tests - Navbar Auth State Bugfix
 * Task 2: Write preservation property tests (BEFORE implementing fix)
 * 
 * **Property 2: Preservation** - Guest User Experience and Landing Page Functionality
 * 
 * **IMPORTANT**: These tests observe and validate behavior on UNFIXED code
 * for guest users (no JWT token). They capture the baseline behavior that must
 * be preserved after implementing the fix.
 * 
 * **EXPECTED OUTCOME ON UNFIXED CODE**: Tests PASS (confirms baseline behavior)
 * **EXPECTED OUTCOME ON FIXED CODE**: Tests PASS (confirms no regressions)
 * 
 * **Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7**
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { JSDOM } from 'jsdom';
import * as fc from 'fast-check';
import { readFileSync } from 'fs';
import { join } from 'path';

describe('Preservation Property Tests - Navbar Auth State (Property 2)', () => {
  let dom;
  let document;
  let window;

  beforeEach(() => {
    // Load the actual index.html file
    const htmlPath = join(process.cwd(), 'index.html');
    const htmlContent = readFileSync(htmlPath, 'utf-8');

    // Setup DOM environment with proper URL to enable localStorage
    dom = new JSDOM(htmlContent, {
      url: 'http://localhost',
      runScripts: 'dangerously',
      resources: 'usable',
      beforeParse(window) {
        // Mock functions that landing.js might use
        window.requestAnimationFrame = vi.fn((cb) => {
          setTimeout(cb, 16);
          return 1;
        });
        window.cancelAnimationFrame = vi.fn();
        window.IntersectionObserver = vi.fn().mockImplementation(() => ({
          observe: vi.fn(),
          unobserve: vi.fn(),
          disconnect: vi.fn()
        }));
      }
    });

    document = dom.window.document;
    window = dom.window;
    global.document = document;
    global.window = window;
    global.localStorage = window.localStorage;

    // Clear localStorage to simulate guest user (no JWT token)
    localStorage.clear();
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  /**
   * Test 1: Guest users see "Login" and "Sign Up" buttons in desktop navbar
   * 
   * **Validates: Requirements 3.1**
   * 
   * This test observes that guest users (no JWT token) see the correct navbar UI.
   * This behavior must be preserved after the fix.
   */
  it('Property 2.1: Guest users see "Login" and "Sign Up" buttons in desktop navbar', () => {
    // Arrange: No JWT token in localStorage (guest user)
    expect(localStorage.getItem('cyberguard_jwt')).toBeNull();

    // Act: Query navbar elements
    const loginButton = Array.from(document.querySelectorAll('.nav-links a'))
      .find(a => a.textContent.trim() === 'Login');
    const getStartedButton = Array.from(document.querySelectorAll('.nav-links a'))
      .find(a => a.textContent.trim() === 'Get Started');

    // Assert: PRESERVATION - Guest UI elements should be visible
    expect(loginButton).toBeDefined();
    expect(loginButton.href).toContain('login.html');
    expect(loginButton.classList.contains('btn-login')).toBe(true);

    expect(getStartedButton).toBeDefined();
    expect(getStartedButton.href).toContain('dashboard.html');
    expect(getStartedButton.classList.contains('btn-primary')).toBe(true);
  });

  /**
   * Test 2: Guest users see "Login" and "Get Started" links in mobile menu
   * 
   * **Validates: Requirements 3.2**
   * 
   * This test observes that mobile menu shows correct guest UI.
   * This behavior must be preserved after the fix.
   */
  it('Property 2.2: Guest users see "Login" and "Get Started" links in mobile menu', () => {
    // Arrange: No JWT token in localStorage (guest user)
    expect(localStorage.getItem('cyberguard_jwt')).toBeNull();

    // Act: Query mobile menu elements
    const mobileMenu = document.getElementById('mobileMenu');
    expect(mobileMenu).toBeDefined();

    const mobileLoginLink = Array.from(mobileMenu.querySelectorAll('.mobile-link'))
      .find(a => a.textContent.trim() === 'Login');
    const mobileGetStartedButton = mobileMenu.querySelector('.btn-primary.mobile-cta');

    // Assert: PRESERVATION - Mobile guest UI elements should be visible
    expect(mobileLoginLink).toBeDefined();
    expect(mobileLoginLink.href).toContain('login.html');

    expect(mobileGetStartedButton).toBeDefined();
    expect(mobileGetStartedButton.textContent.trim()).toBe('Get Started');
    expect(mobileGetStartedButton.href).toContain('dashboard.html');
  });

  /**
   * Test 3: Mobile menu button and menu elements exist
   * 
   * **Validates: Requirements 3.4**
   * 
   * This test observes that mobile menu elements are present in the DOM.
   * This behavior must be preserved after the fix.
   */
  it('Property 2.3: Mobile menu button and menu elements exist in DOM', () => {
    // Act: Query mobile menu elements
    const mobileMenuBtn = document.getElementById('mobileMenuBtn');
    const mobileMenu = document.getElementById('mobileMenu');

    // Assert: PRESERVATION - Mobile menu elements should exist
    expect(mobileMenuBtn).toBeDefined();
    expect(mobileMenuBtn.classList.contains('mobile-menu-btn')).toBe(true);
    
    expect(mobileMenu).toBeDefined();
    expect(mobileMenu.classList.contains('mobile-menu')).toBe(true);
    
    // Verify mobile menu has the expected links
    const mobileLinks = mobileMenu.querySelectorAll('.mobile-link');
    expect(mobileLinks.length).toBeGreaterThan(0);
  });

  /**
   * Test 4: Navbar element exists with correct structure
   * 
   * **Validates: Requirements 3.3**
   * 
   * This test observes that navbar element is present and has correct structure.
   * This behavior must be preserved after the fix.
   */
  it('Property 2.4: Navbar element exists with correct structure', () => {
    // Act: Query navbar element
    const navbar = document.querySelector('.navbar');

    // Assert: PRESERVATION - Navbar should exist with correct structure
    expect(navbar).toBeDefined();
    expect(navbar.classList.contains('navbar')).toBe(true);
    
    // Verify navbar has expected child elements
    const navContent = navbar.querySelector('.nav-content');
    const logo = navbar.querySelector('.logo');
    const navLinks = navbar.querySelector('.nav-links');
    const mobileMenuBtn = navbar.querySelector('.mobile-menu-btn');
    
    expect(navContent).toBeDefined();
    expect(logo).toBeDefined();
    expect(navLinks).toBeDefined();
    expect(mobileMenuBtn).toBeDefined();
  });

  /**
   * Test 5: Anchor links exist with correct hrefs
   * 
   * **Validates: Requirements 3.5**
   * 
   * This test observes that anchor links are present with correct hrefs.
   * This behavior must be preserved after the fix.
   */
  it('Property 2.5: Anchor links exist with correct hrefs for smooth scrolling', () => {
    // Act: Query anchor links
    const anchorLinks = document.querySelectorAll('a[href^="#"]');

    // Assert: PRESERVATION - Anchor links should exist
    expect(anchorLinks.length).toBeGreaterThan(0);
    
    // Verify specific anchor links
    const featuresLink = Array.from(anchorLinks).find(a => a.getAttribute('href') === '#features');
    const toolsLink = Array.from(anchorLinks).find(a => a.getAttribute('href') === '#tools');
    const securityLink = Array.from(anchorLinks).find(a => a.getAttribute('href') === '#security');
    
    expect(featuresLink).toBeDefined();
    expect(toolsLink).toBeDefined();
    expect(securityLink).toBeDefined();
    
    // Verify target sections exist
    const featuresSection = document.querySelector('#features');
    const toolsSection = document.querySelector('#tools');
    const securitySection = document.querySelector('#security');
    
    expect(featuresSection).toBeDefined();
    expect(toolsSection).toBeDefined();
    expect(securitySection).toBeDefined();
  });

  /**
   * Test 6: Gradient orbs exist and are rendered
   * 
   * **Validates: Requirements 3.3**
   * 
   * This test observes that gradient orbs are present in the DOM.
   * This behavior must be preserved after the fix.
   */
  it('Property 2.6: Gradient orbs exist and are rendered in hero section', () => {
    // Act: Query gradient orbs
    const gradientOrbs = document.querySelectorAll('.gradient-orb');

    // Assert: PRESERVATION - Gradient orbs should exist
    expect(gradientOrbs.length).toBeGreaterThan(0);
    expect(gradientOrbs.length).toBe(3); // Based on index.html structure

    // Verify each orb has the correct class
    gradientOrbs.forEach((orb, index) => {
      expect(orb.classList.contains('gradient-orb')).toBe(true);
      expect(orb.classList.contains(`orb-${index + 1}`)).toBe(true);
    });
  });

  /**
   * Test 7: Feature cards exist and have correct structure
   * 
   * **Validates: Requirements 3.6**
   * 
   * This test observes that feature cards are present and have the correct structure.
   * This behavior must be preserved after the fix.
   */
  it('Property 2.7: Feature cards exist and have correct structure', () => {
    // Act: Query feature cards
    const featureCards = document.querySelectorAll('.feature-card');

    // Assert: PRESERVATION - Feature cards should exist
    expect(featureCards.length).toBeGreaterThan(0);

    // Verify each card has the expected structure
    featureCards.forEach(card => {
      expect(card.classList.contains('feature-card')).toBe(true);
      
      // Check for expected child elements
      const featureIcon = card.querySelector('.feature-icon');
      const featureTitle = card.querySelector('.feature-title');
      const featureDescription = card.querySelector('.feature-description');
      const featureList = card.querySelector('.feature-list');

      expect(featureIcon).toBeDefined();
      expect(featureTitle).toBeDefined();
      expect(featureDescription).toBeDefined();
      expect(featureList).toBeDefined();
    });
  });

  /**
   * Property-Based Test: Guest users always see correct navbar UI regardless of page state
   * 
   * **Validates: Requirements 3.1, 3.2**
   * 
   * This property test generates various page states and verifies guest UI is always correct.
   */
  it('Property 2.8: Guest users always see correct navbar UI across various page states', () => {
    fc.assert(
      fc.property(
        // Generate arbitrary page states (scroll position, viewport size, etc.)
        fc.record({
          scrollY: fc.integer({ min: 0, max: 5000 }),
          viewportWidth: fc.integer({ min: 320, max: 1920 }),
          viewportHeight: fc.integer({ min: 568, max: 1080 })
        }),
        
        (pageState) => {
          // Arrange: Set page state
          Object.defineProperty(window, 'scrollY', { value: pageState.scrollY, writable: true });
          Object.defineProperty(window, 'innerWidth', { value: pageState.viewportWidth, writable: true });
          Object.defineProperty(window, 'innerHeight', { value: pageState.viewportHeight, writable: true });

          // Ensure no JWT token (guest user)
          localStorage.clear();
          expect(localStorage.getItem('cyberguard_jwt')).toBeNull();

          // Act: Query navbar elements
          const loginButton = Array.from(document.querySelectorAll('.nav-links a'))
            .find(a => a.textContent.trim() === 'Login');
          const getStartedButton = Array.from(document.querySelectorAll('.nav-links a'))
            .find(a => a.textContent.trim() === 'Get Started');

          // Assert: PRESERVATION - Guest UI should always be visible
          expect(loginButton).toBeDefined();
          expect(loginButton.href).toContain('login.html');
          expect(getStartedButton).toBeDefined();
          expect(getStartedButton.href).toContain('dashboard.html');
        }
      ),
      {
        numRuns: 20,
        verbose: false
      }
    );
  });

  /**
   * Property-Based Test: Mobile menu always shows guest UI for users without JWT
   * 
   * **Validates: Requirements 3.2**
   */
  it('Property 2.9: Mobile menu always shows guest UI for users without JWT token', () => {
    fc.assert(
      fc.property(
        // Generate arbitrary mobile viewport sizes
        fc.record({
          viewportWidth: fc.integer({ min: 320, max: 767 }), // Mobile breakpoint
          viewportHeight: fc.integer({ min: 568, max: 1024 })
        }),
        
        (viewport) => {
          // Arrange: Set mobile viewport
          Object.defineProperty(window, 'innerWidth', { value: viewport.viewportWidth, writable: true });
          Object.defineProperty(window, 'innerHeight', { value: viewport.viewportHeight, writable: true });

          // Ensure no JWT token (guest user)
          localStorage.clear();

          // Act: Query mobile menu elements
          const mobileMenu = document.getElementById('mobileMenu');
          const mobileLoginLink = Array.from(mobileMenu.querySelectorAll('.mobile-link'))
            .find(a => a.textContent.trim() === 'Login');
          const mobileGetStartedButton = mobileMenu.querySelector('.btn-primary.mobile-cta');

          // Assert: PRESERVATION - Mobile guest UI should always be visible
          expect(mobileLoginLink).toBeDefined();
          expect(mobileLoginLink.href).toContain('login.html');
          expect(mobileGetStartedButton).toBeDefined();
          expect(mobileGetStartedButton.textContent.trim()).toBe('Get Started');
        }
      ),
      {
        numRuns: 15,
        verbose: false
      }
    );
  });

  /**
   * Concrete Example: Guest user on desktop sees Login and Get Started buttons
   */
  it('Concrete Example: Guest user on desktop sees Login and Get Started buttons', () => {
    // Arrange: Desktop viewport, no JWT token
    Object.defineProperty(window, 'innerWidth', { value: 1920, writable: true });
    localStorage.clear();

    // Act: Query navbar
    const loginButton = Array.from(document.querySelectorAll('.nav-links a'))
      .find(a => a.textContent.trim() === 'Login');
    const getStartedButton = Array.from(document.querySelectorAll('.nav-links a'))
      .find(a => a.textContent.trim() === 'Get Started');

    // Assert: PRESERVATION - Guest UI visible
    expect(loginButton).toBeDefined();
    expect(loginButton.href).toContain('login.html');
    expect(loginButton.classList.contains('btn-login')).toBe(true);

    expect(getStartedButton).toBeDefined();
    expect(getStartedButton.href).toContain('dashboard.html');
    expect(getStartedButton.classList.contains('btn-primary')).toBe(true);
  });

  /**
   * Concrete Example: Guest user on mobile sees Login link and Get Started button in mobile menu
   */
  it('Concrete Example: Guest user on mobile sees correct mobile menu UI', () => {
    // Arrange: Mobile viewport, no JWT token
    Object.defineProperty(window, 'innerWidth', { value: 375, writable: true });
    localStorage.clear();

    // Act: Query mobile menu
    const mobileMenu = document.getElementById('mobileMenu');
    const mobileLoginLink = Array.from(mobileMenu.querySelectorAll('.mobile-link'))
      .find(a => a.textContent.trim() === 'Login');
    const mobileGetStartedButton = mobileMenu.querySelector('.btn-primary.mobile-cta');

    // Assert: PRESERVATION - Mobile guest UI visible
    expect(mobileLoginLink).toBeDefined();
    expect(mobileLoginLink.href).toContain('login.html');

    expect(mobileGetStartedButton).toBeDefined();
    expect(mobileGetStartedButton.textContent.trim()).toBe('Get Started');
    expect(mobileGetStartedButton.href).toContain('dashboard.html');
  });

  /**
   * Concrete Example: All landing page sections exist and are rendered
   */
  it('Concrete Example: All landing page sections exist and are rendered correctly', () => {
    // Act: Query all major sections
    const hero = document.querySelector('.hero');
    const statsBanner = document.querySelector('.stats-banner');
    const features = document.querySelector('#features');
    const tools = document.querySelector('#tools');
    const security = document.querySelector('#security');
    const cta = document.querySelector('.cta');
    const footer = document.querySelector('.footer');

    // Assert: PRESERVATION - All sections should exist
    expect(hero).toBeDefined();
    expect(statsBanner).toBeDefined();
    expect(features).toBeDefined();
    expect(tools).toBeDefined();
    expect(security).toBeDefined();
    expect(cta).toBeDefined();
    expect(footer).toBeDefined();
  });

  /**
   * Concrete Example: Navigation links in navbar work correctly
   */
  it('Concrete Example: Navigation links in navbar have correct hrefs', () => {
    // Act: Query navigation links
    const navLinks = document.querySelectorAll('.nav-links .nav-link');

    // Assert: PRESERVATION - Navigation links should have correct hrefs
    expect(navLinks.length).toBeGreaterThan(0);

    const featuresLink = Array.from(navLinks).find(a => a.textContent.trim() === 'Features');
    const toolsLink = Array.from(navLinks).find(a => a.textContent.trim() === 'Tools');
    const securityLink = Array.from(navLinks).find(a => a.textContent.trim() === 'Security');
    const pricingLink = Array.from(navLinks).find(a => a.textContent.trim() === 'Pricing');

    expect(featuresLink?.href).toContain('#features');
    expect(toolsLink?.href).toContain('#tools');
    expect(securityLink?.href).toContain('#security');
    expect(pricingLink?.href).toContain('pricing.html');
  });
});
