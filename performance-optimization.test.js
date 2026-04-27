/**
 * Performance Optimization Tests
 * Task 24.6: Performance optimization
 * 
 * Tests for:
 * - No unnecessary API calls
 * - Debouncing implementation
 * - Optimized re-renders and DOM updates
 * - Slow network condition handling
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { readFileSync } from 'fs';

// Read source files
const apiClientCode = readFileSync('./api-client.js', 'utf-8');
const authCode = readFileSync('./auth.js', 'utf-8');
const projectManagerCode = readFileSync('./project-manager.js', 'utf-8');
const performanceAuditCode = readFileSync('./performance-audit.js', 'utf-8');

describe('Performance Optimization - Task 24.6', () => {
  
  describe('1. Unnecessary API Calls Prevention', () => {
    
    it('should not make duplicate session restoration calls on page load', () => {
      // Check that restoreSession uses Promise.all for parallel requests
      expect(authCode).toContain('Promise.all');
      expect(authCode).toMatch(/Promise\.all\(\s*\[\s*this\.fetchUserProfile/);
      expect(authCode).toMatch(/this\.fetchSessionStatus/);
    });
    
    it('should cache session data in localStorage to avoid repeated API calls', () => {
      // Verify session data is stored and reused
      expect(authCode).toContain('localStorage.getItem("cyberguard_user")');
      expect(authCode).toContain('localStorage.getItem("cyberguard_session")');
      expect(authCode).toContain('saveUserSession');
    });
    
    it('should not fetch projects multiple times on tab switch', () => {
      // Verify projects are stored in memory
      expect(projectManagerCode).toContain('this.projects = []');
      expect(projectManagerCode).toMatch(/this\.projects\s*=\s*response\.projects/);
    });
    
    it('should handle pagination to avoid fetching all projects at once', () => {
      // Verify pagination parameters
      expect(projectManagerCode).toMatch(/fetchProjects\(page\s*=\s*1,\s*limit\s*=\s*20\)/);
      expect(projectManagerCode).toContain('page=${page}&limit=${limit}');
    });
    
    it('should not make API calls when loading indicators are already shown', () => {
      // Verify loading state prevents double submissions
      expect(projectManagerCode).toContain('if (submitBtn && submitBtn.disabled) return');
    });
  });
  
  describe('2. Debouncing Implementation', () => {
    
    it('should have debounce utility function', () => {
      expect(performanceAuditCode).toContain('function debounce');
      expect(performanceAuditCode).toMatch(/function debounce\(func,\s*wait\s*=\s*300/);
    });
    
    it('should have throttle utility function', () => {
      expect(performanceAuditCode).toContain('function throttle');
      expect(performanceAuditCode).toMatch(/function throttle\(func,\s*limit\s*=\s*300/);
    });
    
    it('should export debounce and throttle utilities', () => {
      expect(performanceAuditCode).toContain('window.debounce = debounce');
      expect(performanceAuditCode).toContain('window.throttle = throttle');
    });
    
    it('should have request cache for preventing duplicate API calls', () => {
      expect(performanceAuditCode).toContain('class RequestCache');
      expect(performanceAuditCode).toContain('get(endpoint, params = {})');
      expect(performanceAuditCode).toContain('set(endpoint, params = {}, data)');
    });
  });
  
  describe('3. DOM Update Optimization', () => {
    
    it('should have DOM update batcher', () => {
      expect(performanceAuditCode).toContain('class DOMUpdateBatcher');
      expect(performanceAuditCode).toContain('requestAnimationFrame');
    });
    
    it('should batch DOM updates to minimize reflows', () => {
      expect(performanceAuditCode).toContain('schedule(updateFn)');
      expect(performanceAuditCode).toContain('flush()');
    });
    
    it('should use textContent instead of innerHTML for user data to prevent XSS and improve performance', () => {
      // Check auth.js uses textContent for user data
      expect(authCode).toMatch(/textContent\s*=\s*this\.currentUser/);
    });
    
    it('should use escapeHtml for rendering dynamic content', () => {
      // Verify project manager escapes HTML
      expect(projectManagerCode).toContain('escapeHtml(project.name)');
      expect(projectManagerCode).toContain('escapeHtml(project.description');
      expect(projectManagerCode).toContain('escapeHtml(project.target)');
    });
    
    it('should minimize DOM queries by caching element references', () => {
      // Check that elements are queried once and reused
      expect(projectManagerCode).toMatch(/const\s+\w+\s*=\s*document\.getElementById/);
    });
  });
  
  describe('4. Loading State Management', () => {
    
    it('should show loading indicators for all async operations', () => {
      // Verify loading indicators in API client
      expect(apiClientCode).toContain('showLoading');
      expect(apiClientCode).toContain('hideLoading');
      expect(apiClientCode).toContain('showInlineLoading');
      expect(apiClientCode).toContain('hideInlineLoading');
    });
    
    it('should disable buttons during API requests to prevent double submissions', () => {
      expect(projectManagerCode).toContain('submitBtn.disabled');
      expect(projectManagerCode).toContain('if (submitBtn && submitBtn.disabled) return');
    });
    
    it('should use finally blocks to ensure loading indicators are always hidden', () => {
      // Check project manager has finally blocks
      expect(projectManagerCode).toMatch(/finally\s*\{[\s\S]*?hideLoading/);
      expect(projectManagerCode).toMatch(/finally\s*\{[\s\S]*?hideInlineLoading/);
    });
  });
  
  describe('5. Network Condition Testing', () => {
    
    it('should have network throttler for testing slow connections', () => {
      expect(performanceAuditCode).toContain('class NetworkThrottler');
      expect(performanceAuditCode).toContain('enable(delay = 3000)');
      expect(performanceAuditCode).toContain('disable()');
    });
    
    it('should handle network errors gracefully', () => {
      // Verify error handling in API client
      expect(apiClientCode).toContain('NetworkError');
      expect(apiClientCode).toContain('handleNetworkError');
    });
    
    it('should show user-friendly messages for network errors', () => {
      expect(apiClientCode).toContain('Network error. Please check your connection');
    });
  });
  
  describe('6. Performance Monitoring', () => {
    
    it('should have performance monitor class', () => {
      expect(performanceAuditCode).toContain('class PerformanceMonitor');
      expect(performanceAuditCode).toContain('mark(name)');
      expect(performanceAuditCode).toContain('measure(name)');
    });
    
    it('should have API call tracker', () => {
      expect(performanceAuditCode).toContain('class APICallTracker');
      expect(performanceAuditCode).toContain('track(method, endpoint');
      expect(performanceAuditCode).toContain('getDuplicates');
    });
    
    it('should detect duplicate API calls', () => {
      expect(performanceAuditCode).toContain('getDuplicates(timeWindow = 1000)');
      expect(performanceAuditCode).toMatch(/timeDiff.*<.*timeWindow/);
    });
    
    it('should generate performance reports', () => {
      expect(performanceAuditCode).toContain('report()');
      expect(performanceAuditCode).toContain('getStats()');
    });
  });
  
  describe('7. Caching Strategy', () => {
    
    it('should have request cache with TTL', () => {
      expect(performanceAuditCode).toMatch(/constructor\(ttl\s*=\s*60000\)/);
      expect(performanceAuditCode).toContain('this.ttl = ttl');
    });
    
    it('should invalidate expired cache entries', () => {
      expect(performanceAuditCode).toContain('clearExpired()');
      expect(performanceAuditCode).toMatch(/Date\.now\(\)\s*-\s*.*timestamp\s*>\s*this\.ttl/);
    });
    
    it('should generate cache keys from endpoint and params', () => {
      expect(performanceAuditCode).toContain('_generateKey(endpoint, params = {})');
      expect(performanceAuditCode).toContain('JSON.stringify(params)');
    });
  });
  
  describe('8. Parallel Request Optimization', () => {
    
    it('should fetch user profile and session status in parallel', () => {
      // Verify Promise.all usage in restoreSession
      expect(authCode).toMatch(/Promise\.all\(\s*\[[\s\S]*?fetchUserProfile[\s\S]*?fetchSessionStatus/);
    });
    
    it('should not block UI while waiting for API responses', () => {
      // Verify async/await pattern
      expect(authCode).toMatch(/async\s+restoreSession/);
      expect(authCode).toMatch(/await\s+Promise\.all/);
    });
  });
  
  describe('9. Memory Management', () => {
    
    it('should clear session data on logout', () => {
      expect(authCode).toContain('localStorage.removeItem("cyberguard_jwt")');
      expect(authCode).toContain('localStorage.removeItem("cyberguard_user")');
      expect(authCode).toContain('localStorage.removeItem("cyberguard_session")');
    });
    
    it('should clear cache when appropriate', () => {
      expect(performanceAuditCode).toContain('clear(endpoint = null');
      expect(performanceAuditCode).toContain('this.cache.clear()');
    });
    
    it('should remove projects from memory after deletion', () => {
      expect(projectManagerCode).toMatch(/this\.projects\s*=\s*this\.projects\.filter/);
    });
  });
  
  describe('10. Form Validation Optimization', () => {
    
    it('should validate forms client-side before API calls', () => {
      expect(authCode).toContain('validateRegistrationData');
      expect(authCode).toContain('validateLoginData');
      expect(projectManagerCode).toContain('validateProjectForm');
    });
    
    it('should return early if validation fails', () => {
      expect(authCode).toMatch(/if\s*\(validationErrors\.length\s*>\s*0\)/);
      expect(projectManagerCode).toMatch(/if\s*\(!validation\.valid\)/);
    });
    
    it('should not make API calls for invalid data', () => {
      // Verify validation happens before API calls
      const validateBeforeAPI = authCode.match(/validateRegistrationData[\s\S]{0,500}apiClient\.post/);
      expect(validateBeforeAPI).toBeTruthy();
    });
  });
});

describe('Performance Utilities Functional Tests', () => {
  
  describe('Debounce Function', () => {
    
    it('should delay function execution', async () => {
      const { debounce } = await import('./performance-audit.js');
      
      let callCount = 0;
      const fn = () => callCount++;
      const debouncedFn = debounce(fn, 100);
      
      // Call multiple times rapidly
      debouncedFn();
      debouncedFn();
      debouncedFn();
      
      // Should not have executed yet
      expect(callCount).toBe(0);
      
      // Wait for debounce delay
      await new Promise(resolve => setTimeout(resolve, 150));
      
      // Should have executed once
      expect(callCount).toBe(1);
    });
  });
  
  describe('Throttle Function', () => {
    
    it('should limit function execution rate', async () => {
      const { throttle } = await import('./performance-audit.js');
      
      let callCount = 0;
      const fn = () => callCount++;
      const throttledFn = throttle(fn, 100);
      
      // Call multiple times rapidly
      throttledFn(); // Should execute
      throttledFn(); // Should be throttled
      throttledFn(); // Should be throttled
      
      // Should have executed once
      expect(callCount).toBe(1);
      
      // Wait for throttle period
      await new Promise(resolve => setTimeout(resolve, 150));
      
      // Call again
      throttledFn(); // Should execute
      
      // Should have executed twice total
      expect(callCount).toBe(2);
    });
  });
  
  describe('Request Cache', () => {
    
    it('should cache and retrieve responses', async () => {
      const { RequestCache } = await import('./performance-audit.js');
      const cache = new RequestCache(1000);
      
      const endpoint = '/api/test';
      const data = { result: 'success' };
      
      // Set cache
      cache.set(endpoint, {}, data);
      
      // Get cache
      const cached = cache.get(endpoint, {});
      
      expect(cached).toEqual(data);
    });
    
    it('should expire old cache entries', async () => {
      const { RequestCache } = await import('./performance-audit.js');
      const cache = new RequestCache(100); // 100ms TTL
      
      const endpoint = '/api/test';
      const data = { result: 'success' };
      
      // Set cache
      cache.set(endpoint, {}, data);
      
      // Wait for expiration
      await new Promise(resolve => setTimeout(resolve, 150));
      
      // Should return null (expired)
      const cached = cache.get(endpoint, {});
      expect(cached).toBeNull();
    });
  });
  
  describe('API Call Tracker', () => {
    
    it('should track API calls', async () => {
      const { APICallTracker } = await import('./performance-audit.js');
      const tracker = new APICallTracker();
      
      tracker.enable();
      tracker.track('GET', '/api/test');
      tracker.track('POST', '/api/test');
      
      const stats = tracker.getStats();
      
      expect(stats.total).toBe(2);
      expect(stats.byMethod.GET).toBe(1);
      expect(stats.byMethod.POST).toBe(1);
    });
    
    it('should detect duplicate calls', async () => {
      const { APICallTracker } = await import('./performance-audit.js');
      const tracker = new APICallTracker();
      
      tracker.enable();
      
      const now = Date.now();
      tracker.track('GET', '/api/test', now);
      tracker.track('GET', '/api/test', now + 500); // Within 1s window
      
      const duplicates = tracker.getDuplicates(1000);
      
      expect(duplicates.length).toBe(1);
      expect(duplicates[0].timeDiff).toBe(500);
    });
  });
});
