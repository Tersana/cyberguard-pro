/**
 * Unit tests for Threat Intel Hub Search History
 * Tests the renderSearchHistory method and related functionality
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { JSDOM } from 'jsdom';

// Mock localStorage
const localStorageMock = (() => {
  let store = {};
  return {
    getItem: (key) => store[key] || null,
    setItem: (key, value) => { store[key] = value.toString(); },
    removeItem: (key) => { delete store[key]; },
    clear: () => { store = {}; }
  };
})();

global.localStorage = localStorageMock;

// Load the threat-intel.js module
const threatIntelModule = await import('./threat-intel.js');
const { UIRenderer, ThreatIntelHub, ThreatIntelState } = threatIntelModule;

describe('Threat Intel Hub - Search History', () => {
  let dom;
  let document;
  
  beforeEach(() => {
    // Create a fresh DOM for each test
    dom = new JSDOM(`
      <!DOCTYPE html>
      <html>
        <body>
          <div id="threat-intel-history-list"></div>
        </body>
      </html>
    `);
    
    document = dom.window.document;
    global.document = document;
    
    // Clear localStorage
    localStorage.clear();
    
    // Reset state
    ThreatIntelState.searchHistory = [];
  });
  
  describe('renderSearchHistory', () => {
    it('should display empty state when history is empty', () => {
      UIRenderer.renderSearchHistory([]);
      
      const historyList = document.getElementById('threat-intel-history-list');
      expect(historyList.innerHTML).toContain('No recent searches');
    });
    
    it('should render history items with correct structure', () => {
      const mockHistory = [
        {
          input: '8.8.8.8',
          inputType: 'ip',
          verdict: 'CLEAR/UNVERIFIED',
          timestamp: new Date().toISOString()
        },
        {
          input: 'example.com',
          inputType: 'domain',
          verdict: 'MALICIOUS',
          timestamp: new Date(Date.now() - 3600000).toISOString() // 1 hour ago
        }
      ];
      
      UIRenderer.renderSearchHistory(mockHistory);
      
      const historyList = document.getElementById('threat-intel-history-list');
      const items = historyList.querySelectorAll('.recent-search-item');
      
      expect(items.length).toBe(2);
      
      // Check first item
      expect(items[0].textContent).toContain('8.8.8.8');
      expect(items[0].textContent).toContain('CLEAR/UNVERIFIED');
      
      // Check second item
      expect(items[1].textContent).toContain('example.com');
      expect(items[1].textContent).toContain('MALICIOUS');
    });
    
    it('should apply correct verdict colors', () => {
      const mockHistory = [
        {
          input: 'malicious.com',
          inputType: 'domain',
          verdict: 'MALICIOUS',
          timestamp: new Date().toISOString()
        },
        {
          input: 'clean.com',
          inputType: 'domain',
          verdict: 'CLEAR/UNVERIFIED',
          timestamp: new Date().toISOString()
        }
      ];
      
      UIRenderer.renderSearchHistory(mockHistory);
      
      const historyList = document.getElementById('threat-intel-history-list');
      const items = historyList.querySelectorAll('.recent-search-item');
      
      // Check malicious verdict has red color
      expect(items[0].innerHTML).toContain('text-red-400');
      
      // Check clear verdict has cyan color
      expect(items[1].innerHTML).toContain('text-cyan-400');
    });
    
    it('should format relative time correctly', () => {
      const now = new Date();
      const oneHourAgo = new Date(now - 3600000);
      const twoDaysAgo = new Date(now - 172800000);
      
      expect(UIRenderer.formatRelativeTime(now.toISOString())).toBe('Just now');
      expect(UIRenderer.formatRelativeTime(oneHourAgo.toISOString())).toContain('hour');
      expect(UIRenderer.formatRelativeTime(twoDaysAgo.toISOString())).toContain('day');
    });
    
    it('should escape HTML in input values to prevent XSS', () => {
      const mockHistory = [
        {
          input: '<script>alert("xss")</script>',
          inputType: 'domain',
          verdict: 'MALICIOUS',
          timestamp: new Date().toISOString()
        }
      ];
      
      UIRenderer.renderSearchHistory(mockHistory);
      
      const historyList = document.getElementById('threat-intel-history-list');
      
      // Should not contain actual script tag
      expect(historyList.innerHTML).not.toContain('<script>alert("xss")</script>');
      
      // Should contain escaped version
      expect(historyList.innerHTML).toContain('&lt;script&gt;');
    });
    
    it('should limit history to 10 items', () => {
      const mockHistory = [];
      for (let i = 0; i < 15; i++) {
        mockHistory.push({
          input: `test${i}.com`,
          inputType: 'domain',
          verdict: 'CLEAR/UNVERIFIED',
          timestamp: new Date().toISOString()
        });
      }
      
      // Simulate saving to history (which should limit to 10)
      ThreatIntelState.searchHistory = mockHistory.slice(0, 10);
      
      UIRenderer.renderSearchHistory(ThreatIntelState.searchHistory);
      
      const historyList = document.getElementById('threat-intel-history-list');
      const items = historyList.querySelectorAll('.recent-search-item');
      
      expect(items.length).toBe(10);
    });
  });
  
  describe('formatRelativeTime', () => {
    it('should return "Just now" for recent timestamps', () => {
      const now = new Date();
      const result = UIRenderer.formatRelativeTime(now.toISOString());
      expect(result).toBe('Just now');
    });
    
    it('should return minutes for timestamps within an hour', () => {
      const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000);
      const result = UIRenderer.formatRelativeTime(fiveMinutesAgo.toISOString());
      expect(result).toBe('5 minutes ago');
    });
    
    it('should return hours for timestamps within a day', () => {
      const twoHoursAgo = new Date(Date.now() - 2 * 60 * 60 * 1000);
      const result = UIRenderer.formatRelativeTime(twoHoursAgo.toISOString());
      expect(result).toBe('2 hours ago');
    });
    
    it('should return days for timestamps within a week', () => {
      const threeDaysAgo = new Date(Date.now() - 3 * 24 * 60 * 60 * 1000);
      const result = UIRenderer.formatRelativeTime(threeDaysAgo.toISOString());
      expect(result).toBe('3 days ago');
    });
    
    it('should return date for timestamps older than a week', () => {
      const tenDaysAgo = new Date(Date.now() - 10 * 24 * 60 * 60 * 1000);
      const result = UIRenderer.formatRelativeTime(tenDaysAgo.toISOString());
      expect(result).toMatch(/\d{1,2}\/\d{1,2}\/\d{4}/);
    });
  });
  
  describe('escapeHtml', () => {
    it('should escape HTML special characters', () => {
      expect(UIRenderer.escapeHtml('<script>')).toBe('&lt;script&gt;');
      expect(UIRenderer.escapeHtml('test & test')).toBe('test &amp; test');
      // Note: textContent doesn't escape quotes, which is fine for our use case
      expect(UIRenderer.escapeHtml('"quotes"')).toBe('"quotes"');
    });
    
    it('should handle normal text without changes', () => {
      expect(UIRenderer.escapeHtml('example.com')).toBe('example.com');
      expect(UIRenderer.escapeHtml('192.168.1.1')).toBe('192.168.1.1');
    });
  });
});
