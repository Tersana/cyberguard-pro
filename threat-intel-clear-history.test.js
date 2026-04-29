/**
 * Unit tests for Threat Intel Hub Clear History functionality
 * Tests the clearHistory method with confirmation prompt
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

// Mock CyberNotify
const mockCyberNotify = {
  confirm: vi.fn(),
  alert: vi.fn()
};

global.CyberNotify = mockCyberNotify;

// Load the threat-intel.js module
const threatIntelModule = await import('./threat-intel.js');
const { ThreatIntelHub, ThreatIntelState, UIRenderer } = threatIntelModule;

describe('Threat Intel Hub - Clear History', () => {
  let dom;
  let document;
  
  beforeEach(() => {
    // Create a fresh DOM for each test
    dom = new JSDOM(`
      <!DOCTYPE html>
      <html>
        <body>
          <div id="threat-intel-history-list"></div>
          <button id="threat-intel-clear-history-btn">Clear History</button>
        </body>
      </html>
    `);
    
    document = dom.window.document;
    global.document = document;
    
    // Clear localStorage
    localStorage.clear();
    
    // Reset state
    ThreatIntelState.searchHistory = [];
    
    // Reset mocks
    mockCyberNotify.confirm.mockClear();
    mockCyberNotify.alert.mockClear();
  });
  
  describe('clearHistory', () => {
    it('should show confirmation prompt using CyberNotify.confirm', () => {
      // Setup: Add some history
      ThreatIntelState.searchHistory = [
        {
          input: '8.8.8.8',
          inputType: 'ip',
          verdict: 'CLEAR/UNVERIFIED',
          timestamp: new Date().toISOString()
        }
      ];
      localStorage.setItem('threat-intel-history', JSON.stringify(ThreatIntelState.searchHistory));
      
      // Call clearHistory
      ThreatIntelHub.clearHistory();
      
      // Verify CyberNotify.confirm was called
      expect(mockCyberNotify.confirm).toHaveBeenCalledTimes(1);
      expect(mockCyberNotify.confirm).toHaveBeenCalledWith(
        'Are you sure you want to clear all search history? This action cannot be undone.',
        expect.any(Function)
      );
    });
    
    it('should clear localStorage when user confirms', () => {
      // Setup: Add some history
      ThreatIntelState.searchHistory = [
        {
          input: '8.8.8.8',
          inputType: 'ip',
          verdict: 'CLEAR/UNVERIFIED',
          timestamp: new Date().toISOString()
        }
      ];
      localStorage.setItem('threat-intel-history', JSON.stringify(ThreatIntelState.searchHistory));
      
      // Mock confirm to call callback with true
      mockCyberNotify.confirm.mockImplementation((message, callback) => {
        callback(true);
      });
      
      // Call clearHistory
      ThreatIntelHub.clearHistory();
      
      // Verify localStorage was cleared
      expect(localStorage.getItem('threat-intel-history')).toBeNull();
      
      // Verify state was cleared
      expect(ThreatIntelState.searchHistory).toEqual([]);
    });
    
    it('should NOT clear localStorage when user cancels', () => {
      // Setup: Add some history
      const mockHistory = [
        {
          input: '8.8.8.8',
          inputType: 'ip',
          verdict: 'CLEAR/UNVERIFIED',
          timestamp: new Date().toISOString()
        }
      ];
      ThreatIntelState.searchHistory = [...mockHistory];
      localStorage.setItem('threat-intel-history', JSON.stringify(mockHistory));
      
      // Mock confirm to call callback with false
      mockCyberNotify.confirm.mockImplementation((message, callback) => {
        callback(false);
      });
      
      // Call clearHistory
      ThreatIntelHub.clearHistory();
      
      // Verify localStorage was NOT cleared
      expect(localStorage.getItem('threat-intel-history')).not.toBeNull();
      
      // Verify state was NOT cleared
      expect(ThreatIntelState.searchHistory).toEqual(mockHistory);
    });
    
    it('should update UI after clearing history', () => {
      // Setup: Add some history
      ThreatIntelState.searchHistory = [
        {
          input: '8.8.8.8',
          inputType: 'ip',
          verdict: 'CLEAR/UNVERIFIED',
          timestamp: new Date().toISOString()
        }
      ];
      
      // Spy on UIRenderer.renderSearchHistory
      const renderSpy = vi.spyOn(UIRenderer, 'renderSearchHistory');
      
      // Mock confirm to call callback with true
      mockCyberNotify.confirm.mockImplementation((message, callback) => {
        callback(true);
      });
      
      // Call clearHistory
      ThreatIntelHub.clearHistory();
      
      // Verify UI was updated with empty array
      expect(renderSpy).toHaveBeenCalledWith([]);
    });
    
    it('should show success notification after clearing', () => {
      // Setup: Add some history
      ThreatIntelState.searchHistory = [
        {
          input: '8.8.8.8',
          inputType: 'ip',
          verdict: 'CLEAR/UNVERIFIED',
          timestamp: new Date().toISOString()
        }
      ];
      
      // Mock confirm to call callback with true
      mockCyberNotify.confirm.mockImplementation((message, callback) => {
        callback(true);
      });
      
      // Call clearHistory
      ThreatIntelHub.clearHistory();
      
      // Verify success notification was shown
      expect(mockCyberNotify.alert).toHaveBeenCalledWith(
        'Search history cleared successfully',
        { type: 'success' }
      );
    });
    
    it('should handle errors gracefully', () => {
      // Setup: Add some history
      ThreatIntelState.searchHistory = [
        {
          input: '8.8.8.8',
          inputType: 'ip',
          verdict: 'CLEAR/UNVERIFIED',
          timestamp: new Date().toISOString()
        }
      ];
      
      // Mock localStorage.removeItem to throw error
      const originalRemoveItem = localStorage.removeItem;
      localStorage.removeItem = vi.fn(() => {
        throw new Error('Storage error');
      });
      
      // Mock confirm to call callback with true
      mockCyberNotify.confirm.mockImplementation((message, callback) => {
        callback(true);
      });
      
      // Call clearHistory - should not throw
      expect(() => ThreatIntelHub.clearHistory()).not.toThrow();
      
      // Verify error notification was shown
      expect(mockCyberNotify.alert).toHaveBeenCalledWith(
        'Failed to clear search history',
        { type: 'error' }
      );
      
      // Restore original removeItem
      localStorage.removeItem = originalRemoveItem;
    });
    
    it('should fallback to native confirm if CyberNotify is not available', () => {
      // Remove CyberNotify
      const originalCyberNotify = global.CyberNotify;
      global.CyberNotify = undefined;
      
      // Mock native confirm
      global.confirm = vi.fn(() => true);
      
      // Setup: Add some history
      ThreatIntelState.searchHistory = [
        {
          input: '8.8.8.8',
          inputType: 'ip',
          verdict: 'CLEAR/UNVERIFIED',
          timestamp: new Date().toISOString()
        }
      ];
      localStorage.setItem('threat-intel-history', JSON.stringify(ThreatIntelState.searchHistory));
      
      // Call clearHistory
      ThreatIntelHub.clearHistory();
      
      // Verify native confirm was called
      expect(global.confirm).toHaveBeenCalledWith(
        'Are you sure you want to clear all search history? This action cannot be undone.'
      );
      
      // Verify localStorage was cleared
      expect(localStorage.getItem('threat-intel-history')).toBeNull();
      
      // Restore CyberNotify
      global.CyberNotify = originalCyberNotify;
    });
  });
});
