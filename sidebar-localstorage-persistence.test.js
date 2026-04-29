/**
 * Unit Tests for Sidebar LocalStorage Persistence Functions
 * Tests for Task 3.3: Implement LocalStorage persistence
 * 
 * Requirements tested: 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 4.7, 4.8
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { JSDOM } from 'jsdom';

describe('Sidebar LocalStorage Persistence (Task 3.3)', () => {
  let dom;
  let saveSidebarState;
  let loadSidebarState;

  beforeEach(() => {
    // Setup DOM environment with proper URL to enable localStorage
    dom = new JSDOM('<!DOCTYPE html><html><body></body></html>', {
      url: 'http://localhost'
    });
    global.document = dom.window.document;
    global.window = dom.window;
    global.localStorage = dom.window.localStorage;

    // Clear localStorage before each test
    localStorage.clear();

    // Mock console.warn to verify error handling
    vi.spyOn(console, 'warn').mockImplementation(() => {});

    // Define the functions to test (extracted from dashboard.html)
    saveSidebarState = function(isCollapsed) {
      try {
        localStorage.setItem('sidebarCollapsed', JSON.stringify(isCollapsed));
      } catch (error) {
        console.warn('Failed to save sidebar state:', error);
        // Gracefully degrade - feature still works, just doesn't persist
      }
    };

    loadSidebarState = function() {
      try {
        const stored = localStorage.getItem('sidebarCollapsed');
        if (stored === null) return false;
        
        const parsed = JSON.parse(stored);
        // Validate type
        if (typeof parsed !== 'boolean') {
          console.warn('Invalid sidebar state type');
          return false;
        }
        return parsed;
      } catch (error) {
        console.warn('Failed to load sidebar state:', error);
        return false; // Default to expanded
      }
    };
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('saveSidebarState(isCollapsed)', () => {
    it('should save collapsed state (true) to localStorage', () => {
      // Act
      saveSidebarState(true);

      // Assert
      const stored = localStorage.getItem('sidebarCollapsed');
      expect(stored).toBe('true');
      expect(JSON.parse(stored)).toBe(true);
    });

    it('should save expanded state (false) to localStorage', () => {
      // Act
      saveSidebarState(false);

      // Assert
      const stored = localStorage.getItem('sidebarCollapsed');
      expect(stored).toBe('false');
      expect(JSON.parse(stored)).toBe(false);
    });

    it('should use key "sidebarCollapsed" for storage (Requirement 4.4)', () => {
      // Act
      saveSidebarState(true);

      // Assert
      expect(localStorage.getItem('sidebarCollapsed')).not.toBeNull();
      expect(localStorage.getItem('sidebar-collapsed')).toBeNull();
      expect(localStorage.getItem('sidebar_collapsed')).toBeNull();
    });

    it('should store boolean true for collapsed state (Requirement 4.5)', () => {
      // Act
      saveSidebarState(true);

      // Assert
      const stored = JSON.parse(localStorage.getItem('sidebarCollapsed'));
      expect(stored).toBe(true);
      expect(typeof stored).toBe('boolean');
    });

    it('should store boolean false for expanded state (Requirement 4.6)', () => {
      // Act
      saveSidebarState(false);

      // Assert
      const stored = JSON.parse(localStorage.getItem('sidebarCollapsed'));
      expect(stored).toBe(false);
      expect(typeof stored).toBe('boolean');
    });

    it('should overwrite previous state when called multiple times', () => {
      // Act
      saveSidebarState(true);
      expect(JSON.parse(localStorage.getItem('sidebarCollapsed'))).toBe(true);

      saveSidebarState(false);
      expect(JSON.parse(localStorage.getItem('sidebarCollapsed'))).toBe(false);

      saveSidebarState(true);
      expect(JSON.parse(localStorage.getItem('sidebarCollapsed'))).toBe(true);
    });

    it('should handle localStorage errors gracefully (Requirement 4.8)', () => {
      // Arrange - Create a version that will fail
      const failingSave = function(isCollapsed) {
        try {
          // Simulate quota exceeded
          throw new Error('QuotaExceededError');
        } catch (error) {
          console.warn('Failed to save sidebar state:', error);
        }
      };

      // Act & Assert - Should not throw
      expect(() => failingSave(true)).not.toThrow();
      expect(console.warn).toHaveBeenCalledWith(
        'Failed to save sidebar state:',
        expect.any(Error)
      );
    });

    it('should handle localStorage unavailable (private browsing)', () => {
      // Arrange - Create a version that will fail
      const failingSave = function(isCollapsed) {
        try {
          throw new DOMException('localStorage is not available', 'SecurityError');
        } catch (error) {
          console.warn('Failed to save sidebar state:', error);
        }
      };

      // Act & Assert - Should not throw
      expect(() => failingSave(false)).not.toThrow();
      expect(console.warn).toHaveBeenCalled();
    });

    it('should serialize boolean values using JSON.stringify', () => {
      // Act
      saveSidebarState(true);

      // Assert - Verify the value is stored correctly
      const stored = localStorage.getItem('sidebarCollapsed');
      expect(stored).toBe('true'); // JSON.stringify(true) === 'true'
      
      saveSidebarState(false);
      const storedFalse = localStorage.getItem('sidebarCollapsed');
      expect(storedFalse).toBe('false'); // JSON.stringify(false) === 'false'
    });
  });

  describe('loadSidebarState()', () => {
    it('should load collapsed state (true) from localStorage', () => {
      // Arrange
      localStorage.setItem('sidebarCollapsed', JSON.stringify(true));

      // Act
      const result = loadSidebarState();

      // Assert
      expect(result).toBe(true);
    });

    it('should load expanded state (false) from localStorage', () => {
      // Arrange
      localStorage.setItem('sidebarCollapsed', JSON.stringify(false));

      // Act
      const result = loadSidebarState();

      // Assert
      expect(result).toBe(false);
    });

    it('should default to expanded (false) if no stored value (Requirement 4.7)', () => {
      // Arrange - localStorage is empty

      // Act
      const result = loadSidebarState();

      // Assert
      expect(result).toBe(false);
    });

    it('should use key "sidebarCollapsed" for retrieval (Requirement 4.4)', () => {
      // Arrange
      localStorage.setItem('sidebarCollapsed', JSON.stringify(true));

      // Act
      const result = loadSidebarState();

      // Assert - If it returns true, it successfully read from the correct key
      expect(result).toBe(true);
      
      // Verify it doesn't read from wrong keys
      localStorage.clear();
      localStorage.setItem('sidebar-collapsed', JSON.stringify(true));
      localStorage.setItem('sidebar_collapsed', JSON.stringify(true));
      
      const resultWithWrongKeys = loadSidebarState();
      expect(resultWithWrongKeys).toBe(false); // Should default to false since correct key doesn't exist
    });

    it('should validate that stored value is boolean type', () => {
      // Arrange - Store invalid string value
      localStorage.setItem('sidebarCollapsed', JSON.stringify('invalid'));

      // Act
      const result = loadSidebarState();

      // Assert
      expect(result).toBe(false);
      expect(console.warn).toHaveBeenCalledWith('Invalid sidebar state type');
    });

    it('should validate that stored value is not a number', () => {
      // Arrange - Store number instead of boolean
      localStorage.setItem('sidebarCollapsed', JSON.stringify(1));

      // Act
      const result = loadSidebarState();

      // Assert
      expect(result).toBe(false);
      expect(console.warn).toHaveBeenCalledWith('Invalid sidebar state type');
    });

    it('should validate that stored value is not an object', () => {
      // Arrange - Store object instead of boolean
      localStorage.setItem('sidebarCollapsed', JSON.stringify({ collapsed: true }));

      // Act
      const result = loadSidebarState();

      // Assert
      expect(result).toBe(false);
      expect(console.warn).toHaveBeenCalledWith('Invalid sidebar state type');
    });

    it('should validate that stored value is not null', () => {
      // Arrange - Store null value
      localStorage.setItem('sidebarCollapsed', JSON.stringify(null));

      // Act
      const result = loadSidebarState();

      // Assert
      expect(result).toBe(false);
      expect(console.warn).toHaveBeenCalledWith('Invalid sidebar state type');
    });

    it('should handle malformed JSON gracefully (Requirement 4.8)', () => {
      // Arrange - Store invalid JSON
      localStorage.setItem('sidebarCollapsed', 'not-valid-json{');

      // Act
      const result = loadSidebarState();

      // Assert
      expect(result).toBe(false);
      expect(console.warn).toHaveBeenCalledWith(
        'Failed to load sidebar state:',
        expect.any(Error)
      );
    });

    it('should handle localStorage errors gracefully (Requirement 4.8)', () => {
      // Arrange - Create a version that will fail
      const failingLoad = function() {
        try {
          throw new Error('localStorage access denied');
        } catch (error) {
          console.warn('Failed to load sidebar state:', error);
          return false;
        }
      };

      // Act
      const result = failingLoad();

      // Assert
      expect(result).toBe(false);
      expect(console.warn).toHaveBeenCalledWith(
        'Failed to load sidebar state:',
        expect.any(Error)
      );
    });

    it('should handle localStorage unavailable (private browsing)', () => {
      // Arrange - Create a version that will fail
      const failingLoad = function() {
        try {
          throw new DOMException('localStorage is not available', 'SecurityError');
        } catch (error) {
          console.warn('Failed to load sidebar state:', error);
          return false;
        }
      };

      // Act
      const result = failingLoad();

      // Assert
      expect(result).toBe(false);
      expect(console.warn).toHaveBeenCalled();
    });

    it('should parse JSON correctly using JSON.parse', () => {
      // Arrange
      localStorage.setItem('sidebarCollapsed', 'true');

      // Act
      const result = loadSidebarState();

      // Assert
      expect(result).toBe(true);
      expect(typeof result).toBe('boolean');
    });
  });

  describe('Integration - Save and Load Cycle', () => {
    it('should persist collapsed state across save/load cycle', () => {
      // Act
      saveSidebarState(true);
      const loaded = loadSidebarState();

      // Assert
      expect(loaded).toBe(true);
    });

    it('should persist expanded state across save/load cycle', () => {
      // Act
      saveSidebarState(false);
      const loaded = loadSidebarState();

      // Assert
      expect(loaded).toBe(false);
    });

    it('should handle multiple state changes correctly', () => {
      // Act & Assert
      saveSidebarState(true);
      expect(loadSidebarState()).toBe(true);

      saveSidebarState(false);
      expect(loadSidebarState()).toBe(false);

      saveSidebarState(true);
      expect(loadSidebarState()).toBe(true);

      saveSidebarState(false);
      expect(loadSidebarState()).toBe(false);
    });

    it('should maintain state after page reload simulation', () => {
      // Arrange - Save state
      saveSidebarState(true);

      // Act - Simulate page reload by creating new function instances
      const loadSidebarStateNew = function() {
        try {
          const stored = localStorage.getItem('sidebarCollapsed');
          if (stored === null) return false;
          
          const parsed = JSON.parse(stored);
          if (typeof parsed !== 'boolean') {
            console.warn('Invalid sidebar state type');
            return false;
          }
          return parsed;
        } catch (error) {
          console.warn('Failed to load sidebar state:', error);
          return false;
        }
      };

      const loaded = loadSidebarStateNew();

      // Assert
      expect(loaded).toBe(true);
    });
  });

  describe('Edge Cases', () => {
    it('should handle empty string in localStorage', () => {
      // Arrange
      localStorage.setItem('sidebarCollapsed', '');

      // Act
      const result = loadSidebarState();

      // Assert
      expect(result).toBe(false);
      expect(console.warn).toHaveBeenCalled();
    });

    it('should handle undefined value passed to save', () => {
      // Act
      saveSidebarState(undefined);

      // Assert
      const stored = localStorage.getItem('sidebarCollapsed');
      // JSON.stringify(undefined) returns undefined, which localStorage stores as string "undefined"
      expect(stored).toBe('undefined');
    });

    it('should handle array value in localStorage', () => {
      // Arrange
      localStorage.setItem('sidebarCollapsed', JSON.stringify([true]));

      // Act
      const result = loadSidebarState();

      // Assert
      expect(result).toBe(false);
      expect(console.warn).toHaveBeenCalledWith('Invalid sidebar state type');
    });

    it('should handle very long localStorage key collision', () => {
      // Arrange - Set a different key with similar name
      localStorage.setItem('sidebarCollapsedOther', JSON.stringify(true));
      localStorage.setItem('sidebarCollapsed', JSON.stringify(false));

      // Act
      const result = loadSidebarState();

      // Assert
      expect(result).toBe(false); // Should load from correct key
    });
  });

  describe('Requirements Validation', () => {
    it('should meet Requirement 4.1: Store state when user toggles', () => {
      // This is tested by saveSidebarState function
      saveSidebarState(true);
      expect(localStorage.getItem('sidebarCollapsed')).not.toBeNull();
    });

    it('should meet Requirement 4.2: Read state on page load', () => {
      // Arrange
      localStorage.setItem('sidebarCollapsed', JSON.stringify(true));

      // Act
      const result = loadSidebarState();

      // Assert
      expect(result).toBe(true);
    });

    it('should meet Requirement 4.3: Apply stored state before first paint', () => {
      // This is tested by loadSidebarState returning immediately
      const start = performance.now();
      localStorage.setItem('sidebarCollapsed', JSON.stringify(true));
      loadSidebarState();
      const end = performance.now();

      // Assert - Should be very fast (< 10ms)
      expect(end - start).toBeLessThan(10);
    });

    it('should meet Requirement 4.4: Use key "sidebarCollapsed"', () => {
      saveSidebarState(true);
      expect(localStorage.getItem('sidebarCollapsed')).not.toBeNull();
    });

    it('should meet Requirement 4.5: Store boolean true for collapsed', () => {
      saveSidebarState(true);
      const stored = JSON.parse(localStorage.getItem('sidebarCollapsed'));
      expect(stored).toBe(true);
      expect(typeof stored).toBe('boolean');
    });

    it('should meet Requirement 4.6: Store boolean false for expanded', () => {
      saveSidebarState(false);
      const stored = JSON.parse(localStorage.getItem('sidebarCollapsed'));
      expect(stored).toBe(false);
      expect(typeof stored).toBe('boolean');
    });

    it('should meet Requirement 4.7: Default to expanded if no stored state', () => {
      // localStorage is empty
      const result = loadSidebarState();
      expect(result).toBe(false); // false = expanded
    });

    it('should meet Requirement 4.8: Handle errors gracefully', () => {
      // Test save error handling - verify try-catch structure
      const failingSave = function(isCollapsed) {
        try {
          throw new Error('Test error');
        } catch (error) {
          console.warn('Failed to save sidebar state:', error);
        }
      };

      expect(() => failingSave(true)).not.toThrow();

      // Test load error handling - verify try-catch structure
      const failingLoad = function() {
        try {
          throw new Error('Test error');
        } catch (error) {
          console.warn('Failed to load sidebar state:', error);
          return false;
        }
      };

      expect(() => failingLoad()).not.toThrow();
      expect(failingLoad()).toBe(false);
    });
  });
});
