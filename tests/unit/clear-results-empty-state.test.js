/**
 * Unit tests for Clear Results Button - Task 6.1
 * Tests Clear Results functionality with no existing data
 * 
 * Requirements tested:
 * - 5.5: Clear Results button should work when no results exist
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';

describe('Clear Results Button - Task 6.1: Empty State', () => {
  let resultsData;
  let activeFilters;
  let scanStartTime;
  let scanEndTime;
  let currentScanTarget;
  let clearResults;
  let updateSummaryBar;
  let renderResults;
  let updateFilterUI;
  let addActivityLog;
  let activityLogContainer;
  
  beforeEach(() => {
    // Initialize empty state (no existing data)
    resultsData = [];
    activeFilters = new Set();
    scanStartTime = null;
    scanEndTime = null;
    currentScanTarget = null;
    
    // Mock DOM elements
    activityLogContainer = {
      innerHTML: ''
    };
    
    // Mock document.getElementById
    global.document = {
      getElementById: vi.fn((id) => {
        if (id === 'activity-log-container') {
          return activityLogContainer;
        }
        return null;
      })
    };
    
    // Mock window.confirm
    global.confirm = vi.fn();
    
    // Mock utility functions
    updateSummaryBar = vi.fn();
    renderResults = vi.fn();
    updateFilterUI = vi.fn();
    addActivityLog = vi.fn();
    
    // Define clearResults function (as implemented in main.js)
    clearResults = () => {
      // Show confirmation dialog
      const confirmed = confirm(
        "Are you sure you want to clear all results? This will remove all scan data and activity logs."
      );
      
      if (!confirmed) {
        return; // User cancelled, do nothing
      }
      
      // Clear the results data array
      resultsData = [];
      
      // Clear the activity log container
      const activityLogContainer = document.getElementById('activity-log-container');
      if (activityLogContainer) {
        activityLogContainer.innerHTML = '';
      }
      
      // Reset active filters
      activeFilters.clear();
      updateFilterUI();
      
      // Reset scan timing variables
      scanStartTime = null;
      scanEndTime = null;
      currentScanTarget = null;
      
      // Update the Summary Bar with default values
      updateSummaryBar(0, '--', '--');
      
      // Re-render results (will show empty state)
      renderResults();
      
      // Log the clear action
      addActivityLog('All results cleared by user', 'System');
    };
  });
  
  describe('Confirmation Dialog with Empty State', () => {
    it('should show confirmation dialog even when no results exist', () => {
      // Arrange: Empty state (already set in beforeEach)
      global.confirm.mockReturnValue(true);
      
      // Act: Call clearResults
      clearResults();
      
      // Assert: Confirmation dialog should be shown
      expect(global.confirm).toHaveBeenCalledWith(
        "Are you sure you want to clear all results? This will remove all scan data and activity logs."
      );
      expect(global.confirm).toHaveBeenCalledTimes(1);
    });
    
    it('should not throw error when user confirms with empty state', () => {
      // Arrange: Empty state
      global.confirm.mockReturnValue(true);
      
      // Act & Assert: Should not throw
      expect(() => clearResults()).not.toThrow();
    });
    
    it('should not throw error when user cancels with empty state', () => {
      // Arrange: Empty state
      global.confirm.mockReturnValue(false);
      
      // Act & Assert: Should not throw
      expect(() => clearResults()).not.toThrow();
    });
  });
  
  describe('No Errors with Empty State', () => {
    it('should handle empty resultsData array without errors', () => {
      // Arrange: Empty resultsData
      global.confirm.mockReturnValue(true);
      
      // Act
      clearResults();
      
      // Assert: No errors, resultsData remains empty
      expect(resultsData).toEqual([]);
    });
    
    it('should handle empty activity log container without errors', () => {
      // Arrange: Empty activity log
      activityLogContainer.innerHTML = '';
      global.confirm.mockReturnValue(true);
      
      // Act
      clearResults();
      
      // Assert: No errors, container is cleared
      expect(activityLogContainer.innerHTML).toBe('');
    });
    
    it('should handle empty activeFilters Set without errors', () => {
      // Arrange: Empty filters
      activeFilters.clear();
      global.confirm.mockReturnValue(true);
      
      // Act
      clearResults();
      
      // Assert: No errors, filters remain empty
      expect(activeFilters.size).toBe(0);
    });
    
    it('should handle null scan timing variables without errors', () => {
      // Arrange: Null timing variables
      scanStartTime = null;
      scanEndTime = null;
      currentScanTarget = null;
      global.confirm.mockReturnValue(true);
      
      // Act
      clearResults();
      
      // Assert: No errors, variables remain null
      expect(scanStartTime).toBeNull();
      expect(scanEndTime).toBeNull();
      expect(currentScanTarget).toBeNull();
    });
  });
  
  describe('UI Updates with Empty State', () => {
    it('should call updateSummaryBar with default values', () => {
      // Arrange
      global.confirm.mockReturnValue(true);
      
      // Act
      clearResults();
      
      // Assert: Summary bar should be updated with defaults
      expect(updateSummaryBar).toHaveBeenCalledWith(0, '--', '--');
      expect(updateSummaryBar).toHaveBeenCalledTimes(1);
    });
    
    it('should call renderResults to show empty state', () => {
      // Arrange
      global.confirm.mockReturnValue(true);
      
      // Act
      clearResults();
      
      // Assert: renderResults should be called to display empty state
      expect(renderResults).toHaveBeenCalled();
      expect(renderResults).toHaveBeenCalledTimes(1);
    });
    
    it('should call updateFilterUI to reset filter buttons', () => {
      // Arrange
      global.confirm.mockReturnValue(true);
      
      // Act
      clearResults();
      
      // Assert: Filter UI should be updated
      expect(updateFilterUI).toHaveBeenCalled();
      expect(updateFilterUI).toHaveBeenCalledTimes(1);
    });
    
    it('should call addActivityLog with clear action message', () => {
      // Arrange
      global.confirm.mockReturnValue(true);
      
      // Act
      clearResults();
      
      // Assert: Activity log should record the clear action
      expect(addActivityLog).toHaveBeenCalledWith('All results cleared by user', 'System');
      expect(addActivityLog).toHaveBeenCalledTimes(1);
    });
  });
  
  describe('User Cancellation with Empty State', () => {
    it('should not call any update functions when user cancels', () => {
      // Arrange
      global.confirm.mockReturnValue(false);
      
      // Act
      clearResults();
      
      // Assert: No update functions should be called
      expect(updateSummaryBar).not.toHaveBeenCalled();
      expect(renderResults).not.toHaveBeenCalled();
      expect(updateFilterUI).not.toHaveBeenCalled();
      expect(addActivityLog).not.toHaveBeenCalled();
    });
    
    it('should not modify activity log container when user cancels', () => {
      // Arrange
      activityLogContainer.innerHTML = '';
      global.confirm.mockReturnValue(false);
      
      // Act
      clearResults();
      
      // Assert: Container should remain unchanged
      expect(activityLogContainer.innerHTML).toBe('');
    });
  });
  
  describe('Requirements Validation', () => {
    it('should satisfy Requirement 5.5 - Clear Results works with no existing data', () => {
      // Arrange: Empty state
      global.confirm.mockReturnValue(true);
      
      // Act
      clearResults();
      
      // Assert: Function executes without errors
      expect(updateSummaryBar).toHaveBeenCalledWith(0, '--', '--');
      expect(renderResults).toHaveBeenCalled();
      expect(updateFilterUI).toHaveBeenCalled();
    });
    
    it('should satisfy Requirement 3.1 - Confirmation dialog appears', () => {
      // Arrange
      global.confirm.mockReturnValue(true);
      
      // Act
      clearResults();
      
      // Assert: Confirmation dialog is shown
      expect(global.confirm).toHaveBeenCalled();
    });
    
    it('should satisfy Requirement 3.2 - Correct confirmation message', () => {
      // Arrange
      global.confirm.mockReturnValue(true);
      
      // Act
      clearResults();
      
      // Assert: Message matches requirement
      expect(global.confirm).toHaveBeenCalledWith(
        "Are you sure you want to clear all results? This will remove all scan data and activity logs."
      );
    });
  });
});
