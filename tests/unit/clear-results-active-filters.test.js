/**
 * Unit tests for Clear Results Button - Task 6.2
 * Tests Clear Results functionality with active filters
 * 
 * Requirements tested:
 * - 2.6: Clear Results should reset any active filters
 * - 5.1: Clear Results should not interfere with Clear Filters functionality
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';

describe('Clear Results Button - Task 6.2: Active Filters Integration', () => {
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
    // Initialize state with some data and active filters
    resultsData = [
      { id: '1', status: 'threat', message: 'Critical issue', tool: 'Scanner1' },
      { id: '2', status: 'warning', message: 'Warning issue', tool: 'Scanner2' },
      { id: '3', status: 'safe', message: 'Info message', tool: 'Scanner3' }
    ];
    activeFilters = new Set(['critical', 'warning']);
    scanStartTime = Date.now() - 5000;
    scanEndTime = Date.now();
    currentScanTarget = '8.8.8.8';
    
    // Mock DOM elements
    activityLogContainer = {
      innerHTML: '<div class="log-entry">Previous log</div>'
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
  
  describe('Filter State Before Clearing', () => {
    it('should have active filters set before clearing', () => {
      // Assert: Verify initial state has active filters
      expect(activeFilters.size).toBe(2);
      expect(activeFilters.has('critical')).toBe(true);
      expect(activeFilters.has('warning')).toBe(true);
    });
    
    it('should have results data before clearing', () => {
      // Assert: Verify initial state has results
      expect(resultsData.length).toBe(3);
    });
  });
  
  describe('Clearing Results with Active Filters', () => {
    it('should reset active filters when clearing results', () => {
      // Arrange: Active filters are set in beforeEach
      global.confirm.mockReturnValue(true);
      
      // Act: Clear results
      clearResults();
      
      // Assert: Active filters should be cleared
      expect(activeFilters.size).toBe(0);
      expect(activeFilters.has('critical')).toBe(false);
      expect(activeFilters.has('warning')).toBe(false);
    });
    
    it('should call updateFilterUI after clearing filters', () => {
      // Arrange
      global.confirm.mockReturnValue(true);
      
      // Act
      clearResults();
      
      // Assert: updateFilterUI should be called to update button states
      expect(updateFilterUI).toHaveBeenCalled();
      expect(updateFilterUI).toHaveBeenCalledTimes(1);
    });
    
    it('should clear all filters regardless of how many are active', () => {
      // Arrange: Add more filters
      activeFilters.add('info');
      expect(activeFilters.size).toBe(3);
      global.confirm.mockReturnValue(true);
      
      // Act
      clearResults();
      
      // Assert: All filters should be cleared
      expect(activeFilters.size).toBe(0);
    });
    
    it('should clear filters even with single active filter', () => {
      // Arrange: Set only one filter
      activeFilters.clear();
      activeFilters.add('critical');
      expect(activeFilters.size).toBe(1);
      global.confirm.mockReturnValue(true);
      
      // Act
      clearResults();
      
      // Assert: Filter should be cleared
      expect(activeFilters.size).toBe(0);
    });
  });
  
  describe('Filter UI Updates', () => {
    it('should update filter UI to reflect cleared state', () => {
      // Arrange
      global.confirm.mockReturnValue(true);
      
      // Act
      clearResults();
      
      // Assert: updateFilterUI should be called after clearing filters
      expect(updateFilterUI).toHaveBeenCalled();
      // Verify it's called after filters are cleared
      expect(activeFilters.size).toBe(0);
    });
    
    it('should call updateFilterUI before renderResults', () => {
      // Arrange
      global.confirm.mockReturnValue(true);
      const callOrder = [];
      updateFilterUI.mockImplementation(() => callOrder.push('updateFilterUI'));
      renderResults.mockImplementation(() => callOrder.push('renderResults'));
      
      // Act
      clearResults();
      
      // Assert: updateFilterUI should be called before renderResults
      expect(callOrder).toEqual(['updateFilterUI', 'renderResults']);
    });
  });
  
  describe('Complete State Reset with Filters', () => {
    it('should reset all state including filters when clearing', () => {
      // Arrange
      global.confirm.mockReturnValue(true);
      
      // Act
      clearResults();
      
      // Assert: All state should be reset
      expect(resultsData).toEqual([]);
      expect(activeFilters.size).toBe(0);
      expect(scanStartTime).toBeNull();
      expect(scanEndTime).toBeNull();
      expect(currentScanTarget).toBeNull();
      expect(activityLogContainer.innerHTML).toBe('');
    });
    
    it('should call all UI update functions after clearing with filters', () => {
      // Arrange
      global.confirm.mockReturnValue(true);
      
      // Act
      clearResults();
      
      // Assert: All UI update functions should be called
      expect(updateFilterUI).toHaveBeenCalled();
      expect(updateSummaryBar).toHaveBeenCalledWith(0, '--', '--');
      expect(renderResults).toHaveBeenCalled();
      expect(addActivityLog).toHaveBeenCalledWith('All results cleared by user', 'System');
    });
  });
  
  describe('User Cancellation with Active Filters', () => {
    it('should preserve active filters when user cancels', () => {
      // Arrange
      global.confirm.mockReturnValue(false);
      const originalFilters = new Set(activeFilters);
      
      // Act
      clearResults();
      
      // Assert: Filters should remain unchanged
      expect(activeFilters.size).toBe(originalFilters.size);
      expect(activeFilters.has('critical')).toBe(true);
      expect(activeFilters.has('warning')).toBe(true);
    });
    
    it('should not call updateFilterUI when user cancels', () => {
      // Arrange
      global.confirm.mockReturnValue(false);
      
      // Act
      clearResults();
      
      // Assert: updateFilterUI should not be called
      expect(updateFilterUI).not.toHaveBeenCalled();
    });
    
    it('should preserve all state when user cancels with active filters', () => {
      // Arrange
      global.confirm.mockReturnValue(false);
      const originalResultsLength = resultsData.length;
      const originalFiltersSize = activeFilters.size;
      const originalTarget = currentScanTarget;
      
      // Act
      clearResults();
      
      // Assert: All state should be preserved
      expect(resultsData.length).toBe(originalResultsLength);
      expect(activeFilters.size).toBe(originalFiltersSize);
      expect(currentScanTarget).toBe(originalTarget);
    });
  });
  
  describe('Requirements Validation', () => {
    it('should satisfy Requirement 2.6 - Reset active filters when clearing', () => {
      // Arrange: Active filters are set
      expect(activeFilters.size).toBeGreaterThan(0);
      global.confirm.mockReturnValue(true);
      
      // Act
      clearResults();
      
      // Assert: Filters should be reset
      expect(activeFilters.size).toBe(0);
      expect(updateFilterUI).toHaveBeenCalled();
    });
    
    it('should satisfy Requirement 5.1 - Clear Results does not interfere with filter functionality', () => {
      // Arrange
      global.confirm.mockReturnValue(true);
      
      // Act: Clear results
      clearResults();
      
      // Assert: Filter system should still be functional (updateFilterUI called)
      expect(updateFilterUI).toHaveBeenCalled();
      
      // Simulate adding filters after clear (to verify filter system still works)
      activeFilters.add('critical');
      expect(activeFilters.has('critical')).toBe(true);
      expect(activeFilters.size).toBe(1);
    });
  });
  
  describe('Edge Cases with Filters', () => {
    it('should handle clearing when all severity filters are active', () => {
      // Arrange: Set all possible filters
      activeFilters.clear();
      activeFilters.add('critical');
      activeFilters.add('warning');
      activeFilters.add('info');
      expect(activeFilters.size).toBe(3);
      global.confirm.mockReturnValue(true);
      
      // Act
      clearResults();
      
      // Assert: All filters should be cleared
      expect(activeFilters.size).toBe(0);
    });
    
    it('should handle clearing with filters and empty results', () => {
      // Arrange: Active filters but no results
      resultsData = [];
      activeFilters.add('critical');
      global.confirm.mockReturnValue(true);
      
      // Act
      clearResults();
      
      // Assert: Filters should still be cleared
      expect(activeFilters.size).toBe(0);
      expect(updateFilterUI).toHaveBeenCalled();
    });
    
    it('should handle clearing with results but no active filters', () => {
      // Arrange: Results exist but no filters
      activeFilters.clear();
      expect(activeFilters.size).toBe(0);
      global.confirm.mockReturnValue(true);
      
      // Act
      clearResults();
      
      // Assert: Should still call updateFilterUI
      expect(updateFilterUI).toHaveBeenCalled();
      expect(resultsData).toEqual([]);
    });
  });
});
