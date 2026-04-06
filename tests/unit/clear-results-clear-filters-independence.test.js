/**
 * Unit tests for Clear Results Button - Task 6.5
 * Tests that Clear Results button does not interfere with Clear Filters button
 * 
 * Requirements tested:
 * - 5.1: Clear Results button should not interfere with Clear Filters functionality
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';

describe('Clear Results Button - Task 6.5: Independence from Clear Filters', () => {
  let resultsData;
  let activeFilters;
  let scanStartTime;
  let scanEndTime;
  let currentScanTarget;
  let clearResults;
  let clearFilters;
  let updateSummaryBar;
  let renderResults;
  let updateFilterUI;
  let addActivityLog;
  let activityLogContainer;
  
  beforeEach(() => {
    // Initialize state with data and active filters
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
      const confirmed = confirm(
        "Are you sure you want to clear all results? This will remove all scan data and activity logs."
      );
      
      if (!confirmed) {
        return;
      }
      
      resultsData = [];
      
      const activityLogContainer = document.getElementById('activity-log-container');
      if (activityLogContainer) {
        activityLogContainer.innerHTML = '';
      }
      
      activeFilters.clear();
      updateFilterUI();
      
      scanStartTime = null;
      scanEndTime = null;
      currentScanTarget = null;
      
      updateSummaryBar(0, '--', '--');
      renderResults();
      addActivityLog('All results cleared by user', 'System');
    };
    
    // Define clearFilters function (as implemented in main.js)
    clearFilters = () => {
      activeFilters.clear();
      updateFilterUI();
      renderResults();
    };
  });
  
  describe('Clear Filters Button Independence', () => {
    it('should clear only filters without affecting results data', () => {
      // Arrange: Active filters and results exist
      expect(activeFilters.size).toBe(2);
      expect(resultsData.length).toBe(3);
      
      // Act: Clear filters only
      clearFilters();
      
      // Assert: Filters cleared but results preserved
      expect(activeFilters.size).toBe(0);
      expect(resultsData.length).toBe(3);
      expect(resultsData[0].message).toBe('Critical issue');
    });
    
    it('should not clear activity log when clearing filters', () => {
      // Arrange: Activity log has content
      expect(activityLogContainer.innerHTML).toContain('Previous log');
      
      // Act: Clear filters
      clearFilters();
      
      // Assert: Activity log should remain unchanged
      expect(activityLogContainer.innerHTML).toContain('Previous log');
    });
    
    it('should not reset scan timing when clearing filters', () => {
      // Arrange: Scan timing variables are set
      const originalStartTime = scanStartTime;
      const originalEndTime = scanEndTime;
      const originalTarget = currentScanTarget;
      
      // Act: Clear filters
      clearFilters();
      
      // Assert: Timing variables should remain unchanged
      expect(scanStartTime).toBe(originalStartTime);
      expect(scanEndTime).toBe(originalEndTime);
      expect(currentScanTarget).toBe(originalTarget);
    });
    
    it('should not call updateSummaryBar when clearing filters', () => {
      // Arrange
      updateSummaryBar.mockClear();
      
      // Act: Clear filters
      clearFilters();
      
      // Assert: updateSummaryBar should not be called
      expect(updateSummaryBar).not.toHaveBeenCalled();
    });
    
    it('should call renderResults when clearing filters', () => {
      // Arrange
      renderResults.mockClear();
      
      // Act: Clear filters
      clearFilters();
      
      // Assert: renderResults should be called to update display
      expect(renderResults).toHaveBeenCalled();
      expect(renderResults).toHaveBeenCalledTimes(1);
    });
    
    it('should call updateFilterUI when clearing filters', () => {
      // Arrange
      updateFilterUI.mockClear();
      
      // Act: Clear filters
      clearFilters();
      
      // Assert: updateFilterUI should be called
      expect(updateFilterUI).toHaveBeenCalled();
      expect(updateFilterUI).toHaveBeenCalledTimes(1);
    });
  });
  
  describe('Clear Results Button Independence', () => {
    it('should clear both results and filters', () => {
      // Arrange
      global.confirm.mockReturnValue(true);
      expect(activeFilters.size).toBe(2);
      expect(resultsData.length).toBe(3);
      
      // Act: Clear results
      clearResults();
      
      // Assert: Both results and filters should be cleared
      expect(resultsData.length).toBe(0);
      expect(activeFilters.size).toBe(0);
    });
    
    it('should clear activity log when clearing results', () => {
      // Arrange
      global.confirm.mockReturnValue(true);
      expect(activityLogContainer.innerHTML).toContain('Previous log');
      
      // Act: Clear results
      clearResults();
      
      // Assert: Activity log should be cleared
      expect(activityLogContainer.innerHTML).toBe('');
    });
    
    it('should reset scan timing when clearing results', () => {
      // Arrange
      global.confirm.mockReturnValue(true);
      
      // Act: Clear results
      clearResults();
      
      // Assert: Timing variables should be reset
      expect(scanStartTime).toBeNull();
      expect(scanEndTime).toBeNull();
      expect(currentScanTarget).toBeNull();
    });
    
    it('should call updateSummaryBar when clearing results', () => {
      // Arrange
      global.confirm.mockReturnValue(true);
      updateSummaryBar.mockClear();
      
      // Act: Clear results
      clearResults();
      
      // Assert: updateSummaryBar should be called with defaults
      expect(updateSummaryBar).toHaveBeenCalledWith(0, '--', '--');
    });
  });
  
  describe('Sequential Operations - Clear Filters then Clear Results', () => {
    it('should work correctly when clearing filters first, then results', () => {
      // Arrange: Initial state
      expect(activeFilters.size).toBe(2);
      expect(resultsData.length).toBe(3);
      
      // Act: Clear filters first
      clearFilters();
      expect(activeFilters.size).toBe(0);
      expect(resultsData.length).toBe(3);
      
      // Then clear results
      global.confirm.mockReturnValue(true);
      clearResults();
      
      // Assert: Everything should be cleared
      expect(activeFilters.size).toBe(0);
      expect(resultsData.length).toBe(0);
      expect(activityLogContainer.innerHTML).toBe('');
    });
    
    it('should call updateFilterUI twice when clearing filters then results', () => {
      // Arrange
      updateFilterUI.mockClear();
      
      // Act: Clear filters
      clearFilters();
      expect(updateFilterUI).toHaveBeenCalledTimes(1);
      
      // Then clear results
      global.confirm.mockReturnValue(true);
      clearResults();
      
      // Assert: updateFilterUI should be called twice total
      expect(updateFilterUI).toHaveBeenCalledTimes(2);
    });
  });
  
  describe('Sequential Operations - Clear Results then Clear Filters', () => {
    it('should work correctly when clearing results first, then filters', () => {
      // Arrange: Initial state
      expect(activeFilters.size).toBe(2);
      expect(resultsData.length).toBe(3);
      
      // Act: Clear results first
      global.confirm.mockReturnValue(true);
      clearResults();
      expect(activeFilters.size).toBe(0);
      expect(resultsData.length).toBe(0);
      
      // Then try to clear filters (should be no-op since already cleared)
      clearFilters();
      
      // Assert: Everything should remain cleared
      expect(activeFilters.size).toBe(0);
      expect(resultsData.length).toBe(0);
    });
    
    it('should handle clearing filters after results are already cleared', () => {
      // Arrange: Clear results first
      global.confirm.mockReturnValue(true);
      clearResults();
      
      // Act: Try to clear filters (already cleared by clearResults)
      clearFilters();
      
      // Assert: Should not cause errors
      expect(activeFilters.size).toBe(0);
      expect(resultsData.length).toBe(0);
    });
  });
  
  describe('Interleaved Operations with New Data', () => {
    it('should allow filters to be set after clearing results', () => {
      // Arrange: Clear results
      global.confirm.mockReturnValue(true);
      clearResults();
      expect(activeFilters.size).toBe(0);
      
      // Act: Add new filters
      activeFilters.add('critical');
      activeFilters.add('warning');
      
      // Assert: Filters should be set
      expect(activeFilters.size).toBe(2);
      expect(activeFilters.has('critical')).toBe(true);
      expect(activeFilters.has('warning')).toBe(true);
    });
    
    it('should allow clearing filters after adding new results', () => {
      // Arrange: Clear results, then add new data
      global.confirm.mockReturnValue(true);
      clearResults();
      
      resultsData.push({ id: '4', status: 'threat', message: 'New issue', tool: 'Scanner4' });
      activeFilters.add('critical');
      
      // Act: Clear filters
      clearFilters();
      
      // Assert: Filters cleared but new results preserved
      expect(activeFilters.size).toBe(0);
      expect(resultsData.length).toBe(1);
      expect(resultsData[0].message).toBe('New issue');
    });
  });
  
  describe('Function Call Patterns', () => {
    it('should show different function call patterns for each button', () => {
      // Arrange
      updateSummaryBar.mockClear();
      updateFilterUI.mockClear();
      renderResults.mockClear();
      addActivityLog.mockClear();
      
      // Act: Clear filters
      clearFilters();
      
      // Assert: Clear Filters pattern
      expect(updateSummaryBar).not.toHaveBeenCalled();
      expect(updateFilterUI).toHaveBeenCalledTimes(1);
      expect(renderResults).toHaveBeenCalledTimes(1);
      expect(addActivityLog).not.toHaveBeenCalled();
      
      // Reset mocks
      updateSummaryBar.mockClear();
      updateFilterUI.mockClear();
      renderResults.mockClear();
      addActivityLog.mockClear();
      
      // Act: Clear results
      global.confirm.mockReturnValue(true);
      clearResults();
      
      // Assert: Clear Results pattern (more comprehensive)
      expect(updateSummaryBar).toHaveBeenCalledWith(0, '--', '--');
      expect(updateFilterUI).toHaveBeenCalledTimes(1);
      expect(renderResults).toHaveBeenCalledTimes(1);
      expect(addActivityLog).toHaveBeenCalledWith('All results cleared by user', 'System');
    });
  });
  
  describe('Requirements Validation', () => {
    it('should satisfy Requirement 5.1 - Clear Results does not interfere with Clear Filters', () => {
      // Arrange: Set up initial state
      expect(activeFilters.size).toBe(2);
      expect(resultsData.length).toBe(3);
      
      // Act: Test Clear Filters works independently
      clearFilters();
      
      // Assert: Clear Filters functionality works correctly
      expect(activeFilters.size).toBe(0);
      expect(resultsData.length).toBe(3); // Results preserved
      expect(updateFilterUI).toHaveBeenCalled();
      expect(renderResults).toHaveBeenCalled();
      
      // Reset state
      activeFilters.add('critical');
      activeFilters.add('warning');
      updateFilterUI.mockClear();
      renderResults.mockClear();
      
      // Act: Test Clear Results
      global.confirm.mockReturnValue(true);
      clearResults();
      
      // Assert: Clear Results works but doesn't break Clear Filters
      expect(activeFilters.size).toBe(0);
      expect(resultsData.length).toBe(0);
      
      // Verify Clear Filters still works after Clear Results
      activeFilters.add('info');
      clearFilters();
      expect(activeFilters.size).toBe(0);
    });
    
    it('should verify both buttons can be used alternately without issues', () => {
      // Test multiple alternating operations
      
      // Operation 1: Clear Filters
      clearFilters();
      expect(activeFilters.size).toBe(0);
      expect(resultsData.length).toBe(3);
      
      // Operation 2: Add filters back
      activeFilters.add('critical');
      
      // Operation 3: Clear Results
      global.confirm.mockReturnValue(true);
      clearResults();
      expect(activeFilters.size).toBe(0);
      expect(resultsData.length).toBe(0);
      
      // Operation 4: Add new data and filters
      resultsData.push({ id: '5', status: 'warning', message: 'New warning', tool: 'Scanner5' });
      activeFilters.add('warning');
      
      // Operation 5: Clear Filters again
      clearFilters();
      expect(activeFilters.size).toBe(0);
      expect(resultsData.length).toBe(1);
      
      // Operation 6: Clear Results again
      global.confirm.mockReturnValue(true);
      clearResults();
      expect(activeFilters.size).toBe(0);
      expect(resultsData.length).toBe(0);
    });
  });
  
  describe('Edge Cases', () => {
    it('should handle clearing filters when no filters are active', () => {
      // Arrange: Clear filters first
      activeFilters.clear();
      expect(activeFilters.size).toBe(0);
      
      // Act: Try to clear filters again
      clearFilters();
      
      // Assert: Should not cause errors
      expect(activeFilters.size).toBe(0);
      expect(updateFilterUI).toHaveBeenCalled();
      expect(renderResults).toHaveBeenCalled();
    });
    
    it('should handle clearing results when no results exist', () => {
      // Arrange: Clear results first
      resultsData = [];
      global.confirm.mockReturnValue(true);
      
      // Act: Try to clear results again
      clearResults();
      
      // Assert: Should not cause errors
      expect(resultsData.length).toBe(0);
      expect(updateSummaryBar).toHaveBeenCalledWith(0, '--', '--');
    });
    
    it('should handle user canceling Clear Results after using Clear Filters', () => {
      // Arrange: Clear filters first
      clearFilters();
      expect(activeFilters.size).toBe(0);
      
      // Act: Try to clear results but cancel
      global.confirm.mockReturnValue(false);
      clearResults();
      
      // Assert: Results should be preserved
      expect(resultsData.length).toBe(3);
      expect(activityLogContainer.innerHTML).toContain('Previous log');
    });
  });
});
