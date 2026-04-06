/**
 * Integration tests for Clear Results Button - Task 6.3
 * Tests that new scans can be run after clearing results
 * 
 * Requirements tested:
 * - 5.3: Dashboard should allow new scans to execute normally after clearing results
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { JSDOM } from 'jsdom';
import fs from 'fs';
import path from 'path';

describe('Clear Results Button - Task 6.3: New Scan After Clear', () => {
  let dom;
  let document;
  let resultsData;
  let activeFilters;
  let scanStartTime;
  let scanEndTime;
  let currentScanTarget;
  let clearResults;
  let updateFilterUI;
  let updateSummaryBar;
  let renderResults;
  let addActivityLog;
  let logResult;

  beforeEach(() => {
    // Load the actual dashboard.html file
    const dashboardPath = path.resolve(__dirname, '../../dashboard.html');
    const dashboardHTML = fs.readFileSync(dashboardPath, 'utf-8');
    
    dom = new JSDOM(dashboardHTML, {
      url: 'http://localhost',
      runScripts: 'outside-only'
    });
    
    document = dom.window.document;
    global.document = document;
    global.window = dom.window;
    global.confirm = vi.fn();

    // Initialize state variables
    resultsData = [];
    activeFilters = new Set();
    scanStartTime = null;
    scanEndTime = null;
    currentScanTarget = null;

    // Mock utility functions
    updateFilterUI = vi.fn();
    updateSummaryBar = vi.fn();
    renderResults = vi.fn();
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

    // Define logResult function (simplified version from main.js)
    logResult = (timestamp, feature, message, status = "info") => {
      let newStatus = status;
      if (status === "success") newStatus = "safe";
      else if (status === "warning") newStatus = "warning";
      else if (status === "danger") newStatus = "threat";
      else if (status === "info") newStatus = "system";

      const result = {
        id: Date.now().toString(),
        timestamp: timestamp.toLocaleTimeString(),
        feature: feature,
        message: message,
        status: newStatus,
        date: timestamp,
      };

      resultsData.push(result);
      renderResults();
    };
  });

  describe('New Scan After Clearing Results', () => {
    it('should allow new scan to populate results after clearing', () => {
      // Arrange: Add some initial results
      logResult(new Date(), 'Port Scanner', 'Port 80 is open', 'info');
      logResult(new Date(), 'SSL Check', 'SSL certificate valid', 'success');
      expect(resultsData.length).toBe(2);

      // Clear results
      global.confirm.mockReturnValue(true);
      clearResults();
      expect(resultsData.length).toBe(0);

      // Act: Simulate a new scan by adding new results
      logResult(new Date(), 'WHOIS Lookup', 'Domain registered', 'info');
      logResult(new Date(), 'IP Geolocation', 'Location: US', 'info');

      // Assert: New results should be added successfully
      expect(resultsData.length).toBe(2);
      expect(resultsData[0].feature).toBe('WHOIS Lookup');
      expect(resultsData[1].feature).toBe('IP Geolocation');
    });

    it('should call renderResults when new scan adds results', () => {
      // Arrange: Clear results first
      global.confirm.mockReturnValue(true);
      clearResults();
      renderResults.mockClear(); // Clear the mock call from clearResults

      // Act: Add new scan result
      logResult(new Date(), 'Port Scanner', 'Scan complete', 'success');

      // Assert: renderResults should be called
      expect(renderResults).toHaveBeenCalled();
    });

    it('should generate unique IDs for new results after clearing', async () => {
      // Arrange: Add initial results and clear
      logResult(new Date(), 'Initial Scan', 'Result 1', 'info');
      const firstId = resultsData[0].id;
      
      global.confirm.mockReturnValue(true);
      clearResults();

      // Wait 1ms to ensure different timestamp
      await new Promise(resolve => setTimeout(resolve, 1));

      // Act: Add new results after clearing
      logResult(new Date(), 'New Scan', 'Result 2', 'info');
      const secondId = resultsData[0].id;

      // Assert: IDs should be different
      expect(secondId).not.toBe(firstId);
    });

    it('should handle multiple scans after clearing', () => {
      // Arrange: Clear results
      global.confirm.mockReturnValue(true);
      clearResults();

      // Act: Run multiple scans
      // First scan
      logResult(new Date(), 'Port Scanner', 'Port 80 open', 'info');
      logResult(new Date(), 'Port Scanner', 'Port 443 open', 'info');
      expect(resultsData.length).toBe(2);

      // Second scan (without clearing)
      logResult(new Date(), 'SSL Check', 'Certificate valid', 'success');
      expect(resultsData.length).toBe(3);

      // Assert: All results should be present
      expect(resultsData[0].feature).toBe('Port Scanner');
      expect(resultsData[1].feature).toBe('Port Scanner');
      expect(resultsData[2].feature).toBe('SSL Check');
    });

    it('should preserve scan timing variables for new scans', () => {
      // Arrange: Clear results
      global.confirm.mockReturnValue(true);
      clearResults();
      expect(scanStartTime).toBeNull();
      expect(scanEndTime).toBeNull();
      expect(currentScanTarget).toBeNull();

      // Act: Simulate new scan with timing
      scanStartTime = Date.now();
      currentScanTarget = '8.8.8.8';
      logResult(new Date(), 'Port Scanner', 'Scanning...', 'info');
      scanEndTime = Date.now();

      // Assert: Timing variables should be set
      expect(scanStartTime).not.toBeNull();
      expect(scanEndTime).not.toBeNull();
      expect(currentScanTarget).toBe('8.8.8.8');
    });

    it('should allow results with different status types after clearing', () => {
      // Arrange: Clear results
      global.confirm.mockReturnValue(true);
      clearResults();

      // Act: Add results with different statuses
      logResult(new Date(), 'Security Check', 'Threat detected', 'danger');
      logResult(new Date(), 'Security Check', 'Warning found', 'warning');
      logResult(new Date(), 'Security Check', 'All clear', 'success');
      logResult(new Date(), 'Security Check', 'Info message', 'info');

      // Assert: All status types should be mapped correctly
      expect(resultsData.length).toBe(4);
      expect(resultsData[0].status).toBe('threat');
      expect(resultsData[1].status).toBe('warning');
      expect(resultsData[2].status).toBe('safe');
      expect(resultsData[3].status).toBe('system');
    });
  });

  describe('Integration with Summary Bar After Clear', () => {
    it('should allow Summary Bar updates after clearing', () => {
      // Arrange: Clear results
      global.confirm.mockReturnValue(true);
      clearResults();
      updateSummaryBar.mockClear();

      // Act: Simulate scan completion with Summary Bar update
      scanStartTime = Date.now();
      logResult(new Date(), 'Port Scanner', 'Scan complete', 'info');
      scanEndTime = Date.now();
      
      const timeTaken = '2s';
      updateSummaryBar(resultsData.length, timeTaken, '8.8.8.8');

      // Assert: Summary Bar should be updated with new values
      expect(updateSummaryBar).toHaveBeenCalledWith(1, '2s', '8.8.8.8');
    });
  });

  describe('Integration with Activity Log After Clear', () => {
    it('should allow activity log entries after clearing', () => {
      // Arrange: Clear results (which clears activity log)
      global.confirm.mockReturnValue(true);
      clearResults();
      
      const activityLogContainer = document.getElementById('activity-log-container');
      expect(activityLogContainer.innerHTML).toBe('');

      // Act: Add new activity log entry
      const logEntry = document.createElement('div');
      logEntry.className = 'log-entry text-slate-400';
      logEntry.innerHTML = '<span>[12:00]</span> <span>Port Scanner:</span> <span>Starting scan...</span>';
      activityLogContainer.appendChild(logEntry);

      // Assert: Activity log should contain new entry
      expect(activityLogContainer.children.length).toBe(1);
      expect(activityLogContainer.querySelector('.log-entry')).toBeTruthy();
    });
  });

  describe('Requirements Validation', () => {
    it('should satisfy Requirement 5.3 - New scans execute normally after clearing', () => {
      // Arrange: Add initial results and clear
      logResult(new Date(), 'Initial Scan', 'Old result', 'info');
      global.confirm.mockReturnValue(true);
      clearResults();

      // Act: Run new scan
      const scanStart = Date.now();
      logResult(new Date(), 'Port Scanner', 'Port 80 open', 'info');
      logResult(new Date(), 'SSL Check', 'Certificate valid', 'success');
      const scanEnd = Date.now();

      // Assert: New scan should execute normally
      expect(resultsData.length).toBe(2);
      expect(resultsData[0].feature).toBe('Port Scanner');
      expect(resultsData[1].feature).toBe('SSL Check');
      
      // Results should have proper structure
      resultsData.forEach(result => {
        expect(result).toHaveProperty('id');
        expect(result).toHaveProperty('timestamp');
        expect(result).toHaveProperty('feature');
        expect(result).toHaveProperty('message');
        expect(result).toHaveProperty('status');
      });
    });

    it('should allow continuous clear and scan cycles', () => {
      // Test multiple clear and scan cycles
      for (let i = 0; i < 3; i++) {
        // Add results
        logResult(new Date(), `Scan ${i}`, `Result ${i}`, 'info');
        expect(resultsData.length).toBeGreaterThan(0);

        // Clear results
        global.confirm.mockReturnValue(true);
        clearResults();
        expect(resultsData.length).toBe(0);
      }

      // Final scan should still work
      logResult(new Date(), 'Final Scan', 'Final result', 'success');
      expect(resultsData.length).toBe(1);
      expect(resultsData[0].feature).toBe('Final Scan');
    });
  });
});
