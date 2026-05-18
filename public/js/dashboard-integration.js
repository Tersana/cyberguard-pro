/**
 * dashboard-integration.js
 * Integration layer for the Risk Dashboard
 * Connects the StateManager to the scan system via custom events
 */

(function () {
  "use strict";

  /**
   * Initialize the dashboard integration
   * Sets up event listeners for scan lifecycle events
   */
  function initializeDashboard() {
    // === AUTHENTICATION CHECK ===
    if (typeof window.runAuthGuard === 'function' && !window.runAuthGuard()) {
      return; // Stop initialization if not authenticated
    }

    // Reset dashboard to empty state on page load
    if (window.StateManager) {
      window.StateManager.resetDashboard();
    }

    // Register event listener for scan start
    document.addEventListener('cyberguard:scanStart', () => {
      if (window.StateManager) {
        window.StateManager.enterScanningState();
      }
    });

    // Register event listener for scan result
    document.addEventListener('cyberguard:scanResult', (event) => {
      if (window.StateManager && event.detail) {
        window.StateManager.enterResultState(event.detail);
      }
    });

    // Register event listener for scan reset
    document.addEventListener('cyberguard:scanReset', () => {
      if (window.StateManager) {
        window.StateManager.resetDashboard();
      }
    });

    // Register event listener for scan error
    document.addEventListener('cyberguard:scanError', () => {
      if (window.StateManager) {
        window.StateManager.handleScanFailure();
      }
    });
  }

  // Initialize on DOMContentLoaded or immediately if DOM is already loaded
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initializeDashboard);
  } else {
    initializeDashboard();
  }

})();
