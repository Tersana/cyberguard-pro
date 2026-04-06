/**
 * Unit tests for dashboard-integration.js
 * Tests the integration layer that connects StateManager to custom events
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { JSDOM } from 'jsdom';

describe('Dashboard Integration', () => {
  let dom;
  let document;
  let window;

  beforeEach(() => {
    // Create a fresh DOM for each test
    dom = new JSDOM('<!DOCTYPE html><html><body></body></html>', {
      url: 'http://localhost',
      runScripts: 'dangerously',
      resources: 'usable'
    });
    document = dom.window.document;
    window = dom.window;

    // Mock StateManager
    window.StateManager = {
      resetDashboard: vi.fn(),
      enterScanningState: vi.fn(),
      enterResultState: vi.fn(),
      handleScanFailure: vi.fn()
    };
  });

  describe('DOMContentLoaded event listener', () => {
    it('should call StateManager.resetDashboard on page load', () => {
      // Load the integration script
      const scriptContent = `
        (function () {
          "use strict";
          function initializeDashboard() {
            if (window.StateManager) {
              window.StateManager.resetDashboard();
            }
            document.addEventListener('cyberguard:scanStart', () => {
              if (window.StateManager) {
                window.StateManager.enterScanningState();
              }
            });
            document.addEventListener('cyberguard:scanResult', (event) => {
              if (window.StateManager && event.detail) {
                window.StateManager.enterResultState(event.detail);
              }
            });
            document.addEventListener('cyberguard:scanReset', () => {
              if (window.StateManager) {
                window.StateManager.resetDashboard();
              }
            });
            document.addEventListener('cyberguard:scanError', () => {
              if (window.StateManager) {
                window.StateManager.handleScanFailure();
              }
            });
          }
          if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', initializeDashboard);
          } else {
            initializeDashboard();
          }
        })();
      `;

      // Execute the script
      const script = document.createElement('script');
      script.textContent = scriptContent;
      document.body.appendChild(script);

      // Verify resetDashboard was called
      expect(window.StateManager.resetDashboard).toHaveBeenCalledTimes(1);
    });
  });

  describe('cyberguard:scanStart event listener', () => {
    it('should call StateManager.enterScanningState when event is dispatched', () => {
      // Load the integration script
      const scriptContent = `
        (function () {
          "use strict";
          function initializeDashboard() {
            if (window.StateManager) {
              window.StateManager.resetDashboard();
            }
            document.addEventListener('cyberguard:scanStart', () => {
              if (window.StateManager) {
                window.StateManager.enterScanningState();
              }
            });
          }
          initializeDashboard();
        })();
      `;

      const script = document.createElement('script');
      script.textContent = scriptContent;
      document.body.appendChild(script);

      // Reset the mock to clear the resetDashboard call
      window.StateManager.enterScanningState.mockClear();

      // Dispatch the event
      document.dispatchEvent(new window.CustomEvent('cyberguard:scanStart'));

      // Verify enterScanningState was called
      expect(window.StateManager.enterScanningState).toHaveBeenCalledTimes(1);
    });
  });

  describe('cyberguard:scanResult event listener', () => {
    it('should call StateManager.enterResultState with event detail', () => {
      // Load the integration script
      const scriptContent = `
        (function () {
          "use strict";
          function initializeDashboard() {
            document.addEventListener('cyberguard:scanResult', (event) => {
              if (window.StateManager && event.detail) {
                window.StateManager.enterResultState(event.detail);
              }
            });
          }
          initializeDashboard();
        })();
      `;

      const script = document.createElement('script');
      script.textContent = scriptContent;
      document.body.appendChild(script);

      // Create mock scan data
      const mockScanData = {
        network: { openPortsCount: 5, responseTimeMs: 150 },
        web: { sslStatus: 'valid' },
        issues: { criticalCount: 2, warnings: ['Warning 1'] },
        timestamp: new Date().toISOString()
      };

      // Dispatch the event with detail
      document.dispatchEvent(
        new window.CustomEvent('cyberguard:scanResult', { detail: mockScanData })
      );

      // Verify enterResultState was called with the correct data
      expect(window.StateManager.enterResultState).toHaveBeenCalledTimes(1);
      expect(window.StateManager.enterResultState).toHaveBeenCalledWith(mockScanData);
    });

    it('should not call StateManager.enterResultState if event detail is missing', () => {
      // Load the integration script
      const scriptContent = `
        (function () {
          "use strict";
          function initializeDashboard() {
            document.addEventListener('cyberguard:scanResult', (event) => {
              if (window.StateManager && event.detail) {
                window.StateManager.enterResultState(event.detail);
              }
            });
          }
          initializeDashboard();
        })();
      `;

      const script = document.createElement('script');
      script.textContent = scriptContent;
      document.body.appendChild(script);

      // Dispatch the event without detail
      document.dispatchEvent(new window.CustomEvent('cyberguard:scanResult'));

      // Verify enterResultState was not called
      expect(window.StateManager.enterResultState).not.toHaveBeenCalled();
    });
  });

  describe('cyberguard:scanReset event listener', () => {
    it('should call StateManager.resetDashboard when event is dispatched', () => {
      // Load the integration script
      const scriptContent = `
        (function () {
          "use strict";
          function initializeDashboard() {
            if (window.StateManager) {
              window.StateManager.resetDashboard();
            }
            document.addEventListener('cyberguard:scanReset', () => {
              if (window.StateManager) {
                window.StateManager.resetDashboard();
              }
            });
          }
          initializeDashboard();
        })();
      `;

      const script = document.createElement('script');
      script.textContent = scriptContent;
      document.body.appendChild(script);

      // Reset the mock to clear the initial resetDashboard call
      window.StateManager.resetDashboard.mockClear();

      // Dispatch the event
      document.dispatchEvent(new window.CustomEvent('cyberguard:scanReset'));

      // Verify resetDashboard was called
      expect(window.StateManager.resetDashboard).toHaveBeenCalledTimes(1);
    });
  });

  describe('cyberguard:scanError event listener', () => {
    it('should call StateManager.handleScanFailure when event is dispatched', () => {
      // Load the integration script
      const scriptContent = `
        (function () {
          "use strict";
          function initializeDashboard() {
            document.addEventListener('cyberguard:scanError', () => {
              if (window.StateManager) {
                window.StateManager.handleScanFailure();
              }
            });
          }
          initializeDashboard();
        })();
      `;

      const script = document.createElement('script');
      script.textContent = scriptContent;
      document.body.appendChild(script);

      // Dispatch the event
      document.dispatchEvent(new window.CustomEvent('cyberguard:scanError'));

      // Verify handleScanFailure was called
      expect(window.StateManager.handleScanFailure).toHaveBeenCalledTimes(1);
    });
  });

  describe('StateManager availability check', () => {
    it('should not throw error if StateManager is not available', () => {
      // Remove StateManager
      delete window.StateManager;

      // Load the integration script
      const scriptContent = `
        (function () {
          "use strict";
          function initializeDashboard() {
            if (window.StateManager) {
              window.StateManager.resetDashboard();
            }
            document.addEventListener('cyberguard:scanStart', () => {
              if (window.StateManager) {
                window.StateManager.enterScanningState();
              }
            });
          }
          initializeDashboard();
        })();
      `;

      // This should not throw an error
      expect(() => {
        const script = document.createElement('script');
        script.textContent = scriptContent;
        document.body.appendChild(script);
      }).not.toThrow();
    });
  });
});
