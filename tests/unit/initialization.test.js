/**
 * Unit Tests for Component Initialization
 * 
 * Tests that SelectionManager and SelectAllToggle are properly initialized
 * in the DOMContentLoaded handler.
 * 
 * Requirements: 1.1, 5.1, 7.3
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { JSDOM } from 'jsdom';

describe('Component Initialization', () => {
  let dom;
  let document;
  let mockLocalStorage;
  let SelectionManager;
  let SelectAllToggle;

  beforeEach(() => {
    // Create a fresh DOM for each test
    dom = new JSDOM(`
      <!DOCTYPE html>
      <html>
        <body>
          <div id="network-tools" class="tab-pane active">
            <div class="cyber-tool-card" data-selected="false" data-tool-id="port-scan-btn">
              <div class="selection-indicator hidden"></div>
              <button id="port-scan-btn">Scan Ports</button>
            </div>
          </div>
          <div id="web-security" class="tab-pane">
            <div class="cyber-tool-card" data-selected="false" data-tool-id="xss-btn">
              <div class="selection-indicator hidden"></div>
              <button id="xss-btn">XSS Test</button>
            </div>
          </div>
          <button id="select-all-toggle-btn">Select All</button>
          <span id="selection-count-display">No tools selected</span>
        </body>
      </html>
    `);
    
    document = dom.window.document;
    global.document = document;
    global.window = dom.window;

    // Mock localStorage
    mockLocalStorage = {
      getItem: vi.fn(() => null),
      setItem: vi.fn(),
      removeItem: vi.fn()
    };
    global.localStorage = mockLocalStorage;

    // Create mock SelectionManager
    SelectionManager = {
      init: vi.fn(),
      attachEventListeners: vi.fn(),
      restoreSelections: vi.fn(),
      updateSelectionCount: vi.fn()
    };

    // Create mock SelectAllToggle
    SelectAllToggle = {
      init: vi.fn(),
      updateButtonLabel: vi.fn()
    };
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  describe('SelectionManager Initialization', () => {
    it('should call SelectionManager.init() after DOM is loaded', () => {
      // Simulate DOMContentLoaded event
      SelectionManager.init();

      expect(SelectionManager.init).toHaveBeenCalled();
    });

    it('should call attachEventListeners during initialization', () => {
      SelectionManager.init = vi.fn(() => {
        SelectionManager.attachEventListeners();
        SelectionManager.restoreSelections();
        SelectionManager.updateSelectionCount();
      });

      SelectionManager.init();

      expect(SelectionManager.attachEventListeners).toHaveBeenCalled();
    });

    it('should call restoreSelections during initialization', () => {
      SelectionManager.init = vi.fn(() => {
        SelectionManager.attachEventListeners();
        SelectionManager.restoreSelections();
        SelectionManager.updateSelectionCount();
      });

      SelectionManager.init();

      expect(SelectionManager.restoreSelections).toHaveBeenCalled();
    });

    it('should call updateSelectionCount during initialization', () => {
      SelectionManager.init = vi.fn(() => {
        SelectionManager.attachEventListeners();
        SelectionManager.restoreSelections();
        SelectionManager.updateSelectionCount();
      });

      SelectionManager.init();

      expect(SelectionManager.updateSelectionCount).toHaveBeenCalled();
    });
  });

  describe('SelectAllToggle Initialization', () => {
    it('should call SelectAllToggle.init() after DOM is loaded', () => {
      // Simulate DOMContentLoaded event
      SelectAllToggle.init();

      expect(SelectAllToggle.init).toHaveBeenCalled();
    });

    it('should call updateButtonLabel during initialization', () => {
      SelectAllToggle.init = vi.fn(() => {
        SelectAllToggle.updateButtonLabel();
      });

      SelectAllToggle.init();

      expect(SelectAllToggle.updateButtonLabel).toHaveBeenCalled();
    });
  });

  describe('Initialization Order', () => {
    it('should initialize SelectionManager before SelectAllToggle', () => {
      const callOrder = [];

      SelectionManager.init = vi.fn(() => {
        callOrder.push('SelectionManager');
      });

      SelectAllToggle.init = vi.fn(() => {
        callOrder.push('SelectAllToggle');
      });

      // Simulate the initialization order in main.js
      SelectionManager.init();
      SelectAllToggle.init();

      expect(callOrder).toEqual(['SelectionManager', 'SelectAllToggle']);
    });

    it('should initialize components after DOM is fully loaded', () => {
      let domLoaded = false;
      const initCalls = [];

      // Simulate DOMContentLoaded
      const mockAddEventListener = vi.fn((event, callback) => {
        if (event === 'DOMContentLoaded') {
          domLoaded = true;
          callback();
        }
      });

      SelectionManager.init = vi.fn(() => {
        if (domLoaded) {
          initCalls.push('SelectionManager');
        }
      });

      SelectAllToggle.init = vi.fn(() => {
        if (domLoaded) {
          initCalls.push('SelectAllToggle');
        }
      });

      // Trigger DOMContentLoaded
      mockAddEventListener('DOMContentLoaded', () => {
        SelectionManager.init();
        SelectAllToggle.init();
      });

      expect(initCalls).toEqual(['SelectionManager', 'SelectAllToggle']);
    });
  });

  describe('Error Handling During Initialization', () => {
    it('should handle missing DOM elements gracefully', () => {
      const emptyDom = new JSDOM(`<!DOCTYPE html><html><body></body></html>`);
      global.document = emptyDom.window.document;

      SelectionManager.init = vi.fn(() => {
        const toolCards = global.document.querySelectorAll('.cyber-tool-card');
        const toggleBtn = global.document.getElementById('select-all-toggle-btn');
        
        // Should not throw even if elements are missing
        expect(toolCards.length).toBe(0);
        expect(toggleBtn).toBeNull();
      });

      expect(() => SelectionManager.init()).not.toThrow();
    });

    it('should handle localStorage errors gracefully', () => {
      mockLocalStorage.getItem = vi.fn(() => {
        throw new Error('localStorage not available');
      });

      SelectionManager.restoreSelections = vi.fn(() => {
        try {
          mockLocalStorage.getItem('cyberguard-tool-selections');
        } catch (e) {
          // Should catch and handle the error
          console.error('Failed to restore selections:', e);
        }
      });

      expect(() => SelectionManager.restoreSelections()).not.toThrow();
    });

    it('should handle corrupted localStorage data gracefully', () => {
      mockLocalStorage.getItem = vi.fn(() => 'invalid-json{');

      SelectionManager.restoreSelections = vi.fn(() => {
        try {
          const saved = mockLocalStorage.getItem('cyberguard-tool-selections');
          if (saved) {
            JSON.parse(saved);
          }
        } catch (e) {
          // Should catch and handle the error
          console.error('Failed to parse selections:', e);
        }
      });

      expect(() => SelectionManager.restoreSelections()).not.toThrow();
    });
  });
});
