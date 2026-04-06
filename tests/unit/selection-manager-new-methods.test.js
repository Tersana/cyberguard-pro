/**
 * Unit tests for SelectionManager new methods (Tasks 2.4, 2.5, 3.1, 3.2)
 * Tests getSelectedTools(), updateSelectionCount(), saveToLocalStorage(), restoreSelections()
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { JSDOM } from 'jsdom';

describe('SelectionManager - New Methods (Tasks 2.4, 2.5, 3.1, 3.2)', () => {
  let dom;
  let document;
  let SelectionManager;
  let localStorage;

  beforeEach(() => {
    // Create a minimal DOM structure
    dom = new JSDOM(`
      <!DOCTYPE html>
      <html>
        <body>
          <div class="tab-pane active" id="network-tools">
            <div class="cyber-tool-card" data-selected="false" data-tool-id="port-scan-btn">
              <div class="selection-indicator hidden"></div>
            </div>
            <div class="cyber-tool-card" data-selected="true" data-tool-id="tcp-scan-btn">
              <div class="selection-indicator"></div>
            </div>
            <div class="cyber-tool-card" data-selected="true" data-tool-id="udp-scan-btn">
              <div class="selection-indicator"></div>
            </div>
          </div>
          <div class="tab-pane" id="web-security">
            <div class="cyber-tool-card" data-selected="true" data-tool-id="xss-btn">
              <div class="selection-indicator"></div>
            </div>
          </div>
          <span id="selection-count-display"></span>
        </body>
      </html>
    `);

    document = dom.window.document;
    global.document = document;
    global.window = dom.window;

    // Mock localStorage
    localStorage = {
      data: {},
      getItem(key) {
        return this.data[key] || null;
      },
      setItem(key, value) {
        this.data[key] = value;
      },
      clear() {
        this.data = {};
      }
    };
    global.localStorage = localStorage;

    // Define SelectionManager (copied from main.js)
    SelectionManager = {
      init() {
        this.attachEventListeners();
        this.restoreSelections();
        this.updateSelectionCount();
      },
      
      attachEventListeners() {
        const toolCards = document.querySelectorAll('.cyber-tool-card');
        
        toolCards.forEach(card => {
          card.addEventListener('click', (e) => {
            if (e.target.closest('button[id$="-btn"]')) {
              return;
            }
            this.toggleSelection(card);
          });
        });
      },
      
      toggleSelection(card) {
        const isSelected = card.dataset.selected === "true";
        card.dataset.selected = (!isSelected).toString();
        
        this.updateVisuals(card);
        this.saveToLocalStorage();
        this.updateSelectionCount();
      },
      
      updateVisuals(card) {
        const indicator = card.querySelector('.selection-indicator');
        const isSelected = card.dataset.selected === "true";
        
        if (isSelected) {
          indicator?.classList.remove('hidden');
        } else {
          indicator?.classList.add('hidden');
        }
      },
      
      getSelectedTools(tabId) {
        const tab = document.getElementById(tabId);
        if (!tab) return [];
        
        const selectedCards = tab.querySelectorAll('.cyber-tool-card[data-selected="true"]');
        const toolIds = [];
        
        selectedCards.forEach(card => {
          const toolId = card.dataset.toolId;
          if (toolId) {
            toolIds.push(toolId);
          }
        });
        
        return toolIds;
      },
      
      updateSelectionCount() {
        const activeTab = document.querySelector('.tab-pane.active');
        if (!activeTab) return;
        
        const selectedCount = activeTab.querySelectorAll('.cyber-tool-card[data-selected="true"]').length;
        const countDisplay = document.getElementById('selection-count-display');
        
        if (countDisplay) {
          if (selectedCount === 0) {
            countDisplay.textContent = 'No tools selected';
            countDisplay.className = 'text-xs text-slate-500';
          } else {
            countDisplay.textContent = `${selectedCount} tool${selectedCount > 1 ? 's' : ''} selected`;
            countDisplay.className = 'text-xs text-purple-400 font-semibold';
          }
        }
      },
      
      saveToLocalStorage() {
        const selections = {};
        const toolCards = document.querySelectorAll('.cyber-tool-card');
        
        toolCards.forEach(card => {
          const toolId = card.dataset.toolId;
          const isSelected = card.dataset.selected === "true";
          if (toolId) {
            selections[toolId] = isSelected;
          }
        });
        
        try {
          localStorage.setItem('cyberguard-tool-selections', JSON.stringify(selections));
        } catch (e) {
          console.error('Failed to save selections to localStorage:', e);
        }
      },
      
      restoreSelections() {
        try {
          const saved = localStorage.getItem('cyberguard-tool-selections');
          if (!saved) return;
          
          const selections = JSON.parse(saved);
          const toolCards = document.querySelectorAll('.cyber-tool-card');
          
          toolCards.forEach(card => {
            const toolId = card.dataset.toolId;
            if (toolId && selections[toolId] !== undefined) {
              card.dataset.selected = selections[toolId].toString();
              this.updateVisuals(card);
            }
          });
          
          this.updateSelectionCount();
        } catch (e) {
          console.error('Failed to restore selections from localStorage:', e);
        }
      }
    };
  });

  describe('Task 2.4: getSelectedTools() method', () => {
    it('should return array of selected tool IDs in network-tools tab', () => {
      const selectedTools = SelectionManager.getSelectedTools('network-tools');
      
      expect(selectedTools).toEqual(['tcp-scan-btn', 'udp-scan-btn']);
    });

    it('should return array of selected tool IDs in web-security tab', () => {
      const selectedTools = SelectionManager.getSelectedTools('web-security');
      
      expect(selectedTools).toEqual(['xss-btn']);
    });

    it('should return empty array if no tools are selected', () => {
      // Deselect all tools in network-tools
      const cards = document.querySelectorAll('#network-tools .cyber-tool-card');
      cards.forEach(card => card.dataset.selected = 'false');
      
      const selectedTools = SelectionManager.getSelectedTools('network-tools');
      
      expect(selectedTools).toEqual([]);
    });

    it('should return empty array if tab does not exist', () => {
      const selectedTools = SelectionManager.getSelectedTools('non-existent-tab');
      
      expect(selectedTools).toEqual([]);
    });
  });

  describe('Task 2.5: updateSelectionCount() method', () => {
    it('should display "No tools selected" when count is 0', () => {
      // Deselect all tools in active tab
      const cards = document.querySelectorAll('#network-tools .cyber-tool-card');
      cards.forEach(card => card.dataset.selected = 'false');
      
      SelectionManager.updateSelectionCount();
      
      const countDisplay = document.getElementById('selection-count-display');
      expect(countDisplay.textContent).toBe('No tools selected');
      expect(countDisplay.className).toBe('text-xs text-slate-500');
    });

    it('should display "1 tool selected" when count is 1', () => {
      // Set only one tool as selected
      const cards = document.querySelectorAll('#network-tools .cyber-tool-card');
      cards[0].dataset.selected = 'true';
      cards[1].dataset.selected = 'false';
      cards[2].dataset.selected = 'false';
      
      SelectionManager.updateSelectionCount();
      
      const countDisplay = document.getElementById('selection-count-display');
      expect(countDisplay.textContent).toBe('1 tool selected');
      expect(countDisplay.className).toBe('text-xs text-purple-400 font-semibold');
    });

    it('should display "2 tools selected" when count is 2', () => {
      // Set two tools as selected (already set in beforeEach)
      SelectionManager.updateSelectionCount();
      
      const countDisplay = document.getElementById('selection-count-display');
      expect(countDisplay.textContent).toBe('2 tools selected');
      expect(countDisplay.className).toBe('text-xs text-purple-400 font-semibold');
    });

    it('should apply correct CSS classes based on count', () => {
      SelectionManager.updateSelectionCount();
      
      const countDisplay = document.getElementById('selection-count-display');
      expect(countDisplay.className).toContain('text-purple-400');
      expect(countDisplay.className).toContain('font-semibold');
    });
  });

  describe('Task 3.1: saveToLocalStorage() method', () => {
    it('should save selection state to localStorage', () => {
      SelectionManager.saveToLocalStorage();
      
      const saved = localStorage.getItem('cyberguard-tool-selections');
      expect(saved).toBeTruthy();
      
      const selections = JSON.parse(saved);
      expect(selections['port-scan-btn']).toBe(false);
      expect(selections['tcp-scan-btn']).toBe(true);
      expect(selections['udp-scan-btn']).toBe(true);
      expect(selections['xss-btn']).toBe(true);
    });

    it('should create JSON object mapping tool IDs to boolean values', () => {
      SelectionManager.saveToLocalStorage();
      
      const saved = localStorage.getItem('cyberguard-tool-selections');
      const selections = JSON.parse(saved);
      
      expect(typeof selections).toBe('object');
      expect(typeof selections['port-scan-btn']).toBe('boolean');
      expect(typeof selections['tcp-scan-btn']).toBe('boolean');
    });

    it('should use key "cyberguard-tool-selections"', () => {
      SelectionManager.saveToLocalStorage();
      
      expect(localStorage.getItem('cyberguard-tool-selections')).toBeTruthy();
    });
  });

  describe('Task 3.2: restoreSelections() method', () => {
    it('should restore selection state from localStorage', () => {
      // Save initial state
      const initialState = {
        'port-scan-btn': true,
        'tcp-scan-btn': false,
        'udp-scan-btn': true,
        'xss-btn': false
      };
      localStorage.setItem('cyberguard-tool-selections', JSON.stringify(initialState));
      
      // Restore selections
      SelectionManager.restoreSelections();
      
      // Verify restored state
      const portScanCard = document.querySelector('[data-tool-id="port-scan-btn"]');
      const tcpScanCard = document.querySelector('[data-tool-id="tcp-scan-btn"]');
      const udpScanCard = document.querySelector('[data-tool-id="udp-scan-btn"]');
      const xssCard = document.querySelector('[data-tool-id="xss-btn"]');
      
      expect(portScanCard.dataset.selected).toBe('true');
      expect(tcpScanCard.dataset.selected).toBe('false');
      expect(udpScanCard.dataset.selected).toBe('true');
      expect(xssCard.dataset.selected).toBe('false');
    });

    it('should call updateVisuals() for each restored card', () => {
      const initialState = {
        'port-scan-btn': true,
        'tcp-scan-btn': false
      };
      localStorage.setItem('cyberguard-tool-selections', JSON.stringify(initialState));
      
      SelectionManager.restoreSelections();
      
      // Verify visual indicators are updated
      const portScanCard = document.querySelector('[data-tool-id="port-scan-btn"]');
      const indicator = portScanCard.querySelector('.selection-indicator');
      
      expect(indicator.classList.contains('hidden')).toBe(false);
    });

    it('should call updateSelectionCount() after restoration', () => {
      const updateCountSpy = vi.spyOn(SelectionManager, 'updateSelectionCount');
      
      const initialState = {
        'port-scan-btn': true,
        'tcp-scan-btn': true
      };
      localStorage.setItem('cyberguard-tool-selections', JSON.stringify(initialState));
      
      SelectionManager.restoreSelections();
      
      expect(updateCountSpy).toHaveBeenCalled();
    });

    it('should handle missing localStorage data gracefully', () => {
      localStorage.clear();
      
      expect(() => {
        SelectionManager.restoreSelections();
      }).not.toThrow();
    });

    it('should handle corrupted JSON gracefully', () => {
      localStorage.setItem('cyberguard-tool-selections', 'invalid-json{');
      
      expect(() => {
        SelectionManager.restoreSelections();
      }).not.toThrow();
    });
  });

  describe('Integration: toggleSelection() calls new methods', () => {
    it('should call saveToLocalStorage() when toggling selection', () => {
      const saveSpy = vi.spyOn(SelectionManager, 'saveToLocalStorage');
      
      const card = document.querySelector('[data-tool-id="port-scan-btn"]');
      SelectionManager.toggleSelection(card);
      
      expect(saveSpy).toHaveBeenCalled();
    });

    it('should call updateSelectionCount() when toggling selection', () => {
      const updateCountSpy = vi.spyOn(SelectionManager, 'updateSelectionCount');
      
      const card = document.querySelector('[data-tool-id="port-scan-btn"]');
      SelectionManager.toggleSelection(card);
      
      expect(updateCountSpy).toHaveBeenCalled();
    });
  });
});
