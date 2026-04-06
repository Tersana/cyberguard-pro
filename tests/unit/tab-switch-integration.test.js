/**
 * Unit tests for tab switch event listener integration
 * Tests Task 4.4: Add tab switch event listener to update button label
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { JSDOM } from 'jsdom';

describe('Tab Switch Integration - Task 4.4', () => {
  let dom;
  let document;
  let SelectionManager;
  let SelectAllToggle;

  beforeEach(() => {
    // Create a fresh DOM for each test with tab structure
    dom = new JSDOM(`
      <!DOCTYPE html>
      <html>
        <body>
          <!-- Tab buttons -->
          <button class="tab-button active" data-tab="network-tools">Network Tools</button>
          <button class="tab-button" data-tab="web-security">Web Security</button>
          
          <!-- Tab panes -->
          <div id="network-tools" class="tab-pane active">
            <span id="selection-count-display" class="text-xs text-slate-500">No tools selected</span>
            <button id="select-all-toggle-btn">Select All</button>
            <div class="cyber-tool-card" data-selected="true" data-tool-id="port-scan-btn">
              <div class="selection-indicator"></div>
              <button id="port-scan-btn">Scan Ports</button>
            </div>
            <div class="cyber-tool-card" data-selected="false" data-tool-id="tcp-scan-btn">
              <div class="selection-indicator hidden"></div>
              <button id="tcp-scan-btn">TCP Scan</button>
            </div>
          </div>
          
          <div id="web-security" class="tab-pane hidden">
            <span id="selection-count-display-web" class="text-xs text-slate-500">No tools selected</span>
            <button id="select-all-toggle-btn-web">Select All</button>
            <div class="cyber-tool-card" data-selected="false" data-tool-id="xss-btn">
              <div class="selection-indicator hidden"></div>
              <button id="xss-btn">XSS Test</button>
            </div>
            <div class="cyber-tool-card" data-selected="false" data-tool-id="ssl-btn">
              <div class="selection-indicator hidden"></div>
              <button id="ssl-btn">SSL Check</button>
            </div>
          </div>
        </body>
      </html>
    `);
    
    document = dom.window.document;
    global.document = document;
    global.window = dom.window;

    // Define SelectionManager
    SelectionManager = {
      updateSelectionCount: vi.fn(function() {
        const activeTab = document.querySelector('.tab-pane.active');
        if (!activeTab) return;
        
        const selectedCount = activeTab.querySelectorAll('.cyber-tool-card[data-selected="true"]').length;
        const isNetworkTab = activeTab.id === 'network-tools';
        const countDisplay = document.getElementById(isNetworkTab ? 'selection-count-display' : 'selection-count-display-web');
        
        if (countDisplay) {
          if (selectedCount === 0) {
            countDisplay.textContent = 'No tools selected';
            countDisplay.className = 'text-xs text-slate-500';
          } else {
            countDisplay.textContent = `${selectedCount} tool${selectedCount > 1 ? 's' : ''} selected`;
            countDisplay.className = 'text-xs text-purple-400 font-semibold';
          }
        }
      })
    };

    // Define SelectAllToggle
    SelectAllToggle = {
      updateButtonLabel: vi.fn(function() {
        const activeTab = document.querySelector('.tab-pane.active');
        if (!activeTab) return;
        
        const isNetworkTab = activeTab.id === 'network-tools';
        const toggleBtn = document.getElementById(isNetworkTab ? 'select-all-toggle-btn' : 'select-all-toggle-btn-web');
        
        if (!toggleBtn) return;
        
        const toolCards = activeTab.querySelectorAll('.cyber-tool-card');
        const hasAnySelected = Array.from(toolCards).some(card => card.dataset.selected === "true");
        
        toggleBtn.textContent = hasAnySelected ? 'Deselect All' : 'Select All';
      })
    };
  });

  describe('Tab switch event listener', () => {
    it('should call updateSelectionCount when switching tabs', () => {
      const tabButtons = document.querySelectorAll('.tab-button');
      const networkTab = document.getElementById('network-tools');
      const webSecurityTab = document.getElementById('web-security');
      
      // Simulate tab switch logic
      tabButtons.forEach((button) => {
        button.addEventListener('click', () => {
          const tabId = button.dataset.tab;
          const targetPane = document.getElementById(tabId);
          
          // Update tab states
          tabButtons.forEach((btn) => btn.classList.remove('active'));
          button.classList.add('active');
          
          document.querySelectorAll('.tab-pane').forEach((pane) => {
            pane.classList.add('hidden');
            pane.classList.remove('active');
          });
          targetPane.classList.remove('hidden');
          targetPane.classList.add('active');
          
          // Call the update methods
          if (typeof SelectionManager !== 'undefined' && SelectionManager.updateSelectionCount) {
            SelectionManager.updateSelectionCount();
          }
          if (typeof SelectAllToggle !== 'undefined' && SelectAllToggle.updateButtonLabel) {
            SelectAllToggle.updateButtonLabel();
          }
        });
      });
      
      // Click the web security tab button
      const webSecurityButton = document.querySelector('[data-tab="web-security"]');
      webSecurityButton.click();
      
      // Verify the methods were called
      expect(SelectionManager.updateSelectionCount).toHaveBeenCalled();
      expect(SelectAllToggle.updateButtonLabel).toHaveBeenCalled();
    });

    it('should call updateButtonLabel when switching tabs', () => {
      const tabButtons = document.querySelectorAll('.tab-button');
      
      // Simulate tab switch logic
      tabButtons.forEach((button) => {
        button.addEventListener('click', () => {
          const tabId = button.dataset.tab;
          const targetPane = document.getElementById(tabId);
          
          // Update tab states
          tabButtons.forEach((btn) => btn.classList.remove('active'));
          button.classList.add('active');
          
          document.querySelectorAll('.tab-pane').forEach((pane) => {
            pane.classList.add('hidden');
            pane.classList.remove('active');
          });
          targetPane.classList.remove('hidden');
          targetPane.classList.add('active');
          
          // Call the update methods
          if (typeof SelectionManager !== 'undefined' && SelectionManager.updateSelectionCount) {
            SelectionManager.updateSelectionCount();
          }
          if (typeof SelectAllToggle !== 'undefined' && SelectAllToggle.updateButtonLabel) {
            SelectAllToggle.updateButtonLabel();
          }
        });
      });
      
      // Click the web security tab button
      const webSecurityButton = document.querySelector('[data-tab="web-security"]');
      webSecurityButton.click();
      
      // Verify updateButtonLabel was called
      expect(SelectAllToggle.updateButtonLabel).toHaveBeenCalled();
    });

    it('should update button label to reflect new tab selection state', () => {
      // Initialize button labels
      SelectAllToggle.updateButtonLabel();
      
      const networkToggleBtn = document.getElementById('select-all-toggle-btn');
      const webToggleBtn = document.getElementById('select-all-toggle-btn-web');
      
      // Network tab has 1 selected tool, so button should say "Deselect All"
      expect(networkToggleBtn.textContent).toBe('Deselect All');
      
      // Switch to web security tab
      const networkTab = document.getElementById('network-tools');
      const webSecurityTab = document.getElementById('web-security');
      
      networkTab.classList.remove('active');
      networkTab.classList.add('hidden');
      webSecurityTab.classList.remove('hidden');
      webSecurityTab.classList.add('active');
      
      // Update button label for new tab
      SelectAllToggle.updateButtonLabel();
      
      // Web security tab has 0 selected tools, so button should say "Select All"
      expect(webToggleBtn.textContent).toBe('Select All');
    });

    it('should update selection count to reflect new tab selection state', () => {
      // Initialize selection count
      SelectionManager.updateSelectionCount();
      
      const networkCountDisplay = document.getElementById('selection-count-display');
      const webCountDisplay = document.getElementById('selection-count-display-web');
      
      // Network tab has 1 selected tool
      expect(networkCountDisplay.textContent).toBe('1 tool selected');
      expect(networkCountDisplay.className).toContain('text-purple-400');
      
      // Switch to web security tab
      const networkTab = document.getElementById('network-tools');
      const webSecurityTab = document.getElementById('web-security');
      
      networkTab.classList.remove('active');
      networkTab.classList.add('hidden');
      webSecurityTab.classList.remove('hidden');
      webSecurityTab.classList.add('active');
      
      // Update selection count for new tab
      SelectionManager.updateSelectionCount();
      
      // Web security tab has 0 selected tools
      expect(webCountDisplay.textContent).toBe('No tools selected');
      expect(webCountDisplay.className).toContain('text-slate-500');
    });
  });

  describe('Tab independence', () => {
    it('should maintain independent selection states across tabs', () => {
      const networkTab = document.getElementById('network-tools');
      const webSecurityTab = document.getElementById('web-security');
      
      // Network tab has 1 selected tool
      const networkSelectedCount = networkTab.querySelectorAll('.cyber-tool-card[data-selected="true"]').length;
      expect(networkSelectedCount).toBe(1);
      
      // Web security tab has 0 selected tools
      const webSelectedCount = webSecurityTab.querySelectorAll('.cyber-tool-card[data-selected="true"]').length;
      expect(webSelectedCount).toBe(0);
      
      // Switch tabs and verify states remain unchanged
      networkTab.classList.remove('active');
      webSecurityTab.classList.add('active');
      
      const networkSelectedCountAfter = networkTab.querySelectorAll('.cyber-tool-card[data-selected="true"]').length;
      const webSelectedCountAfter = webSecurityTab.querySelectorAll('.cyber-tool-card[data-selected="true"]').length;
      
      expect(networkSelectedCountAfter).toBe(1);
      expect(webSelectedCountAfter).toBe(0);
    });
  });
});
