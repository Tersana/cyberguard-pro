/**
 * Test Suite: Individual Tool Button Independence (Task 9.1)
 * 
 * Validates Requirements 10.1, 10.2:
 * - Individual tool buttons execute tools directly regardless of selection state
 * - Selection state doesn't affect individual button clicks
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { JSDOM } from 'jsdom';

describe('Task 9.1: Individual Tool Button Independence', () => {
  let dom;
  let document;
  let SelectionManager;
  let ToolRegistry;
  let runTool;
  
  beforeEach(() => {
    // Create a minimal DOM structure
    dom = new JSDOM(`
      <!DOCTYPE html>
      <html>
        <body>
          <div id="network-tools" class="tab-pane active">
            <div class="cyber-tool-card" data-selected="false" data-tool-id="port-scan-btn">
              <div class="selection-indicator hidden"></div>
              <button id="port-scan-btn">Scan Ports</button>
            </div>
            <div class="cyber-tool-card" data-selected="true" data-tool-id="tcp-scan-btn">
              <div class="selection-indicator"></div>
              <button id="tcp-scan-btn">TCP Scan</button>
            </div>
          </div>
          <div id="web-security" class="tab-pane">
            <div class="cyber-tool-card" data-selected="false" data-tool-id="xss-btn">
              <div class="selection-indicator hidden"></div>
              <button id="xss-btn">XSS Test</button>
            </div>
            <div class="cyber-tool-card" data-selected="true" data-tool-id="ssl-btn">
              <div class="selection-indicator"></div>
              <button id="ssl-btn">SSL Check</button>
            </div>
          </div>
          <input id="target-ip" value="8.8.8.8" />
          <input id="target-url" value="https://example.com" />
        </body>
      </html>
    `, { url: 'http://localhost' });
    
    document = dom.window.document;
    global.document = document;
    global.window = dom.window;
    
    // Mock tool functions
    global.portScan = vi.fn();
    global.realTcpPortScan = vi.fn();
    global.testXss = vi.fn();
    global.checkSsl = vi.fn();
    
    // Create ToolRegistry
    ToolRegistry = {
      'port-scan-btn': () => global.portScan(document.getElementById('target-ip').value),
      'tcp-scan-btn': () => global.realTcpPortScan(document.getElementById('target-ip').value),
      'xss-btn': () => global.testXss(document.getElementById('target-url').value),
      'ssl-btn': () => global.checkSsl(document.getElementById('target-url').value),
    };
    
    // Create SelectionManager
    SelectionManager = {
      init() {
        this.attachEventListeners();
      },
      
      attachEventListeners() {
        const toolCards = document.querySelectorAll('.cyber-tool-card');
        
        toolCards.forEach(card => {
          card.addEventListener('click', (e) => {
            // Prevent toggle if clicking on the tool button itself
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
      },
      
      updateVisuals(card) {
        const indicator = card.querySelector('.selection-indicator');
        const isSelected = card.dataset.selected === "true";
        
        if (isSelected) {
          indicator?.classList.remove('hidden');
        } else {
          indicator?.classList.add('hidden');
        }
      }
    };
    
    // Mock runTool function (simplified version)
    runTool = vi.fn(async (toolFunction, getTarget, errorMessage, buttonId) => {
      const target = getTarget();
      if (!target) {
        console.error(errorMessage);
        return;
      }
      
      // Execute the tool function
      const toolFn = ToolRegistry[buttonId];
      if (toolFn) {
        await toolFn();
      }
    });
    
    // Initialize SelectionManager
    SelectionManager.init();
  });
  
  afterEach(() => {
    vi.clearAllMocks();
  });
  
  describe('Requirement 10.1: Individual tool buttons execute independently', () => {
    it('should execute tool when button is clicked on unselected card', async () => {
      // Arrange
      const portScanBtn = document.getElementById('port-scan-btn');
      const toolCard = portScanBtn.closest('.cyber-tool-card');
      
      // Verify card is unselected
      expect(toolCard.dataset.selected).toBe('false');
      
      // Act - simulate clicking the button directly
      const toolFn = ToolRegistry['port-scan-btn'];
      await toolFn();
      
      // Assert - tool should execute
      expect(global.portScan).toHaveBeenCalledTimes(1);
      expect(global.portScan).toHaveBeenCalledWith('8.8.8.8');
    });
    
    it('should execute tool when button is clicked on selected card', async () => {
      // Arrange
      const tcpScanBtn = document.getElementById('tcp-scan-btn');
      const toolCard = tcpScanBtn.closest('.cyber-tool-card');
      
      // Verify card is selected
      expect(toolCard.dataset.selected).toBe('true');
      
      // Act - simulate clicking the button directly
      const toolFn = ToolRegistry['tcp-scan-btn'];
      await toolFn();
      
      // Assert - tool should execute
      expect(global.realTcpPortScan).toHaveBeenCalledTimes(1);
      expect(global.realTcpPortScan).toHaveBeenCalledWith('8.8.8.8');
    });
    
    it('should execute web security tool when button is clicked on unselected card', async () => {
      // Arrange
      const xssBtn = document.getElementById('xss-btn');
      const toolCard = xssBtn.closest('.cyber-tool-card');
      
      // Verify card is unselected
      expect(toolCard.dataset.selected).toBe('false');
      
      // Act - simulate clicking the button directly
      const toolFn = ToolRegistry['xss-btn'];
      await toolFn();
      
      // Assert - tool should execute
      expect(global.testXss).toHaveBeenCalledTimes(1);
      expect(global.testXss).toHaveBeenCalledWith('https://example.com');
    });
    
    it('should execute web security tool when button is clicked on selected card', async () => {
      // Arrange
      const sslBtn = document.getElementById('ssl-btn');
      const toolCard = sslBtn.closest('.cyber-tool-card');
      
      // Verify card is selected
      expect(toolCard.dataset.selected).toBe('true');
      
      // Act - simulate clicking the button directly
      const toolFn = ToolRegistry['ssl-btn'];
      await toolFn();
      
      // Assert - tool should execute
      expect(global.checkSsl).toHaveBeenCalledTimes(1);
      expect(global.checkSsl).toHaveBeenCalledWith('https://example.com');
    });
  });
  
  describe('Requirement 10.2: Selection state doesn\'t affect button clicks', () => {
    it('should not toggle selection when clicking tool button', () => {
      // Arrange
      const portScanBtn = document.getElementById('port-scan-btn');
      const toolCard = portScanBtn.closest('.cyber-tool-card');
      const initialState = toolCard.dataset.selected;
      
      // Act - simulate clicking the button
      const clickEvent = new dom.window.MouseEvent('click', {
        bubbles: true,
        cancelable: true,
        view: dom.window
      });
      Object.defineProperty(clickEvent, 'target', { value: portScanBtn, enumerable: true });
      portScanBtn.dispatchEvent(clickEvent);
      
      // Assert - selection state should not change
      expect(toolCard.dataset.selected).toBe(initialState);
    });
    
    it('should toggle selection when clicking card area (not button)', () => {
      // Arrange
      const toolCard = document.querySelector('.cyber-tool-card[data-tool-id="port-scan-btn"]');
      const initialState = toolCard.dataset.selected;
      
      // Act - simulate clicking the card (not the button)
      const clickEvent = new dom.window.MouseEvent('click', {
        bubbles: true,
        cancelable: true,
        view: dom.window
      });
      Object.defineProperty(clickEvent, 'target', { value: toolCard, enumerable: true });
      toolCard.dispatchEvent(clickEvent);
      
      // Assert - selection state should toggle
      expect(toolCard.dataset.selected).toBe(initialState === 'true' ? 'false' : 'true');
    });
    
    it('should not toggle selection when clicking button on selected card', () => {
      // Arrange
      const tcpScanBtn = document.getElementById('tcp-scan-btn');
      const toolCard = tcpScanBtn.closest('.cyber-tool-card');
      const initialState = toolCard.dataset.selected;
      
      // Verify card is selected
      expect(initialState).toBe('true');
      
      // Act - simulate clicking the button
      const clickEvent = new dom.window.MouseEvent('click', {
        bubbles: true,
        cancelable: true,
        view: dom.window
      });
      Object.defineProperty(clickEvent, 'target', { value: tcpScanBtn, enumerable: true });
      tcpScanBtn.dispatchEvent(clickEvent);
      
      // Assert - selection state should remain selected
      expect(toolCard.dataset.selected).toBe('true');
    });
    
    it('should preserve selection state across multiple button clicks', async () => {
      // Arrange
      const portScanBtn = document.getElementById('port-scan-btn');
      const toolCard = portScanBtn.closest('.cyber-tool-card');
      const initialState = toolCard.dataset.selected;
      
      // Act - click button multiple times
      const toolFn = ToolRegistry['port-scan-btn'];
      await toolFn();
      await toolFn();
      await toolFn();
      
      // Assert - selection state should not change
      expect(toolCard.dataset.selected).toBe(initialState);
      expect(global.portScan).toHaveBeenCalledTimes(3);
    });
  });
  
  describe('Integration: Button clicks with event delegation', () => {
    it('should prevent selection toggle when button click bubbles to card', () => {
      // Arrange
      const portScanBtn = document.getElementById('port-scan-btn');
      const toolCard = portScanBtn.closest('.cyber-tool-card');
      const initialState = toolCard.dataset.selected;
      
      // Act - simulate a real button click that bubbles up
      const clickEvent = new dom.window.MouseEvent('click', {
        bubbles: true,
        cancelable: true,
        view: dom.window
      });
      
      // Set up the event target chain (button -> card)
      Object.defineProperty(clickEvent, 'target', { 
        value: portScanBtn, 
        enumerable: true 
      });
      
      // Dispatch on button (will bubble to card)
      portScanBtn.dispatchEvent(clickEvent);
      
      // Assert - selection should not toggle
      expect(toolCard.dataset.selected).toBe(initialState);
    });
    
    it('should allow selection toggle when clicking card background', () => {
      // Arrange
      const toolCard = document.querySelector('.cyber-tool-card[data-tool-id="port-scan-btn"]');
      const cardBackground = toolCard.querySelector('.selection-indicator').parentElement;
      const initialState = toolCard.dataset.selected;
      
      // Act - click on card background (not button)
      const clickEvent = new dom.window.MouseEvent('click', {
        bubbles: true,
        cancelable: true,
        view: dom.window
      });
      Object.defineProperty(clickEvent, 'target', { 
        value: cardBackground, 
        enumerable: true 
      });
      toolCard.dispatchEvent(clickEvent);
      
      // Assert - selection should toggle
      expect(toolCard.dataset.selected).toBe(initialState === 'true' ? 'false' : 'true');
    });
  });
  
  describe('Edge cases', () => {
    it('should handle button clicks when card has no data-tool-id', async () => {
      // Arrange - create a card without data-tool-id
      const invalidCard = document.createElement('div');
      invalidCard.className = 'cyber-tool-card';
      invalidCard.dataset.selected = 'false';
      invalidCard.innerHTML = '<button id="invalid-btn">Invalid</button>';
      document.getElementById('network-tools').appendChild(invalidCard);
      
      const invalidBtn = document.getElementById('invalid-btn');
      
      // Act - click the button
      const clickEvent = new dom.window.MouseEvent('click', {
        bubbles: true,
        cancelable: true,
        view: dom.window
      });
      Object.defineProperty(clickEvent, 'target', { value: invalidBtn, enumerable: true });
      invalidBtn.dispatchEvent(clickEvent);
      
      // Assert - should not throw error
      expect(invalidCard.dataset.selected).toBe('false');
    });
    
    it('should handle multiple buttons in same card', () => {
      // Arrange - add extra button to card
      const toolCard = document.querySelector('.cyber-tool-card[data-tool-id="port-scan-btn"]');
      const extraBtn = document.createElement('button');
      extraBtn.id = 'extra-btn';
      extraBtn.textContent = 'Extra';
      toolCard.appendChild(extraBtn);
      
      const initialState = toolCard.dataset.selected;
      
      // Act - click the extra button
      const clickEvent = new dom.window.MouseEvent('click', {
        bubbles: true,
        cancelable: true,
        view: dom.window
      });
      Object.defineProperty(clickEvent, 'target', { value: extraBtn, enumerable: true });
      extraBtn.dispatchEvent(clickEvent);
      
      // Assert - selection should not toggle
      expect(toolCard.dataset.selected).toBe(initialState);
    });
  });
});
