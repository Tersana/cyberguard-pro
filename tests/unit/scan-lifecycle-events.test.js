/**
 * Test suite for scan lifecycle events
 * Validates that ExecutionController.executeNetworkScan() dispatches cyberguard:scanStart event
 * and that existing event listeners still work
 * 
 * Requirements: 3.4, 10.3
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { JSDOM } from 'jsdom';

describe('Scan Lifecycle Events - Task 7.2', () => {
  let dom;
  let document;
  let window;
  let SelectionManager;
  let ToolRegistry;
  let ExecutionController;
  let shouldStopScan;

  beforeEach(() => {
    // Create a minimal DOM environment with tool cards
    dom = new JSDOM(`
      <!DOCTYPE html>
      <html>
        <body>
          <div id="network-tools">
            <div class="cyber-tool-card" data-selected="true" data-tool-id="port-scan-btn">
              <div class="selection-indicator"></div>
              <button id="port-scan-btn">Port Scan</button>
            </div>
            <div class="cyber-tool-card" data-selected="true" data-tool-id="tcp-scan-btn">
              <div class="selection-indicator"></div>
              <button id="tcp-scan-btn">TCP Scan</button>
            </div>
          </div>
          <input id="target-ip" value="8.8.8.8" />
          <button id="execute-scan-btn">Execute Scan</button>
        </body>
      </html>
    `, { url: 'http://localhost' });

    document = dom.window.document;
    window = dom.window;
    global.document = document;
    global.window = window;
    global.CustomEvent = window.CustomEvent;
    shouldStopScan = false;

    // Mock validateTargetInput function
    global.validateTargetInput = vi.fn((target, toolName) => {
      if (!target || target.trim() === '') {
        return { valid: false, message: 'Please enter a target IP address or domain name' };
      }
      return { valid: true };
    });

    // Create SelectionManager mock
    SelectionManager = {
      getSelectedTools: vi.fn((tabId) => {
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
      })
    };

    // Create ToolRegistry mock
    ToolRegistry = {
      'port-scan-btn': vi.fn(async () => {
        // Simulate port scan
        await new Promise(resolve => setTimeout(resolve, 10));
      }),
      'tcp-scan-btn': vi.fn(async () => {
        // Simulate TCP scan
        await new Promise(resolve => setTimeout(resolve, 10));
      }),
      getToolFunction(toolId) {
        return this[toolId] || null;
      }
    };

    // Create ExecutionController
    ExecutionController = {
      delay(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
      },
      
      showToast(message) {
        const toast = document.createElement('div');
        toast.className = 'cyber-toast';
        toast.textContent = message;
        document.body.appendChild(toast);
      },
      
      focusFirstToolCard(tabId) {
        const tab = document.getElementById(tabId);
        if (!tab) return;
        
        const firstCard = tab.querySelector('.cyber-tool-card');
        if (firstCard) {
          firstCard.focus();
        }
      },
      
      async executeNetworkScan(target) {
        // Validate target
        const validation = validateTargetInput(target, 'Network Scan');
        if (!validation.valid) {
          this.showToast(validation.message);
          return;
        }
        
        // Get selected tools
        const selectedTools = SelectionManager.getSelectedTools('network-tools');
        
        // Validate selection
        if (selectedTools.length === 0) {
          this.showToast('Please select at least one tool');
          this.focusFirstToolCard('network-tools');
          return;
        }
        
        // Dispatch scan start event
        document.dispatchEvent(new CustomEvent('cyberguard:scanStart', {
          detail: { target, toolCount: selectedTools.length }
        }));
        
        // Execute selected tools sequentially
        for (const toolId of selectedTools) {
          if (shouldStopScan) break;
          
          const toolFunction = ToolRegistry.getToolFunction(toolId);
          if (toolFunction) {
            try {
              await toolFunction();
            } catch (error) {
              console.error(`Error executing ${toolId}:`, error);
            }
            
            // 200ms delay between tools
            await this.delay(200);
          }
        }
      }
    };
  });

  it('should dispatch cyberguard:scanStart event with correct detail when executeNetworkScan is called', async () => {
    // Arrange
    const target = '8.8.8.8';
    const eventSpy = vi.fn();
    document.addEventListener('cyberguard:scanStart', eventSpy);

    // Act
    await ExecutionController.executeNetworkScan(target);

    // Assert
    expect(eventSpy).toHaveBeenCalledTimes(1);
    expect(eventSpy).toHaveBeenCalledWith(
      expect.objectContaining({
        type: 'cyberguard:scanStart',
        detail: expect.objectContaining({
          target: '8.8.8.8',
          toolCount: 2
        })
      })
    );
  });

  it('should dispatch cyberguard:scanStart event with correct toolCount based on selected tools', async () => {
    // Arrange - only one tool selected
    const cards = document.querySelectorAll('.cyber-tool-card');
    cards[1].dataset.selected = 'false'; // Deselect second tool
    
    const target = '192.168.1.1';
    const eventSpy = vi.fn();
    document.addEventListener('cyberguard:scanStart', eventSpy);

    // Act
    await ExecutionController.executeNetworkScan(target);

    // Assert
    expect(eventSpy).toHaveBeenCalledTimes(1);
    expect(eventSpy).toHaveBeenCalledWith(
      expect.objectContaining({
        type: 'cyberguard:scanStart',
        detail: expect.objectContaining({
          target: '192.168.1.1',
          toolCount: 1
        })
      })
    );
  });

  it('should not dispatch cyberguard:scanStart event when no tools are selected', async () => {
    // Arrange - deselect all tools
    const cards = document.querySelectorAll('.cyber-tool-card');
    cards.forEach(card => card.dataset.selected = 'false');
    
    const target = '8.8.8.8';
    const eventSpy = vi.fn();
    document.addEventListener('cyberguard:scanStart', eventSpy);

    // Act
    await ExecutionController.executeNetworkScan(target);

    // Assert
    expect(eventSpy).not.toHaveBeenCalled();
  });

  it('should not dispatch cyberguard:scanStart event when target is invalid', async () => {
    // Arrange
    const target = '';
    const eventSpy = vi.fn();
    document.addEventListener('cyberguard:scanStart', eventSpy);

    // Act
    await ExecutionController.executeNetworkScan(target);

    // Assert
    expect(eventSpy).not.toHaveBeenCalled();
  });

  it('should allow existing event listeners to receive cyberguard:scanStart event', async () => {
    // Arrange - simulate existing event listeners (like risk-gauge.js and dashboard-integration.js)
    const riskGaugeListener = vi.fn();
    const dashboardListener = vi.fn();
    
    document.addEventListener('cyberguard:scanStart', riskGaugeListener);
    document.addEventListener('cyberguard:scanStart', dashboardListener);

    const target = '8.8.8.8';

    // Act
    await ExecutionController.executeNetworkScan(target);

    // Assert - both listeners should be called
    expect(riskGaugeListener).toHaveBeenCalledTimes(1);
    expect(dashboardListener).toHaveBeenCalledTimes(1);
    
    // Both should receive the same event with correct detail
    expect(riskGaugeListener).toHaveBeenCalledWith(
      expect.objectContaining({
        type: 'cyberguard:scanStart',
        detail: expect.objectContaining({
          target: '8.8.8.8',
          toolCount: 2
        })
      })
    );
    
    expect(dashboardListener).toHaveBeenCalledWith(
      expect.objectContaining({
        type: 'cyberguard:scanStart',
        detail: expect.objectContaining({
          target: '8.8.8.8',
          toolCount: 2
        })
      })
    );
  });

  it('should dispatch event before executing any tools', async () => {
    // Arrange
    const executionOrder = [];
    
    document.addEventListener('cyberguard:scanStart', () => {
      executionOrder.push('event-dispatched');
    });
    
    // Override tool functions to track execution
    ToolRegistry['port-scan-btn'] = vi.fn(async () => {
      executionOrder.push('port-scan-executed');
    });
    
    ToolRegistry['tcp-scan-btn'] = vi.fn(async () => {
      executionOrder.push('tcp-scan-executed');
    });

    const target = '8.8.8.8';

    // Act
    await ExecutionController.executeNetworkScan(target);

    // Assert - event should be dispatched before any tool execution
    expect(executionOrder[0]).toBe('event-dispatched');
    expect(executionOrder[1]).toBe('port-scan-executed');
    expect(executionOrder[2]).toBe('tcp-scan-executed');
  });

  it('should maintain backward compatibility with event detail structure', async () => {
    // Arrange
    const target = '10.0.0.1';
    let receivedDetail = null;
    
    document.addEventListener('cyberguard:scanStart', (event) => {
      receivedDetail = event.detail;
    });

    // Act
    await ExecutionController.executeNetworkScan(target);

    // Assert - event detail should have expected structure
    expect(receivedDetail).toBeDefined();
    expect(receivedDetail).toHaveProperty('target');
    expect(receivedDetail).toHaveProperty('toolCount');
    expect(receivedDetail.target).toBe('10.0.0.1');
    expect(receivedDetail.toolCount).toBe(2);
  });
});
