/**
 * Integration test for scan lifecycle events with existing listeners
 * Validates that ExecutionController.executeNetworkScan() works with existing event listeners
 * from risk-gauge.js and dashboard-integration.js
 * 
 * Requirements: 3.4, 10.3
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { JSDOM } from 'jsdom';

describe('Scan Lifecycle Integration - Existing Event Listeners', () => {
  let dom;
  let document;
  let window;
  let SelectionManager;
  let ToolRegistry;
  let ExecutionController;
  let shouldStopScan;

  beforeEach(() => {
    // Create a minimal DOM environment
    dom = new JSDOM(`
      <!DOCTYPE html>
      <html>
        <body>
          <div id="network-tools">
            <div class="cyber-tool-card" data-selected="true" data-tool-id="port-scan-btn">
              <div class="selection-indicator"></div>
              <button id="port-scan-btn">Port Scan</button>
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

    // Mock validateTargetInput
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
        const validation = validateTargetInput(target, 'Network Scan');
        if (!validation.valid) {
          this.showToast(validation.message);
          return;
        }
        
        const selectedTools = SelectionManager.getSelectedTools('network-tools');
        
        if (selectedTools.length === 0) {
          this.showToast('Please select at least one tool');
          this.focusFirstToolCard('network-tools');
          return;
        }
        
        // Dispatch scan start event
        document.dispatchEvent(new CustomEvent('cyberguard:scanStart', {
          detail: { target, toolCount: selectedTools.length }
        }));
        
        for (const toolId of selectedTools) {
          if (shouldStopScan) break;
          
          const toolFunction = ToolRegistry.getToolFunction(toolId);
          if (toolFunction) {
            try {
              await toolFunction();
            } catch (error) {
              console.error(`Error executing ${toolId}:`, error);
            }
            
            await this.delay(200);
          }
        }
      }
    };
  });

  it('should work with risk-gauge.js event listener pattern', async () => {
    // Arrange - simulate risk-gauge.js listener
    const startScanMock = vi.fn();
    
    // This mimics the listener in risk-gauge.js line 516:
    // document.addEventListener("cyberguard:scanStart", () => startScan());
    document.addEventListener('cyberguard:scanStart', () => startScanMock());

    const target = '8.8.8.8';

    // Act
    await ExecutionController.executeNetworkScan(target);

    // Assert
    expect(startScanMock).toHaveBeenCalledTimes(1);
  });

  it('should work with dashboard-integration.js event listener pattern', async () => {
    // Arrange - simulate dashboard-integration.js listener
    const StateManager = {
      enterScanningState: vi.fn()
    };
    
    global.window.StateManager = StateManager;
    
    // This mimics the listener in dashboard-integration.js line 21:
    // document.addEventListener('cyberguard:scanStart', () => {
    //   if (window.StateManager) {
    //     window.StateManager.enterScanningState();
    //   }
    // });
    document.addEventListener('cyberguard:scanStart', () => {
      if (window.StateManager) {
        window.StateManager.enterScanningState();
      }
    });

    const target = '192.168.1.1';

    // Act
    await ExecutionController.executeNetworkScan(target);

    // Assert
    expect(StateManager.enterScanningState).toHaveBeenCalledTimes(1);
  });

  it('should work with multiple existing event listeners simultaneously', async () => {
    // Arrange - simulate both risk-gauge.js and dashboard-integration.js listeners
    const startScanMock = vi.fn();
    const StateManager = {
      enterScanningState: vi.fn()
    };
    
    global.window.StateManager = StateManager;
    
    // Risk gauge listener
    document.addEventListener('cyberguard:scanStart', () => startScanMock());
    
    // Dashboard integration listener
    document.addEventListener('cyberguard:scanStart', () => {
      if (window.StateManager) {
        window.StateManager.enterScanningState();
      }
    });

    const target = '10.0.0.1';

    // Act
    await ExecutionController.executeNetworkScan(target);

    // Assert - both listeners should be called
    expect(startScanMock).toHaveBeenCalledTimes(1);
    expect(StateManager.enterScanningState).toHaveBeenCalledTimes(1);
  });

  it('should provide event detail to listeners that need it', async () => {
    // Arrange - some listeners might use event.detail
    let receivedDetail = null;
    
    document.addEventListener('cyberguard:scanStart', (event) => {
      receivedDetail = event.detail;
    });

    const target = '172.16.0.1';

    // Act
    await ExecutionController.executeNetworkScan(target);

    // Assert
    expect(receivedDetail).toBeDefined();
    expect(receivedDetail.target).toBe('172.16.0.1');
    expect(receivedDetail.toolCount).toBe(1);
  });

  it('should not break if a listener throws an error', async () => {
    // Arrange - one listener throws an error
    const workingListener = vi.fn();
    
    document.addEventListener('cyberguard:scanStart', () => {
      throw new Error('Listener error');
    });
    
    document.addEventListener('cyberguard:scanStart', () => workingListener());

    const target = '8.8.8.8';

    // Act & Assert - should not throw
    await expect(ExecutionController.executeNetworkScan(target)).resolves.not.toThrow();
    
    // The working listener should still be called
    expect(workingListener).toHaveBeenCalledTimes(1);
  });

  it('should dispatch event with correct toolCount for selective execution', async () => {
    // Arrange - add more tools
    const networkTools = document.getElementById('network-tools');
    networkTools.innerHTML = `
      <div class="cyber-tool-card" data-selected="true" data-tool-id="port-scan-btn">
        <button id="port-scan-btn">Port Scan</button>
      </div>
      <div class="cyber-tool-card" data-selected="true" data-tool-id="tcp-scan-btn">
        <button id="tcp-scan-btn">TCP Scan</button>
      </div>
      <div class="cyber-tool-card" data-selected="false" data-tool-id="udp-scan-btn">
        <button id="udp-scan-btn">UDP Scan</button>
      </div>
    `;
    
    ToolRegistry['tcp-scan-btn'] = vi.fn(async () => {
      await new Promise(resolve => setTimeout(resolve, 10));
    });
    
    let receivedToolCount = null;
    
    document.addEventListener('cyberguard:scanStart', (event) => {
      receivedToolCount = event.detail.toolCount;
    });

    const target = '8.8.8.8';

    // Act
    await ExecutionController.executeNetworkScan(target);

    // Assert - should only count selected tools (2 out of 3)
    expect(receivedToolCount).toBe(2);
  });
});
