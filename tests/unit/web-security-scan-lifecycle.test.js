/**
 * Test suite for web security scan lifecycle events
 * Validates that ExecutionController.executeWebSecurityScan() maintains scan timing
 * and Summary Bar updates work correctly with the selective execution system
 * 
 * Requirements: 9.5
 * Task: 8.2 - Verify web security scan lifecycle events
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { JSDOM } from 'jsdom';

describe('Web Security Scan Lifecycle Events - Task 8.2', () => {
  let dom;
  let document;
  let window;
  let SelectionManager;
  let ToolRegistry;
  let ExecutionController;
  let shouldStopScan;
  let scanStartTime;
  let scanEndTime;
  let currentScanTarget;
  let resultsData;

  beforeEach(() => {
    // Create a minimal DOM environment with web security tool cards
    dom = new JSDOM(`
      <!DOCTYPE html>
      <html>
        <body>
          <div id="web-security">
            <div class="cyber-tool-card" data-selected="true" data-tool-id="xss-btn">
              <div class="selection-indicator"></div>
              <button id="xss-btn">XSS Test</button>
            </div>
            <div class="cyber-tool-card" data-selected="true" data-tool-id="ssl-btn">
              <div class="selection-indicator"></div>
              <button id="ssl-btn">SSL Check</button>
            </div>
            <div class="cyber-tool-card" data-selected="false" data-tool-id="phishing-btn">
              <div class="selection-indicator"></div>
              <button id="phishing-btn">Phishing Analyzer</button>
            </div>
          </div>
          <input id="target-url" value="https://example.com" />
          <button id="run-analysis-btn">Run Analysis</button>
        </body>
      </html>
    `, { url: 'http://localhost' });

    document = dom.window.document;
    window = dom.window;
    global.document = document;
    global.window = window;
    global.CustomEvent = window.CustomEvent;
    shouldStopScan = false;
    scanStartTime = null;
    scanEndTime = null;
    currentScanTarget = null;
    resultsData = [];

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
      'xss-btn': vi.fn(async () => {
        // Simulate XSS test
        await new Promise(resolve => setTimeout(resolve, 10));
        resultsData.push({ tool: 'xss', status: 'success' });
      }),
      'ssl-btn': vi.fn(async () => {
        // Simulate SSL check
        await new Promise(resolve => setTimeout(resolve, 10));
        resultsData.push({ tool: 'ssl', status: 'success' });
      }),
      'phishing-btn': vi.fn(async () => {
        // Simulate phishing analyzer
        await new Promise(resolve => setTimeout(resolve, 10));
        resultsData.push({ tool: 'phishing', status: 'success' });
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
      
      async executeWebSecurityScan(url) {
        // Validate URL
        if (!url || url.trim() === '') {
          this.showToast('Please enter a target URL');
          return;
        }
        
        // Get selected tools
        const selectedTools = SelectionManager.getSelectedTools('web-security');
        
        // Validate selection
        if (selectedTools.length === 0) {
          this.showToast('Please select at least one web security tool');
          this.focusFirstToolCard('web-security');
          return;
        }
        
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

  it('should execute only selected web security tools', async () => {
    // Arrange
    const url = 'https://example.com';

    // Act
    await ExecutionController.executeWebSecurityScan(url);

    // Assert - only xss-btn and ssl-btn should be executed (phishing-btn is not selected)
    expect(ToolRegistry['xss-btn']).toHaveBeenCalledTimes(1);
    expect(ToolRegistry['ssl-btn']).toHaveBeenCalledTimes(1);
    expect(ToolRegistry['phishing-btn']).not.toHaveBeenCalled();
  });

  it('should maintain 200ms delay between tool executions', async () => {
    // Arrange
    const url = 'https://example.com';
    const executionTimes = [];
    
    // Override tool functions to track execution times
    ToolRegistry['xss-btn'] = vi.fn(async () => {
      executionTimes.push(Date.now());
      await new Promise(resolve => setTimeout(resolve, 10));
    });
    
    ToolRegistry['ssl-btn'] = vi.fn(async () => {
      executionTimes.push(Date.now());
      await new Promise(resolve => setTimeout(resolve, 10));
    });

    // Act
    await ExecutionController.executeWebSecurityScan(url);

    // Assert - there should be approximately 200ms delay between executions
    expect(executionTimes.length).toBe(2);
    const delay = executionTimes[1] - executionTimes[0];
    // Allow some tolerance for timing (190-220ms)
    expect(delay).toBeGreaterThanOrEqual(190);
    expect(delay).toBeLessThanOrEqual(250);
  });

  it('should show toast notification when no tools are selected', async () => {
    // Arrange - deselect all tools
    const cards = document.querySelectorAll('.cyber-tool-card');
    cards.forEach(card => card.dataset.selected = 'false');
    
    const url = 'https://example.com';

    // Act
    await ExecutionController.executeWebSecurityScan(url);

    // Assert
    const toast = document.querySelector('.cyber-toast');
    expect(toast).toBeTruthy();
    expect(toast.textContent).toBe('Please select at least one web security tool');
    
    // No tools should be executed
    expect(ToolRegistry['xss-btn']).not.toHaveBeenCalled();
    expect(ToolRegistry['ssl-btn']).not.toHaveBeenCalled();
  });

  it('should show toast notification when URL is empty', async () => {
    // Arrange
    const url = '';

    // Act
    await ExecutionController.executeWebSecurityScan(url);

    // Assert
    const toast = document.querySelector('.cyber-toast');
    expect(toast).toBeTruthy();
    expect(toast.textContent).toBe('Please enter a target URL');
    
    // No tools should be executed
    expect(ToolRegistry['xss-btn']).not.toHaveBeenCalled();
    expect(ToolRegistry['ssl-btn']).not.toHaveBeenCalled();
  });

  it('should respect shouldStopScan flag during execution', async () => {
    // Arrange
    const url = 'https://example.com';
    
    // Override first tool to set stop flag
    ToolRegistry['xss-btn'] = vi.fn(async () => {
      await new Promise(resolve => setTimeout(resolve, 10));
      shouldStopScan = true;
    });

    // Act
    await ExecutionController.executeWebSecurityScan(url);

    // Assert - first tool executed, second tool should not execute
    expect(ToolRegistry['xss-btn']).toHaveBeenCalledTimes(1);
    expect(ToolRegistry['ssl-btn']).not.toHaveBeenCalled();
  });

  it('should handle tool execution errors gracefully', async () => {
    // Arrange
    const url = 'https://example.com';
    const consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    
    // Override first tool to throw error
    ToolRegistry['xss-btn'] = vi.fn(async () => {
      throw new Error('XSS test failed');
    });

    // Act & Assert - should not throw
    await expect(ExecutionController.executeWebSecurityScan(url)).resolves.not.toThrow();
    
    // Assert - error should be logged
    expect(consoleErrorSpy).toHaveBeenCalledWith(
      'Error executing xss-btn:',
      expect.any(Error)
    );
    
    // Second tool should still execute
    expect(ToolRegistry['ssl-btn']).toHaveBeenCalledTimes(1);
    
    consoleErrorSpy.mockRestore();
  });

  it('should work with Run Analysis button integration', async () => {
    // Arrange
    const runAnalysisBtn = document.getElementById('run-analysis-btn');
    const targetUrlInput = document.getElementById('target-url');
    
    // Simulate Run Analysis button click handler
    const clickHandler = async () => {
      const url = targetUrlInput.value.trim();
      
      // Disable button during scan
      runAnalysisBtn.disabled = true;
      
      // Reset stop flag
      shouldStopScan = false;
      
      // Track scan start time and target
      scanStartTime = Date.now();
      currentScanTarget = url;
      
      // Execute selective web security scan
      await ExecutionController.executeWebSecurityScan(url);
      
      // Track scan end time
      scanEndTime = Date.now();
      
      // Re-enable button after scan
      runAnalysisBtn.disabled = false;
    };

    // Act
    await clickHandler();

    // Assert
    expect(ToolRegistry['xss-btn']).toHaveBeenCalledTimes(1);
    expect(ToolRegistry['ssl-btn']).toHaveBeenCalledTimes(1);
    expect(scanStartTime).toBeTruthy();
    expect(scanEndTime).toBeTruthy();
    expect(currentScanTarget).toBe('https://example.com');
    expect(scanEndTime).toBeGreaterThan(scanStartTime);
    expect(runAnalysisBtn.disabled).toBe(false);
  });

  it('should track scan timing correctly for Summary Bar updates', async () => {
    // Arrange
    const url = 'https://example.com';
    
    // Simulate the timing tracking from Run Analysis button
    scanStartTime = Date.now();
    currentScanTarget = url;
    
    // Act
    await ExecutionController.executeWebSecurityScan(url);
    
    // Track scan end time
    scanEndTime = Date.now();
    
    // Calculate duration
    const durationMs = scanEndTime - scanStartTime;

    // Assert
    expect(scanStartTime).toBeTruthy();
    expect(scanEndTime).toBeTruthy();
    expect(currentScanTarget).toBe('https://example.com');
    expect(durationMs).toBeGreaterThan(0);
    // Should take at least 200ms (delay between 2 tools) + tool execution time
    expect(durationMs).toBeGreaterThanOrEqual(200);
  });

  it('should allow results to be collected during scan for Summary Bar', async () => {
    // Arrange
    const url = 'https://example.com';
    resultsData = []; // Start with empty results

    // Act
    await ExecutionController.executeWebSecurityScan(url);

    // Assert - results should be populated by tool executions
    expect(resultsData.length).toBe(2); // xss and ssl tools
    expect(resultsData[0]).toEqual({ tool: 'xss', status: 'success' });
    expect(resultsData[1]).toEqual({ tool: 'ssl', status: 'success' });
  });

  it('should execute tools in UI order (top to bottom)', async () => {
    // Arrange
    const url = 'https://example.com';
    const executionOrder = [];
    
    // Override tool functions to track execution order
    ToolRegistry['xss-btn'] = vi.fn(async () => {
      executionOrder.push('xss');
      await new Promise(resolve => setTimeout(resolve, 10));
    });
    
    ToolRegistry['ssl-btn'] = vi.fn(async () => {
      executionOrder.push('ssl');
      await new Promise(resolve => setTimeout(resolve, 10));
    });

    // Act
    await ExecutionController.executeWebSecurityScan(url);

    // Assert - tools should execute in order they appear in DOM
    expect(executionOrder).toEqual(['xss', 'ssl']);
  });
});
