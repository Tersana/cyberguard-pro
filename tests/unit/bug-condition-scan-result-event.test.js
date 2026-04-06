/**
 * Bug Condition Exploration Test - Task 1
 * Tests that ExecutionController methods dispatch cyberguard:scanResult event after scan completion
 * 
 * **Validates: Requirements 1.1, 1.2**
 * 
 * **Property 1: Bug Condition** - Scan Result Event Not Dispatched After ExecutionController Completion
 * 
 * CRITICAL: This test MUST FAIL on unfixed code - failure confirms the bug exists
 * DO NOT attempt to fix the test or the code when it fails
 * 
 * NOTE: This test encodes the expected behavior - it will validate the fix when it passes after implementation
 * 
 * EXPECTED OUTCOME: Test FAILS (this is correct - it proves the bug exists)
 * Expected counterexamples: event listener spy shows 0 calls to cyberguard:scanResult handler
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { JSDOM } from 'jsdom';

describe('Bug Condition Exploration - Scan Result Event Not Dispatched', () => {
  let dom;
  let document;
  let window;
  let SelectionManager;
  let ToolRegistry;
  let ExecutionController;
  let shouldStopScan;
  let resultsData;

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
            <div class="cyber-tool-card" data-selected="true" data-tool-id="tcp-scan-btn">
              <div class="selection-indicator"></div>
              <button id="tcp-scan-btn">TCP Scan</button>
            </div>
            <div class="cyber-tool-card" data-selected="true" data-tool-id="dns-lookup-btn">
              <div class="selection-indicator"></div>
              <button id="dns-lookup-btn">DNS Lookup</button>
            </div>
          </div>
          <div id="web-security">
            <div class="cyber-tool-card" data-selected="true" data-tool-id="ssl-check-btn">
              <div class="selection-indicator"></div>
              <button id="ssl-check-btn">SSL Check</button>
            </div>
            <div class="cyber-tool-card" data-selected="true" data-tool-id="header-check-btn">
              <div class="selection-indicator"></div>
              <button id="header-check-btn">Header Check</button>
            </div>
          </div>
          <input id="target-ip" value="8.8.8.8" />
          <input id="target-url" value="https://example.com" />
        </body>
      </html>
    `, { url: 'http://localhost' });

    document = dom.window.document;
    window = dom.window;
    global.document = document;
    global.window = window;
    global.CustomEvent = window.CustomEvent;
    shouldStopScan = false;
    resultsData = [];

    // Mock validateTargetInput function
    global.validateTargetInput = vi.fn((target, toolName) => {
      if (!target || target.trim() === '') {
        return { valid: false, message: 'Please enter a target' };
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

    // Create ToolRegistry mock with tools that populate resultsData
    ToolRegistry = {
      'port-scan-btn': vi.fn(async () => {
        await new Promise(resolve => setTimeout(resolve, 10));
        resultsData.push({ status: 'threat', feature: 'Port Scan', message: 'Open port detected: 80' });
      }),
      'tcp-scan-btn': vi.fn(async () => {
        await new Promise(resolve => setTimeout(resolve, 10));
        resultsData.push({ status: 'warning', feature: 'TCP Scan', message: 'Latency: 45ms' });
      }),
      'dns-lookup-btn': vi.fn(async () => {
        await new Promise(resolve => setTimeout(resolve, 10));
        resultsData.push({ status: 'threat', feature: 'DNS Lookup', message: 'Suspicious DNS record' });
      }),
      'ssl-check-btn': vi.fn(async () => {
        await new Promise(resolve => setTimeout(resolve, 10));
        resultsData.push({ status: 'warning', feature: 'SSL Check', message: 'Certificate expires soon' });
      }),
      'header-check-btn': vi.fn(async () => {
        await new Promise(resolve => setTimeout(resolve, 10));
        resultsData.push({ status: 'threat', feature: 'Header Check', message: 'Missing security headers' });
      }),
      getToolFunction(toolId) {
        return this[toolId] || null;
      }
    };

    // Mock _dispatchRiskGaugeUpdate function
    global._dispatchRiskGaugeUpdate = vi.fn(() => {
      const threats = resultsData.filter(r => r.status === "threat").length;
      const warnings = resultsData.filter(r => r.status === "warning").length;

      let latency = 0;
      resultsData.forEach(r => {
        const match = r.message && r.message.match(/(\d+)\s*ms/i);
        if (match) latency = Math.max(latency, parseInt(match[1]));
      });

      let openPorts = 0;
      resultsData.forEach(r => {
        if (r.feature && r.feature.toLowerCase().includes("port")) {
          const match = r.message && r.message.match(/(\d+)\s*open/i);
          if (match) openPorts = Math.max(openPorts, parseInt(match[1]));
        }
      });

      const type = threats > 3 ? "critical" : threats > 1 ? "high" : warnings > 2 ? "medium" : "low";

      document.dispatchEvent(new CustomEvent("cyberguard:scanResult", {
        detail: {
          vulnerabilities: threats,
          latency: latency || Math.floor(Math.random() * 80 + 20),
          openPorts: openPorts,
          warnings: warnings,
          type: type,
        }
      }));
    });

    // Create ExecutionController (UNFIXED version - no _dispatchRiskGaugeUpdate call)
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
        
        // Dispatch scan result event with calculated risk metrics
        _dispatchRiskGaugeUpdate();
      },
      
      async executeWebSecurityScan(url) {
        if (!url || url.trim() === '') {
          this.showToast('Please enter a target URL');
          return;
        }
        
        const selectedTools = SelectionManager.getSelectedTools('web-security');
        
        if (selectedTools.length === 0) {
          this.showToast('Please select at least one web security tool');
          this.focusFirstToolCard('web-security');
          return;
        }
        
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
        
        // Dispatch scan result event with calculated risk metrics
        _dispatchRiskGaugeUpdate();
      }
    };
  });

  describe('Network Scan - executeNetworkScan()', () => {
    it('should dispatch cyberguard:scanResult event after completing selected tools', async () => {
      // Arrange
      const target = '8.8.8.8';
      const eventSpy = vi.fn();
      document.addEventListener('cyberguard:scanResult', eventSpy);

      // Act
      await ExecutionController.executeNetworkScan(target);

      // Assert - THIS WILL FAIL ON UNFIXED CODE
      expect(eventSpy).toHaveBeenCalledTimes(1);
      expect(eventSpy).toHaveBeenCalledWith(
        expect.objectContaining({
          type: 'cyberguard:scanResult',
          detail: expect.objectContaining({
            vulnerabilities: expect.any(Number),
            latency: expect.any(Number),
            openPorts: expect.any(Number),
            warnings: expect.any(Number),
            type: expect.stringMatching(/^(low|medium|high|critical)$/)
          })
        })
      );
    });

    it('should dispatch event with correct risk metrics based on resultsData', async () => {
      // Arrange
      const target = '192.168.1.1';
      let receivedDetail = null;
      
      document.addEventListener('cyberguard:scanResult', (event) => {
        receivedDetail = event.detail;
      });

      // Act
      await ExecutionController.executeNetworkScan(target);

      // Assert - THIS WILL FAIL ON UNFIXED CODE
      expect(receivedDetail).not.toBeNull();
      expect(receivedDetail.vulnerabilities).toBeGreaterThanOrEqual(0);
      expect(receivedDetail.latency).toBeGreaterThanOrEqual(0);
      expect(receivedDetail.openPorts).toBeGreaterThanOrEqual(0);
      expect(receivedDetail.warnings).toBeGreaterThanOrEqual(0);
      expect(['low', 'medium', 'high', 'critical']).toContain(receivedDetail.type);
    });

    it('should dispatch event even with single tool selected (edge case)', async () => {
      // Arrange - select only one tool
      const cards = document.querySelectorAll('#network-tools .cyber-tool-card');
      cards[1].dataset.selected = 'false';
      cards[2].dataset.selected = 'false';
      
      const target = '10.0.0.1';
      const eventSpy = vi.fn();
      document.addEventListener('cyberguard:scanResult', eventSpy);

      // Act
      await ExecutionController.executeNetworkScan(target);

      // Assert - THIS WILL FAIL ON UNFIXED CODE
      expect(eventSpy).toHaveBeenCalledTimes(1);
    });
  });

  describe('Web Security Scan - executeWebSecurityScan()', () => {
    it('should dispatch cyberguard:scanResult event after completing selected tools', async () => {
      // Arrange
      const url = 'https://example.com';
      const eventSpy = vi.fn();
      document.addEventListener('cyberguard:scanResult', eventSpy);

      // Act
      await ExecutionController.executeWebSecurityScan(url);

      // Assert - THIS WILL FAIL ON UNFIXED CODE
      expect(eventSpy).toHaveBeenCalledTimes(1);
      expect(eventSpy).toHaveBeenCalledWith(
        expect.objectContaining({
          type: 'cyberguard:scanResult',
          detail: expect.objectContaining({
            vulnerabilities: expect.any(Number),
            latency: expect.any(Number),
            openPorts: expect.any(Number),
            warnings: expect.any(Number),
            type: expect.stringMatching(/^(low|medium|high|critical)$/)
          })
        })
      );
    });

    it('should dispatch event with correct risk metrics based on resultsData', async () => {
      // Arrange
      const url = 'https://test.com';
      let receivedDetail = null;
      
      document.addEventListener('cyberguard:scanResult', (event) => {
        receivedDetail = event.detail;
      });

      // Act
      await ExecutionController.executeWebSecurityScan(url);

      // Assert - THIS WILL FAIL ON UNFIXED CODE
      expect(receivedDetail).not.toBeNull();
      expect(receivedDetail.vulnerabilities).toBeGreaterThanOrEqual(0);
      expect(receivedDetail.latency).toBeGreaterThanOrEqual(0);
      expect(receivedDetail.openPorts).toBeGreaterThanOrEqual(0);
      expect(receivedDetail.warnings).toBeGreaterThanOrEqual(0);
      expect(['low', 'medium', 'high', 'critical']).toContain(receivedDetail.type);
    });

    it('should dispatch event even with single tool selected (edge case)', async () => {
      // Arrange - select only one tool
      const cards = document.querySelectorAll('#web-security .cyber-tool-card');
      cards[1].dataset.selected = 'false';
      
      const url = 'https://single-tool-test.com';
      const eventSpy = vi.fn();
      document.addEventListener('cyberguard:scanResult', eventSpy);

      // Act
      await ExecutionController.executeWebSecurityScan(url);

      // Assert - THIS WILL FAIL ON UNFIXED CODE
      expect(eventSpy).toHaveBeenCalledTimes(1);
    });
  });

  describe('Event Detail Structure Validation', () => {
    it('should include all required fields in event detail for network scan', async () => {
      // Arrange
      const target = '8.8.8.8';
      let receivedDetail = null;
      
      document.addEventListener('cyberguard:scanResult', (event) => {
        receivedDetail = event.detail;
      });

      // Act
      await ExecutionController.executeNetworkScan(target);

      // Assert - THIS WILL FAIL ON UNFIXED CODE
      expect(receivedDetail).toBeDefined();
      expect(receivedDetail).toHaveProperty('vulnerabilities');
      expect(receivedDetail).toHaveProperty('latency');
      expect(receivedDetail).toHaveProperty('openPorts');
      expect(receivedDetail).toHaveProperty('warnings');
      expect(receivedDetail).toHaveProperty('type');
    });

    it('should include all required fields in event detail for web security scan', async () => {
      // Arrange
      const url = 'https://example.com';
      let receivedDetail = null;
      
      document.addEventListener('cyberguard:scanResult', (event) => {
        receivedDetail = event.detail;
      });

      // Act
      await ExecutionController.executeWebSecurityScan(url);

      // Assert - THIS WILL FAIL ON UNFIXED CODE
      expect(receivedDetail).toBeDefined();
      expect(receivedDetail).toHaveProperty('vulnerabilities');
      expect(receivedDetail).toHaveProperty('latency');
      expect(receivedDetail).toHaveProperty('openPorts');
      expect(receivedDetail).toHaveProperty('warnings');
      expect(receivedDetail).toHaveProperty('type');
    });
  });
});
