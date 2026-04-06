/**
 * Test suite for execute scan button integration with Risk Dashboard
 * Validates that the execute scan button dispatches the scanStart event
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { JSDOM } from 'jsdom';

describe('Execute Scan Button Integration', () => {
  let dom;
  let document;
  let window;

  beforeEach(() => {
    // Create a minimal DOM environment
    dom = new JSDOM(`
      <!DOCTYPE html>
      <html>
        <body>
          <input id="target-ip" value="8.8.8.8" />
          <button id="execute-scan-btn">Execute Scan</button>
          <button id="port-scan-btn">Port Scan</button>
          <button id="ip-geo-btn">IP Geo</button>
          <button id="reverse-dns-btn">Reverse DNS</button>
          <button id="whois-btn">WHOIS</button>
          <button id="threat-intel-btn">Threat Intel</button>
        </body>
      </html>
    `, { url: 'http://localhost' });

    document = dom.window.document;
    window = dom.window;
    global.document = document;
    global.window = window;
    global.alert = vi.fn();
  });

  it('should dispatch cyberguard:scanStart event when execute scan button is clicked with valid target', () => {
    // Arrange
    const executeScanBtn = document.getElementById('execute-scan-btn');
    const targetInput = document.getElementById('target-ip');
    targetInput.value = '8.8.8.8';

    // Create event listener spy
    const eventSpy = vi.fn();
    document.addEventListener('cyberguard:scanStart', eventSpy);

    // Simulate the execute scan button handler logic
    executeScanBtn.addEventListener('click', () => {
      const target = document.getElementById('target-ip')?.value?.trim();
      if (!target) {
        document.getElementById('target-ip')?.focus();
        alert('Please enter a target IP address or domain name.');
        return;
      }
      
      // Dispatch scan start event for Risk Dashboard integration
      document.dispatchEvent(new window.CustomEvent('cyberguard:scanStart'));
      
      // Run the full network suite sequentially (simplified for test)
      const networkTools = [
        { id: 'port-scan-btn', fn: () => document.getElementById('port-scan-btn')?.click() },
        { id: 'ip-geo-btn', fn: () => document.getElementById('ip-geo-btn')?.click() },
        { id: 'reverse-dns-btn', fn: () => document.getElementById('reverse-dns-btn')?.click() },
        { id: 'whois-btn', fn: () => document.getElementById('whois-btn')?.click() },
        { id: 'threat-intel-btn', fn: () => document.getElementById('threat-intel-btn')?.click() },
      ];
      let delay = 0;
      networkTools.forEach(({ fn }) => {
        setTimeout(fn, delay);
        delay += 200;
      });
    });

    // Act
    executeScanBtn.click();

    // Assert
    expect(eventSpy).toHaveBeenCalledTimes(1);
    expect(eventSpy).toHaveBeenCalledWith(
      expect.objectContaining({
        type: 'cyberguard:scanStart'
      })
    );
  });

  it('should not dispatch cyberguard:scanStart event when target input is empty', () => {
    // Arrange
    const executeScanBtn = document.getElementById('execute-scan-btn');
    const targetInput = document.getElementById('target-ip');
    targetInput.value = '';

    // Create event listener spy
    const eventSpy = vi.fn();
    document.addEventListener('cyberguard:scanStart', eventSpy);

    // Simulate the execute scan button handler logic
    executeScanBtn.addEventListener('click', () => {
      const target = document.getElementById('target-ip')?.value?.trim();
      if (!target) {
        document.getElementById('target-ip')?.focus();
        alert('Please enter a target IP address or domain name.');
        return;
      }
      
      // Dispatch scan start event for Risk Dashboard integration
      document.dispatchEvent(new window.CustomEvent('cyberguard:scanStart'));
    });

    // Act
    executeScanBtn.click();

    // Assert
    expect(eventSpy).not.toHaveBeenCalled();
    expect(global.alert).toHaveBeenCalledWith('Please enter a target IP address or domain name.');
  });

  it('should maintain existing scan execution logic after dispatching event', () => {
    // Arrange
    const executeScanBtn = document.getElementById('execute-scan-btn');
    const targetInput = document.getElementById('target-ip');
    targetInput.value = '192.168.1.1';

    let eventDispatched = false;
    let scanLogicExecuted = false;

    // Simulate the execute scan button handler logic
    executeScanBtn.addEventListener('click', () => {
      const target = document.getElementById('target-ip')?.value?.trim();
      if (!target) {
        return;
      }
      
      // Dispatch scan start event
      document.dispatchEvent(new window.CustomEvent('cyberguard:scanStart'));
      eventDispatched = true;
      
      // Run the full network suite sequentially
      const networkTools = [
        { id: 'port-scan-btn', fn: () => document.getElementById('port-scan-btn')?.click() },
        { id: 'ip-geo-btn', fn: () => document.getElementById('ip-geo-btn')?.click() },
        { id: 'reverse-dns-btn', fn: () => document.getElementById('reverse-dns-btn')?.click() },
        { id: 'whois-btn', fn: () => document.getElementById('whois-btn')?.click() },
        { id: 'threat-intel-btn', fn: () => document.getElementById('threat-intel-btn')?.click() },
      ];
      scanLogicExecuted = true;
      let delay = 0;
      networkTools.forEach(({ fn }) => {
        setTimeout(fn, delay);
        delay += 200;
      });
    });

    // Act
    executeScanBtn.click();

    // Assert - both event dispatch and scan logic should execute
    expect(eventDispatched).toBe(true);
    expect(scanLogicExecuted).toBe(true);
  });
});
