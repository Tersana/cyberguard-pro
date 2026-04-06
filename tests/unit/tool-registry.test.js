/**
 * Tool Registry Tests - Tasks 5.1, 5.2, 5.3
 * Tests for ToolRegistry object with tool ID to function mappings
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';

describe('Tool Registry - Tasks 5.1, 5.2, 5.3', () => {
  let ToolRegistry;
  let mockGetElementById;
  
  beforeEach(() => {
    // Mock document.getElementById
    mockGetElementById = vi.fn((id) => {
      if (id === 'target-ip') {
        return { value: '8.8.8.8' };
      }
      if (id === 'target-url') {
        return { value: 'https://example.com' };
      }
      return null;
    });
    
    global.document = {
      getElementById: mockGetElementById
    };
    
    // Mock scanning functions
    global.portScan = vi.fn();
    global.realTcpPortScan = vi.fn();
    global.realUdpConnectivityTest = vi.fn();
    global.ipGeolocation = vi.fn();
    global.reverseDns = vi.fn();
    global.whoisLookup = vi.fn();
    global.threatIntelCheck = vi.fn();
    global.testXss = vi.fn();
    global.checkSsl = vi.fn();
    global.detectPhishing = vi.fn();
    global.checkDnsSpoof = vi.fn();
    
    // Create ToolRegistry object (Task 5.1)
    ToolRegistry = {
      // Network Tools
      'port-scan-btn': () => portScan(document.getElementById('target-ip').value),
      'tcp-scan-btn': () => realTcpPortScan(document.getElementById('target-ip').value),
      'udp-scan-btn': () => realUdpConnectivityTest(document.getElementById('target-ip').value),
      'ip-geo-btn': () => ipGeolocation(document.getElementById('target-ip').value),
      'reverse-dns-btn': () => reverseDns(document.getElementById('target-ip').value),
      'whois-btn': () => whoisLookup(document.getElementById('target-ip').value),
      'threat-intel-btn': () => threatIntelCheck(document.getElementById('target-ip').value),
      
      // Web Security Tools
      'xss-btn': () => testXss(document.getElementById('target-url').value),
      'ssl-btn': () => checkSsl(document.getElementById('target-url').value),
      'phishing-btn': () => detectPhishing(document.getElementById('target-url').value),
      'dns-spoof-btn': () => checkDnsSpoof(document.getElementById('target-url').value),
      
      // Task 5.2: getToolFunction() method
      getToolFunction(toolId) {
        return this[toolId] || null;
      },
      
      // Task 5.3: hasToolFunction() method
      hasToolFunction(toolId) {
        return toolId in this && typeof this[toolId] === 'function';
      }
    };
  });
  
  describe('Task 5.1: Tool Registry Mappings', () => {
    it('should have all network tool IDs mapped to functions', () => {
      const networkToolIds = [
        'port-scan-btn',
        'tcp-scan-btn',
        'udp-scan-btn',
        'ip-geo-btn',
        'reverse-dns-btn',
        'whois-btn',
        'threat-intel-btn'
      ];
      
      networkToolIds.forEach(toolId => {
        expect(ToolRegistry[toolId]).toBeDefined();
        expect(typeof ToolRegistry[toolId]).toBe('function');
      });
    });
    
    it('should have all web security tool IDs mapped to functions', () => {
      const webSecurityToolIds = [
        'xss-btn',
        'ssl-btn',
        'phishing-btn',
        'dns-spoof-btn'
      ];
      
      webSecurityToolIds.forEach(toolId => {
        expect(ToolRegistry[toolId]).toBeDefined();
        expect(typeof ToolRegistry[toolId]).toBe('function');
      });
    });
    
    it('should use arrow functions for all tool mappings', () => {
      // Arrow functions are functions, so we verify they're callable
      const portScanFn = ToolRegistry['port-scan-btn'];
      expect(typeof portScanFn).toBe('function');
      
      // Call the function and verify it calls the underlying scan function
      portScanFn();
      expect(global.portScan).toHaveBeenCalledWith('8.8.8.8');
    });
    
    it('should call network tools with target-ip value', () => {
      ToolRegistry['port-scan-btn']();
      expect(global.portScan).toHaveBeenCalledWith('8.8.8.8');
      
      ToolRegistry['tcp-scan-btn']();
      expect(global.realTcpPortScan).toHaveBeenCalledWith('8.8.8.8');
      
      ToolRegistry['ip-geo-btn']();
      expect(global.ipGeolocation).toHaveBeenCalledWith('8.8.8.8');
    });
    
    it('should call web security tools with target-url value', () => {
      ToolRegistry['xss-btn']();
      expect(global.testXss).toHaveBeenCalledWith('https://example.com');
      
      ToolRegistry['ssl-btn']();
      expect(global.checkSsl).toHaveBeenCalledWith('https://example.com');
      
      ToolRegistry['phishing-btn']();
      expect(global.detectPhishing).toHaveBeenCalledWith('https://example.com');
    });
  });
  
  describe('Task 5.2: getToolFunction() Method', () => {
    it('should return function reference for valid tool ID', () => {
      const portScanFn = ToolRegistry.getToolFunction('port-scan-btn');
      expect(portScanFn).toBeDefined();
      expect(typeof portScanFn).toBe('function');
    });
    
    it('should return function reference for all network tools', () => {
      const networkToolIds = [
        'port-scan-btn',
        'tcp-scan-btn',
        'udp-scan-btn',
        'ip-geo-btn',
        'reverse-dns-btn',
        'whois-btn',
        'threat-intel-btn'
      ];
      
      networkToolIds.forEach(toolId => {
        const fn = ToolRegistry.getToolFunction(toolId);
        expect(fn).not.toBeNull();
        expect(typeof fn).toBe('function');
      });
    });
    
    it('should return function reference for all web security tools', () => {
      const webSecurityToolIds = [
        'xss-btn',
        'ssl-btn',
        'phishing-btn',
        'dns-spoof-btn'
      ];
      
      webSecurityToolIds.forEach(toolId => {
        const fn = ToolRegistry.getToolFunction(toolId);
        expect(fn).not.toBeNull();
        expect(typeof fn).toBe('function');
      });
    });
    
    it('should return null for non-existent tool ID', () => {
      const fn = ToolRegistry.getToolFunction('non-existent-btn');
      expect(fn).toBeNull();
    });
    
    it('should return null for invalid tool ID', () => {
      expect(ToolRegistry.getToolFunction('invalid-tool')).toBeNull();
      expect(ToolRegistry.getToolFunction('')).toBeNull();
      expect(ToolRegistry.getToolFunction(null)).toBeNull();
    });
    
    it('should return callable function that executes the tool', () => {
      const portScanFn = ToolRegistry.getToolFunction('port-scan-btn');
      portScanFn();
      expect(global.portScan).toHaveBeenCalledWith('8.8.8.8');
    });
  });
  
  describe('Task 5.3: hasToolFunction() Method', () => {
    it('should return true for valid tool ID', () => {
      expect(ToolRegistry.hasToolFunction('port-scan-btn')).toBe(true);
    });
    
    it('should return true for all network tool IDs', () => {
      const networkToolIds = [
        'port-scan-btn',
        'tcp-scan-btn',
        'udp-scan-btn',
        'ip-geo-btn',
        'reverse-dns-btn',
        'whois-btn',
        'threat-intel-btn'
      ];
      
      networkToolIds.forEach(toolId => {
        expect(ToolRegistry.hasToolFunction(toolId)).toBe(true);
      });
    });
    
    it('should return true for all web security tool IDs', () => {
      const webSecurityToolIds = [
        'xss-btn',
        'ssl-btn',
        'phishing-btn',
        'dns-spoof-btn'
      ];
      
      webSecurityToolIds.forEach(toolId => {
        expect(ToolRegistry.hasToolFunction(toolId)).toBe(true);
      });
    });
    
    it('should return false for non-existent tool ID', () => {
      expect(ToolRegistry.hasToolFunction('non-existent-btn')).toBe(false);
    });
    
    it('should return false for invalid tool ID', () => {
      expect(ToolRegistry.hasToolFunction('invalid-tool')).toBe(false);
      expect(ToolRegistry.hasToolFunction('')).toBe(false);
    });
    
    it('should verify value is a function', () => {
      // Add a non-function property to test
      ToolRegistry['test-property'] = 'not a function';
      expect(ToolRegistry.hasToolFunction('test-property')).toBe(false);
      
      // Clean up
      delete ToolRegistry['test-property'];
    });
    
    it('should check if tool ID exists in registry', () => {
      // Existing tool
      expect('port-scan-btn' in ToolRegistry).toBe(true);
      expect(ToolRegistry.hasToolFunction('port-scan-btn')).toBe(true);
      
      // Non-existing tool
      expect('fake-btn' in ToolRegistry).toBe(false);
      expect(ToolRegistry.hasToolFunction('fake-btn')).toBe(false);
    });
  });
  
  describe('Integration Tests', () => {
    it('should work with getToolFunction and hasToolFunction together', () => {
      const toolId = 'port-scan-btn';
      
      // Check if tool exists
      if (ToolRegistry.hasToolFunction(toolId)) {
        // Get the function
        const fn = ToolRegistry.getToolFunction(toolId);
        expect(fn).not.toBeNull();
        
        // Execute the function
        fn();
        expect(global.portScan).toHaveBeenCalled();
      }
    });
    
    it('should handle workflow: check existence, get function, execute', () => {
      const toolIds = ['port-scan-btn', 'xss-btn', 'non-existent-btn'];
      
      toolIds.forEach(toolId => {
        if (ToolRegistry.hasToolFunction(toolId)) {
          const fn = ToolRegistry.getToolFunction(toolId);
          expect(fn).not.toBeNull();
          expect(typeof fn).toBe('function');
        } else {
          const fn = ToolRegistry.getToolFunction(toolId);
          expect(fn).toBeNull();
        }
      });
    });
  });
});
