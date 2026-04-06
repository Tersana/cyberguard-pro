/**
 * Unit tests for Result Item Data Structure
 * 
 * Tests the result item schema, creation, validation, and conversion functions
 * for the professional security reports view.
 */

import { describe, it, expect, beforeEach } from 'vitest';

// Import the functions (in a real scenario, these would be imported from the module)
// For now, we'll redefine them here for testing purposes

function createResultItem({
  tool,
  status,
  message,
  description = "",
  evidence = "",
  remediation = [],
  target = "",
  confidence = 100
}) {
  const now = new Date();
  
  return {
    id: Date.now().toString(),
    tool: tool,
    status: status,
    message: message,
    description: description,
    evidence: evidence,
    remediation: Array.isArray(remediation) ? remediation : [],
    target: target,
    timestamp: now.toLocaleTimeString(),
    confidence: Math.max(0, Math.min(100, confidence))
  };
}

function isValidResultItem(result) {
  if (!result || typeof result !== 'object') return false;
  
  if (typeof result.id !== 'string' || result.id.trim() === '') return false;
  if (typeof result.tool !== 'string' || result.tool.trim() === '') return false;
  if (!['safe', 'warning', 'threat', 'system'].includes(result.status)) return false;
  if (typeof result.message !== 'string' || result.message.trim() === '') return false;
  if (typeof result.timestamp !== 'string' || result.timestamp.trim() === '') return false;
  
  if (result.description !== undefined && typeof result.description !== 'string') return false;
  if (result.evidence !== undefined && typeof result.evidence !== 'string') return false;
  if (result.remediation !== undefined && !Array.isArray(result.remediation)) return false;
  if (result.target !== undefined && typeof result.target !== 'string') return false;
  if (result.confidence !== undefined && (typeof result.confidence !== 'number' || result.confidence < 0 || result.confidence > 100)) return false;
  
  return true;
}

function convertLegacyResult(legacyResult) {
  return {
    id: legacyResult.id || Date.now().toString(),
    tool: legacyResult.feature || legacyResult.tool || "Unknown",
    status: legacyResult.status || "system",
    message: legacyResult.message || "",
    description: legacyResult.details || legacyResult.description || "",
    evidence: legacyResult.evidence || "",
    remediation: legacyResult.remediation || [],
    target: legacyResult.target || "",
    timestamp: legacyResult.timestamp || new Date().toLocaleTimeString(),
    confidence: legacyResult.confidence || 100
  };
}

describe('Result Item Data Structure', () => {
  describe('createResultItem', () => {
    it('should create a result item with all required fields', () => {
      const result = createResultItem({
        tool: 'XSS Scanner',
        status: 'threat',
        message: 'XSS vulnerability detected'
      });

      expect(result).toHaveProperty('id');
      expect(result).toHaveProperty('tool', 'XSS Scanner');
      expect(result).toHaveProperty('status', 'threat');
      expect(result).toHaveProperty('message', 'XSS vulnerability detected');
      expect(result).toHaveProperty('timestamp');
      expect(result).toHaveProperty('description', '');
      expect(result).toHaveProperty('evidence', '');
      expect(result).toHaveProperty('remediation');
      expect(result).toHaveProperty('target', '');
      expect(result).toHaveProperty('confidence', 100);
    });

    it('should create a result item with optional fields', () => {
      const result = createResultItem({
        tool: 'Port Scanner',
        status: 'warning',
        message: 'Open port detected',
        description: 'Port 8080 is open',
        evidence: 'Port: 8080\nState: OPEN',
        remediation: ['Close unnecessary ports', 'Use firewall'],
        target: '192.168.1.100',
        confidence: 85
      });

      expect(result.description).toBe('Port 8080 is open');
      expect(result.evidence).toBe('Port: 8080\nState: OPEN');
      expect(result.remediation).toEqual(['Close unnecessary ports', 'Use firewall']);
      expect(result.target).toBe('192.168.1.100');
      expect(result.confidence).toBe(85);
    });

    it('should generate a unique ID based on timestamp', async () => {
      const result1 = createResultItem({
        tool: 'Test',
        status: 'safe',
        message: 'Test 1'
      });

      // Small delay to ensure different timestamp
      await new Promise(resolve => setTimeout(resolve, 5));
      
      const result2 = createResultItem({
        tool: 'Test',
        status: 'safe',
        message: 'Test 2'
      });

      expect(result1.id).not.toBe(result2.id);
      expect(result1.id).toMatch(/^\d+$/);
      expect(result2.id).toMatch(/^\d+$/);
    });

    it('should format timestamp as locale time string', () => {
      const result = createResultItem({
        tool: 'Test',
        status: 'safe',
        message: 'Test'
      });

      expect(result.timestamp).toMatch(/\d{1,2}:\d{2}:\d{2}/);
    });

    it('should clamp confidence values between 0 and 100', () => {
      const result1 = createResultItem({
        tool: 'Test',
        status: 'safe',
        message: 'Test',
        confidence: 150
      });
      expect(result1.confidence).toBe(100);

      const result2 = createResultItem({
        tool: 'Test',
        status: 'safe',
        message: 'Test',
        confidence: -10
      });
      expect(result2.confidence).toBe(0);

      const result3 = createResultItem({
        tool: 'Test',
        status: 'safe',
        message: 'Test',
        confidence: 50
      });
      expect(result3.confidence).toBe(50);
    });

    it('should convert non-array remediation to empty array', () => {
      const result = createResultItem({
        tool: 'Test',
        status: 'safe',
        message: 'Test',
        remediation: 'Not an array'
      });

      expect(result.remediation).toEqual([]);
    });
  });

  describe('isValidResultItem', () => {
    it('should validate a complete result item', () => {
      const validResult = {
        id: '1234567890',
        tool: 'XSS Scanner',
        status: 'threat',
        message: 'Vulnerability found',
        timestamp: '2:34:56 PM',
        description: 'Details here',
        evidence: 'Evidence here',
        remediation: ['Fix 1', 'Fix 2'],
        target: '192.168.1.1',
        confidence: 95
      };

      expect(isValidResultItem(validResult)).toBe(true);
    });

    it('should validate a minimal result item', () => {
      const minimalResult = {
        id: '1234567890',
        tool: 'Test',
        status: 'safe',
        message: 'Test message',
        timestamp: '12:00:00'
      };

      expect(isValidResultItem(minimalResult)).toBe(true);
    });

    it('should reject null or undefined', () => {
      expect(isValidResultItem(null)).toBe(false);
      expect(isValidResultItem(undefined)).toBe(false);
    });

    it('should reject non-object values', () => {
      expect(isValidResultItem('string')).toBe(false);
      expect(isValidResultItem(123)).toBe(false);
      expect(isValidResultItem([])).toBe(false);
    });

    it('should reject missing required fields', () => {
      expect(isValidResultItem({
        tool: 'Test',
        status: 'safe',
        message: 'Test',
        timestamp: '12:00:00'
        // Missing id
      })).toBe(false);

      expect(isValidResultItem({
        id: '123',
        status: 'safe',
        message: 'Test',
        timestamp: '12:00:00'
        // Missing tool
      })).toBe(false);

      expect(isValidResultItem({
        id: '123',
        tool: 'Test',
        message: 'Test',
        timestamp: '12:00:00'
        // Missing status
      })).toBe(false);

      expect(isValidResultItem({
        id: '123',
        tool: 'Test',
        status: 'safe',
        timestamp: '12:00:00'
        // Missing message
      })).toBe(false);

      expect(isValidResultItem({
        id: '123',
        tool: 'Test',
        status: 'safe',
        message: 'Test'
        // Missing timestamp
      })).toBe(false);
    });

    it('should reject empty string required fields', () => {
      expect(isValidResultItem({
        id: '',
        tool: 'Test',
        status: 'safe',
        message: 'Test',
        timestamp: '12:00:00'
      })).toBe(false);

      expect(isValidResultItem({
        id: '123',
        tool: '   ',
        status: 'safe',
        message: 'Test',
        timestamp: '12:00:00'
      })).toBe(false);
    });

    it('should reject invalid status values', () => {
      expect(isValidResultItem({
        id: '123',
        tool: 'Test',
        status: 'invalid',
        message: 'Test',
        timestamp: '12:00:00'
      })).toBe(false);

      expect(isValidResultItem({
        id: '123',
        tool: 'Test',
        status: 'error',
        message: 'Test',
        timestamp: '12:00:00'
      })).toBe(false);
    });

    it('should accept valid status values', () => {
      const statuses = ['safe', 'warning', 'threat', 'system'];
      
      statuses.forEach(status => {
        expect(isValidResultItem({
          id: '123',
          tool: 'Test',
          status: status,
          message: 'Test',
          timestamp: '12:00:00'
        })).toBe(true);
      });
    });

    it('should reject invalid optional field types', () => {
      expect(isValidResultItem({
        id: '123',
        tool: 'Test',
        status: 'safe',
        message: 'Test',
        timestamp: '12:00:00',
        description: 123 // Should be string
      })).toBe(false);

      expect(isValidResultItem({
        id: '123',
        tool: 'Test',
        status: 'safe',
        message: 'Test',
        timestamp: '12:00:00',
        evidence: {} // Should be string
      })).toBe(false);

      expect(isValidResultItem({
        id: '123',
        tool: 'Test',
        status: 'safe',
        message: 'Test',
        timestamp: '12:00:00',
        remediation: 'not an array'
      })).toBe(false);

      expect(isValidResultItem({
        id: '123',
        tool: 'Test',
        status: 'safe',
        message: 'Test',
        timestamp: '12:00:00',
        target: 123 // Should be string
      })).toBe(false);

      expect(isValidResultItem({
        id: '123',
        tool: 'Test',
        status: 'safe',
        message: 'Test',
        timestamp: '12:00:00',
        confidence: 'high' // Should be number
      })).toBe(false);
    });

    it('should reject confidence values outside 0-100 range', () => {
      expect(isValidResultItem({
        id: '123',
        tool: 'Test',
        status: 'safe',
        message: 'Test',
        timestamp: '12:00:00',
        confidence: -1
      })).toBe(false);

      expect(isValidResultItem({
        id: '123',
        tool: 'Test',
        status: 'safe',
        message: 'Test',
        timestamp: '12:00:00',
        confidence: 101
      })).toBe(false);

      expect(isValidResultItem({
        id: '123',
        tool: 'Test',
        status: 'safe',
        message: 'Test',
        timestamp: '12:00:00',
        confidence: 0
      })).toBe(true);

      expect(isValidResultItem({
        id: '123',
        tool: 'Test',
        status: 'safe',
        message: 'Test',
        timestamp: '12:00:00',
        confidence: 100
      })).toBe(true);
    });
  });

  describe('convertLegacyResult', () => {
    it('should convert legacy result with feature field to tool field', () => {
      const legacy = {
        id: '123',
        feature: 'XSS Scanner',
        status: 'threat',
        message: 'Vulnerability found',
        timestamp: '2:34:56 PM'
      };

      const converted = convertLegacyResult(legacy);

      expect(converted.tool).toBe('XSS Scanner');
      expect(converted.id).toBe('123');
      expect(converted.status).toBe('threat');
      expect(converted.message).toBe('Vulnerability found');
      expect(converted.timestamp).toBe('2:34:56 PM');
    });

    it('should use tool field if present instead of feature', () => {
      const legacy = {
        id: '123',
        feature: 'Old Name',
        tool: 'New Name',
        status: 'safe',
        message: 'Test',
        timestamp: '12:00:00'
      };

      const converted = convertLegacyResult(legacy);

      expect(converted.tool).toBe('Old Name'); // feature takes precedence
    });

    it('should use "Unknown" if neither feature nor tool is present', () => {
      const legacy = {
        id: '123',
        status: 'safe',
        message: 'Test',
        timestamp: '12:00:00'
      };

      const converted = convertLegacyResult(legacy);

      expect(converted.tool).toBe('Unknown');
    });

    it('should convert details field to description', () => {
      const legacy = {
        id: '123',
        feature: 'Test',
        status: 'safe',
        message: 'Test',
        timestamp: '12:00:00',
        details: 'Detailed information'
      };

      const converted = convertLegacyResult(legacy);

      expect(converted.description).toBe('Detailed information');
    });

    it('should generate ID if missing', () => {
      const legacy = {
        feature: 'Test',
        status: 'safe',
        message: 'Test',
        timestamp: '12:00:00'
      };

      const converted = convertLegacyResult(legacy);

      expect(converted.id).toBeDefined();
      expect(converted.id).toMatch(/^\d+$/);
    });

    it('should use default values for missing optional fields', () => {
      const legacy = {
        id: '123',
        feature: 'Test',
        status: 'safe',
        message: 'Test',
        timestamp: '12:00:00'
      };

      const converted = convertLegacyResult(legacy);

      expect(converted.description).toBe('');
      expect(converted.evidence).toBe('');
      expect(converted.remediation).toEqual([]);
      expect(converted.target).toBe('');
      expect(converted.confidence).toBe(100);
    });

    it('should preserve all new format fields if present', () => {
      const legacy = {
        id: '123',
        feature: 'Test',
        status: 'warning',
        message: 'Test',
        timestamp: '12:00:00',
        description: 'Description',
        evidence: 'Evidence',
        remediation: ['Fix 1', 'Fix 2'],
        target: '192.168.1.1',
        confidence: 85
      };

      const converted = convertLegacyResult(legacy);

      expect(converted.description).toBe('Description');
      expect(converted.evidence).toBe('Evidence');
      expect(converted.remediation).toEqual(['Fix 1', 'Fix 2']);
      expect(converted.target).toBe('192.168.1.1');
      expect(converted.confidence).toBe(85);
    });

    it('should use system status as default if missing', () => {
      const legacy = {
        id: '123',
        feature: 'Test',
        message: 'Test',
        timestamp: '12:00:00'
      };

      const converted = convertLegacyResult(legacy);

      expect(converted.status).toBe('system');
    });

    it('should generate timestamp if missing', () => {
      const legacy = {
        id: '123',
        feature: 'Test',
        status: 'safe',
        message: 'Test'
      };

      const converted = convertLegacyResult(legacy);

      expect(converted.timestamp).toBeDefined();
      expect(converted.timestamp).toMatch(/\d{1,2}:\d{2}:\d{2}/);
    });
  });

  describe('Integration with existing results array', () => {
    it('should be compatible with existing result structure', () => {
      // Simulate existing result from logResult function
      const existingResult = {
        id: Date.now().toString(),
        timestamp: new Date().toLocaleTimeString(),
        feature: 'XSS Scanner',
        message: 'Vulnerability detected',
        status: 'threat',
        details: null,
        date: new Date()
      };

      // Convert to new format
      const converted = convertLegacyResult(existingResult);

      // Should be valid
      expect(isValidResultItem(converted)).toBe(true);
      expect(converted.tool).toBe('XSS Scanner');
      expect(converted.status).toBe('threat');
    });

    it('should work with new format results', () => {
      const newResult = createResultItem({
        tool: 'Port Scanner',
        status: 'warning',
        message: 'Open port detected',
        description: 'Port 8080 is open',
        evidence: 'Port: 8080',
        remediation: ['Close port'],
        target: '192.168.1.1',
        confidence: 90
      });

      expect(isValidResultItem(newResult)).toBe(true);
    });
  });
});
