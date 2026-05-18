/**
 * Unit tests for Data Mapper
 * Feature: data-driven-risk-dashboard
 * Task 3.1: Create mapDataToUI function
 * 
 * Requirements tested: 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7, 1.8, 1.9, 1.10, 6.4, 6.5, 6.6, 6.7, 6.8
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { JSDOM } from 'jsdom';
import fs from 'fs';
import path from 'path';

describe('Data Mapper - mapDataToUI', () => {
  let mapDataToUI;
  let document;

  beforeEach(() => {
    // Load risk-gauge.js in a DOM context
    const riskGaugeCode = fs.readFileSync(
      path.resolve(process.cwd(), 'public/js/risk-gauge.js'),
      'utf-8'
    );

    // Create a minimal DOM with required elements
    const dom = new JSDOM(`
      <!DOCTYPE html>
      <html>
        <body>
          <div id="openPortsCount">0</div>
          <div id="sslHealthStatus">N/A</div>
          <div id="warningStatCount">0</div>
          <div id="lastScanTime">Waiting</div>
          <div id="vulnCount">0</div>
          <div id="latencyVal">0ms</div>
        </body>
      </html>
    `);

    const window = dom.window;
    document = window.document;
    global.document = document;
    global.window = window;

    // Execute risk-gauge.js in the window context
    const script = new Function('window', 'document', riskGaugeCode);
    script.call(window, window, document);

    // Extract mapDataToUI from the exposed API
    mapDataToUI = window.RiskGauge.mapDataToUI;
  });

  /**
   * Requirement 1.1: Data Mapper accepts valid scan data
   */
  it('should accept valid scan data without throwing errors', () => {
    const validData = {
      network: { openPortsCount: 5, responseTimeMs: 150 },
      web: { sslStatus: 'valid' },
      issues: { criticalCount: 2, warnings: ['Warning 1'] },
      timestamp: new Date().toISOString()
    };

    expect(() => mapDataToUI(validData)).not.toThrow();
  });

  /**
   * Requirement 1.2, 1.3: Map open ports count, display "None" for 0
   */
  it('should display port count correctly', () => {
    const scanData = {
      network: { openPortsCount: 7 }
    };
    mapDataToUI(scanData);
    expect(document.getElementById('openPortsCount').textContent).toBe('7');
  });

  it('should display "None" for zero open ports', () => {
    const scanData = {
      network: { openPortsCount: 0 }
    };
    mapDataToUI(scanData);
    expect(document.getElementById('openPortsCount').textContent).toBe('None');
  });

  /**
   * Requirement 1.4, 1.5, 6.4, 6.5: SSL status mapping with color coding
   */
  it('should display "Healthy" with green color for valid SSL', () => {
    const scanData = {
      web: { sslStatus: 'valid' }
    };
    mapDataToUI(scanData);
    const el = document.getElementById('sslHealthStatus');
    expect(el.textContent).toBe('Healthy');
    expect(el.style.color).toBe('rgb(52, 211, 153)'); // #34D399 in RGB
  });

  it('should display "Critical" with red color for expired SSL', () => {
    const scanData = {
      web: { sslStatus: 'expired' }
    };
    mapDataToUI(scanData);
    const el = document.getElementById('sslHealthStatus');
    expect(el.textContent).toBe('Critical');
    expect(el.style.color).toBe('rgb(248, 113, 113)'); // #F87171 in RGB
  });

  it('should display "Critical" with red color for missing SSL', () => {
    const scanData = {
      web: { sslStatus: 'missing' }
    };
    mapDataToUI(scanData);
    const el = document.getElementById('sslHealthStatus');
    expect(el.textContent).toBe('Critical');
    expect(el.style.color).toBe('rgb(248, 113, 113)'); // #F87171 in RGB
  });

  /**
   * Requirement 1.6: Map warnings count from array
   */
  it('should display warnings count from array', () => {
    const scanData = {
      issues: { warnings: ['Warning 1', 'Warning 2', 'Warning 3'] }
    };
    mapDataToUI(scanData);
    expect(document.getElementById('warningStatCount').textContent).toBe('3');
  });

  it('should display warnings count from number', () => {
    const scanData = {
      issues: { warnings: 5 }
    };
    mapDataToUI(scanData);
    expect(document.getElementById('warningStatCount').textContent).toBe('5');
  });

  /**
   * Requirement 6.6, 6.7, 6.8: Warnings color coding
   */
  it('should display green color for 0 warnings', () => {
    const scanData = {
      issues: { warnings: 0 }
    };
    mapDataToUI(scanData);
    const el = document.getElementById('warningStatCount');
    expect(el.style.color).toBe('rgb(52, 211, 153)'); // green (#34D399)
  });

  it('should display yellow color for 1-5 warnings', () => {
    const scanData = {
      issues: { warnings: 3 }
    };
    mapDataToUI(scanData);
    const el = document.getElementById('warningStatCount');
    expect(el.style.color).toBe('rgb(251, 191, 36)'); // yellow (#FBBF24)
  });

  it('should display red color for >5 warnings', () => {
    const scanData = {
      issues: { warnings: 8 }
    };
    mapDataToUI(scanData);
    const el = document.getElementById('warningStatCount');
    expect(el.style.color).toBe('rgb(248, 113, 113)'); // red (#F87171)
  });

  /**
   * Requirement 1.7: Timestamp formatting DD/MM/YYYY HH:mm
   */
  it('should format timestamp correctly', () => {
    const scanData = {
      timestamp: '2024-03-15T14:30:00.000Z'
    };
    mapDataToUI(scanData);
    const el = document.getElementById('lastScanTime');
    // Note: The exact output depends on timezone, so we check format pattern
    expect(el.textContent).toMatch(/\d{2}\/\d{2}\/\d{4} \d{2}:\d{2}/);
  });

  it('should use current time if timestamp is missing', () => {
    const scanData = {};
    mapDataToUI(scanData);
    const el = document.getElementById('lastScanTime');
    expect(el.textContent).toMatch(/\d{2}\/\d{2}\/\d{4} \d{2}:\d{2}/);
  });

  /**
   * Requirement 1.9: Map critical count
   */
  it('should display vulnerabilities count', () => {
    const scanData = {
      issues: { criticalCount: 5 }
    };
    mapDataToUI(scanData);
    expect(document.getElementById('vulnCount').textContent).toBe('5');
  });

  /**
   * Requirement 1.10: Map latency with "ms" suffix
   */
  it('should display latency with ms suffix', () => {
    const scanData = {
      network: { responseTimeMs: 250 }
    };
    mapDataToUI(scanData);
    expect(document.getElementById('latencyVal').textContent).toBe('250ms');
  });

  /**
   * Requirement 8.8: Graceful error handling
   */
  it('should handle null input gracefully', () => {
    expect(() => mapDataToUI(null)).not.toThrow();
  });

  it('should handle undefined input gracefully', () => {
    expect(() => mapDataToUI(undefined)).not.toThrow();
  });

  it('should handle empty object gracefully', () => {
    expect(() => mapDataToUI({})).not.toThrow();
  });

  it('should handle missing nested properties gracefully', () => {
    const scanData = {
      network: {},
      web: {},
      issues: {}
    };
    expect(() => mapDataToUI(scanData)).not.toThrow();
  });

  /**
   * Integration test: Complete scan data
   */
  it('should map complete scan data correctly', () => {
    const scanData = {
      network: {
        openPortsCount: 3,
        responseTimeMs: 120
      },
      web: {
        sslStatus: 'valid'
      },
      issues: {
        criticalCount: 1,
        warnings: ['Warning 1', 'Warning 2']
      },
      timestamp: '2024-03-15T10:00:00.000Z'
    };

    mapDataToUI(scanData);

    expect(document.getElementById('openPortsCount').textContent).toBe('3');
    expect(document.getElementById('sslHealthStatus').textContent).toBe('Healthy');
    expect(document.getElementById('warningStatCount').textContent).toBe('2');
    expect(document.getElementById('vulnCount').textContent).toBe('1');
    expect(document.getElementById('latencyVal').textContent).toBe('120ms');
    expect(document.getElementById('lastScanTime').textContent).toMatch(/\d{2}\/\d{2}\/\d{4} \d{2}:\d{2}/);
  });

  /**
   * Task 3.11: Edge case tests
   * Requirement 8.8: Graceful error handling for edge cases
   */
  describe('Edge Cases', () => {
    it('should handle missing scanData object', () => {
      // Test with various falsy values
      expect(() => mapDataToUI(null)).not.toThrow();
      expect(() => mapDataToUI(undefined)).not.toThrow();
      expect(() => mapDataToUI(false)).not.toThrow();
      expect(() => mapDataToUI(0)).not.toThrow();
      expect(() => mapDataToUI('')).not.toThrow();
    });

    it('should handle missing nested properties', () => {
      // Test with missing network property
      const scanData1 = {
        web: { sslStatus: 'valid' },
        issues: { criticalCount: 1 }
      };
      expect(() => mapDataToUI(scanData1)).not.toThrow();

      // Test with missing web property
      const scanData2 = {
        network: { openPortsCount: 5 },
        issues: { warnings: 2 }
      };
      expect(() => mapDataToUI(scanData2)).not.toThrow();

      // Test with missing issues property
      const scanData3 = {
        network: { responseTimeMs: 100 },
        web: { sslStatus: 'expired' }
      };
      expect(() => mapDataToUI(scanData3)).not.toThrow();

      // Test with all nested properties missing
      const scanData4 = {};
      expect(() => mapDataToUI(scanData4)).not.toThrow();
    });

    it('should handle invalid timestamp formats', () => {
      // Test with invalid ISO string
      const scanData1 = { timestamp: 'invalid-date' };
      mapDataToUI(scanData1);
      const el1 = document.getElementById('lastScanTime');
      // Invalid Date will produce "Invalid Date" or NaN values
      expect(el1.textContent).toBeTruthy();

      // Test with non-string timestamp
      const scanData2 = { timestamp: 12345 };
      mapDataToUI(scanData2);
      const el2 = document.getElementById('lastScanTime');
      expect(el2.textContent).toBeTruthy();

      // Test with null timestamp
      const scanData3 = { timestamp: null };
      mapDataToUI(scanData3);
      const el3 = document.getElementById('lastScanTime');
      expect(el3.textContent).toMatch(/\d{2}\/\d{2}\/\d{4} \d{2}:\d{2}/);

      // Test with empty string timestamp
      const scanData4 = { timestamp: '' };
      mapDataToUI(scanData4);
      const el4 = document.getElementById('lastScanTime');
      expect(el4.textContent).toBeTruthy();
    });

    it('should handle array vs number for warnings', () => {
      // Test with warnings as array
      const scanData1 = {
        issues: { warnings: ['Warning 1', 'Warning 2', 'Warning 3'] }
      };
      mapDataToUI(scanData1);
      expect(document.getElementById('warningStatCount').textContent).toBe('3');

      // Test with warnings as number
      const scanData2 = {
        issues: { warnings: 7 }
      };
      mapDataToUI(scanData2);
      expect(document.getElementById('warningStatCount').textContent).toBe('7');

      // Test with warnings as 0
      const scanData3 = {
        issues: { warnings: 0 }
      };
      mapDataToUI(scanData3);
      expect(document.getElementById('warningStatCount').textContent).toBe('0');

      // Test with warnings as empty array
      const scanData4 = {
        issues: { warnings: [] }
      };
      mapDataToUI(scanData4);
      expect(document.getElementById('warningStatCount').textContent).toBe('0');

      // Test with warnings as null
      const scanData5 = {
        issues: { warnings: null }
      };
      mapDataToUI(scanData5);
      // Should handle gracefully - element may not update or show 0
      expect(() => document.getElementById('warningStatCount').textContent).not.toThrow();

      // Test with warnings as undefined
      const scanData6 = {
        issues: {}
      };
      mapDataToUI(scanData6);
      // Should handle gracefully
      expect(() => document.getElementById('warningStatCount').textContent).not.toThrow();
    });

    it('should handle deeply nested missing properties', () => {
      // Test with partial network object
      const scanData1 = {
        network: { openPortsCount: 5 }
        // missing responseTimeMs
      };
      expect(() => mapDataToUI(scanData1)).not.toThrow();

      // Test with partial issues object
      const scanData2 = {
        issues: { criticalCount: 3 }
        // missing warnings
      };
      expect(() => mapDataToUI(scanData2)).not.toThrow();

      // Test with empty nested objects
      const scanData3 = {
        network: {},
        web: {},
        issues: {}
      };
      expect(() => mapDataToUI(scanData3)).not.toThrow();
    });

    it('should handle non-numeric values in numeric fields', () => {
      // Test with string instead of number for openPortsCount
      const scanData1 = {
        network: { openPortsCount: 'invalid' }
      };
      mapDataToUI(scanData1);
      // Should display the value or handle gracefully
      expect(() => document.getElementById('openPortsCount').textContent).not.toThrow();

      // Test with string instead of number for responseTimeMs
      const scanData2 = {
        network: { responseTimeMs: 'slow' }
      };
      mapDataToUI(scanData2);
      expect(() => document.getElementById('latencyVal').textContent).not.toThrow();

      // Test with negative numbers
      const scanData3 = {
        network: { openPortsCount: -5, responseTimeMs: -100 },
        issues: { criticalCount: -2 }
      };
      expect(() => mapDataToUI(scanData3)).not.toThrow();
    });

    it('should handle unexpected sslStatus values', () => {
      // Test with unknown SSL status
      const scanData1 = {
        web: { sslStatus: 'unknown' }
      };
      mapDataToUI(scanData1);
      // Should not update or handle gracefully
      expect(() => document.getElementById('sslHealthStatus').textContent).not.toThrow();

      // Test with null SSL status
      const scanData2 = {
        web: { sslStatus: null }
      };
      mapDataToUI(scanData2);
      expect(() => document.getElementById('sslHealthStatus').textContent).not.toThrow();

      // Test with empty string SSL status
      const scanData3 = {
        web: { sslStatus: '' }
      };
      mapDataToUI(scanData3);
      expect(() => document.getElementById('sslHealthStatus').textContent).not.toThrow();
    });
  });
});
