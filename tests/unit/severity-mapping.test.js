/**
 * Unit tests for Severity Mapping Function
 * Feature: professional-security-reports-view
 * Task 3.1: Create severity mapping function
 * 
 * Requirements tested: 3.3, 3.4, 3.5
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { JSDOM } from 'jsdom';
import fs from 'fs';
import path from 'path';

describe('Severity Mapping - mapStatusToSeverity', () => {
  let mapStatusToSeverity;

  beforeEach(() => {
    // Load main.js in a DOM context
    const mainCode = fs.readFileSync(
      path.resolve(process.cwd(), 'main.js'),
      'utf-8'
    );

    // Create a minimal DOM
    const dom = new JSDOM(`
      <!DOCTYPE html>
      <html>
        <body>
          <div id="target-ip"></div>
          <div id="results-container"></div>
        </body>
      </html>
    `);

    const window = dom.window;
    const document = window.document;
    global.document = document;
    global.window = window;

    // Execute main.js to get the function
    // Extract just the mapStatusToSeverity function
    const functionMatch = mainCode.match(/function mapStatusToSeverity\(status\) \{[\s\S]*?\n\}/);
    if (functionMatch) {
      const functionCode = functionMatch[0];
      const script = new Function('return ' + functionCode);
      mapStatusToSeverity = script();
    }
  });

  /**
   * Requirement 3.3: Map 'threat' status to 'critical' severity
   */
  it('should map "threat" status to "critical" severity', () => {
    expect(mapStatusToSeverity('threat')).toBe('critical');
  });

  /**
   * Requirement 3.4: Map 'warning' status to 'warning' severity
   */
  it('should map "warning" status to "warning" severity', () => {
    expect(mapStatusToSeverity('warning')).toBe('warning');
  });

  /**
   * Requirement 3.5: Map 'safe' status to 'info' severity
   */
  it('should map "safe" status to "info" severity', () => {
    expect(mapStatusToSeverity('safe')).toBe('info');
  });

  /**
   * Requirement 3.5: Map 'system' status to 'info' severity
   */
  it('should map "system" status to "info" severity', () => {
    expect(mapStatusToSeverity('system')).toBe('info');
  });

  /**
   * Edge case: Unknown status values should default to 'info'
   */
  it('should default to "info" for unknown status values', () => {
    expect(mapStatusToSeverity('unknown')).toBe('info');
    expect(mapStatusToSeverity('error')).toBe('info');
    expect(mapStatusToSeverity('custom')).toBe('info');
  });

  /**
   * Edge case: Handle null and undefined inputs
   */
  it('should default to "info" for null input', () => {
    expect(mapStatusToSeverity(null)).toBe('info');
  });

  it('should default to "info" for undefined input', () => {
    expect(mapStatusToSeverity(undefined)).toBe('info');
  });

  /**
   * Edge case: Handle empty string
   */
  it('should default to "info" for empty string', () => {
    expect(mapStatusToSeverity('')).toBe('info');
  });

  /**
   * Edge case: Case sensitivity - function should be case-sensitive
   */
  it('should be case-sensitive for status values', () => {
    expect(mapStatusToSeverity('THREAT')).toBe('info'); // uppercase not mapped
    expect(mapStatusToSeverity('Threat')).toBe('info'); // capitalized not mapped
    expect(mapStatusToSeverity('WARNING')).toBe('info'); // uppercase not mapped
    expect(mapStatusToSeverity('Warning')).toBe('info'); // capitalized not mapped
  });

  /**
   * Edge case: Handle non-string inputs
   */
  it('should handle numeric inputs gracefully', () => {
    expect(mapStatusToSeverity(0)).toBe('info');
    expect(mapStatusToSeverity(1)).toBe('info');
    expect(mapStatusToSeverity(123)).toBe('info');
  });

  it('should handle boolean inputs gracefully', () => {
    expect(mapStatusToSeverity(true)).toBe('info');
    expect(mapStatusToSeverity(false)).toBe('info');
  });

  it('should handle object inputs gracefully', () => {
    expect(mapStatusToSeverity({})).toBe('info');
    expect(mapStatusToSeverity({ status: 'threat' })).toBe('info');
  });

  it('should handle array inputs gracefully', () => {
    expect(mapStatusToSeverity([])).toBe('info');
    // Note: ['threat'] converts to string 'threat' when used as object key
    expect(mapStatusToSeverity(['threat'])).toBe('critical');
  });

  /**
   * Integration test: Verify all valid status mappings
   */
  it('should correctly map all valid status values', () => {
    const statusMappings = [
      { status: 'threat', expected: 'critical' },
      { status: 'warning', expected: 'warning' },
      { status: 'safe', expected: 'info' },
      { status: 'system', expected: 'info' }
    ];

    statusMappings.forEach(({ status, expected }) => {
      expect(mapStatusToSeverity(status)).toBe(expected);
    });
  });

  /**
   * Performance test: Function should execute quickly
   */
  it('should execute quickly for multiple calls', () => {
    const startTime = performance.now();
    
    for (let i = 0; i < 1000; i++) {
      mapStatusToSeverity('threat');
      mapStatusToSeverity('warning');
      mapStatusToSeverity('safe');
      mapStatusToSeverity('system');
    }
    
    const endTime = performance.now();
    const executionTime = endTime - startTime;
    
    // Should complete 4000 calls in less than 100ms
    expect(executionTime).toBeLessThan(100);
  });

  /**
   * Consistency test: Function should return same result for same input
   */
  it('should return consistent results for repeated calls', () => {
    const firstCall = mapStatusToSeverity('threat');
    const secondCall = mapStatusToSeverity('threat');
    const thirdCall = mapStatusToSeverity('threat');
    
    expect(firstCall).toBe(secondCall);
    expect(secondCall).toBe(thirdCall);
    expect(firstCall).toBe('critical');
  });
});
