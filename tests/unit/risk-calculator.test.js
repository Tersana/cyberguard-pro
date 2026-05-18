/**
 * Unit tests for Risk Calculator edge cases
 * Feature: data-driven-risk-dashboard
 * Task 2.7: Test edge cases for calculateScore function
 * 
 * Requirements tested: 2.7, 8.8
 */

import { describe, it, expect, beforeEach } from 'vitest';

// Import the calculateScore function from risk-gauge.js
// Since risk-gauge.js is an IIFE, we need to load it in the DOM context
import { JSDOM } from 'jsdom';
import fs from 'fs';
import path from 'path';

describe('Risk Calculator Edge Cases', () => {
  let calculateScore;
  
  beforeEach(() => {
    // Load risk-gauge.js in a DOM context to extract calculateScore
    const riskGaugeCode = fs.readFileSync(
      path.resolve(process.cwd(), 'public/js/risk-gauge.js'),
      'utf-8'
    );
    
    // Create a minimal DOM environment
    const dom = new JSDOM('<!DOCTYPE html><html><body></body></html>', {
      runScripts: 'outside-only'
    });
    
    const window = dom.window;
    const document = window.document;
    
    // Execute the risk-gauge.js code in the window context
    const script = new window.Function(riskGaugeCode);
    script.call(window);
    
    // Extract the calculateScore function from the exposed API
    calculateScore = window.RiskGauge.calculateScore;
  });

  /**
   * Test: Empty scan data returns 0
   * Validates: Requirement 2.7 - Edge case handling
   * Validates: Requirement 8.8 - Graceful error handling
   */
  it('should return 0 for empty scan data', () => {
    const result = calculateScore({});
    expect(result).toBe(0);
  });

  /**
   * Test: Null input returns 0
   * Validates: Requirement 2.7 - Edge case handling
   * Validates: Requirement 8.8 - Graceful error handling
   */
  it('should return 0 for null input', () => {
    const result = calculateScore(null);
    expect(result).toBe(0);
  });

  /**
   * Test: Undefined input returns 0
   * Validates: Requirement 2.7 - Edge case handling
   * Validates: Requirement 8.8 - Graceful error handling
   */
  it('should return 0 for undefined input', () => {
    const result = calculateScore(undefined);
    expect(result).toBe(0);
  });

  /**
   * Test: Score capping at 100
   * Validates: Requirement 2.5 - Score capping
   * Validates: Requirement 2.7 - Edge case handling
   */
  it('should cap score at 100 even with extreme values', () => {
    const extremeData = {
      vulnerabilities: 100,  // Would contribute 50 points (capped at 10 vulns)
      latency: 1000,         // Would contribute 20 points
      openPorts: 100,        // Would contribute 20 points (capped at 10 ports)
      warnings: 100,         // Would contribute 10 points (capped at 5 warnings)
      sslStatus: 'expired',  // Would contribute 15 points
      type: 'critical'       // Would contribute 10 points
    };
    // Total would be 125, but should be capped at 100
    const result = calculateScore(extremeData);
    expect(result).toBe(100);
    expect(result).toBeLessThanOrEqual(100);
  });

  /**
   * Test: Negative values handled gracefully
   * Validates: Requirement 2.7 - Edge case handling
   * Validates: Requirement 8.8 - Graceful error handling
   */
  it('should handle negative values gracefully', () => {
    const negativeData = {
      vulnerabilities: -5,
      latency: -100,
      openPorts: -10,
      warnings: -3
    };
    const result = calculateScore(negativeData);
    // Negative values should be treated as 0 due to Math.min/max logic
    expect(result).toBeGreaterThanOrEqual(0);
    expect(result).toBeLessThanOrEqual(100);
  });

  /**
   * Test: Score with low severity type can reduce score
   * Validates: Requirement 2.7 - Edge case handling
   */
  it('should handle low severity type modifier correctly', () => {
    const lowSeverityData = {
      vulnerabilities: 1,  // 5 points
      type: 'low'          // -5 points
    };
    const result = calculateScore(lowSeverityData);
    // Should be 0 (5 - 5 = 0)
    expect(result).toBe(0);
  });

  /**
   * Test: Missing optional fields don't cause errors
   * Validates: Requirement 8.8 - Graceful error handling
   */
  it('should handle missing optional fields without errors', () => {
    const partialData = {
      vulnerabilities: 2
      // Missing: latency, openPorts, warnings, sslStatus, type
    };
    const result = calculateScore(partialData);
    expect(result).toBe(10); // 2 vulns * 5 = 10
  });

  /**
   * Test: Invalid sslStatus values
   * Validates: Requirement 2.7 - Edge case handling
   */
  it('should handle invalid sslStatus values', () => {
    const invalidSSLData = {
      sslStatus: 'invalid-status'
    };
    const result = calculateScore(invalidSSLData);
    // Invalid status (not 'valid') should add 15 points
    expect(result).toBe(15);
  });

  /**
   * Test: Invalid type values default to 0 modifier
   * Validates: Requirement 2.7 - Edge case handling
   */
  it('should handle invalid type values with 0 modifier', () => {
    const invalidTypeData = {
      vulnerabilities: 2,  // 10 points
      type: 'invalid-type' // 0 points (default)
    };
    const result = calculateScore(invalidTypeData);
    expect(result).toBe(10);
  });

  /**
   * Test: Zero values in all fields
   * Validates: Requirement 2.7 - Edge case handling
   */
  it('should return 0 when all values are zero', () => {
    const zeroData = {
      vulnerabilities: 0,
      latency: 0,
      openPorts: 0,
      warnings: 0,
      sslStatus: 'valid',
      type: 'medium'
    };
    const result = calculateScore(zeroData);
    expect(result).toBe(0);
  });

  /**
   * Test: Boundary value for latency thresholds
   * Validates: Requirement 2.7 - Edge case handling
   */
  it('should handle latency boundary values correctly', () => {
    // Test exactly at threshold
    expect(calculateScore({ latency: 100 })).toBe(0);  // Not > 100
    expect(calculateScore({ latency: 101 })).toBe(5);  // > 100
    expect(calculateScore({ latency: 200 })).toBe(5);  // Not > 200
    expect(calculateScore({ latency: 201 })).toBe(10); // > 200
    expect(calculateScore({ latency: 500 })).toBe(10); // Not > 500
    expect(calculateScore({ latency: 501 })).toBe(20); // > 500
  });

  /**
   * Test: Capping behavior for vulnerabilities
   * Validates: Requirement 2.7 - Edge case handling
   */
  it('should cap vulnerabilities contribution at 10 vulns', () => {
    const tenVulns = calculateScore({ vulnerabilities: 10 });
    const twentyVulns = calculateScore({ vulnerabilities: 20 });
    // Both should contribute same amount (50 points)
    expect(tenVulns).toBe(50);
    expect(twentyVulns).toBe(50);
  });

  /**
   * Test: Capping behavior for open ports
   * Validates: Requirement 2.7 - Edge case handling
   */
  it('should cap open ports contribution at 10 ports', () => {
    const tenPorts = calculateScore({ openPorts: 10 });
    const twentyPorts = calculateScore({ openPorts: 20 });
    // Both should contribute same amount (20 points)
    expect(tenPorts).toBe(20);
    expect(twentyPorts).toBe(20);
  });

  /**
   * Test: Capping behavior for warnings
   * Validates: Requirement 2.7 - Edge case handling
   */
  it('should cap warnings contribution at 5 warnings', () => {
    const fiveWarnings = calculateScore({ warnings: 5 });
    const tenWarnings = calculateScore({ warnings: 10 });
    // Both should contribute same amount (10 points)
    expect(fiveWarnings).toBe(10);
    expect(tenWarnings).toBe(10);
  });
});
