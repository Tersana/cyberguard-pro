/**
 * Unit tests for getColorForScore function
 * Feature: data-driven-risk-dashboard
 * Task 6.1: Test color threshold logic for Risk Gauge
 * 
 * Requirements tested: 6.1, 6.2, 6.3
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { JSDOM } from 'jsdom';
import fs from 'fs';
import path from 'path';

describe('getColorForScore - Color Threshold Logic', () => {
  let getColorForScore;
  
  beforeEach(() => {
    // Load risk-gauge.js in a DOM context to extract getColorForScore
    const riskGaugeCode = fs.readFileSync(
      path.resolve(process.cwd(), 'public/js/risk-gauge.js'),
      'utf-8'
    );
    
    // Create a minimal DOM environment
    const dom = new JSDOM('<!DOCTYPE html><html><body></body></html>', {
      runScripts: 'outside-only'
    });
    
    const window = dom.window;
    
    // Execute the risk-gauge.js code in the window context
    const script = new window.Function(riskGaugeCode);
    script.call(window);
    
    // Extract the getColorForScore function from the exposed API
    getColorForScore = window.RiskGauge.getColorForScore;
  });

  /**
   * Test: Low risk range (0-30) returns green
   * Validates: Requirement 6.1 - Green color for scores 0-30
   */
  describe('Low Risk Range (0-30)', () => {
    it('should return green color for score 0', () => {
      const result = getColorForScore(0);
      expect(result.color).toBe('#34D399');
      expect(result.label).toBe('LOW RISK');
    });

    it('should return green color for score 15', () => {
      const result = getColorForScore(15);
      expect(result.color).toBe('#34D399');
      expect(result.label).toBe('LOW RISK');
    });

    it('should return green color for score 30', () => {
      const result = getColorForScore(30);
      expect(result.color).toBe('#34D399');
      expect(result.label).toBe('LOW RISK');
    });
  });

  /**
   * Test: Medium risk range (31-69) returns yellow
   * Validates: Requirement 6.2 - Yellow color for scores 31-69
   */
  describe('Medium Risk Range (31-69)', () => {
    it('should return yellow color for score 31', () => {
      const result = getColorForScore(31);
      expect(result.color).toBe('#FBBF24');
      expect(result.label).toBe('MEDIUM RISK');
    });

    it('should return yellow color for score 50', () => {
      const result = getColorForScore(50);
      expect(result.color).toBe('#FBBF24');
      expect(result.label).toBe('MEDIUM RISK');
    });

    it('should return yellow color for score 69', () => {
      const result = getColorForScore(69);
      expect(result.color).toBe('#FBBF24');
      expect(result.label).toBe('MEDIUM RISK');
    });
  });

  /**
   * Test: High risk range (70-100) returns red
   * Validates: Requirement 6.3 - Red color for scores 70-100
   */
  describe('High Risk Range (70-100)', () => {
    it('should return red color for score 70', () => {
      const result = getColorForScore(70);
      expect(result.color).toBe('#F87171');
      expect(result.label).toBe('HIGH RISK');
    });

    it('should return red color for score 85', () => {
      const result = getColorForScore(85);
      expect(result.color).toBe('#F87171');
      expect(result.label).toBe('HIGH RISK');
    });

    it('should return red color for score 100', () => {
      const result = getColorForScore(100);
      expect(result.color).toBe('#F87171');
      expect(result.label).toBe('HIGH RISK');
    });
  });

  /**
   * Test: Boundary values between ranges
   * Validates: Requirements 6.1, 6.2, 6.3 - Correct boundary handling
   */
  describe('Boundary Values', () => {
    it('should handle boundary between low and medium (30 vs 31)', () => {
      const low = getColorForScore(30);
      const medium = getColorForScore(31);
      
      expect(low.color).toBe('#34D399');
      expect(low.label).toBe('LOW RISK');
      expect(medium.color).toBe('#FBBF24');
      expect(medium.label).toBe('MEDIUM RISK');
    });

    it('should handle boundary between medium and high (69 vs 70)', () => {
      const medium = getColorForScore(69);
      const high = getColorForScore(70);
      
      expect(medium.color).toBe('#FBBF24');
      expect(medium.label).toBe('MEDIUM RISK');
      expect(high.color).toBe('#F87171');
      expect(high.label).toBe('HIGH RISK');
    });
  });

  /**
   * Test: Edge cases and invalid inputs
   * Validates: Requirement 8.8 - Graceful error handling
   */
  describe('Edge Cases and Invalid Inputs', () => {
    it('should handle negative scores by clamping to 0', () => {
      const result = getColorForScore(-10);
      expect(result.color).toBe('#34D399');
      expect(result.label).toBe('LOW RISK');
    });

    it('should handle scores above 100 by clamping to 100', () => {
      const result = getColorForScore(150);
      expect(result.color).toBe('#F87171');
      expect(result.label).toBe('HIGH RISK');
    });

    it('should handle NaN input gracefully', () => {
      const result = getColorForScore(NaN);
      expect(result.color).toBe('#64748B');
      expect(result.label).toBe('INVALID');
    });

    it('should handle non-number input gracefully', () => {
      const result = getColorForScore('invalid');
      expect(result.color).toBe('#64748B');
      expect(result.label).toBe('INVALID');
    });

    it('should handle null input gracefully', () => {
      const result = getColorForScore(null);
      expect(result.color).toBe('#64748B');
      expect(result.label).toBe('INVALID');
    });

    it('should handle undefined input gracefully', () => {
      const result = getColorForScore(undefined);
      expect(result.color).toBe('#64748B');
      expect(result.label).toBe('INVALID');
    });
  });

  /**
   * Test: Decimal scores
   * Validates: Requirements 6.1, 6.2, 6.3 - Handling non-integer scores
   */
  describe('Decimal Scores', () => {
    it('should handle decimal score in low range', () => {
      const result = getColorForScore(15.5);
      expect(result.color).toBe('#34D399');
      expect(result.label).toBe('LOW RISK');
    });

    it('should handle decimal score in medium range', () => {
      const result = getColorForScore(50.7);
      expect(result.color).toBe('#FBBF24');
      expect(result.label).toBe('MEDIUM RISK');
    });

    it('should handle decimal score in high range', () => {
      const result = getColorForScore(85.3);
      expect(result.color).toBe('#F87171');
      expect(result.label).toBe('HIGH RISK');
    });

    it('should handle decimal boundary values correctly', () => {
      const result30_5 = getColorForScore(30.5);
      const result69_5 = getColorForScore(69.5);
      
      // 30.5 is > 30, so it should be medium risk
      expect(result30_5.color).toBe('#FBBF24');
      expect(result30_5.label).toBe('MEDIUM RISK');
      
      // 69.5 is > 69, so it should be high risk
      expect(result69_5.color).toBe('#F87171');
      expect(result69_5.label).toBe('HIGH RISK');
    });
  });

  /**
   * Test: Return value structure
   * Validates: Requirements 6.1, 6.2, 6.3 - Correct return format
   */
  describe('Return Value Structure', () => {
    it('should return object with color and label properties', () => {
      const result = getColorForScore(50);
      expect(result).toHaveProperty('color');
      expect(result).toHaveProperty('label');
      expect(typeof result.color).toBe('string');
      expect(typeof result.label).toBe('string');
    });

    it('should return valid hex color codes', () => {
      const hexColorRegex = /^#[0-9a-f]{6}$/i;
      
      expect(getColorForScore(15).color).toMatch(hexColorRegex);
      expect(getColorForScore(50).color).toMatch(hexColorRegex);
      expect(getColorForScore(85).color).toMatch(hexColorRegex);
    });

    it('should return uppercase risk level labels', () => {
      expect(getColorForScore(15).label).toMatch(/^[A-Z\s]+$/);
      expect(getColorForScore(50).label).toMatch(/^[A-Z\s]+$/);
      expect(getColorForScore(85).label).toMatch(/^[A-Z\s]+$/);
    });
  });
});
