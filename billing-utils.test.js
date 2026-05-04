/**
 * Unit Tests for Billing Utilities
 * Tests for amount formatting, date formatting, and other utility functions
 * 
 * Requirements: 12.1, 12.2, 12.3, 12.4, 12.5, 12.6
 */

import { describe, it, expect } from 'vitest';
import {
  formatAmount,
  formatDate,
  capitalize,
  getDaysRemaining,
  formatNumber,
  getStatusBadgeClass,
  getSubscriptionStatusBadgeClass
} from './billing-utils.js';

describe('formatAmount', () => {
  it('should convert cents to EGP with 2 decimal places', () => {
    expect(formatAmount(49900)).toBe('499.00 EGP');
    expect(formatAmount(0)).toBe('0.00 EGP');
    expect(formatAmount(12345)).toBe('123.45 EGP');
    expect(formatAmount(100)).toBe('1.00 EGP');
  });

  it('should handle large amounts correctly', () => {
    expect(formatAmount(1000000)).toBe('10000.00 EGP');
    expect(formatAmount(999999)).toBe('9999.99 EGP');
  });

  it('should handle negative amounts', () => {
    expect(formatAmount(-49900)).toBe('-499.00 EGP');
    expect(formatAmount(-100)).toBe('-1.00 EGP');
  });

  it('should handle invalid input gracefully', () => {
    expect(formatAmount(NaN)).toBe('0.00 EGP');
    expect(formatAmount(null)).toBe('0.00 EGP');
    expect(formatAmount(undefined)).toBe('0.00 EGP');
    expect(formatAmount('invalid')).toBe('0.00 EGP');
  });

  it('should always append " EGP" suffix', () => {
    expect(formatAmount(49900)).toContain(' EGP');
    expect(formatAmount(0)).toContain(' EGP');
    expect(formatAmount(12345)).toContain(' EGP');
  });

  it('should format with exactly 2 decimal places', () => {
    expect(formatAmount(49900)).toMatch(/^\d+\.\d{2} EGP$/);
    expect(formatAmount(100)).toMatch(/^\d+\.\d{2} EGP$/);
    expect(formatAmount(12345)).toMatch(/^\d+\.\d{2} EGP$/);
  });
});

describe('formatDate', () => {
  it('should format ISO date to readable format', () => {
    const isoDate = '2024-01-15T10:30:00Z';
    expect(formatDate(isoDate)).toBe('January 15, 2024');
  });

  it('should handle different months correctly', () => {
    expect(formatDate('2024-12-25T00:00:00Z')).toBe('December 25, 2024');
    expect(formatDate('2024-06-01T00:00:00Z')).toBe('June 1, 2024');
  });

  it('should handle invalid dates gracefully', () => {
    const invalidDate = 'invalid-date';
    expect(formatDate(invalidDate)).toBe(invalidDate);
  });
});

describe('capitalize', () => {
  it('should capitalize first letter and lowercase rest', () => {
    expect(capitalize('pro')).toBe('Pro');
    expect(capitalize('starter')).toBe('Starter');
    expect(capitalize('free')).toBe('Free');
    expect(capitalize('PAID')).toBe('Paid');
  });

  it('should handle empty string', () => {
    expect(capitalize('')).toBe('');
  });

  it('should handle null and undefined', () => {
    expect(capitalize(null)).toBe('');
    expect(capitalize(undefined)).toBe('');
  });

  it('should handle single character', () => {
    expect(capitalize('a')).toBe('A');
  });
});

describe('getDaysRemaining', () => {
  it('should calculate days remaining for future dates', () => {
    const futureDate = new Date();
    futureDate.setDate(futureDate.getDate() + 5);
    
    expect(getDaysRemaining(futureDate.toISOString())).toBe(5);
  });

  it('should return negative for past dates', () => {
    const pastDate = new Date();
    pastDate.setDate(pastDate.getDate() - 3);
    
    expect(getDaysRemaining(pastDate.toISOString())).toBeLessThan(0);
  });

  it('should return 0 for today', () => {
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    
    const result = getDaysRemaining(today.toISOString());
    expect(result).toBeGreaterThanOrEqual(0);
    expect(result).toBeLessThanOrEqual(1);
  });

  it('should handle invalid dates gracefully', () => {
    expect(getDaysRemaining('invalid-date')).toBe(0);
  });
});

describe('formatNumber', () => {
  it('should format numbers with commas', () => {
    expect(formatNumber(1000)).toBe('1,000');
    expect(formatNumber(1000000)).toBe('1,000,000');
    expect(formatNumber(12345)).toBe('12,345');
  });

  it('should handle numbers without thousands', () => {
    expect(formatNumber(100)).toBe('100');
    expect(formatNumber(50)).toBe('50');
    expect(formatNumber(0)).toBe('0');
  });

  it('should handle invalid input gracefully', () => {
    expect(formatNumber(NaN)).toBe('0');
    expect(formatNumber(null)).toBe('0');
    expect(formatNumber(undefined)).toBe('0');
    expect(formatNumber('invalid')).toBe('0');
  });
});

describe('getStatusBadgeClass', () => {
  it('should return correct class for paid status', () => {
    expect(getStatusBadgeClass('paid')).toBe('cyber-badge-success');
  });

  it('should return correct class for pending status', () => {
    expect(getStatusBadgeClass('pending')).toBe('cyber-badge-warning');
  });

  it('should return correct class for failed status', () => {
    expect(getStatusBadgeClass('failed')).toBe('cyber-badge-danger');
  });

  it('should return default class for unknown status', () => {
    expect(getStatusBadgeClass('unknown')).toBe('cyber-badge-info');
    expect(getStatusBadgeClass('')).toBe('cyber-badge-info');
  });
});

describe('getSubscriptionStatusBadgeClass', () => {
  it('should return correct class for active status', () => {
    expect(getSubscriptionStatusBadgeClass('active')).toBe('cyber-badge-success');
  });

  it('should return correct class for expired status', () => {
    expect(getSubscriptionStatusBadgeClass('expired')).toBe('cyber-badge-danger');
  });

  it('should return correct class for cancelled status', () => {
    expect(getSubscriptionStatusBadgeClass('cancelled')).toBe('cyber-badge-info');
  });

  it('should return default class for unknown status', () => {
    expect(getSubscriptionStatusBadgeClass('unknown')).toBe('cyber-badge-info');
    expect(getSubscriptionStatusBadgeClass('')).toBe('cyber-badge-info');
  });
});

describe('Edge Cases', () => {
  it('formatAmount should handle very small amounts', () => {
    expect(formatAmount(1)).toBe('0.01 EGP');
    expect(formatAmount(10)).toBe('0.10 EGP');
  });

  it('formatAmount should handle fractional cents correctly', () => {
    // Even though cents should be integers, test rounding behavior
    expect(formatAmount(49950)).toBe('499.50 EGP');
    expect(formatAmount(49999)).toBe('499.99 EGP');
  });

  it('formatNumber should handle negative numbers', () => {
    expect(formatNumber(-1000)).toBe('-1,000');
    expect(formatNumber(-1000000)).toBe('-1,000,000');
  });

  it('getDaysRemaining should handle dates far in the future', () => {
    const farFuture = new Date();
    farFuture.setFullYear(farFuture.getFullYear() + 1);
    
    const days = getDaysRemaining(farFuture.toISOString());
    expect(days).toBeGreaterThan(300);
  });

  it('getDaysRemaining should handle dates far in the past', () => {
    const farPast = new Date();
    farPast.setFullYear(farPast.getFullYear() - 1);
    
    const days = getDaysRemaining(farPast.toISOString());
    expect(days).toBeLessThan(-300);
  });
});
