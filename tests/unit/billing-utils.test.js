import { describe, it, expect } from 'vitest';
import { formatFailureReason } from '../../public/js/billing-utils.js';

describe('billing-utils - formatFailureReason', () => {
  it('should return a dash for null, undefined, or empty values', () => {
    expect(formatFailureReason(null)).toBe('—');
    expect(formatFailureReason(undefined)).toBe('—');
    expect(formatFailureReason('')).toBe('—');
  });

  it('should return the original string for a plain text message', () => {
    expect(formatFailureReason('Insufficient funds')).toBe('Insufficient funds');
    expect(formatFailureReason('Expired card')).toBe('Expired card');
  });

  it('should return a user-friendly message for raw HTML strings', () => {
    const rawHtml = '<div id="3ds-redirect"><form action="https://bank.com"></form></div>';
    expect(formatFailureReason(rawHtml)).toBe('3D Secure Verification Incomplete');
  });

  describe('JSON response parsing', () => {
    it('should extract message from standard error objects', () => {
      const response = JSON.stringify({
        error: {
          explanation: 'The card has expired. Please check the expiry date and try again.',
          message: 'Expired Card'
        }
      });
      expect(formatFailureReason(response)).toBe('The card has expired. Please check the expiry date and try again.');
    });

    it('should extract message from simple message property', () => {
      const response = JSON.stringify({
        message: 'Security violation. Transaction blocked.'
      });
      expect(formatFailureReason(response)).toBe('Security violation. Transaction blocked.');
    });

    it('should handle Mastercard MPGS structure with acquirer message', () => {
      const response = JSON.stringify({
        response: {
          acquirer: {
            message: 'MOCK ACQUIRER DECLINE'
          }
        }
      });
      expect(formatFailureReason(response)).toBe('MOCK ACQUIRER DECLINE');
    });

    it('should handle 3DS HTML redirect objects', () => {
      const response = JSON.stringify({
        html: '<div id="redirect"></div>',
        gatewayCode: 'AUTHENTICATION_IN_PROGRESS',
        authenticationStatus: 'AUTHENTICATION_IN_PROGRESS'
      });
      expect(formatFailureReason(response)).toBe('3D Secure Verification Incomplete (Authentication In Progress)');
    });

    it('should parse 3DS HTML redirect objects with regex when double-escaped or corrupted', () => {
      const response = '{"html":"<div id=\\"redirect\\"></div>","gatewayCode":"AUTHENTICATION_IN_PROGRESS"}';
      expect(formatFailureReason(response)).toBe('3D Secure Verification Incomplete (Authentication In Progress)');
    });

    it('should fallback to stringifying simple key/value pairs if no matches found', () => {
      const response = JSON.stringify({
        code: '5001',
        response_type: 'Unknown type'
      });
      expect(formatFailureReason(response)).toContain('Code: 5001');
      expect(formatFailureReason(response)).toContain('Response Type: Unknown type');
    });
  });
});
