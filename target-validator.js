/**
 * CyberGuard Pro - Target Validation Utility
 * Provides type-specific client-side validation for security scan targets.
 *
 * Supported types:
 *   domain  — hostname without protocol or www prefix (e.g. example.com)
 *   ip      — valid IPv4 address in dotted-decimal notation (e.g. 203.0.113.10)
 *   network — valid IPv4 CIDR notation (e.g. 192.0.2.0/24)
 *
 * Requirements: 7.1 – 7.7
 */

const TargetValidator = {
  /**
   * Validation regex patterns
   */
  patterns: {
    // Domain: alphanumeric labels separated by dots, no protocol or www prefix
    domain:
      /^(?!https?:\/\/)(?!www\.)([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/,

    // IPv4: four octets 0-255 in dotted-decimal notation
    ip: /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/,

    // CIDR: IPv4 address followed by /subnet (1-32)
    network:
      /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/([1-9]|[12][0-9]|3[0-2])$/,
  },

  /**
   * Validate a target value against the given type.
   *
   * @param {string} type  - 'domain' | 'ip' | 'network'
   * @param {string} value - Raw input from the user
   * @returns {{ valid: boolean, error: string|null }}
   */
  validate(type, value) {
    if (!value || typeof value !== 'string') {
      return { valid: false, error: 'Value is required.' };
    }

    const trimmedValue = value.trim();

    if (!trimmedValue) {
      return { valid: false, error: 'Value cannot be empty.' };
    }

    switch (type) {
      case 'domain':
        return this.validateDomain(trimmedValue);
      case 'ip':
        return this.validateIP(trimmedValue);
      case 'network':
        return this.validateNetwork(trimmedValue);
      default:
        return { valid: false, error: 'Invalid target type.' };
    }
  },

  /**
   * Validate a domain hostname.
   * Rejects http://, https://, and www. prefixes.
   *
   * @param {string} value
   * @returns {{ valid: boolean, error: string|null }}
   */
  validateDomain(value) {
    if (/^https?:\/\//i.test(value)) {
      return {
        valid: false,
        error: 'Domain should not include http:// or https://',
      };
    }

    if (/^www\./i.test(value)) {
      return {
        valid: false,
        error: 'Domain should not include the www. prefix.',
      };
    }

    if (!this.patterns.domain.test(value)) {
      return {
        valid: false,
        error: 'Invalid domain format. Example: example.com',
      };
    }

    return { valid: true, error: null };
  },

  /**
   * Validate an IPv4 address.
   *
   * @param {string} value
   * @returns {{ valid: boolean, error: string|null }}
   */
  validateIP(value) {
    if (!this.patterns.ip.test(value)) {
      return {
        valid: false,
        error: 'Invalid IPv4 address. Example: 203.0.113.10',
      };
    }

    return { valid: true, error: null };
  },

  /**
   * Validate IPv4 CIDR notation.
   * Subnet mask must be between /1 and /32.
   *
   * @param {string} value
   * @returns {{ valid: boolean, error: string|null }}
   */
  validateNetwork(value) {
    if (!this.patterns.network.test(value)) {
      return {
        valid: false,
        error: 'Invalid CIDR notation. Example: 192.0.2.0/24',
      };
    }

    return { valid: true, error: null };
  },

  /**
   * Return placeholder text for a given target type.
   *
   * @param {string} type
   * @returns {string}
   */
  getPlaceholder(type) {
    const placeholders = {
      domain: 'e.g. example.com  (no https:// or www.)',
      ip: 'e.g. 203.0.113.10',
      network: 'e.g. 192.0.2.0/24',
    };
    return placeholders[type] || '';
  },

  /**
   * Return hint / instruction text for a given target type.
   *
   * @param {string} type
   * @returns {string}
   */
  getHint(type) {
    const hints = {
      domain:
        'Enter a valid hostname without protocol (http/https) or www prefix.',
      ip: 'Enter a valid IPv4 address in dotted-decimal notation (0-255.0-255.0-255.0-255).',
      network:
        'Enter a valid IPv4 CIDR block with subnet mask between /1 and /32.',
    };
    return hints[type] || '';
  },
};

// Universal export
if (typeof module !== 'undefined' && module.exports) {
  // Node.js / test environment
  module.exports = { TargetValidator };
} else {
  // Browser environment
  window.TargetValidator = TargetValidator;
  console.log('[TargetValidator] Loaded and attached to window.TargetValidator');
}
