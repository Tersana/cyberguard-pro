/**
 * Billing Utilities
 * Helper functions for billing and subscription operations
 * 
 * Requirements: 12.1, 12.2, 12.3, 12.4, 12.5, 12.6
 */

/**
 * Format amount from cents to EGP with suffix
 * Converts amount_cents to EGP with 2 decimal places and " EGP" suffix
 * 
 * @param {number} amountCents - Amount in cents (e.g., 49900)
 * @returns {string} Formatted amount (e.g., "499.00 EGP")
 * 
 * Requirements: 12.1, 12.2, 12.3
 */
function formatAmount(amountCents) {
  if (typeof amountCents !== 'number' || isNaN(amountCents)) {
    console.warn('[BillingUtils] Invalid amount:', amountCents);
    return '0.00 EGP';
  }

  // Convert cents to EGP (divide by 100)
  const amountEGP = amountCents / 100;

  // Format with 2 decimal places
  const formatted = amountEGP.toFixed(2);

  // Append " EGP" suffix
  return `${formatted} EGP`;
}

/**
 * Format date to readable format
 * Converts ISO 8601 timestamp to "Month Day, Year" format
 * 
 * @param {string} isoDate - ISO 8601 timestamp (e.g., "2024-01-15T10:30:00Z")
 * @returns {string} Formatted date (e.g., "January 15, 2024")
 */
function formatDate(isoDate) {
  try {
    const date = new Date(isoDate);
    return new Intl.DateTimeFormat('en-US', {
      year: 'numeric',
      month: 'long',
      day: 'numeric'
    }).format(date);
  } catch (error) {
    console.error('[BillingUtils] Error formatting date:', error);
    return isoDate;
  }
}

/**
 * Capitalize first letter of string
 * Converts "pro" to "Pro", "starter" to "Starter", etc.
 * 
 * @param {string} str - String to capitalize
 * @returns {string} Capitalized string
 */
function capitalize(str) {
  if (!str || typeof str !== 'string') return '';
  return str.charAt(0).toUpperCase() + str.slice(1).toLowerCase();
}

/**
 * Calculate days remaining until expiration
 * Returns positive number for future dates, negative for past dates
 * 
 * @param {string} expiresAt - ISO 8601 timestamp
 * @returns {number} Days remaining (negative if expired)
 */
function getDaysRemaining(expiresAt) {
  try {
    const now = new Date();
    const expiry = new Date(expiresAt);
    
    // Check if date is invalid
    if (isNaN(expiry.getTime())) {
      console.error('[BillingUtils] Invalid date:', expiresAt);
      return 0;
    }
    
    const diffMs = expiry - now;
    const diffDays = Math.ceil(diffMs / (1000 * 60 * 60 * 24));
    return diffDays;
  } catch (error) {
    console.error('[BillingUtils] Error calculating days remaining:', error);
    return 0;
  }
}

/**
 * Format number with commas for thousands separator
 * Converts 1000 to "1,000", 1000000 to "1,000,000", etc.
 * 
 * @param {number} num - Number to format
 * @returns {string} Formatted number with commas
 */
function formatNumber(num) {
  if (typeof num !== 'number' || isNaN(num)) {
    return '0';
  }
  return num.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ',');
}

/**
 * Get status badge class for order status
 * Maps order status to appropriate CSS class
 * 
 * @param {string} status - Order status (paid, pending, failed)
 * @returns {string} CSS class name
 */
function getStatusBadgeClass(status) {
  const statusMap = {
    'paid': 'cyber-badge-success',
    'pending': 'cyber-badge-warning',
    'failed': 'cyber-badge-danger'
  };
  return statusMap[status] || 'cyber-badge-info';
}

/**
 * Get status badge class for subscription status
 * Maps subscription status to appropriate CSS class
 * 
 * @param {string} status - Subscription status (active, expired, cancelled)
 * @returns {string} CSS class name
 */
function getSubscriptionStatusBadgeClass(status) {
  const statusMap = {
    'active': 'cyber-badge-success',
    'expired': 'cyber-badge-danger',
    'cancelled': 'cyber-badge-info'
  };
  return statusMap[status] || 'cyber-badge-info';
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    formatAmount,
    formatDate,
    capitalize,
    getDaysRemaining,
    formatNumber,
    getStatusBadgeClass,
    getSubscriptionStatusBadgeClass
  };
}
