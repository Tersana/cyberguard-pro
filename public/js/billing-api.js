/**
 * Billing API Service Layer
 * Centralized API communication for billing and subscription operations
 * 
 * Dependencies:
 * - APIClient from api-client.js
 * - ErrorHandler from error-handler.js
 */

/**
 * BillingAPI Class
 * Handles all billing-related API communication
 */
class BillingAPI {
  /**
   * Get available subscription plans
   * No authentication required
   * 
   * @returns {Promise<Array>} Array of plan objects
   * @throws {APIError} On API failure
   * 
   * Requirements: 1.1, 1.8, 1.9
   */
  static async getPlans() {
    try {
      const apiClient = new APIClient();
      // PUBLIC endpoint — must NOT send Authorization header.
      // skipAuth: true ensures no JWT is attached even if one exists in
      // localStorage; an expired/invalid token would otherwise cause a 401
      // that bubbles up as "Failed to Load Plans".
      const response = await apiClient.get('/billing/plans', { skipAuth: true });

      // Log raw response to aid debugging
      console.log('[BillingAPI] Raw plans response:', response);

      // Handle new API response format containing user_plans and organization_plans
      if (response && response.data && (response.data.user_plans || response.data.organization_plans)) {
        console.log('[BillingAPI] Parsed new format plans:', response.data);
        return response.data;
      }

      // Handle all known API response shapes:
      //   Shape 1: raw array → [{...}, ...]
      //   Shape 2: { status, data: [{...}] }       (data IS the array)
      //   Shape 3: { status, data: { currency, plans: [{...}] } }  ← ACTUAL API
      //   Shape 4: { currency, plans: [{...}] }
      //   Shape 5: { status, plans: [{...}] }
      let plans;
      if (Array.isArray(response)) {
        plans = response;
      } else if (Array.isArray(response.data)) {
        // data is directly the array
        plans = response.data;
      } else if (response.data && Array.isArray(response.data.plans)) {
        // data is an object with a nested plans array (actual API shape)
        plans = response.data.plans;
      } else if (Array.isArray(response.plans)) {
        plans = response.plans;
      } else if (response.data && typeof response.data === 'object') {
        // Last resort: look inside data object for any array value
        const arrayVal = Object.values(response.data).find(v => Array.isArray(v));
        plans = arrayVal || [];
      } else {
        plans = [];
      }

      const normalized = {
        currency: 'EGP',
        user_plans: plans,
        organization_plans: []
      };
      console.log('[BillingAPI] Parsed plans:', normalized);
      return normalized;
    } catch (error) {
      console.error('[BillingAPI] Error in getPlans:', {
        error: error,
        timestamp: new Date().toISOString()
      });
      throw error;
    }
  }

  /**
   * Start checkout process and get Paymob iframe URL
   * Requires JWT authentication
   * 
   * @param {string} plan - Plan ID (free, starter, pro)
   * @param {Object} billingData - Customer billing information
   * @param {string} billingData.first_name - Customer first name
   * @param {string} billingData.last_name - Customer last name
   * @param {string} billingData.email - Customer email
   * @param {string} billingData.phone_number - Phone number (format: +201XXXXXXXXX)
   * @param {string} billingData.city - City name
   * @param {string} billingData.country - ISO 3166-1 alpha-2 code (e.g., 'EG')
   * @param {string} [billingData.street] - Street address (optional)
   * @param {string} [billingData.building] - Building number (optional)
   * @param {string} [billingData.floor] - Floor number (optional)
   * @param {string} [billingData.apartment] - Apartment number (optional)
   * @param {string} [billingData.postal_code] - Postal/ZIP code (optional)
   * 
   * @returns {Promise<Object>} Response data containing billing_order_id, iframe_url, etc.
   * @throws {ValidationError} On validation failure (422)
   * @throws {APIError} On API failure
   * 
   * Requirements: 1.2, 1.7, 1.8, 1.9
   */
  static async startCheckout(plan, billingData) {
    try {
      const apiClient = new APIClient();
      const response = await apiClient.post('/billing/checkout', {
        plan: plan,
        billing_data: billingData
      });
      
      // Extract data from wrapped response
      // API returns: {status: 'success', data: {billing_order_id, iframe_url, ...}}
      return response.data || response;
    } catch (error) {
      console.error('[BillingAPI] Error in startCheckout:', {
        error: error,
        plan: plan,
        timestamp: new Date().toISOString()
      });
      throw error;
    }
  }

  /**
   * Get billing order history
   * Requires JWT authentication
   * 
   * @returns {Promise<Array>} Array of billing order objects
   * @throws {APIError} On API failure
   * 
   * Requirements: 1.3, 1.7, 1.8, 1.9
   */
  static async getOrderHistory() {
    try {
      const apiClient = new APIClient();
      const response = await apiClient.get('/billing/orders');
      
      let orders = [];
      if (Array.isArray(response)) {
        orders = response;
      } else if (response) {
        const data = response.data || response;
        if (Array.isArray(data)) {
          orders = data;
        } else if (data && Array.isArray(data.orders)) {
          orders = data.orders;
        } else if (Array.isArray(response.orders)) {
          orders = response.orders;
        } else if (data && typeof data === 'object') {
          const arrayVal = Object.values(data).find(v => Array.isArray(v));
          orders = arrayVal || [];
        }
      }
      
      return orders;
    } catch (error) {
      console.error('[BillingAPI] Error in getOrderHistory:', {
        error: error,
        timestamp: new Date().toISOString()
      });
      throw error;
    }
  }

  /**
   * Get current subscription details
   * Requires JWT authentication
   * 
   * @returns {Promise<Object>} Subscription object
   * @throws {APIError} On API failure (404 if no subscription)
   * 
   * Requirements: 1.4, 1.7, 1.8, 1.9
   */
  static async getCurrentSubscription() {
    try {
      const apiClient = new APIClient();
      const response = await apiClient.get('/subscription');
      
      // Extract data from wrapped response
      // API returns: {status: 'success', data: {plan, status, limits, ...}}
      return response.data || response;
    } catch (error) {
      console.error('[BillingAPI] Error in getCurrentSubscription:', {
        error: error,
        timestamp: new Date().toISOString()
      });
      throw error;
    }
  }

  /**
   * Update subscription plan (admin/dev only)
   * 
   * WARNING: This bypasses Paymob payment gateway. Only use for admin overrides,
   * downgrades, or dev testing. For paid upgrades, use POST /api/billing/checkout
   * 
   * Requires JWT authentication
   * 
   * @param {string} plan - Plan ID (free, starter, pro)
   * @returns {Promise<Object>} Updated subscription object
   * @throws {APIError} On API failure
   * 
   * Requirements: 1.5, 1.7, 1.8, 1.9
   */
  static async updateSubscriptionPlan(plan) {
    try {
      const apiClient = new APIClient();
      const response = await apiClient.patch('/subscription', {
        plan: plan
      });
      
      // Extract data from wrapped response
      // API returns: {status: 'success', data: {plan, status, limits, ...}}
      return response.data || response;
    } catch (error) {
      console.error('[BillingAPI] Error in updateSubscriptionPlan:', {
        error: error,
        plan: plan,
        timestamp: new Date().toISOString()
      });
      throw error;
    }
  }

  /**
   * Poll subscription status until active
   * Helper method for subscription activation confirmation
   * 
   * @param {number} interval - Polling interval in ms (default: 3000)
   * @param {number} maxAttempts - Maximum polling attempts (default: 5)
   * @returns {Promise<Object>} Subscription object when active or last response
   * 
   * Requirements: 1.6, 1.8, 1.9
   */
  static async pollSubscriptionUntilActive(interval = 3000, maxAttempts = 5, expectedPlan = null) {
    const targetPlan = expectedPlan || localStorage.getItem('pending_billing_plan');

    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      try {
        const subscription = await this.getCurrentSubscription();
        
        // If we are waiting for a specific paid plan, ensure it is active and matching.
        // Otherwise, if no specific plan is defined, accept any active non-free plan.
        const isTargetPlanActive = targetPlan
          ? (subscription.plan === targetPlan && subscription.status === 'active')
          : (subscription.status === 'active' && subscription.plan !== 'free');
        
        if (isTargetPlanActive) {
          console.log('[BillingAPI] Subscription activated successfully:', {
            plan: subscription.plan,
            attempt: attempt,
            timestamp: new Date().toISOString()
          });
          return subscription;
        }
        
        console.log('[BillingAPI] Polling subscription status:', {
          status: subscription.status,
          plan: subscription.plan,
          waitingFor: targetPlan,
          attempt: attempt,
          maxAttempts: maxAttempts,
          timestamp: new Date().toISOString()
        });
      } catch (error) {
        // Continue polling even on error
        console.warn(`[BillingAPI] Polling attempt ${attempt} failed:`, error);
      }
      
      // Wait before next attempt (unless it's the last attempt)
      if (attempt < maxAttempts) {
        await new Promise(resolve => setTimeout(resolve, interval));
      }
    }
    
    // Return last response or null if all attempts failed
    try {
      const lastResponse = await this.getCurrentSubscription();
      console.warn('[BillingAPI] Polling timeout - subscription not active:', {
        status: lastResponse.status,
        maxAttempts: maxAttempts,
        timestamp: new Date().toISOString()
      });
      return lastResponse;
    } catch (error) {
      console.error('[BillingAPI] Polling failed - could not get subscription:', error);
      return null;
    }
  }
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    BillingAPI
  };
}
