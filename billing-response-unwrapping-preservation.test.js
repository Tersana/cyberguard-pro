/**
 * Preservation Property Tests for Billing Response Unwrapping
 * 
 * **Validates: Bugfix Preservation Properties**
 * 
 * This test suite verifies that the response unwrapping fix preserves all existing functionality:
 * - Property 1: Backward Compatibility - handles both wrapped and unwrapped responses
 * - Property 2: Error Handling Preservation - 422 validation errors and 401 auth errors still work
 * - Property 3: Data Type Invariants - getPlans() always returns array
 * 
 * Test Framework: Vitest
 * Property-Based Testing: fast-check
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import fc from 'fast-check';
import { APIClient, APIError, ValidationError } from './api-client.js';

// Make APIClient available globally for billing-api.js
global.APIClient = APIClient;

// Now import BillingAPI after setting up global
import { BillingAPI } from './billing-api.js';

describe('Preservation Properties: Response Unwrapping', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('Property 1: Backward Compatibility', () => {
    describe('getPlans() - Array Responses', () => {
      it('should handle unwrapped array responses', async () => {
        const unwrappedResponse = [
          { id: 'free', amount_egp: 0, checkout_available: false },
          { id: 'starter', amount_egp: 199, checkout_available: true }
        ];

        vi.spyOn(APIClient.prototype, 'get').mockResolvedValue(unwrappedResponse);

        const plans = await BillingAPI.getPlans();

        expect(Array.isArray(plans)).toBe(true);
        expect(plans).toHaveLength(2);
        expect(plans[0].id).toBe('free');
        expect(plans[1].id).toBe('starter');
      });

      it('should handle wrapped responses with data field', async () => {
        const wrappedResponse = {
          status: 'success',
          data: [
            { id: 'free', amount_egp: 0 },
            { id: 'starter', amount_egp: 199 }
          ]
        };

        vi.spyOn(APIClient.prototype, 'get').mockResolvedValue(wrappedResponse);

        const plans = await BillingAPI.getPlans();

        expect(Array.isArray(plans)).toBe(true);
        expect(plans).toHaveLength(2);
        expect(plans[0].id).toBe('free');
      });

      it('should handle wrapped responses with plans field (alternative)', async () => {
        const wrappedResponse = {
          status: 'success',
          plans: [
            { id: 'free', amount_egp: 0 },
            { id: 'pro', amount_egp: 999 }
          ]
        };

        vi.spyOn(APIClient.prototype, 'get').mockResolvedValue(wrappedResponse);

        const plans = await BillingAPI.getPlans();

        expect(Array.isArray(plans)).toBe(true);
        expect(plans).toHaveLength(2);
      });

      it('should return empty array for missing data', async () => {
        const emptyResponse = { status: 'success' };

        vi.spyOn(APIClient.prototype, 'get').mockResolvedValue(emptyResponse);

        const plans = await BillingAPI.getPlans();

        expect(Array.isArray(plans)).toBe(true);
        expect(plans).toHaveLength(0);
      });

      it('should handle empty wrapped array', async () => {
        const wrappedEmptyResponse = {
          status: 'success',
          data: []
        };

        vi.spyOn(APIClient.prototype, 'get').mockResolvedValue(wrappedEmptyResponse);

        const plans = await BillingAPI.getPlans();

        expect(Array.isArray(plans)).toBe(true);
        expect(plans).toHaveLength(0);
      });
    });

    describe('startCheckout() - Object Responses', () => {
      const validBillingData = {
        first_name: 'John',
        last_name: 'Doe',
        email: 'john@example.com',
        phone_number: '+201234567890',
        city: 'Cairo',
        country: 'EG'
      };

      it('should handle wrapped object responses', async () => {
        const wrappedResponse = {
          status: 'success',
          data: {
            billing_order_id: 123,
            iframe_url: 'https://paymob.com/iframe/abc123'
          }
        };

        vi.spyOn(APIClient.prototype, 'post').mockResolvedValue(wrappedResponse);

        const response = await BillingAPI.startCheckout('pro', validBillingData);

        expect(response.billing_order_id).toBe(123);
        expect(response.iframe_url).toContain('paymob.com');
      });

      it('should handle unwrapped object responses', async () => {
        const unwrappedResponse = {
          billing_order_id: 456,
          iframe_url: 'https://paymob.com/iframe/xyz789'
        };

        vi.spyOn(APIClient.prototype, 'post').mockResolvedValue(unwrappedResponse);

        const response = await BillingAPI.startCheckout('pro', validBillingData);

        expect(response.billing_order_id).toBe(456);
        expect(response.iframe_url).toContain('paymob.com');
      });
    });

    describe('getOrderHistory() - Array Responses', () => {
      it('should handle unwrapped array responses', async () => {
        const unwrappedResponse = [
          { id: 1, plan: 'pro', status: 'paid' },
          { id: 2, plan: 'starter', status: 'pending' }
        ];

        vi.spyOn(APIClient.prototype, 'get').mockResolvedValue(unwrappedResponse);

        const orders = await BillingAPI.getOrderHistory();

        expect(Array.isArray(orders)).toBe(true);
        expect(orders).toHaveLength(2);
      });

      it('should handle wrapped responses with data field', async () => {
        const wrappedResponse = {
          status: 'success',
          data: [
            { id: 1, plan: 'pro', status: 'paid' }
          ]
        };

        vi.spyOn(APIClient.prototype, 'get').mockResolvedValue(wrappedResponse);

        const orders = await BillingAPI.getOrderHistory();

        expect(Array.isArray(orders)).toBe(true);
        expect(orders).toHaveLength(1);
      });

      it('should handle wrapped responses with orders field', async () => {
        const wrappedResponse = {
          status: 'success',
          orders: [
            { id: 1, plan: 'pro', status: 'paid' }
          ]
        };

        vi.spyOn(APIClient.prototype, 'get').mockResolvedValue(wrappedResponse);

        const orders = await BillingAPI.getOrderHistory();

        expect(Array.isArray(orders)).toBe(true);
        expect(orders).toHaveLength(1);
      });

      it('should return empty array for missing data', async () => {
        const emptyResponse = { status: 'success' };

        vi.spyOn(APIClient.prototype, 'get').mockResolvedValue(emptyResponse);

        const orders = await BillingAPI.getOrderHistory();

        expect(Array.isArray(orders)).toBe(true);
        expect(orders).toHaveLength(0);
      });
    });

    describe('getCurrentSubscription() - Object Responses', () => {
      it('should handle wrapped object responses', async () => {
        const wrappedResponse = {
          status: 'success',
          data: {
            plan: 'pro',
            status: 'active',
            limits: { max_projects: 10 }
          }
        };

        vi.spyOn(APIClient.prototype, 'get').mockResolvedValue(wrappedResponse);

        const subscription = await BillingAPI.getCurrentSubscription();

        expect(subscription.plan).toBe('pro');
        expect(subscription.status).toBe('active');
      });

      it('should handle unwrapped object responses', async () => {
        const unwrappedResponse = {
          plan: 'starter',
          status: 'active',
          limits: { max_projects: 5 }
        };

        vi.spyOn(APIClient.prototype, 'get').mockResolvedValue(unwrappedResponse);

        const subscription = await BillingAPI.getCurrentSubscription();

        expect(subscription.plan).toBe('starter');
        expect(subscription.status).toBe('active');
      });
    });

    describe('updateSubscriptionPlan() - Object Responses', () => {
      it('should handle wrapped object responses', async () => {
        const wrappedResponse = {
          status: 'success',
          data: {
            plan: 'pro',
            status: 'active'
          }
        };

        vi.spyOn(APIClient.prototype, 'patch').mockResolvedValue(wrappedResponse);

        const subscription = await BillingAPI.updateSubscriptionPlan('pro');

        expect(subscription.plan).toBe('pro');
        expect(subscription.status).toBe('active');
      });

      it('should handle unwrapped object responses', async () => {
        const unwrappedResponse = {
          plan: 'starter',
          status: 'active'
        };

        vi.spyOn(APIClient.prototype, 'patch').mockResolvedValue(unwrappedResponse);

        const subscription = await BillingAPI.updateSubscriptionPlan('starter');

        expect(subscription.plan).toBe('starter');
        expect(subscription.status).toBe('active');
      });
    });
  });

  describe('Property 2: Error Handling Preservation', () => {
    describe('422 Validation Errors', () => {
      it('should preserve 422 validation error handling in startCheckout', async () => {
        const validationError = new ValidationError([
          { field: 'billing_data.country', message: 'Invalid country code' },
          { field: 'billing_data.phone_number', message: 'Invalid phone format' }
        ]);
        validationError.status = 422;

        vi.spyOn(APIClient.prototype, 'post').mockRejectedValue(validationError);

        await expect(
          BillingAPI.startCheckout('pro', {})
        ).rejects.toThrow(ValidationError);

        await expect(
          BillingAPI.startCheckout('pro', {})
        ).rejects.toThrow('Validation failed');
      });

      it('should preserve validation error structure', async () => {
        const validationError = new ValidationError([
          { field: 'billing_data.email', message: 'Invalid email' }
        ]);
        validationError.status = 422;

        vi.spyOn(APIClient.prototype, 'post').mockRejectedValue(validationError);

        try {
          await BillingAPI.startCheckout('pro', {});
          expect.fail('Should have thrown ValidationError');
        } catch (error) {
          expect(error).toBeInstanceOf(ValidationError);
          expect(error.errors).toHaveLength(1);
          expect(error.errors[0].field).toBe('billing_data.email');
        }
      });
    });

    describe('401 Authentication Errors', () => {
      it('should preserve 401 error handling in getOrderHistory', async () => {
        const authError = new APIError('Unauthorized', 401);

        vi.spyOn(APIClient.prototype, 'get').mockRejectedValue(authError);

        await expect(
          BillingAPI.getOrderHistory()
        ).rejects.toThrow(APIError);

        await expect(
          BillingAPI.getOrderHistory()
        ).rejects.toThrow('Unauthorized');
      });

      it('should preserve 401 error handling in getCurrentSubscription', async () => {
        const authError = new APIError('Unauthorized', 401);

        vi.spyOn(APIClient.prototype, 'get').mockRejectedValue(authError);

        await expect(
          BillingAPI.getCurrentSubscription()
        ).rejects.toThrow(APIError);
      });

      it('should preserve 401 error handling in startCheckout', async () => {
        const authError = new APIError('Unauthorized', 401);

        vi.spyOn(APIClient.prototype, 'post').mockRejectedValue(authError);

        await expect(
          BillingAPI.startCheckout('pro', {})
        ).rejects.toThrow(APIError);
      });

      it('should preserve 401 error handling in updateSubscriptionPlan', async () => {
        const authError = new APIError('Unauthorized', 401);

        vi.spyOn(APIClient.prototype, 'patch').mockRejectedValue(authError);

        await expect(
          BillingAPI.updateSubscriptionPlan('pro')
        ).rejects.toThrow(APIError);
      });
    });

    describe('500+ Server Errors', () => {
      it('should preserve 500 error handling in getPlans', async () => {
        const serverError = new APIError('Server error', 500);

        vi.spyOn(APIClient.prototype, 'get').mockRejectedValue(serverError);

        await expect(
          BillingAPI.getPlans()
        ).rejects.toThrow(APIError);

        await expect(
          BillingAPI.getPlans()
        ).rejects.toThrow('Server error');
      });

      it('should preserve 502 error handling in startCheckout', async () => {
        const gatewayError = new APIError('Bad Gateway', 502);

        vi.spyOn(APIClient.prototype, 'post').mockRejectedValue(gatewayError);

        await expect(
          BillingAPI.startCheckout('pro', {})
        ).rejects.toThrow(APIError);

        await expect(
          BillingAPI.startCheckout('pro', {})
        ).rejects.toThrow('Bad Gateway');
      });
    });

    describe('404 Not Found Errors', () => {
      it('should preserve 404 error handling in getCurrentSubscription', async () => {
        const notFoundError = new APIError('Not Found', 404);

        vi.spyOn(APIClient.prototype, 'get').mockRejectedValue(notFoundError);

        await expect(
          BillingAPI.getCurrentSubscription()
        ).rejects.toThrow(APIError);

        await expect(
          BillingAPI.getCurrentSubscription()
        ).rejects.toThrow('Not Found');
      });
    });
  });

  describe('Property 3: Data Type Invariants', () => {
    describe('getPlans() always returns array', () => {
      it('should return array for wrapped response', async () => {
        const wrappedResponse = {
          status: 'success',
          data: [{ id: 'free' }, { id: 'pro' }]
        };

        vi.spyOn(APIClient.prototype, 'get').mockResolvedValue(wrappedResponse);

        const plans = await BillingAPI.getPlans();

        expect(Array.isArray(plans)).toBe(true);
      });

      it('should return array for unwrapped response', async () => {
        const unwrappedResponse = [{ id: 'free' }, { id: 'pro' }];

        vi.spyOn(APIClient.prototype, 'get').mockResolvedValue(unwrappedResponse);

        const plans = await BillingAPI.getPlans();

        expect(Array.isArray(plans)).toBe(true);
      });

      it('should return array for empty response', async () => {
        const emptyResponse = { status: 'success' };

        vi.spyOn(APIClient.prototype, 'get').mockResolvedValue(emptyResponse);

        const plans = await BillingAPI.getPlans();

        expect(Array.isArray(plans)).toBe(true);
      });

      it('should return array with correct plan structure', async () => {
        const wrappedResponse = {
          status: 'success',
          data: [
            {
              id: 'free',
              name: 'Free Plan',
              amount_egp: 0,
              checkout_available: false,
              limits: { max_projects: 1 }
            }
          ]
        };

        vi.spyOn(APIClient.prototype, 'get').mockResolvedValue(wrappedResponse);

        const plans = await BillingAPI.getPlans();

        expect(Array.isArray(plans)).toBe(true);
        expect(plans[0]).toHaveProperty('id');
        expect(plans[0]).toHaveProperty('amount_egp');
        expect(plans[0]).toHaveProperty('limits');
      });
    });

    describe('getOrderHistory() always returns array', () => {
      it('should return array for wrapped response', async () => {
        const wrappedResponse = {
          status: 'success',
          data: [{ id: 1, plan: 'pro' }]
        };

        vi.spyOn(APIClient.prototype, 'get').mockResolvedValue(wrappedResponse);

        const orders = await BillingAPI.getOrderHistory();

        expect(Array.isArray(orders)).toBe(true);
      });

      it('should return array for unwrapped response', async () => {
        const unwrappedResponse = [{ id: 1, plan: 'pro' }];

        vi.spyOn(APIClient.prototype, 'get').mockResolvedValue(unwrappedResponse);

        const orders = await BillingAPI.getOrderHistory();

        expect(Array.isArray(orders)).toBe(true);
      });

      it('should return array for empty response', async () => {
        const emptyResponse = { status: 'success' };

        vi.spyOn(APIClient.prototype, 'get').mockResolvedValue(emptyResponse);

        const orders = await BillingAPI.getOrderHistory();

        expect(Array.isArray(orders)).toBe(true);
      });
    });

    describe('startCheckout() always returns object with required fields', () => {
      const validBillingData = {
        first_name: 'John',
        last_name: 'Doe',
        email: 'john@example.com',
        phone_number: '+201234567890',
        city: 'Cairo',
        country: 'EG'
      };

      it('should return object with billing_order_id and iframe_url', async () => {
        const wrappedResponse = {
          status: 'success',
          data: {
            billing_order_id: 123,
            iframe_url: 'https://paymob.com/iframe'
          }
        };

        vi.spyOn(APIClient.prototype, 'post').mockResolvedValue(wrappedResponse);

        const response = await BillingAPI.startCheckout('pro', validBillingData);

        expect(response).toHaveProperty('billing_order_id');
        expect(response).toHaveProperty('iframe_url');
        expect(typeof response.billing_order_id).toBe('number');
        expect(typeof response.iframe_url).toBe('string');
      });
    });

    describe('getCurrentSubscription() always returns object', () => {
      it('should return object with subscription fields', async () => {
        const wrappedResponse = {
          status: 'success',
          data: {
            plan: 'pro',
            status: 'active',
            limits: { max_projects: 10 }
          }
        };

        vi.spyOn(APIClient.prototype, 'get').mockResolvedValue(wrappedResponse);

        const subscription = await BillingAPI.getCurrentSubscription();

        expect(typeof subscription).toBe('object');
        expect(subscription).toHaveProperty('plan');
        expect(subscription).toHaveProperty('status');
      });
    });

    describe('updateSubscriptionPlan() always returns object', () => {
      it('should return object with updated subscription', async () => {
        const wrappedResponse = {
          status: 'success',
          data: {
            plan: 'pro',
            status: 'active'
          }
        };

        vi.spyOn(APIClient.prototype, 'patch').mockResolvedValue(wrappedResponse);

        const subscription = await BillingAPI.updateSubscriptionPlan('pro');

        expect(typeof subscription).toBe('object');
        expect(subscription).toHaveProperty('plan');
        expect(subscription).toHaveProperty('status');
      });
    });
  });

  describe('Property-Based Tests with fast-check', () => {
    describe('getPlans() array invariant', () => {
      it('should always return array regardless of response format', async () => {
        await fc.assert(
          fc.asyncProperty(
            fc.oneof(
              // Unwrapped array
              fc.array(fc.record({ id: fc.string(), amount_egp: fc.nat() })),
              // Wrapped with data field
              fc.record({
                status: fc.constant('success'),
                data: fc.array(fc.record({ id: fc.string(), amount_egp: fc.nat() }))
              }),
              // Wrapped with plans field
              fc.record({
                status: fc.constant('success'),
                plans: fc.array(fc.record({ id: fc.string(), amount_egp: fc.nat() }))
              }),
              // Empty object
              fc.record({ status: fc.constant('success') })
            ),
            async (response) => {
              vi.spyOn(APIClient.prototype, 'get').mockResolvedValue(response);
              const plans = await BillingAPI.getPlans();
              return Array.isArray(plans);
            }
          ),
          { numRuns: 50 }
        );
      });
    });

    describe('getOrderHistory() array invariant', () => {
      it('should always return array regardless of response format', async () => {
        await fc.assert(
          fc.asyncProperty(
            fc.oneof(
              // Unwrapped array
              fc.array(fc.record({ id: fc.nat(), plan: fc.string() })),
              // Wrapped with data field
              fc.record({
                status: fc.constant('success'),
                data: fc.array(fc.record({ id: fc.nat(), plan: fc.string() }))
              }),
              // Wrapped with orders field
              fc.record({
                status: fc.constant('success'),
                orders: fc.array(fc.record({ id: fc.nat(), plan: fc.string() }))
              }),
              // Empty object
              fc.record({ status: fc.constant('success') })
            ),
            async (response) => {
              vi.spyOn(APIClient.prototype, 'get').mockResolvedValue(response);
              const orders = await BillingAPI.getOrderHistory();
              return Array.isArray(orders);
            }
          ),
          { numRuns: 50 }
        );
      });
    });

    describe('startCheckout() object invariant', () => {
      it('should always return object with required fields', async () => {
        const validBillingData = {
          first_name: 'John',
          last_name: 'Doe',
          email: 'john@example.com',
          phone_number: '+201234567890',
          city: 'Cairo',
          country: 'EG'
        };

        await fc.assert(
          fc.asyncProperty(
            fc.oneof(
              // Wrapped response
              fc.record({
                status: fc.constant('success'),
                data: fc.record({
                  billing_order_id: fc.nat(),
                  iframe_url: fc.webUrl()
                })
              }),
              // Unwrapped response
              fc.record({
                billing_order_id: fc.nat(),
                iframe_url: fc.webUrl()
              })
            ),
            async (response) => {
              vi.spyOn(APIClient.prototype, 'post').mockResolvedValue(response);
              const result = await BillingAPI.startCheckout('pro', validBillingData);
              return (
                typeof result === 'object' &&
                'billing_order_id' in result &&
                'iframe_url' in result
              );
            }
          ),
          { numRuns: 50 }
        );
      });
    });
  });
});
