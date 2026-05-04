/**
 * Unit Tests for BillingAPI
 * Tests all BillingAPI methods with mocked APIClient
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { APIClient, APIError, ValidationError } from './api-client.js';

// Make APIClient available globally for billing-api.js
global.APIClient = APIClient;

// Now import BillingAPI after setting up global
import { BillingAPI } from './billing-api.js';

describe('BillingAPI', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('getPlans', () => {
    it('should fetch plans without authentication', async () => {
      const mockPlans = [
        {
          id: 'free',
          name: 'Free Plan',
          amount_egp: 0,
          amount_cents: 0,
          checkout_available: false,
          limits: {
            max_projects: 1,
            max_targets: 5,
            max_scans_per_month: 10
          }
        },
        {
          id: 'pro',
          name: 'Pro Plan',
          amount_egp: 499,
          amount_cents: 49900,
          checkout_available: true,
          limits: {
            max_projects: 10,
            max_targets: 50,
            max_scans_per_month: 1000
          }
        }
      ];

      // Mock APIClient.get
      vi.spyOn(APIClient.prototype, 'get').mockResolvedValue(mockPlans);

      const plans = await BillingAPI.getPlans();

      expect(plans).toEqual(mockPlans);
      expect(APIClient.prototype.get).toHaveBeenCalledWith('/billing/plans');
    });

    it('should throw APIError on API failure', async () => {
      const mockError = new APIError('Server error', 500);
      vi.spyOn(APIClient.prototype, 'get').mockRejectedValue(mockError);

      await expect(BillingAPI.getPlans()).rejects.toThrow(APIError);
      await expect(BillingAPI.getPlans()).rejects.toThrow('Server error');
    });
  });

  describe('startCheckout', () => {
    const validBillingData = {
      first_name: 'John',
      last_name: 'Doe',
      email: 'john@example.com',
      phone_number: '+201234567890',
      city: 'Cairo',
      country: 'EG'
    };

    it('should start checkout with valid data', async () => {
      const mockResponse = {
        status: 'success',
        data: {
          billing_order_id: 123,
          merchant_reference: 'uuid-abc-123',
          paymob_order_id: 98765,
          plan: 'pro',
          amount_cents: 49900,
          currency: 'EGP',
          iframe_url: 'https://accept.paymob.com/api/acceptance/iframes/123456?payment_token=abc123xyz'
        }
      };

      vi.spyOn(APIClient.prototype, 'post').mockResolvedValue(mockResponse);

      const response = await BillingAPI.startCheckout('pro', validBillingData);

      // BillingAPI.startCheckout now returns response.data directly
      expect(response.billing_order_id).toBe(123);
      expect(response.iframe_url).toContain('paymob.com');
      expect(APIClient.prototype.post).toHaveBeenCalledWith('/billing/checkout', {
        plan: 'pro',
        billing_data: validBillingData
      });
    });

    it('should throw ValidationError on 422 response', async () => {
      const mockValidationError = new ValidationError([
        { field: 'billing_data.country', message: 'Country must be a 2-character ISO code' },
        { field: 'billing_data.phone_number', message: 'Phone number must match format +201XXXXXXXXX' }
      ]);
      mockValidationError.status = 422;

      vi.spyOn(APIClient.prototype, 'post').mockRejectedValue(mockValidationError);

      await expect(BillingAPI.startCheckout('pro', validBillingData)).rejects.toThrow(ValidationError);
    });

    it('should throw APIError on 401 response', async () => {
      const mockError = new APIError('Unauthorized', 401);
      vi.spyOn(APIClient.prototype, 'post').mockRejectedValue(mockError);

      await expect(BillingAPI.startCheckout('pro', validBillingData)).rejects.toThrow(APIError);
      await expect(BillingAPI.startCheckout('pro', validBillingData)).rejects.toThrow('Unauthorized');
    });

    it('should throw APIError on 502 response', async () => {
      const mockError = new APIError('Bad Gateway', 502);
      vi.spyOn(APIClient.prototype, 'post').mockRejectedValue(mockError);

      await expect(BillingAPI.startCheckout('pro', validBillingData)).rejects.toThrow(APIError);
    });

    it('should throw APIError on 500+ response', async () => {
      const mockError = new APIError('Server error', 500);
      vi.spyOn(APIClient.prototype, 'post').mockRejectedValue(mockError);

      await expect(BillingAPI.startCheckout('pro', validBillingData)).rejects.toThrow(APIError);
    });
  });

  describe('getOrderHistory', () => {
    it('should fetch order history with authentication', async () => {
      const mockOrders = [
        {
          id: 1,
          plan: 'pro',
          amount_cents: 49900,
          status: 'paid',
          created_at: '2024-01-15T10:30:00Z',
          paymob_transaction_id: 'TXN_123456'
        },
        {
          id: 2,
          plan: 'starter',
          amount_cents: 19900,
          status: 'failed',
          created_at: '2024-01-10T08:00:00Z',
          paymob_transaction_id: null,
          failure_reason: 'Insufficient funds'
        }
      ];

      vi.spyOn(APIClient.prototype, 'get').mockResolvedValue(mockOrders);

      const orders = await BillingAPI.getOrderHistory();

      expect(orders).toEqual(mockOrders);
      expect(orders).toHaveLength(2);
      expect(APIClient.prototype.get).toHaveBeenCalledWith('/billing/orders');
    });

    it('should throw APIError on 401 response', async () => {
      const mockError = new APIError('Unauthorized', 401);
      vi.spyOn(APIClient.prototype, 'get').mockRejectedValue(mockError);

      await expect(BillingAPI.getOrderHistory()).rejects.toThrow(APIError);
    });
  });

  describe('getCurrentSubscription', () => {
    it('should fetch current subscription with authentication', async () => {
      const mockSubscription = {
        id: 789,
        user_id: 456,
        plan: 'pro',
        status: 'active',
        expires_at: '2024-02-15T23:59:59Z',
        limits: {
          max_projects: 10,
          max_targets: 50,
          max_scans_per_month: 1000
        },
        created_at: '2024-01-15T10:35:00Z',
        updated_at: '2024-01-15T10:35:00Z'
      };

      vi.spyOn(APIClient.prototype, 'get').mockResolvedValue(mockSubscription);

      const subscription = await BillingAPI.getCurrentSubscription();

      expect(subscription).toEqual(mockSubscription);
      expect(subscription.status).toBe('active');
      expect(APIClient.prototype.get).toHaveBeenCalledWith('/subscription');
    });

    it('should throw APIError on 404 response (no subscription)', async () => {
      const mockError = new APIError('Not Found', 404);
      vi.spyOn(APIClient.prototype, 'get').mockRejectedValue(mockError);

      await expect(BillingAPI.getCurrentSubscription()).rejects.toThrow(APIError);
    });
  });

  describe('updateSubscriptionPlan', () => {
    it('should update subscription plan', async () => {
      const mockUpdatedSubscription = {
        id: 789,
        user_id: 456,
        plan: 'starter',
        status: 'active',
        expires_at: '2024-02-15T23:59:59Z',
        limits: {
          max_projects: 5,
          max_targets: 20,
          max_scans_per_month: 100
        }
      };

      vi.spyOn(APIClient.prototype, 'patch').mockResolvedValue(mockUpdatedSubscription);

      const subscription = await BillingAPI.updateSubscriptionPlan('starter');

      expect(subscription.plan).toBe('starter');
      expect(APIClient.prototype.patch).toHaveBeenCalledWith('/subscription', {
        plan: 'starter'
      });
    });

    it('should throw APIError on failure', async () => {
      const mockError = new APIError('Server error', 500);
      vi.spyOn(APIClient.prototype, 'patch').mockRejectedValue(mockError);

      await expect(BillingAPI.updateSubscriptionPlan('pro')).rejects.toThrow(APIError);
    });
  });

  describe('pollSubscriptionUntilActive', () => {
    it('should poll until subscription is active', async () => {
      let pollCount = 0;

      // Mock getCurrentSubscription to return active after 3 attempts
      vi.spyOn(BillingAPI, 'getCurrentSubscription').mockImplementation(async () => {
        pollCount++;
        if (pollCount >= 3) {
          return { status: 'active', plan: 'pro' };
        }
        return { status: 'pending', plan: 'pro' };
      });

      const subscription = await BillingAPI.pollSubscriptionUntilActive(100, 5);

      expect(subscription.status).toBe('active');
      expect(pollCount).toBe(3);
    });

    it('should return last response after max attempts', async () => {
      vi.spyOn(BillingAPI, 'getCurrentSubscription').mockResolvedValue({
        status: 'pending',
        plan: 'pro'
      });

      const subscription = await BillingAPI.pollSubscriptionUntilActive(100, 3);

      expect(subscription.status).toBe('pending');
      expect(BillingAPI.getCurrentSubscription).toHaveBeenCalledTimes(4); // 3 attempts + 1 final call
    });

    it('should continue polling on errors', async () => {
      let callCount = 0;

      vi.spyOn(BillingAPI, 'getCurrentSubscription').mockImplementation(async () => {
        callCount++;
        if (callCount < 3) {
          throw new APIError('Server error', 500);
        }
        return { status: 'active', plan: 'pro' };
      });

      const subscription = await BillingAPI.pollSubscriptionUntilActive(100, 5);

      expect(subscription.status).toBe('active');
      expect(callCount).toBe(3);
    });

    it('should return null if all attempts fail', async () => {
      vi.spyOn(BillingAPI, 'getCurrentSubscription').mockRejectedValue(
        new APIError('Server error', 500)
      );

      const subscription = await BillingAPI.pollSubscriptionUntilActive(100, 3);

      expect(subscription).toBeNull();
    });
  });
});
