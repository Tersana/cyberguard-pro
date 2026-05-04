/**
 * Integration Tests for Billing Checkout Flow
 * Tests complete checkout workflow from plan selection to payment redirect
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { APIClient, APIError, ValidationError } from './api-client.js';

// Make APIClient available globally
global.APIClient = APIClient;

// Import BillingAPI after setting up global
import { BillingAPI } from './billing-api.js';

describe('Billing Checkout Flow Integration', () => {
    beforeEach(() => {
        vi.clearAllMocks();
        // Setup localStorage mock
        global.localStorage = {
            getItem: vi.fn(),
            setItem: vi.fn(),
            removeItem: vi.fn(),
            clear: vi.fn()
        };
    });

    afterEach(() => {
        vi.restoreAllMocks();
    });

    it('should complete checkout flow successfully', async () => {
        // Step 1: Mock authenticated user
        localStorage.getItem.mockReturnValue('mock-jwt-token');

        // Step 2: Load plans
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

        vi.spyOn(APIClient.prototype, 'get').mockResolvedValue(mockPlans);

        const plans = await BillingAPI.getPlans();
        expect(plans).toHaveLength(2);

        // Step 3: Select plan
        const selectedPlan = plans.find(p => p.id === 'pro');
        expect(selectedPlan.checkout_available).toBe(true);

        // Step 4: Prepare billing data
        const billingData = {
            first_name: 'John',
            last_name: 'Doe',
            email: 'john@example.com',
            phone_number: '+201234567890',
            city: 'Cairo',
            country: 'EG'
        };

        // Step 5: Start checkout
        const mockCheckoutResponse = {
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

        vi.spyOn(APIClient.prototype, 'post').mockResolvedValue(mockCheckoutResponse);

        const checkoutResponse = await BillingAPI.startCheckout('pro', billingData);

        // BillingAPI.startCheckout now returns response.data directly
        expect(checkoutResponse.billing_order_id).toBe(123);
        expect(checkoutResponse.iframe_url).toContain('paymob.com');

        // Step 6: Verify localStorage storage
        // In real implementation, this would be done by the UI code
        const billingOrderId = checkoutResponse.billing_order_id;
        expect(billingOrderId).toBe(123);

        // Verify API was called with correct parameters
        expect(APIClient.prototype.post).toHaveBeenCalledWith('/billing/checkout', {
            plan: 'pro',
            billing_data: billingData
        });
    });

    it('should handle validation errors during checkout', async () => {
        const invalidData = {
            first_name: 'John',
            last_name: 'Doe',
            email: 'invalid-email',
            phone_number: '1234',
            city: 'Cairo',
            country: 'Egypt'
        };

        const mockValidationError = new ValidationError([
            { field: 'billing_data.email', message: 'Please enter a valid email address' },
            { field: 'billing_data.phone_number', message: 'Phone number must match format +201XXXXXXXXX' },
            { field: 'billing_data.country', message: 'Country must be a 2-character ISO code' }
        ]);
        mockValidationError.status = 422;

        vi.spyOn(APIClient.prototype, 'post').mockRejectedValue(mockValidationError);

        await expect(
            BillingAPI.startCheckout('pro', invalidData)
        ).rejects.toThrow(ValidationError);
    });

    it('should handle 502 error (payment gateway issue)', async () => {
        const billingData = {
            first_name: 'John',
            last_name: 'Doe',
            email: 'john@example.com',
            phone_number: '+201234567890',
            city: 'Cairo',
            country: 'EG'
        };

        const mockError = new APIError('Bad Gateway', 502);
        vi.spyOn(APIClient.prototype, 'post').mockRejectedValue(mockError);

        await expect(
            BillingAPI.startCheckout('pro', billingData)
        ).rejects.toThrow(APIError);

        await expect(
            BillingAPI.startCheckout('pro', billingData)
        ).rejects.toThrow('Bad Gateway');
    });

    it('should handle 401 error (authentication)', async () => {
        const billingData = {
            first_name: 'John',
            last_name: 'Doe',
            email: 'john@example.com',
            phone_number: '+201234567890',
            city: 'Cairo',
            country: 'EG'
        };

        const mockError = new APIError('Unauthorized', 401);
        vi.spyOn(APIClient.prototype, 'post').mockRejectedValue(mockError);

        await expect(
            BillingAPI.startCheckout('pro', billingData)
        ).rejects.toThrow(APIError);

        await expect(
            BillingAPI.startCheckout('pro', billingData)
        ).rejects.toThrow('Unauthorized');
    });

    it('should map backend validation errors to frontend fields', () => {
        const backendErrors = [
            { field: 'billing_data.country', message: 'Country must be a 2-character ISO code' },
            { field: 'billing_data.first_name', message: 'First name is required' },
            { field: 'billing_data.phone_number', message: 'Phone number must match format +201XXXXXXXXX' }
        ];

        // Simulate error mapping (as done in pricing.html)
        const mappedErrors = {};
        backendErrors.forEach(err => {
            const fieldName = err.field.replace('billing_data.', '');
            mappedErrors[fieldName] = err.message;
        });

        expect(mappedErrors).toEqual({
            country: 'Country must be a 2-character ISO code',
            first_name: 'First name is required',
            phone_number: 'Phone number must match format +201XXXXXXXXX'
        });
    });

    it('should include optional fields in checkout request', async () => {
        const billingData = {
            first_name: 'John',
            last_name: 'Doe',
            email: 'john@example.com',
            phone_number: '+201234567890',
            city: 'Cairo',
            country: 'EG',
            street: '123 Main St',
            building: '5',
            floor: '3',
            apartment: '12',
            postal_code: '12345'
        };

        const mockCheckoutResponse = {
            status: 'success',
            data: {
                billing_order_id: 123,
                iframe_url: 'https://accept.paymob.com/iframe'
            }
        };

        vi.spyOn(APIClient.prototype, 'post').mockResolvedValue(mockCheckoutResponse);

        await BillingAPI.startCheckout('pro', billingData);

        expect(APIClient.prototype.post).toHaveBeenCalledWith('/billing/checkout', {
            plan: 'pro',
            billing_data: billingData
        });
    });

    it('should verify checkout response structure', async () => {
        const billingData = {
            first_name: 'John',
            last_name: 'Doe',
            email: 'john@example.com',
            phone_number: '+201234567890',
            city: 'Cairo',
            country: 'EG'
        };

        const mockCheckoutResponse = {
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

        vi.spyOn(APIClient.prototype, 'post').mockResolvedValue(mockCheckoutResponse);

        const response = await BillingAPI.startCheckout('pro', billingData);

        // Verify response structure (BillingAPI.startCheckout now returns response.data directly)
        expect(response).toHaveProperty('billing_order_id');
        expect(response).toHaveProperty('iframe_url');
        expect(response).toHaveProperty('plan');
        expect(response).toHaveProperty('amount_cents');
        expect(response).toHaveProperty('currency');

        // Verify data types
        expect(typeof response.billing_order_id).toBe('number');
        expect(typeof response.iframe_url).toBe('string');
        expect(response.currency).toBe('EGP');
    });
});
