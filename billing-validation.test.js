/**
 * Unit Tests for Billing Form Validation
 * Tests validation logic for checkout form
 */

import { describe, it, expect } from 'vitest';

// Validation rules (copied from pricing.html for testing)
const validationRules = {
    notEmpty: (value) => value.trim().length > 0,
    email: (value) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value),
    phone: (value) => /^\+201\d{9}$/.test(value),
    isoCountry: (value) => /^[A-Z]{2}$/i.test(value)
};

// Validation function (copied from pricing.html for testing)
function validateBillingData(data) {
    const errors = {};

    // Required field validation
    if (!validationRules.notEmpty(data.first_name || '')) {
        errors.first_name = 'First name is required';
    }

    if (!validationRules.notEmpty(data.last_name || '')) {
        errors.last_name = 'Last name is required';
    }

    // Email validation
    if (!validationRules.notEmpty(data.email || '')) {
        errors.email = 'Email is required';
    } else if (!validationRules.email(data.email)) {
        errors.email = 'Please enter a valid email address';
    }

    // Phone validation
    if (!validationRules.notEmpty(data.phone_number || '')) {
        errors.phone_number = 'Phone number is required';
    } else if (!validationRules.phone(data.phone_number)) {
        errors.phone_number = 'Phone number must match format +201XXXXXXXXX';
    }

    // City validation
    if (!validationRules.notEmpty(data.city || '')) {
        errors.city = 'City is required';
    }

    // Country validation
    if (!validationRules.notEmpty(data.country || '')) {
        errors.country = 'Country is required';
    } else if (!validationRules.isoCountry(data.country)) {
        errors.country = 'Country must be a 2-character ISO code (e.g., EG)';
    }

    return {
        isValid: Object.keys(errors).length === 0,
        errors: errors
    };
}

describe('Billing Form Validation', () => {
    describe('validateBillingData', () => {
        it('should validate required fields', () => {
            const data = {
                first_name: '',
                last_name: 'Doe',
                email: 'john@example.com',
                phone_number: '+201234567890',
                city: 'Cairo',
                country: 'EG'
            };

            const result = validateBillingData(data);

            expect(result.isValid).toBe(false);
            expect(result.errors.first_name).toBe('First name is required');
        });

        it('should validate all empty required fields', () => {
            const data = {
                first_name: '',
                last_name: '',
                email: '',
                phone_number: '',
                city: '',
                country: ''
            };

            const result = validateBillingData(data);

            expect(result.isValid).toBe(false);
            expect(result.errors.first_name).toBeDefined();
            expect(result.errors.last_name).toBeDefined();
            expect(result.errors.email).toBeDefined();
            expect(result.errors.phone_number).toBeDefined();
            expect(result.errors.city).toBeDefined();
            expect(result.errors.country).toBeDefined();
        });

        it('should validate email format', () => {
            const data = {
                first_name: 'John',
                last_name: 'Doe',
                email: 'invalid-email',
                phone_number: '+201234567890',
                city: 'Cairo',
                country: 'EG'
            };

            const result = validateBillingData(data);

            expect(result.isValid).toBe(false);
            expect(result.errors.email).toContain('valid email');
        });

        it('should accept valid email formats', () => {
            const validEmails = [
                'john@example.com',
                'john.doe@example.com',
                'john+tag@example.co.uk',
                'john_doe@example-domain.com'
            ];

            validEmails.forEach(email => {
                const data = {
                    first_name: 'John',
                    last_name: 'Doe',
                    email: email,
                    phone_number: '+201234567890',
                    city: 'Cairo',
                    country: 'EG'
                };

                const result = validateBillingData(data);
                expect(result.isValid).toBe(true);
            });
        });

        it('should validate phone number format (+201XXXXXXXXX)', () => {
            const invalidPhones = [
                '1234567890',           // Missing +20 prefix
                '+20123456789',         // Too short
                '+2012345678901',       // Too long
                '+211234567890',        // Wrong country code
                'phone',                // Not a number
                '+20 123 456 7890'      // Contains spaces
            ];

            invalidPhones.forEach(phone => {
                const data = {
                    first_name: 'John',
                    last_name: 'Doe',
                    email: 'john@example.com',
                    phone_number: phone,
                    city: 'Cairo',
                    country: 'EG'
                };

                const result = validateBillingData(data);
                expect(result.isValid).toBe(false);
                expect(result.errors.phone_number).toContain('+201');
            });
        });

        it('should accept valid phone number format', () => {
            const validPhones = [
                '+201234567890',
                '+201000000000',
                '+201999999999'
            ];

            validPhones.forEach(phone => {
                const data = {
                    first_name: 'John',
                    last_name: 'Doe',
                    email: 'john@example.com',
                    phone_number: phone,
                    city: 'Cairo',
                    country: 'EG'
                };

                const result = validateBillingData(data);
                expect(result.isValid).toBe(true);
            });
        });

        it('should validate country ISO code (exactly 2 characters)', () => {
            const invalidCountries = [
                'Egypt',    // Full name
                'E',        // Too short
                'EGY',      // Too long
                '12',       // Numbers
                'E1'        // Mixed
            ];

            invalidCountries.forEach(country => {
                const data = {
                    first_name: 'John',
                    last_name: 'Doe',
                    email: 'john@example.com',
                    phone_number: '+201234567890',
                    city: 'Cairo',
                    country: country
                };

                const result = validateBillingData(data);
                expect(result.isValid).toBe(false);
                expect(result.errors.country).toContain('2-character');
            });
        });

        it('should accept valid country ISO codes', () => {
            const validCountries = ['EG', 'US', 'GB', 'FR', 'DE', 'eg', 'us'];

            validCountries.forEach(country => {
                const data = {
                    first_name: 'John',
                    last_name: 'Doe',
                    email: 'john@example.com',
                    phone_number: '+201234567890',
                    city: 'Cairo',
                    country: country
                };

                const result = validateBillingData(data);
                expect(result.isValid).toBe(true);
            });
        });

        it('should pass validation with valid data', () => {
            const data = {
                first_name: 'John',
                last_name: 'Doe',
                email: 'john@example.com',
                phone_number: '+201234567890',
                city: 'Cairo',
                country: 'EG'
            };

            const result = validateBillingData(data);

            expect(result.isValid).toBe(true);
            expect(result.errors).toEqual({});
        });

        it('should handle optional fields', () => {
            const data = {
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

            const result = validateBillingData(data);

            expect(result.isValid).toBe(true);
            expect(result.errors).toEqual({});
        });

        it('should trim whitespace from required fields', () => {
            const data = {
                first_name: '   ',
                last_name: '  Doe  ',
                email: 'john@example.com',
                phone_number: '+201234567890',
                city: 'Cairo',
                country: 'EG'
            };

            const result = validateBillingData(data);

            expect(result.isValid).toBe(false);
            expect(result.errors.first_name).toBe('First name is required');
        });
    });

    describe('Validation Rules', () => {
        describe('notEmpty', () => {
            it('should return false for empty string', () => {
                expect(validationRules.notEmpty('')).toBe(false);
            });

            it('should return false for whitespace only', () => {
                expect(validationRules.notEmpty('   ')).toBe(false);
            });

            it('should return true for non-empty string', () => {
                expect(validationRules.notEmpty('test')).toBe(true);
            });
        });

        describe('email', () => {
            it('should validate email format', () => {
                expect(validationRules.email('john@example.com')).toBe(true);
                expect(validationRules.email('invalid')).toBe(false);
                expect(validationRules.email('invalid@')).toBe(false);
                expect(validationRules.email('@example.com')).toBe(false);
                expect(validationRules.email('invalid@example')).toBe(false);
            });
        });

        describe('phone', () => {
            it('should validate Egyptian phone format', () => {
                expect(validationRules.phone('+201234567890')).toBe(true);
                expect(validationRules.phone('1234567890')).toBe(false);
                expect(validationRules.phone('+20123456789')).toBe(false);
                expect(validationRules.phone('+211234567890')).toBe(false);
            });
        });

        describe('isoCountry', () => {
            it('should validate 2-character ISO code', () => {
                expect(validationRules.isoCountry('EG')).toBe(true);
                expect(validationRules.isoCountry('eg')).toBe(true);
                expect(validationRules.isoCountry('US')).toBe(true);
                expect(validationRules.isoCountry('E')).toBe(false);
                expect(validationRules.isoCountry('EGY')).toBe(false);
                expect(validationRules.isoCountry('12')).toBe(false);
            });
        });
    });
});
