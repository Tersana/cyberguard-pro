/**
 * Integration Tests for Data Normalizer with Auth System
 * Validates Requirements 2.2, 13.1, 13.2, 13.3, 13.4, 13.5
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { normalizeUserData, prepareUserDataForAPI } from './data-normalizer.js';

describe('Data Normalizer Integration with Auth Flow', () => {
  describe('Registration Flow', () => {
    it('should prepare registration data for API request', () => {
      const formData = {
        fullName: 'John Doe',
        email: 'john@example.com',
        jobTitle: 'Security Analyst',
        password: 'SecurePass123!'
      };

      const apiData = prepareUserDataForAPI(formData);

      expect(apiData).toEqual({
        full_name: 'John Doe',
        email: 'john@example.com',
        job_title: 'Security Analyst',
        password: 'SecurePass123!'
      });
    });

    it('should normalize registration response with job_title', () => {
      const apiResponse = {
        id: 1,
        email: 'john@example.com',
        full_name: 'John Doe',
        job_title: 'Security Analyst',
        email_verified: false,
        two_factor_enabled: false,
        role: 'user',
        created_at: '2024-01-01T00:00:00Z'
      };

      const normalized = normalizeUserData(apiResponse);

      expect(normalized.id).toBe(1);
      expect(normalized.email).toBe('john@example.com');
      expect(normalized.fullName).toBe('John Doe');
      expect(normalized.jobTitle).toBe('Security Analyst');
      expect(normalized.emailVerified).toBe(false);
      expect(normalized.twoFactorEnabled).toBe(false);
    });

    it('should normalize registration response with job_tittle (typo)', () => {
      const apiResponse = {
        id: 2,
        email: 'jane@example.com',
        full_name: 'Jane Smith',
        job_tittle: 'Penetration Tester', // Backend typo
        email_verified: false,
        two_factor_enabled: false
      };

      const normalized = normalizeUserData(apiResponse);

      expect(normalized.jobTitle).toBe('Penetration Tester');
      expect(normalized.fullName).toBe('Jane Smith');
    });
  });

  describe('Login Flow', () => {
    it('should normalize login response with complete user data', () => {
      const apiResponse = {
        id: 5,
        email: 'analyst@example.com',
        full_name: 'Security Analyst',
        job_title: 'Senior Analyst',
        email_verified: true,
        two_factor_enabled: true,
        role: 'user',
        created_at: '2023-06-15T10:00:00Z',
        last_login: '2024-01-15T14:30:00Z',
        preferences: {
          theme: 'dark',
          notifications: true
        }
      };

      const normalized = normalizeUserData(apiResponse);

      expect(normalized).toEqual({
        id: 5,
        email: 'analyst@example.com',
        name: 'Security Analyst',
        fullName: 'Security Analyst',
        jobTitle: 'Senior Analyst',
        emailVerified: true,
        twoFactorEnabled: true,
        role: 'user',
        createdAt: '2023-06-15T10:00:00Z',
        lastLogin: '2024-01-15T14:30:00Z',
        preferences: {
          theme: 'dark',
          notifications: true
        }
      });
    });

    it('should handle login response with missing optional fields', () => {
      const apiResponse = {
        id: 6,
        email: 'minimal@example.com',
        full_name: 'Minimal User'
      };

      const normalized = normalizeUserData(apiResponse);

      expect(normalized.jobTitle).toBe('');
      expect(normalized.emailVerified).toBe(false);
      expect(normalized.twoFactorEnabled).toBe(false);
      expect(normalized.role).toBe('user');
      expect(normalized.preferences).toEqual({});
    });
  });

  describe('Session Restoration Flow', () => {
    it('should normalize user profile from /auth/me endpoint', () => {
      const profileResponse = {
        id: 10,
        email: 'restored@example.com',
        full_name: 'Restored User',
        job_title: 'Security Engineer',
        role: 'admin',
        created_at: '2023-01-01T00:00:00Z',
        last_login: '2024-01-15T09:00:00Z'
      };

      const normalized = normalizeUserData(profileResponse);

      expect(normalized.id).toBe(10);
      expect(normalized.fullName).toBe('Restored User');
      expect(normalized.jobTitle).toBe('Security Engineer');
      expect(normalized.role).toBe('admin');
    });

    it('should handle session status merge with user profile', () => {
      const profileResponse = {
        id: 11,
        email: 'user@example.com',
        full_name: 'Test User',
        job_title: 'Analyst'
      };

      const sessionStatus = {
        email_verified: true,
        two_factor_enabled: true
      };

      const normalizedProfile = normalizeUserData(profileResponse);
      const mergedUser = {
        ...normalizedProfile,
        emailVerified: sessionStatus.email_verified,
        twoFactorEnabled: sessionStatus.two_factor_enabled
      };

      expect(mergedUser.emailVerified).toBe(true);
      expect(mergedUser.twoFactorEnabled).toBe(true);
      expect(mergedUser.jobTitle).toBe('Analyst');
    });
  });

  describe('2FA Flow', () => {
    it('should normalize user data after 2FA verification', () => {
      const twoFAResponse = {
        id: 15,
        email: '2fa@example.com',
        full_name: '2FA User',
        job_tittle: 'Security Specialist', // Typo in backend
        email_verified: true,
        two_factor_enabled: true
      };

      const normalized = normalizeUserData(twoFAResponse);

      expect(normalized.jobTitle).toBe('Security Specialist');
      expect(normalized.twoFactorEnabled).toBe(true);
    });
  });

  describe('Edge Cases', () => {
    it('should handle both job_title and job_tittle present (prioritize job_title)', () => {
      const apiResponse = {
        id: 20,
        email: 'edge@example.com',
        full_name: 'Edge Case User',
        job_title: 'Correct Title',
        job_tittle: 'Wrong Title'
      };

      const normalized = normalizeUserData(apiResponse);

      expect(normalized.jobTitle).toBe('Correct Title');
    });

    it('should handle empty string job_title', () => {
      const apiResponse = {
        id: 21,
        email: 'empty@example.com',
        full_name: 'Empty Job User',
        job_title: ''
      };

      const normalized = normalizeUserData(apiResponse);

      expect(normalized.jobTitle).toBe('');
    });

    it('should handle null job_title and job_tittle', () => {
      const apiResponse = {
        id: 22,
        email: 'null@example.com',
        full_name: 'Null Job User',
        job_title: null,
        job_tittle: null
      };

      const normalized = normalizeUserData(apiResponse);

      expect(normalized.jobTitle).toBe('');
    });

    it('should handle legacy name field instead of full_name', () => {
      const apiResponse = {
        id: 23,
        email: 'legacy@example.com',
        name: 'Legacy Name',
        job_title: 'Analyst'
      };

      const normalized = normalizeUserData(apiResponse);

      expect(normalized.name).toBe('Legacy Name');
      expect(normalized.fullName).toBe('Legacy Name');
    });
  });

  describe('Round-trip Conversion', () => {
    it('should maintain data integrity through prepare -> normalize cycle', () => {
      const internalData = {
        fullName: 'Round Trip User',
        email: 'roundtrip@example.com',
        jobTitle: 'Test Engineer',
        password: 'SecurePass123!'
      };

      // Prepare for API
      const apiData = prepareUserDataForAPI(internalData);

      // Simulate API response (without password)
      const apiResponse = {
        id: 100,
        email: apiData.email,
        full_name: apiData.full_name,
        job_title: apiData.job_title,
        email_verified: false,
        two_factor_enabled: false
      };

      // Normalize response
      const normalized = normalizeUserData(apiResponse);

      expect(normalized.fullName).toBe(internalData.fullName);
      expect(normalized.email).toBe(internalData.email);
      expect(normalized.jobTitle).toBe(internalData.jobTitle);
    });
  });
});
