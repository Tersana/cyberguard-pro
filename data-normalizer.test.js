/**
 * Unit Tests for Data Normalizer Utility
 * Tests Requirements 2.2, 13.1, 13.2, 13.3, 13.4, 13.5
 */

import { describe, it, expect } from 'vitest';
import {
  normalizeUserData,
  validateNormalizedUser,
  prepareUserDataForAPI,
  normalizeProjectData,
  normalizeCollaboratorData
} from './data-normalizer.js';

describe('normalizeUserData', () => {
  it('should normalize user data with job_title field', () => {
    const rawData = {
      id: 1,
      email: 'user@example.com',
      full_name: 'John Doe',
      job_title: 'Security Analyst',
      email_verified: true,
      two_factor_enabled: false,
      role: 'user',
      created_at: '2024-01-01T00:00:00Z',
      last_login: '2024-01-15T10:30:00Z',
      preferences: { theme: 'dark' }
    };

    const normalized = normalizeUserData(rawData);

    expect(normalized).toEqual({
      id: 1,
      email: 'user@example.com',
      name: 'John Doe',
      fullName: 'John Doe',
      jobTitle: 'Security Analyst',
      emailVerified: true,
      twoFactorEnabled: false,
      role: 'user',
      createdAt: '2024-01-01T00:00:00Z',
      lastLogin: '2024-01-15T10:30:00Z',
      preferences: { theme: 'dark' }
    });
  });

  it('should normalize user data with job_tittle field (typo)', () => {
    const rawData = {
      id: 2,
      email: 'analyst@example.com',
      full_name: 'Jane Smith',
      job_tittle: 'Penetration Tester', // Typo in backend
      email_verified: false,
      two_factor_enabled: true
    };

    const normalized = normalizeUserData(rawData);

    expect(normalized.jobTitle).toBe('Penetration Tester');
    expect(normalized.fullName).toBe('Jane Smith');
  });

  it('should prioritize job_title over job_tittle when both exist', () => {
    const rawData = {
      id: 3,
      email: 'user@example.com',
      full_name: 'Test User',
      job_title: 'Correct Title',
      job_tittle: 'Typo Title'
    };

    const normalized = normalizeUserData(rawData);

    expect(normalized.jobTitle).toBe('Correct Title');
  });

  it('should handle missing job_title and job_tittle fields', () => {
    const rawData = {
      id: 4,
      email: 'user@example.com',
      full_name: 'No Title User'
    };

    const normalized = normalizeUserData(rawData);

    expect(normalized.jobTitle).toBe('');
  });

  it('should handle null values for optional fields', () => {
    const rawData = {
      id: 5,
      email: 'user@example.com',
      full_name: 'Minimal User',
      job_title: null,
      preferences: null
    };

    const normalized = normalizeUserData(rawData);

    expect(normalized.jobTitle).toBe('');
    expect(normalized.preferences).toEqual({});
  });

  it('should handle undefined values for optional fields', () => {
    const rawData = {
      id: 6,
      email: 'user@example.com',
      full_name: 'Basic User'
      // No job_title, preferences, etc.
    };

    const normalized = normalizeUserData(rawData);

    expect(normalized.jobTitle).toBe('');
    expect(normalized.emailVerified).toBe(false);
    expect(normalized.twoFactorEnabled).toBe(false);
    expect(normalized.role).toBe('user');
    expect(normalized.preferences).toEqual({});
  });

  it('should handle name field when full_name is missing', () => {
    const rawData = {
      id: 7,
      email: 'user@example.com',
      name: 'Legacy Name Format',
      job_title: 'Analyst'
    };

    const normalized = normalizeUserData(rawData);

    expect(normalized.name).toBe('Legacy Name Format');
    expect(normalized.fullName).toBe('Legacy Name Format');
  });

  it('should prioritize full_name over name when both exist', () => {
    const rawData = {
      id: 8,
      email: 'user@example.com',
      full_name: 'Full Name',
      name: 'Short Name',
      job_title: 'Analyst'
    };

    const normalized = normalizeUserData(rawData);

    expect(normalized.name).toBe('Full Name');
    expect(normalized.fullName).toBe('Full Name');
  });

  it('should return null for null input', () => {
    const normalized = normalizeUserData(null);
    expect(normalized).toBeNull();
  });

  it('should return null for undefined input', () => {
    const normalized = normalizeUserData(undefined);
    expect(normalized).toBeNull();
  });

  it('should return null for non-object input', () => {
    expect(normalizeUserData('string')).toBeNull();
    expect(normalizeUserData(123)).toBeNull();
    expect(normalizeUserData(true)).toBeNull();
  });

  it('should generate ISO timestamps for missing date fields', () => {
    const rawData = {
      id: 9,
      email: 'user@example.com',
      full_name: 'New User'
    };

    const normalized = normalizeUserData(rawData);

    expect(normalized.createdAt).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/);
    expect(normalized.lastLogin).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/);
  });
});

describe('validateNormalizedUser', () => {
  it('should validate a complete normalized user', () => {
    const user = {
      id: 1,
      email: 'user@example.com',
      fullName: 'John Doe',
      jobTitle: 'Analyst',
      emailVerified: true,
      twoFactorEnabled: false,
      role: 'user',
      createdAt: '2024-01-01T00:00:00Z',
      lastLogin: '2024-01-15T10:30:00Z',
      preferences: {}
    };

    expect(validateNormalizedUser(user)).toBe(true);
  });

  it('should reject user with null id', () => {
    const user = {
      id: null,
      email: 'user@example.com',
      fullName: 'John Doe'
    };

    expect(validateNormalizedUser(user)).toBe(false);
  });

  it('should reject user with empty email', () => {
    const user = {
      id: 1,
      email: '',
      fullName: 'John Doe'
    };

    expect(validateNormalizedUser(user)).toBe(false);
  });

  it('should reject user with empty fullName', () => {
    const user = {
      id: 1,
      email: 'user@example.com',
      fullName: ''
    };

    expect(validateNormalizedUser(user)).toBe(false);
  });

  it('should reject null input', () => {
    expect(validateNormalizedUser(null)).toBe(false);
  });

  it('should reject undefined input', () => {
    expect(validateNormalizedUser(undefined)).toBe(false);
  });

  it('should reject non-object input', () => {
    expect(validateNormalizedUser('string')).toBe(false);
    expect(validateNormalizedUser(123)).toBe(false);
  });
});

describe('prepareUserDataForAPI', () => {
  it('should convert internal format to API format', () => {
    const internalData = {
      fullName: 'John Doe',
      email: 'user@example.com',
      jobTitle: 'Security Analyst',
      password: 'SecurePass123!'
    };

    const apiData = prepareUserDataForAPI(internalData);

    expect(apiData).toEqual({
      full_name: 'John Doe',
      email: 'user@example.com',
      job_title: 'Security Analyst',
      password: 'SecurePass123!'
    });
  });

  it('should only include provided fields', () => {
    const internalData = {
      email: 'user@example.com',
      password: 'SecurePass123!'
    };

    const apiData = prepareUserDataForAPI(internalData);

    expect(apiData).toEqual({
      email: 'user@example.com',
      password: 'SecurePass123!'
    });
    expect(apiData.full_name).toBeUndefined();
    expect(apiData.job_title).toBeUndefined();
  });

  it('should use job_title (not job_tittle) for API requests', () => {
    const internalData = {
      jobTitle: 'Analyst'
    };

    const apiData = prepareUserDataForAPI(internalData);

    expect(apiData.job_title).toBe('Analyst');
    expect(apiData.job_tittle).toBeUndefined();
  });

  it('should handle null input', () => {
    const apiData = prepareUserDataForAPI(null);
    expect(apiData).toEqual({});
  });

  it('should handle undefined input', () => {
    const apiData = prepareUserDataForAPI(undefined);
    expect(apiData).toEqual({});
  });

  it('should handle non-object input', () => {
    expect(prepareUserDataForAPI('string')).toEqual({});
    expect(prepareUserDataForAPI(123)).toEqual({});
  });

  it('should include role field when provided', () => {
    const internalData = {
      email: 'admin@example.com',
      role: 'admin'
    };

    const apiData = prepareUserDataForAPI(internalData);

    expect(apiData.role).toBe('admin');
  });
});

describe('normalizeProjectData', () => {
  it('should normalize complete project data', () => {
    const rawData = {
      id: 1,
      name: 'Security Assessment',
      description: 'Q1 2024 Assessment',
      target: 'example.com',
      status: 'active',
      owner_id: 5,
      created_at: '2024-01-01T00:00:00Z',
      updated_at: '2024-01-15T10:30:00Z',
      collaborators: [
        {
          id: 10,
          full_name: 'Jane Doe',
          email: 'jane@example.com',
          role: 'analyst'
        }
      ]
    };

    const normalized = normalizeProjectData(rawData);

    expect(normalized).toEqual({
      id: 1,
      name: 'Security Assessment',
      description: 'Q1 2024 Assessment',
      target: 'example.com',
      status: 'active',
      ownerId: 5,
      createdAt: '2024-01-01T00:00:00Z',
      updatedAt: '2024-01-15T10:30:00Z',
      collaborators: [
        {
          id: 10,
          fullName: 'Jane Doe',
          email: 'jane@example.com',
          role: 'analyst',
          jobTitle: ''
        }
      ]
    });
  });

  it('should handle missing optional fields', () => {
    const rawData = {
      id: 2,
      name: 'Minimal Project'
    };

    const normalized = normalizeProjectData(rawData);

    expect(normalized.description).toBe('');
    expect(normalized.target).toBe('');
    expect(normalized.status).toBe('active');
    expect(normalized.collaborators).toEqual([]);
  });

  it('should return null for invalid input', () => {
    expect(normalizeProjectData(null)).toBeNull();
    expect(normalizeProjectData(undefined)).toBeNull();
    expect(normalizeProjectData('string')).toBeNull();
  });
});

describe('normalizeCollaboratorData', () => {
  it('should normalize collaborator with job_title', () => {
    const rawData = {
      id: 1,
      full_name: 'John Collaborator',
      email: 'john@example.com',
      role: 'analyst',
      job_title: 'Senior Analyst'
    };

    const normalized = normalizeCollaboratorData(rawData);

    expect(normalized).toEqual({
      id: 1,
      fullName: 'John Collaborator',
      email: 'john@example.com',
      role: 'analyst',
      jobTitle: 'Senior Analyst'
    });
  });

  it('should normalize collaborator with job_tittle (typo)', () => {
    const rawData = {
      id: 2,
      full_name: 'Jane Collaborator',
      email: 'jane@example.com',
      job_tittle: 'Junior Analyst'
    };

    const normalized = normalizeCollaboratorData(rawData);

    expect(normalized.jobTitle).toBe('Junior Analyst');
  });

  it('should handle missing job title fields', () => {
    const rawData = {
      id: 3,
      full_name: 'No Title Collaborator',
      email: 'notitle@example.com'
    };

    const normalized = normalizeCollaboratorData(rawData);

    expect(normalized.jobTitle).toBe('');
    expect(normalized.role).toBe('collaborator');
  });

  it('should return null for invalid input', () => {
    expect(normalizeCollaboratorData(null)).toBeNull();
    expect(normalizeCollaboratorData(undefined)).toBeNull();
    expect(normalizeCollaboratorData('string')).toBeNull();
  });
});
