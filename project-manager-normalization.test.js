/**
 * Project Manager Normalization Tests
 * Validates: Requirements 13.1, 13.2, 13.3
 * 
 * Tests that ProjectManager correctly uses data normalization
 * for collaborator data handling
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { ProjectManager } from './project-manager.js';
import { normalizeCollaboratorData } from './data-normalizer.js';

describe('ProjectManager - Data Normalization', () => {
  let projectManager;
  let mockApiClient;

  beforeEach(() => {
    // Create mock API client
    mockApiClient = {
      get: vi.fn(),
      post: vi.fn(),
      put: vi.fn(),
      delete: vi.fn()
    };

    projectManager = new ProjectManager(mockApiClient);
  });

  describe('fetchCollaborators', () => {
    it('should normalize collaborator data with job_title field', async () => {
      // Arrange
      const mockCollaborators = [
        {
          id: 1,
          full_name: 'John Doe',
          email: 'john@example.com',
          job_title: 'Security Analyst',
          role: 'collaborator'
        },
        {
          id: 2,
          full_name: 'Jane Smith',
          email: 'jane@example.com',
          job_title: 'Penetration Tester',
          role: 'collaborator'
        }
      ];

      mockApiClient.get.mockResolvedValue({ collaborators: mockCollaborators });

      // Act
      const result = await projectManager.fetchCollaborators(1);

      // Assert
      expect(result).toHaveLength(2);
      expect(result[0]).toHaveProperty('fullName', 'John Doe');
      expect(result[0]).toHaveProperty('jobTitle', 'Security Analyst');
      expect(result[1]).toHaveProperty('fullName', 'Jane Smith');
      expect(result[1]).toHaveProperty('jobTitle', 'Penetration Tester');
    });

    it('should normalize collaborator data with job_tittle field (typo)', async () => {
      // Arrange - Backend returns job_tittle instead of job_title
      const mockCollaborators = [
        {
          id: 1,
          full_name: 'John Doe',
          email: 'john@example.com',
          job_tittle: 'Security Analyst', // Note the typo
          role: 'collaborator'
        }
      ];

      mockApiClient.get.mockResolvedValue({ collaborators: mockCollaborators });

      // Act
      const result = await projectManager.fetchCollaborators(1);

      // Assert
      expect(result).toHaveLength(1);
      expect(result[0]).toHaveProperty('jobTitle', 'Security Analyst');
      expect(result[0]).not.toHaveProperty('job_tittle');
      expect(result[0]).not.toHaveProperty('job_title');
    });

    it('should handle both job_title and job_tittle (prioritize job_title)', async () => {
      // Arrange
      const mockCollaborators = [
        {
          id: 1,
          full_name: 'Test User',
          email: 'test@example.com',
          job_title: 'Correct Title',
          job_tittle: 'Wrong Title',
          role: 'collaborator'
        }
      ];

      mockApiClient.get.mockResolvedValue(mockCollaborators);

      // Act
      const result = await projectManager.fetchCollaborators(1);

      // Assert
      expect(result[0].jobTitle).toBe('Correct Title');
    });

    it('should handle missing job_title and job_tittle fields', async () => {
      // Arrange
      const mockCollaborators = [
        {
          id: 1,
          full_name: 'No Job Title User',
          email: 'nojob@example.com',
          role: 'collaborator'
        }
      ];

      mockApiClient.get.mockResolvedValue(mockCollaborators);

      // Act
      const result = await projectManager.fetchCollaborators(1);

      // Assert
      expect(result[0].jobTitle).toBe('');
    });
  });

  describe('addCollaborator', () => {
    it('should normalize added collaborator data with job_title', async () => {
      // Arrange
      const mockCollaborator = {
        id: 3,
        full_name: 'New Collaborator',
        email: 'new@example.com',
        job_title: 'Junior Analyst',
        role: 'collaborator'
      };

      mockApiClient.post.mockResolvedValue({ collaborator: mockCollaborator });

      // Act
      const result = await projectManager.addCollaborator(1, 3);

      // Assert
      expect(result).toHaveProperty('fullName', 'New Collaborator');
      expect(result).toHaveProperty('jobTitle', 'Junior Analyst');
      expect(result).not.toHaveProperty('job_title');
    });

    it('should normalize added collaborator data with job_tittle (typo)', async () => {
      // Arrange
      const mockCollaborator = {
        id: 3,
        full_name: 'New Collaborator',
        email: 'new@example.com',
        job_tittle: 'Junior Analyst', // Backend typo
        role: 'collaborator'
      };

      mockApiClient.post.mockResolvedValue(mockCollaborator);

      // Act
      const result = await projectManager.addCollaborator(1, 3);

      // Assert
      expect(result).toHaveProperty('jobTitle', 'Junior Analyst');
      expect(result).not.toHaveProperty('job_tittle');
    });
  });

  describe('renderCollaboratorItem', () => {
    it('should render collaborator with normalized data', () => {
      // Arrange
      const normalizedCollaborator = {
        id: 1,
        fullName: 'John Doe',
        email: 'john@example.com',
        jobTitle: 'Security Analyst',
        role: 'collaborator'
      };

      // Act
      const html = projectManager.renderCollaboratorItem(normalizedCollaborator, 1);

      // Assert
      expect(html).toContain('John Doe');
      expect(html).toContain('Security Analyst');
      expect(html).toContain('JD'); // Initials
    });

    it('should use jobTitle for display when available', () => {
      // Arrange
      const normalizedCollaborator = {
        id: 1,
        fullName: 'Jane Smith',
        email: 'jane@example.com',
        jobTitle: 'Penetration Tester',
        role: 'collaborator'
      };

      // Act
      const html = projectManager.renderCollaboratorItem(normalizedCollaborator, 1);

      // Assert
      expect(html).toContain('Penetration Tester');
      // Check that jobTitle is displayed in the role area (not the generic role)
      expect(html).toContain('<p class="text-xs text-slate-400">Penetration Tester</p>');
    });

    it('should fallback to role when jobTitle is empty', () => {
      // Arrange
      const normalizedCollaborator = {
        id: 1,
        fullName: 'No Job User',
        email: 'nojob@example.com',
        jobTitle: '',
        role: 'admin'
      };

      // Act
      const html = projectManager.renderCollaboratorItem(normalizedCollaborator, 1);

      // Assert
      expect(html).toContain('admin'); // Should fallback to role
    });
  });
});
