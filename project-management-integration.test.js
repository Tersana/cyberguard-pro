/**
 * Integration Tests for Complete Project Management Flow
 * Task 24.2: Test complete project management flow
 * 
 * Tests:
 * - Create project → View → Edit → Delete
 * - Add collaborator → Remove collaborator
 * - Error handling for all operations
 * 
 * Requirements: 9.*, 10.*, 11.*
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { JSDOM } from 'jsdom';

describe('Complete Project Management Flow Integration Tests', () => {
  let dom;
  let document;
  let window;
  let localStorage;
  let ProjectManager;
  let APIClient;
  let projectManager;
  let fetchMock;

  beforeEach(async () => {
    // Setup fresh DOM for each test
    dom = new JSDOM('<!DOCTYPE html><html><body></body></html>', {
      url: 'http://localhost',
      runScripts: 'dangerously'
    });
    document = dom.window.document;
    window = dom.window;
    localStorage = dom.window.localStorage;
    
    // Make globals available
    global.document = document;
    global.window = window;
    global.localStorage = localStorage;
    global.HTMLElement = dom.window.HTMLElement;
    
    // Clear localStorage
    localStorage.clear();
    
    // Mock fetch
    fetchMock = vi.fn();
    global.fetch = fetchMock;
    
    // Mock loading indicators
    global.showLoading = vi.fn();
    global.hideLoading = vi.fn();
    global.showContainerLoading = vi.fn();
    global.hideContainerLoading = vi.fn();
    global.showInlineLoading = vi.fn();
    global.hideInlineLoading = vi.fn();
    
    // Mock data normalizer functions
    global.normalizeCollaboratorData = (collaboratorData) => {
      return {
        id: collaboratorData.id,
        email: collaboratorData.email,
        fullName: collaboratorData.full_name || collaboratorData.fullName,
        jobTitle: collaboratorData.job_title || collaboratorData.job_tittle || collaboratorData.jobTitle || '',
        role: collaboratorData.role || 'collaborator'
      };
    };
    
    // Load APIClient
    const apiClientModule = await import('./api-client.js');
    APIClient = apiClientModule.APIClient;
    
    // Make APIClient available globally
    global.APIClient = APIClient;
    window.APIClient = APIClient;
    
    // Mock ErrorHandler
    global.ErrorHandler = {
      handleAPIError: vi.fn(),
      handleValidationError: vi.fn(),
      handleNetworkError: vi.fn()
    };
    window.ErrorHandler = global.ErrorHandler;
    
    // Mock CyberNotify
    global.CyberNotify = {
      alert: vi.fn(),
      confirm: vi.fn((message, callback, options) => {
        // Auto-confirm for tests
        callback(true);
      })
    };
    window.CyberNotify = global.CyberNotify;
    
    // Load ProjectManager
    const projectManagerModule = await import('./project-manager.js');
    ProjectManager = projectManagerModule.ProjectManager;
    
    // Create instances
    const apiClient = new APIClient();
    projectManager = new ProjectManager(apiClient);
    
    // Set JWT token for authenticated requests
    apiClient.setToken('mock-jwt-token');
  });

  afterEach(() => {
    vi.clearAllMocks();
    localStorage.clear();
  });

  describe('Flow 1: Create Project → View → Edit → Delete', () => {
    it('should complete full project lifecycle', async () => {
      // Step 1: Create Project
      const projectData = {
        name: 'Security Assessment 2024',
        description: 'Comprehensive security audit for web application',
        target: 'example.com',
        status: 'active'
      };

      // Mock create project response
      fetchMock.mockResolvedValueOnce({
        ok: true,
        status: 201,
        json: async () => ({
          project: {
            id: 1,
            name: 'Security Assessment 2024',
            description: 'Comprehensive security audit for web application',
            target: 'example.com',
            status: 'active',
            owner_id: 1,
            created_at: '2024-01-15T10:00:00Z',
            updated_at: '2024-01-15T10:00:00Z'
          }
        })
      });

      const createdProject = await projectManager.createProject(projectData);

      // Verify project was created
      expect(createdProject.id).toBe(1);
      expect(createdProject.name).toBe('Security Assessment 2024');
      expect(createdProject.target).toBe('example.com');
      expect(createdProject.status).toBe('active');
      
      // Verify project was added to local array
      expect(projectManager.projects).toHaveLength(1);
      expect(projectManager.projects[0].id).toBe(1);

      // Step 2: View Project (Fetch single project)
      fetchMock.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          project: {
            id: 1,
            name: 'Security Assessment 2024',
            description: 'Comprehensive security audit for web application',
            target: 'example.com',
            status: 'active',
            owner_id: 1,
            created_at: '2024-01-15T10:00:00Z',
            updated_at: '2024-01-15T10:00:00Z',
            collaborators: []
          }
        })
      });

      const fetchedProject = await projectManager.fetchProject(1);

      // Verify project details
      expect(fetchedProject.id).toBe(1);
      expect(fetchedProject.name).toBe('Security Assessment 2024');
      expect(fetchedProject.collaborators).toEqual([]);

      // Step 3: Edit Project
      const updatedData = {
        name: 'Security Assessment 2024 - Updated',
        description: 'Updated comprehensive security audit',
        target: 'updated-example.com',
        status: 'completed'
      };

      fetchMock.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          project: {
            id: 1,
            name: 'Security Assessment 2024 - Updated',
            description: 'Updated comprehensive security audit',
            target: 'updated-example.com',
            status: 'completed',
            owner_id: 1,
            created_at: '2024-01-15T10:00:00Z',
            updated_at: '2024-01-15T11:00:00Z'
          }
        })
      });

      const updatedProject = await projectManager.updateProject(1, updatedData);

      // Verify project was updated
      expect(updatedProject.name).toBe('Security Assessment 2024 - Updated');
      expect(updatedProject.description).toBe('Updated comprehensive security audit');
      expect(updatedProject.target).toBe('updated-example.com');
      expect(updatedProject.status).toBe('completed');
      
      // Verify local array was updated
      expect(projectManager.projects[0].name).toBe('Security Assessment 2024 - Updated');

      // Step 4: Delete Project
      fetchMock.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          message: 'Project deleted successfully'
        })
      });

      const deleteResult = await projectManager.deleteProject(1);

      // Verify deletion response
      expect(deleteResult.message).toBe('Project deleted successfully');
      
      // Verify project was removed from local array
      expect(projectManager.projects).toHaveLength(0);
    });

    it('should fetch and display multiple projects', async () => {
      // Mock fetch projects response with multiple projects
      fetchMock.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          projects: [
            {
              id: 1,
              name: 'Project Alpha',
              description: 'First project',
              target: 'alpha.com',
              status: 'active',
              created_at: '2024-01-10T10:00:00Z'
            },
            {
              id: 2,
              name: 'Project Beta',
              description: 'Second project',
              target: 'beta.com',
              status: 'completed',
              created_at: '2024-01-12T10:00:00Z'
            },
            {
              id: 3,
              name: 'Project Gamma',
              description: 'Third project',
              target: 'gamma.com',
              status: 'archived',
              created_at: '2024-01-14T10:00:00Z'
            }
          ],
          pagination: {
            page: 1,
            limit: 20,
            total: 3
          }
        })
      });

      const result = await projectManager.fetchProjects();

      // Verify projects were fetched
      expect(result.projects).toHaveLength(3);
      expect(result.projects[0].name).toBe('Project Alpha');
      expect(result.projects[1].name).toBe('Project Beta');
      expect(result.projects[2].name).toBe('Project Gamma');
      
      // Verify pagination info
      expect(result.pagination.total).toBe(3);
      
      // Verify projects were stored locally
      expect(projectManager.projects).toHaveLength(3);
    });

    it('should handle non-paginated project list response', async () => {
      // Mock fetch projects response as direct array (non-paginated)
      fetchMock.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ([
          {
            id: 1,
            name: 'Project One',
            description: 'First project',
            target: 'one.com',
            status: 'active',
            created_at: '2024-01-10T10:00:00Z'
          },
          {
            id: 2,
            name: 'Project Two',
            description: 'Second project',
            target: 'two.com',
            status: 'active',
            created_at: '2024-01-11T10:00:00Z'
          }
        ])
      });

      const result = await projectManager.fetchProjects();

      // Verify projects were fetched
      expect(result.projects).toHaveLength(2);
      expect(result.pagination).toBeNull();
      expect(projectManager.projects).toHaveLength(2);
    });
  });

  describe('Flow 2: Add Collaborator → Remove Collaborator', () => {
    beforeEach(async () => {
      // Setup: Create a project first
      fetchMock.mockResolvedValueOnce({
        ok: true,
        status: 201,
        json: async () => ({
          project: {
            id: 1,
            name: 'Test Project',
            description: 'Project for collaboration testing',
            target: 'test.com',
            status: 'active',
            owner_id: 1,
            created_at: '2024-01-15T10:00:00Z'
          }
        })
      });

      await projectManager.createProject({
        name: 'Test Project',
        description: 'Project for collaboration testing',
        target: 'test.com',
        status: 'active'
      });
    });

    it('should add and remove collaborators successfully', async () => {
      const projectId = 1;
      const userId = 5;

      // Step 1: Add Collaborator
      fetchMock.mockResolvedValueOnce({
        ok: true,
        status: 201,
        json: async () => ({
          collaborator: {
            id: userId,
            email: 'collaborator@example.com',
            full_name: 'Jane Collaborator',
            job_title: 'Security Analyst',
            role: 'collaborator'
          }
        })
      });

      const addedCollaborator = await projectManager.addCollaborator(projectId, userId);

      // Verify collaborator was added
      expect(addedCollaborator.id).toBe(userId);
      expect(addedCollaborator.fullName).toBe('Jane Collaborator');
      expect(addedCollaborator.jobTitle).toBe('Security Analyst');
      expect(addedCollaborator.role).toBe('collaborator');

      // Step 2: Fetch Collaborators
      fetchMock.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          collaborators: [
            {
              id: userId,
              email: 'collaborator@example.com',
              full_name: 'Jane Collaborator',
              job_title: 'Security Analyst',
              role: 'collaborator'
            }
          ]
        })
      });

      const collaborators = await projectManager.fetchCollaborators(projectId);

      // Verify collaborators list
      expect(collaborators).toHaveLength(1);
      expect(collaborators[0].id).toBe(userId);
      expect(collaborators[0].fullName).toBe('Jane Collaborator');

      // Step 3: Remove Collaborator
      fetchMock.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          message: 'Collaborator removed successfully'
        })
      });

      const removeResult = await projectManager.removeCollaborator(projectId, userId);

      // Verify removal response
      expect(removeResult.message).toBe('Collaborator removed successfully');
    });

    it('should handle collaborator data with job_tittle (typo)', async () => {
      const projectId = 1;
      const userId = 6;

      // Mock add collaborator response with job_tittle typo
      fetchMock.mockResolvedValueOnce({
        ok: true,
        status: 201,
        json: async () => ({
          collaborator: {
            id: userId,
            email: 'typo@example.com',
            full_name: 'Typo User',
            job_tittle: 'Penetration Tester', // Backend typo
            role: 'collaborator'
          }
        })
      });

      const addedCollaborator = await projectManager.addCollaborator(projectId, userId);

      // Verify normalization handled the typo
      expect(addedCollaborator.jobTitle).toBe('Penetration Tester');
      expect(addedCollaborator.fullName).toBe('Typo User');
    });

    it('should fetch multiple collaborators and normalize data', async () => {
      const projectId = 1;

      // Mock fetch collaborators with mixed field names
      fetchMock.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          collaborators: [
            {
              id: 5,
              email: 'user1@example.com',
              full_name: 'User One',
              job_title: 'Security Analyst',
              role: 'collaborator'
            },
            {
              id: 6,
              email: 'user2@example.com',
              full_name: 'User Two',
              job_tittle: 'Penetration Tester', // Typo
              role: 'collaborator'
            },
            {
              id: 7,
              email: 'user3@example.com',
              full_name: 'User Three',
              // No job title field
              role: 'admin'
            }
          ]
        })
      });

      const collaborators = await projectManager.fetchCollaborators(projectId);

      // Verify all collaborators were normalized
      expect(collaborators).toHaveLength(3);
      expect(collaborators[0].jobTitle).toBe('Security Analyst');
      expect(collaborators[1].jobTitle).toBe('Penetration Tester'); // Normalized from job_tittle
      expect(collaborators[2].jobTitle).toBe(''); // Default empty string
    });
  });

  describe('Flow 3: Error Handling for All Operations', () => {
    it('should handle project creation validation errors (422)', async () => {
      const invalidData = {
        name: '', // Empty name
        description: 'Test',
        target: '', // Empty target
        status: 'active'
      };

      // Attempt to create project - should fail client-side validation first
      await expect(projectManager.createProject(invalidData)).rejects.toThrow('Project name is required');
    });

    it('should handle API validation errors (422) from backend', async () => {
      const dataWithServerSideError = {
        name: 'Valid Name',
        description: 'Test',
        target: 'valid-target.com',
        status: 'active'
      };

      // Mock 422 validation error response from backend
      fetchMock.mockResolvedValueOnce({
        ok: false,
        status: 422,
        json: async () => ({
          errors: {
            name: ['Project name already exists'],
            target: ['Target is already being scanned']
          }
        })
      });

      // Attempt to create project - should get backend validation error
      await expect(projectManager.createProject(dataWithServerSideError)).rejects.toThrow('Validation failed');
    });

    it('should handle project not found error (404)', async () => {
      const nonExistentProjectId = 999;

      // Mock 404 response
      fetchMock.mockResolvedValueOnce({
        ok: false,
        status: 404,
        json: async () => ({
          message: 'Project not found'
        })
      });

      // Attempt to fetch non-existent project
      await expect(projectManager.fetchProject(nonExistentProjectId)).rejects.toThrow();
    });

    it('should handle unauthorized access (401)', async () => {
      // Mock 401 response
      fetchMock.mockResolvedValueOnce({
        ok: false,
        status: 401,
        json: async () => ({
          message: 'Unauthorized'
        })
      });

      // Attempt to fetch projects without valid token
      await expect(projectManager.fetchProjects()).rejects.toThrow('Unauthorized');
    });

    it('should handle server error (500)', async () => {
      // Mock 500 response
      fetchMock.mockResolvedValueOnce({
        ok: false,
        status: 500,
        json: async () => ({
          message: 'Internal Server Error'
        })
      });

      // Attempt to create project
      await expect(projectManager.createProject({
        name: 'Test',
        target: 'test.com',
        status: 'active'
      })).rejects.toThrow('Server error');
    });

    it('should handle network errors', async () => {
      // Mock network error
      fetchMock.mockRejectedValueOnce(new TypeError('Failed to fetch'));

      // Attempt to fetch projects
      await expect(projectManager.fetchProjects()).rejects.toThrow('Network error');
    });

    it('should handle "User not found" error when adding collaborator', async () => {
      const projectId = 1;
      const invalidUserId = 999;

      // Mock 404 response for user not found
      fetchMock.mockResolvedValueOnce({
        ok: false,
        status: 404,
        json: async () => ({
          message: 'User not found'
        })
      });

      // Attempt to add non-existent user as collaborator
      await expect(projectManager.addCollaborator(projectId, invalidUserId)).rejects.toThrow();
    });

    it('should handle "Already a collaborator" error', async () => {
      const projectId = 1;
      const userId = 5;

      // Mock 400 response for already a collaborator
      fetchMock.mockResolvedValueOnce({
        ok: false,
        status: 400,
        json: async () => ({
          message: 'User is already a collaborator on this project'
        })
      });

      // Attempt to add existing collaborator
      await expect(projectManager.addCollaborator(projectId, userId)).rejects.toThrow();
    });

    it('should handle delete project with active collaborators', async () => {
      const projectId = 1;

      // Mock successful deletion (backend handles cleanup)
      fetchMock.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          message: 'Project and all collaborators deleted successfully'
        })
      });

      const result = await projectManager.deleteProject(projectId);

      // Verify deletion succeeded
      expect(result.message).toContain('deleted successfully');
    });
  });

  describe('Flow 4: Complete End-to-End Scenario', () => {
    it('should complete full project workflow with collaborators', async () => {
      // Step 1: Create Project
      fetchMock.mockResolvedValueOnce({
        ok: true,
        status: 201,
        json: async () => ({
          project: {
            id: 1,
            name: 'E2E Test Project',
            description: 'End-to-end testing project',
            target: 'e2e-test.com',
            status: 'active',
            owner_id: 1,
            created_at: '2024-01-15T10:00:00Z'
          }
        })
      });

      const project = await projectManager.createProject({
        name: 'E2E Test Project',
        description: 'End-to-end testing project',
        target: 'e2e-test.com',
        status: 'active'
      });

      expect(project.id).toBe(1);

      // Step 2: Add First Collaborator
      fetchMock.mockResolvedValueOnce({
        ok: true,
        status: 201,
        json: async () => ({
          collaborator: {
            id: 5,
            email: 'collab1@example.com',
            full_name: 'Collaborator One',
            job_title: 'Security Analyst',
            role: 'collaborator'
          }
        })
      });

      const collab1 = await projectManager.addCollaborator(1, 5);
      expect(collab1.fullName).toBe('Collaborator One');

      // Step 3: Add Second Collaborator
      fetchMock.mockResolvedValueOnce({
        ok: true,
        status: 201,
        json: async () => ({
          collaborator: {
            id: 6,
            email: 'collab2@example.com',
            full_name: 'Collaborator Two',
            job_tittle: 'Penetration Tester', // Typo
            role: 'collaborator'
          }
        })
      });

      const collab2 = await projectManager.addCollaborator(1, 6);
      expect(collab2.jobTitle).toBe('Penetration Tester'); // Normalized

      // Step 4: Fetch All Collaborators
      fetchMock.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          collaborators: [
            {
              id: 5,
              email: 'collab1@example.com',
              full_name: 'Collaborator One',
              job_title: 'Security Analyst',
              role: 'collaborator'
            },
            {
              id: 6,
              email: 'collab2@example.com',
              full_name: 'Collaborator Two',
              job_tittle: 'Penetration Tester',
              role: 'collaborator'
            }
          ]
        })
      });

      const collaborators = await projectManager.fetchCollaborators(1);
      expect(collaborators).toHaveLength(2);

      // Step 5: Update Project Status
      fetchMock.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          project: {
            id: 1,
            name: 'E2E Test Project',
            description: 'End-to-end testing project',
            target: 'e2e-test.com',
            status: 'completed',
            owner_id: 1,
            created_at: '2024-01-15T10:00:00Z',
            updated_at: '2024-01-15T12:00:00Z'
          }
        })
      });

      const updatedProject = await projectManager.updateProject(1, {
        name: 'E2E Test Project',
        description: 'End-to-end testing project',
        target: 'e2e-test.com',
        status: 'completed'
      });

      expect(updatedProject.status).toBe('completed');

      // Step 6: Remove One Collaborator
      fetchMock.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          message: 'Collaborator removed successfully'
        })
      });

      await projectManager.removeCollaborator(1, 6);

      // Step 7: Verify Remaining Collaborators
      fetchMock.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          collaborators: [
            {
              id: 5,
              email: 'collab1@example.com',
              full_name: 'Collaborator One',
              job_title: 'Security Analyst',
              role: 'collaborator'
            }
          ]
        })
      });

      const remainingCollaborators = await projectManager.fetchCollaborators(1);
      expect(remainingCollaborators).toHaveLength(1);
      expect(remainingCollaborators[0].id).toBe(5);

      // Step 8: Delete Project
      fetchMock.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          message: 'Project deleted successfully'
        })
      });

      await projectManager.deleteProject(1);

      // Verify project was removed from local array
      expect(projectManager.projects).toHaveLength(0);
    });
  });

  describe('Edge Cases and Data Validation', () => {
    it('should validate required fields before API call', async () => {
      const invalidData = {
        name: '',
        description: 'Test',
        target: '',
        status: 'active'
      };

      // Should throw error before making API call
      await expect(projectManager.createProject(invalidData)).rejects.toThrow('Project name is required');
    });

    it('should handle empty project list', async () => {
      // Mock empty projects response
      fetchMock.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          projects: [],
          pagination: {
            page: 1,
            limit: 20,
            total: 0
          }
        })
      });

      const result = await projectManager.fetchProjects();

      expect(result.projects).toHaveLength(0);
      expect(projectManager.projects).toHaveLength(0);
    });

    it('should handle empty collaborators list', async () => {
      const projectId = 1;

      // Mock empty collaborators response
      fetchMock.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          collaborators: []
        })
      });

      const collaborators = await projectManager.fetchCollaborators(projectId);

      expect(collaborators).toHaveLength(0);
    });

    it('should handle project with null description', async () => {
      fetchMock.mockResolvedValueOnce({
        ok: true,
        status: 201,
        json: async () => ({
          project: {
            id: 1,
            name: 'Minimal Project',
            description: null,
            target: 'minimal.com',
            status: 'active',
            owner_id: 1,
            created_at: '2024-01-15T10:00:00Z'
          }
        })
      });

      const project = await projectManager.createProject({
        name: 'Minimal Project',
        description: '',
        target: 'minimal.com',
        status: 'active'
      });

      expect(project.description).toBeNull();
    });

    it('should handle collaborator with missing job title', async () => {
      const projectId = 1;

      fetchMock.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          collaborators: [
            {
              id: 5,
              email: 'minimal@example.com',
              full_name: 'Minimal User',
              role: 'collaborator'
              // No job_title or job_tittle field
            }
          ]
        })
      });

      const collaborators = await projectManager.fetchCollaborators(projectId);

      expect(collaborators[0].jobTitle).toBe('');
    });
  });
});
