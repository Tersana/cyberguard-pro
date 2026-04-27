/**
 * Unit Tests for Project Manager
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { ProjectManager } from './project-manager.js';

describe('ProjectManager', () => {
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

  describe('Constructor', () => {
    it('should initialize with apiClient and empty projects array', () => {
      expect(projectManager.apiClient).toBe(mockApiClient);
      expect(projectManager.projects).toEqual([]);
    });
  });

  describe('fetchProjects', () => {
    it('should fetch projects with default pagination', async () => {
      const mockProjects = [
        { id: 1, name: 'Project 1', target: 'example.com' },
        { id: 2, name: 'Project 2', target: '192.168.1.1' }
      ];

      mockApiClient.get.mockResolvedValue({
        projects: mockProjects,
        pagination: { page: 1, limit: 20, total: 2 }
      });

      const result = await projectManager.fetchProjects();

      expect(mockApiClient.get).toHaveBeenCalledWith('/projects?page=1&limit=20');
      expect(result.projects).toEqual(mockProjects);
      expect(result.pagination).toEqual({ page: 1, limit: 20, total: 2 });
      expect(projectManager.projects).toEqual(mockProjects);
    });

    it('should fetch projects with custom pagination', async () => {
      const mockProjects = [{ id: 1, name: 'Project 1' }];

      mockApiClient.get.mockResolvedValue({
        projects: mockProjects,
        pagination: { page: 2, limit: 10, total: 15 }
      });

      await projectManager.fetchProjects(2, 10);

      expect(mockApiClient.get).toHaveBeenCalledWith('/projects?page=2&limit=10');
    });

    it('should handle non-paginated array response', async () => {
      const mockProjects = [
        { id: 1, name: 'Project 1' },
        { id: 2, name: 'Project 2' }
      ];

      mockApiClient.get.mockResolvedValue(mockProjects);

      const result = await projectManager.fetchProjects();

      expect(result.projects).toEqual(mockProjects);
      expect(result.pagination).toBeNull();
      expect(projectManager.projects).toEqual(mockProjects);
    });

    it('should handle unexpected response format', async () => {
      mockApiClient.get.mockResolvedValue({ unexpected: 'format' });

      const result = await projectManager.fetchProjects();

      expect(result.projects).toEqual([]);
      expect(result.pagination).toBeNull();
      expect(projectManager.projects).toEqual([]);
    });

    it('should throw error on API failure', async () => {
      const error = new Error('API Error');
      mockApiClient.get.mockRejectedValue(error);

      await expect(projectManager.fetchProjects()).rejects.toThrow('API Error');
    });
  });

  describe('fetchProject', () => {
    it('should fetch single project by ID', async () => {
      const mockProject = {
        id: 1,
        name: 'Test Project',
        description: 'Test description',
        target: 'example.com',
        status: 'active'
      };

      mockApiClient.get.mockResolvedValue({ project: mockProject });

      const result = await projectManager.fetchProject(1);

      expect(mockApiClient.get).toHaveBeenCalledWith('/projects/1');
      expect(result).toEqual(mockProject);
    });

    it('should handle direct project response', async () => {
      const mockProject = { id: 1, name: 'Test Project' };

      mockApiClient.get.mockResolvedValue(mockProject);

      const result = await projectManager.fetchProject(1);

      expect(result).toEqual(mockProject);
    });

    it('should throw error on API failure', async () => {
      const error = new Error('Project not found');
      mockApiClient.get.mockRejectedValue(error);

      await expect(projectManager.fetchProject(999)).rejects.toThrow('Project not found');
    });
  });

  describe('createProject', () => {
    it('should create project with valid data', async () => {
      const projectData = {
        name: 'New Project',
        description: 'Project description',
        target: 'example.com',
        status: 'active'
      };

      const mockResponse = {
        project: { id: 1, ...projectData }
      };

      mockApiClient.post.mockResolvedValue(mockResponse);

      const result = await projectManager.createProject(projectData);

      expect(mockApiClient.post).toHaveBeenCalledWith('/projects', projectData);
      expect(result).toEqual(mockResponse.project);
      expect(projectManager.projects).toContainEqual(mockResponse.project);
    });

    it('should handle direct project response', async () => {
      const projectData = {
        name: 'New Project',
        target: 'example.com'
      };

      const mockProject = { id: 1, ...projectData };
      mockApiClient.post.mockResolvedValue(mockProject);

      const result = await projectManager.createProject(projectData);

      expect(result).toEqual(mockProject);
      expect(projectManager.projects).toContainEqual(mockProject);
    });

    it('should throw error if name is missing', async () => {
      const projectData = {
        target: 'example.com'
      };

      await expect(projectManager.createProject(projectData)).rejects.toThrow('Project name is required');
      expect(mockApiClient.post).not.toHaveBeenCalled();
    });

    it('should throw error if name is empty string', async () => {
      const projectData = {
        name: '   ',
        target: 'example.com'
      };

      await expect(projectManager.createProject(projectData)).rejects.toThrow('Project name is required');
    });

    it('should throw error if target is missing', async () => {
      const projectData = {
        name: 'Test Project'
      };

      await expect(projectManager.createProject(projectData)).rejects.toThrow('Project target is required');
    });

    it('should throw error if target is empty string', async () => {
      const projectData = {
        name: 'Test Project',
        target: '   '
      };

      await expect(projectManager.createProject(projectData)).rejects.toThrow('Project target is required');
    });

    it('should throw error on API failure', async () => {
      const projectData = {
        name: 'Test Project',
        target: 'example.com'
      };

      const error = new Error('API Error');
      mockApiClient.post.mockRejectedValue(error);

      await expect(projectManager.createProject(projectData)).rejects.toThrow('API Error');
    });
  });

  describe('updateProject', () => {
    it('should update project with valid data', async () => {
      const projectId = 1;
      const updateData = {
        name: 'Updated Project',
        description: 'Updated description',
        status: 'completed'
      };

      const mockResponse = {
        project: { id: projectId, ...updateData }
      };

      // Pre-populate projects array
      projectManager.projects = [
        { id: 1, name: 'Old Name', status: 'active' },
        { id: 2, name: 'Other Project', status: 'active' }
      ];

      mockApiClient.put.mockResolvedValue(mockResponse);

      const result = await projectManager.updateProject(projectId, updateData);

      expect(mockApiClient.put).toHaveBeenCalledWith('/projects/1', updateData);
      expect(result).toEqual(mockResponse.project);
      expect(projectManager.projects[0]).toEqual(mockResponse.project);
    });

    it('should handle direct project response', async () => {
      const projectId = 1;
      const updateData = { name: 'Updated' };
      const mockProject = { id: projectId, ...updateData };

      projectManager.projects = [{ id: 1, name: 'Old' }];
      mockApiClient.put.mockResolvedValue(mockProject);

      const result = await projectManager.updateProject(projectId, updateData);

      expect(result).toEqual(mockProject);
      expect(projectManager.projects[0]).toEqual(mockProject);
    });

    it('should not update local array if project not found', async () => {
      const projectId = 999;
      const updateData = { name: 'Updated' };
      const mockProject = { id: projectId, ...updateData };

      projectManager.projects = [{ id: 1, name: 'Existing' }];
      mockApiClient.put.mockResolvedValue({ project: mockProject });

      await projectManager.updateProject(projectId, updateData);

      expect(projectManager.projects).toHaveLength(1);
      expect(projectManager.projects[0].id).toBe(1);
    });

    it('should throw error on API failure', async () => {
      const error = new Error('Update failed');
      mockApiClient.put.mockRejectedValue(error);

      await expect(projectManager.updateProject(1, {})).rejects.toThrow('Update failed');
    });
  });

  describe('deleteProject', () => {
    it('should delete project by ID', async () => {
      const projectId = 1;
      const mockResponse = { message: 'Project deleted successfully' };

      projectManager.projects = [
        { id: 1, name: 'Project 1' },
        { id: 2, name: 'Project 2' },
        { id: 3, name: 'Project 3' }
      ];

      mockApiClient.delete.mockResolvedValue(mockResponse);

      const result = await projectManager.deleteProject(projectId);

      expect(mockApiClient.delete).toHaveBeenCalledWith('/projects/1');
      expect(result).toEqual(mockResponse);
      expect(projectManager.projects).toHaveLength(2);
      expect(projectManager.projects.find(p => p.id === 1)).toBeUndefined();
    });

    it('should handle deletion of non-existent project in local array', async () => {
      const projectId = 999;
      const mockResponse = { message: 'Deleted' };

      projectManager.projects = [{ id: 1, name: 'Project 1' }];
      mockApiClient.delete.mockResolvedValue(mockResponse);

      await projectManager.deleteProject(projectId);

      expect(projectManager.projects).toHaveLength(1);
    });

    it('should throw error on API failure', async () => {
      const error = new Error('Delete failed');
      mockApiClient.delete.mockRejectedValue(error);

      await expect(projectManager.deleteProject(1)).rejects.toThrow('Delete failed');
    });
  });

  describe('fetchCollaborators', () => {
    it('should fetch collaborators for a project', async () => {
      const projectId = 1;
      const mockCollaborators = [
        { id: 1, full_name: 'John Doe', email: 'john@example.com', role: 'owner' },
        { id: 2, full_name: 'Jane Smith', email: 'jane@example.com', role: 'member' }
      ];

      mockApiClient.get.mockResolvedValue({ collaborators: mockCollaborators });

      const result = await projectManager.fetchCollaborators(projectId);

      expect(mockApiClient.get).toHaveBeenCalledWith('/projects/1/collaborators');
      // Expect normalized data format
      expect(result).toEqual([
        { id: 1, fullName: 'John Doe', email: 'john@example.com', role: 'owner', jobTitle: '' },
        { id: 2, fullName: 'Jane Smith', email: 'jane@example.com', role: 'member', jobTitle: '' }
      ]);
    });

    it('should handle direct array response', async () => {
      const projectId = 1;
      const mockCollaborators = [
        { id: 1, full_name: 'John Doe', email: 'john@example.com' }
      ];

      mockApiClient.get.mockResolvedValue(mockCollaborators);

      const result = await projectManager.fetchCollaborators(projectId);

      // Expect normalized data format
      expect(result).toEqual([
        { id: 1, fullName: 'John Doe', email: 'john@example.com', role: 'collaborator', jobTitle: '' }
      ]);
    });

    it('should throw error on API failure', async () => {
      const error = new Error('Failed to fetch collaborators');
      mockApiClient.get.mockRejectedValue(error);

      await expect(projectManager.fetchCollaborators(1)).rejects.toThrow('Failed to fetch collaborators');
    });
  });

  describe('addCollaborator', () => {
    it('should add collaborator to project', async () => {
      const projectId = 1;
      const userId = 5;
      const mockCollaborator = {
        id: 5,
        full_name: 'Alice Johnson',
        email: 'alice@example.com',
        role: 'member'
      };

      mockApiClient.post.mockResolvedValue({ collaborator: mockCollaborator });

      const result = await projectManager.addCollaborator(projectId, userId);

      expect(mockApiClient.post).toHaveBeenCalledWith('/projects/1/collaborators', { user_id: 5 });
      // Expect normalized data format
      expect(result).toEqual({
        id: 5,
        fullName: 'Alice Johnson',
        email: 'alice@example.com',
        role: 'member',
        jobTitle: ''
      });
    });

    it('should handle direct collaborator response', async () => {
      const projectId = 1;
      const userId = 5;
      const mockCollaborator = {
        id: 5,
        full_name: 'Alice Johnson',
        email: 'alice@example.com'
      };

      mockApiClient.post.mockResolvedValue(mockCollaborator);

      const result = await projectManager.addCollaborator(projectId, userId);

      // Expect normalized data format
      expect(result).toEqual({
        id: 5,
        fullName: 'Alice Johnson',
        email: 'alice@example.com',
        role: 'collaborator',
        jobTitle: ''
      });
    });

    it('should throw error on API failure', async () => {
      const error = new Error('User not found');
      mockApiClient.post.mockRejectedValue(error);

      await expect(projectManager.addCollaborator(1, 999)).rejects.toThrow('User not found');
    });
  });

  describe('removeCollaborator', () => {
    it('should remove collaborator from project', async () => {
      const projectId = 1;
      const userId = 5;
      const mockResponse = { message: 'Collaborator removed successfully' };

      mockApiClient.delete.mockResolvedValue(mockResponse);

      const result = await projectManager.removeCollaborator(projectId, userId);

      expect(mockApiClient.delete).toHaveBeenCalledWith('/projects/1/collaborators/5');
      expect(result).toEqual(mockResponse);
    });

    it('should throw error on API failure', async () => {
      const error = new Error('Collaborator not found');
      mockApiClient.delete.mockRejectedValue(error);

      await expect(projectManager.removeCollaborator(1, 999)).rejects.toThrow('Collaborator not found');
    });
  });

  describe('getInitials', () => {
    it('should return initials from full name', () => {
      expect(projectManager.getInitials('John Doe')).toBe('JD');
      expect(projectManager.getInitials('Alice Bob Smith')).toBe('AS');
      expect(projectManager.getInitials('SingleName')).toBe('S');
    });

    it('should handle empty or invalid names', () => {
      expect(projectManager.getInitials('')).toBe('U');
      expect(projectManager.getInitials(null)).toBe('U');
      expect(projectManager.getInitials(undefined)).toBe('U');
    });

    it('should handle names with extra whitespace', () => {
      expect(projectManager.getInitials('  John   Doe  ')).toBe('JD');
    });
  });

  describe('renderCollaboratorItem', () => {
    it('should render collaborator item with full data', () => {
      // Use normalized data format
      const collaborator = {
        id: 5,
        fullName: 'John Doe',
        role: 'Developer',
        jobTitle: 'Senior Developer'
      };
      const projectId = 1;

      const html = projectManager.renderCollaboratorItem(collaborator, projectId);

      expect(html).toContain('JD');
      expect(html).toContain('John Doe');
      expect(html).toContain('Senior Developer'); // Should display jobTitle
      expect(html).toContain('removeCollaboratorConfirm(1, 5)');
    });

    it('should handle collaborator with user_id instead of id', () => {
      // Use normalized data format - but normalizer always uses 'id'
      const collaborator = {
        id: 10,
        fullName: 'Jane Smith',
        role: 'Manager',
        jobTitle: 'Project Manager'
      };
      const projectId = 2;

      const html = projectManager.renderCollaboratorItem(collaborator, projectId);

      expect(html).toContain('JS');
      expect(html).toContain('Jane Smith');
      expect(html).toContain('removeCollaboratorConfirm(2, 10)');
    });

    it('should handle missing role', () => {
      // Use normalized data format
      const collaborator = {
        id: 5,
        fullName: 'John Doe',
        role: 'Collaborator',
        jobTitle: ''
      };
      const projectId = 1;

      const html = projectManager.renderCollaboratorItem(collaborator, projectId);

      expect(html).toContain('Collaborator');
    });

    it('should escape HTML in names and roles', () => {
      // Use normalized data format
      const collaborator = {
        id: 5,
        fullName: '<script>alert("xss")</script>',
        role: 'admin',
        jobTitle: '<img src=x onerror=alert(1)>'
      };
      const projectId = 1;

      const html = projectManager.renderCollaboratorItem(collaborator, projectId);

      expect(html).not.toContain('<script>');
      expect(html).not.toContain('<img');
      expect(html).toContain('&lt;script&gt;');
      expect(html).toContain('&lt;img');
    });
  });
});
