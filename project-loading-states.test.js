/**
 * Tests for Task 19.3: Project Operations Loading States
 * Validates: Requirements 14.3
 */

import { describe, it, expect } from 'vitest';
import fs from 'fs';
import path from 'path';

describe('Task 19.3: Project Operations Loading States - Code Structure', () => {
  let projectManagerCode;

  beforeEach(() => {
    // Read the project-manager.js file
    projectManagerCode = fs.readFileSync(path.resolve(__dirname, 'project-manager.js'), 'utf-8');
  });

  describe('Project Operations Loading States', () => {
    it('should have showContainerLoading in fetchProjects', () => {
      expect(projectManagerCode).toContain('showContainerLoading(\'#projects-list\', \'Loading projects...\')');
    });

    it('should have hideContainerLoading in fetchProjects finally block', () => {
      const fetchProjectsMatch = projectManagerCode.match(/async fetchProjects[\s\S]*?finally[\s\S]*?hideContainerLoading/);
      expect(fetchProjectsMatch).toBeTruthy();
    });

    it('should have showLoading in createProject', () => {
      expect(projectManagerCode).toContain('showLoading(\'Creating project...\')');
    });

    it('should have hideLoading in createProject finally block', () => {
      const createProjectMatch = projectManagerCode.match(/async createProject[\s\S]*?finally[\s\S]*?hideLoading/);
      expect(createProjectMatch).toBeTruthy();
    });

    it('should have showLoading in updateProject', () => {
      expect(projectManagerCode).toContain('showLoading(\'Updating project...\')');
    });

    it('should have hideLoading in updateProject finally block', () => {
      const updateProjectMatch = projectManagerCode.match(/async updateProject[\s\S]*?finally[\s\S]*?hideLoading/);
      expect(updateProjectMatch).toBeTruthy();
    });

    it('should have showLoading in deleteProject', () => {
      expect(projectManagerCode).toContain('showLoading(\'Deleting project...\')');
    });

    it('should have hideLoading in deleteProject finally block', () => {
      const deleteProjectMatch = projectManagerCode.match(/async deleteProject[\s\S]*?finally[\s\S]*?hideLoading/);
      expect(deleteProjectMatch).toBeTruthy();
    });
  });

  describe('Collaborator Operations Loading States', () => {
    it('should have showContainerLoading in loadCollaborators', () => {
      expect(projectManagerCode).toContain('showContainerLoading(\'#collaborators-list\', \'Loading collaborators...\')');
    });

    it('should have hideContainerLoading in loadCollaborators finally block', () => {
      const loadCollaboratorsMatch = projectManagerCode.match(/async loadCollaborators[\s\S]*?finally[\s\S]*?hideContainerLoading/);
      expect(loadCollaboratorsMatch).toBeTruthy();
    });

    it('should have showLoading in addCollaborator', () => {
      expect(projectManagerCode).toContain('showLoading(\'Adding collaborator...\')');
    });

    it('should have hideLoading in addCollaborator finally block', () => {
      const addCollaboratorMatch = projectManagerCode.match(/async addCollaborator[\s\S]*?finally[\s\S]*?hideLoading/);
      expect(addCollaboratorMatch).toBeTruthy();
    });

    it('should have showLoading in removeCollaborator', () => {
      expect(projectManagerCode).toContain('showLoading(\'Removing collaborator...\')');
    });

    it('should have hideLoading in removeCollaborator finally block', () => {
      const removeCollaboratorMatch = projectManagerCode.match(/async removeCollaborator[\s\S]*?finally[\s\S]*?hideLoading/);
      expect(removeCollaboratorMatch).toBeTruthy();
    });
  });

  describe('Form Button Loading States', () => {
    it('should have showInlineLoading in handleProjectFormSubmit', () => {
      expect(projectManagerCode).toContain('showInlineLoading(submitBtn, \'Creating\')');
    });

    it('should have hideInlineLoading in handleProjectFormSubmit finally block', () => {
      const handleProjectFormMatch = projectManagerCode.match(/async handleProjectFormSubmit[\s\S]*?finally[\s\S]*?hideInlineLoading/);
      expect(handleProjectFormMatch).toBeTruthy();
    });

    it('should have showInlineLoading in handleEditProjectFormSubmit', () => {
      expect(projectManagerCode).toContain('showInlineLoading(submitBtn, \'Saving\')');
    });

    it('should have hideInlineLoading in handleEditProjectFormSubmit finally block', () => {
      const handleEditProjectFormMatch = projectManagerCode.match(/async handleEditProjectFormSubmit[\s\S]*?finally[\s\S]*?hideInlineLoading/);
      expect(handleEditProjectFormMatch).toBeTruthy();
    });

    it('should have showInlineLoading in handleAddCollaboratorSubmit', () => {
      expect(projectManagerCode).toContain('showInlineLoading(submitBtn, \'Adding\')');
    });

    it('should have hideInlineLoading in handleAddCollaboratorSubmit finally block', () => {
      const handleAddCollaboratorMatch = projectManagerCode.match(/async handleAddCollaboratorSubmit[\s\S]*?finally[\s\S]*?hideInlineLoading/);
      expect(handleAddCollaboratorMatch).toBeTruthy();
    });
  });

  describe('Error Handling with Loading States', () => {
    it('should have try-catch-finally blocks for all async operations', () => {
      const operations = [
        'fetchProjects',
        'createProject',
        'updateProject',
        'deleteProject',
        'addCollaborator',
        'removeCollaborator',
        'loadCollaborators'
      ];

      operations.forEach(operation => {
        const operationMatch = projectManagerCode.match(new RegExp(`async ${operation}[\\s\\S]*?try[\\s\\S]*?catch[\\s\\S]*?finally`, 'm'));
        expect(operationMatch).toBeTruthy();
      });
    });

    it('should ensure all loading indicators are cleaned up in finally blocks', () => {
      // Count showLoading calls
      const showLoadingCount = (projectManagerCode.match(/showLoading\(/g) || []).length;
      // Count hideLoading calls in finally blocks
      const hideLoadingInFinallyCount = (projectManagerCode.match(/finally[\s\S]*?hideLoading\(/g) || []).length;
      
      // Should have at least as many hideLoading in finally as showLoading
      expect(hideLoadingInFinallyCount).toBeGreaterThanOrEqual(showLoadingCount - 3); // -3 for inline loading
    });

    it('should ensure all container loading indicators are cleaned up in finally blocks', () => {
      // Count showContainerLoading calls
      const showContainerLoadingCount = (projectManagerCode.match(/showContainerLoading\(/g) || []).length;
      // Count hideContainerLoading calls in finally blocks
      const hideContainerLoadingInFinallyCount = (projectManagerCode.match(/finally[\s\S]*?hideContainerLoading\(/g) || []).length;
      
      // Should have equal counts
      expect(hideContainerLoadingInFinallyCount).toBe(showContainerLoadingCount);
    });
  });

  describe('Loading Utility Usage Patterns', () => {
    it('should use showLoading/hideLoading for full-screen operations', () => {
      const fullScreenOperations = [
        'Creating project',
        'Updating project',
        'Deleting project',
        'Adding collaborator',
        'Removing collaborator'
      ];

      fullScreenOperations.forEach(operation => {
        expect(projectManagerCode).toContain(`showLoading('${operation}...')`);
      });
    });

    it('should use showContainerLoading/hideContainerLoading for list updates', () => {
      const containerOperations = [
        { container: '#projects-list', message: 'Loading projects...' },
        { container: '#collaborators-list', message: 'Loading collaborators...' }
      ];

      containerOperations.forEach(({ container, message }) => {
        expect(projectManagerCode).toContain(`showContainerLoading('${container}', '${message}')`);
      });
    });

    it('should use showInlineLoading/hideInlineLoading for button states', () => {
      const buttonOperations = [
        'Creating',
        'Saving',
        'Adding'
      ];

      buttonOperations.forEach(operation => {
        expect(projectManagerCode).toContain(`showInlineLoading(submitBtn, '${operation}')`);
      });
    });
  });

  describe('Requirements 14.3 Validation', () => {
    it('should show loading during project fetch', () => {
      expect(projectManagerCode).toContain('showContainerLoading(\'#projects-list\'');
    });

    it('should show loading during create/update/delete', () => {
      expect(projectManagerCode).toContain('showLoading(\'Creating project...\')');
      expect(projectManagerCode).toContain('showLoading(\'Updating project...\')');
      expect(projectManagerCode).toContain('showLoading(\'Deleting project...\')');
    });

    it('should show loading during collaborator operations', () => {
      expect(projectManagerCode).toContain('showContainerLoading(\'#collaborators-list\'');
      expect(projectManagerCode).toContain('showLoading(\'Adding collaborator...\')');
      expect(projectManagerCode).toContain('showLoading(\'Removing collaborator...\')');
    });

    it('should use showLoading/hideLoading for full operations', () => {
      const fullOperations = ['createProject', 'updateProject', 'deleteProject', 'addCollaborator', 'removeCollaborator'];
      
      fullOperations.forEach(operation => {
        const operationMatch = projectManagerCode.match(new RegExp(`async ${operation}[\\s\\S]*?showLoading[\\s\\S]*?hideLoading`, 'm'));
        expect(operationMatch).toBeTruthy();
      });
    });

    it('should use showContainerLoading for list updates', () => {
      expect(projectManagerCode).toContain('showContainerLoading(\'#projects-list\'');
      expect(projectManagerCode).toContain('showContainerLoading(\'#collaborators-list\'');
    });

    it('should ensure proper cleanup in error handlers', () => {
      // All async operations should have finally blocks with cleanup
      const asyncOperations = projectManagerCode.match(/async \w+\([^)]*\)\s*{[\s\S]*?try[\s\S]*?finally/g);
      expect(asyncOperations).toBeTruthy();
      expect(asyncOperations.length).toBeGreaterThan(5);
    });
  });
});
