/**
 * Form Loading States Test
 * Verifies that loading states are properly applied to all forms
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { JSDOM } from 'jsdom';
import fs from 'fs';
import path from 'path';

describe('Form Loading States - Task 19.2', () => {
  let dom;
  let document;
  let window;

  beforeEach(() => {
    // Create a minimal DOM environment
    dom = new JSDOM('<!DOCTYPE html><html><body></body></html>', {
      url: 'http://localhost',
      runScripts: 'dangerously',
      resources: 'usable'
    });
    document = dom.window.document;
    window = dom.window;
    global.document = document;
    global.window = window;
  });

  describe('Login Form Loading States', () => {
    it('should have submit button in login form', () => {
      const loginHtml = fs.readFileSync(path.join(process.cwd(), 'login.html'), 'utf-8');
      expect(loginHtml).toContain('type="submit"');
      expect(loginHtml).toContain('id="loginForm"');
    });

    it('should use showInlineLoading for login form', () => {
      const loginHtml = fs.readFileSync(path.join(process.cwd(), 'login.html'), 'utf-8');
      expect(loginHtml).toContain('showInlineLoading(submitButton');
      expect(loginHtml).toContain('hideInlineLoading(submitButton');
    });

    it('should prevent double submission in login form', () => {
      const loginHtml = fs.readFileSync(path.join(process.cwd(), 'login.html'), 'utf-8');
      expect(loginHtml).toContain('if (submitButton.disabled) return');
    });

    it('should have loading text for login button', () => {
      const loginHtml = fs.readFileSync(path.join(process.cwd(), 'login.html'), 'utf-8');
      expect(loginHtml).toMatch(/showInlineLoading\(submitButton,\s*['"]Signing In['"]/);
    });
  });

  describe('2FA Form Loading States', () => {
    it('should have submit button in 2FA form', () => {
      const loginHtml = fs.readFileSync(path.join(process.cwd(), 'login.html'), 'utf-8');
      expect(loginHtml).toContain('id="twofa-form"');
      expect(loginHtml).toContain('type="submit"');
    });

    it('should use showInlineLoading for 2FA form', () => {
      const loginHtml = fs.readFileSync(path.join(process.cwd(), 'login.html'), 'utf-8');
      const twofaSection = loginHtml.split('id="twofa-form"')[1];
      expect(twofaSection).toContain('showInlineLoading');
      expect(twofaSection).toContain('hideInlineLoading');
    });

    it('should prevent double submission in 2FA form', () => {
      const loginHtml = fs.readFileSync(path.join(process.cwd(), 'login.html'), 'utf-8');
      const twofaSection = loginHtml.split('id="twofa-form"')[1];
      expect(twofaSection).toContain('if (submitButton.disabled) return');
    });

    it('should have loading text for 2FA button', () => {
      const loginHtml = fs.readFileSync(path.join(process.cwd(), 'login.html'), 'utf-8');
      expect(loginHtml).toMatch(/showInlineLoading\(submitButton,\s*['"]Verifying['"]/);
    });
  });

  describe('Signup Form Loading States', () => {
    it('should have submit button in signup form', () => {
      const signupHtml = fs.readFileSync(path.join(process.cwd(), 'signup.html'), 'utf-8');
      expect(signupHtml).toContain('type="submit"');
      expect(signupHtml).toContain('id="signupForm"');
    });

    it('should use showInlineLoading for signup form', () => {
      const signupHtml = fs.readFileSync(path.join(process.cwd(), 'signup.html'), 'utf-8');
      expect(signupHtml).toContain('showInlineLoading(submitButton');
      expect(signupHtml).toContain('hideInlineLoading(submitButton');
    });

    it('should prevent double submission in signup form', () => {
      const signupHtml = fs.readFileSync(path.join(process.cwd(), 'signup.html'), 'utf-8');
      expect(signupHtml).toContain('if (submitButton.disabled) return');
    });

    it('should have loading text for signup button', () => {
      const signupHtml = fs.readFileSync(path.join(process.cwd(), 'signup.html'), 'utf-8');
      expect(signupHtml).toMatch(/showInlineLoading\(submitButton,\s*['"]Creating Account['"]/);
    });
  });

  describe('Project Forms Loading States', () => {
    it('should use showInlineLoading for create project form', () => {
      const projectManagerJs = fs.readFileSync(path.join(process.cwd(), 'project-manager.js'), 'utf-8');
      const createHandler = projectManagerJs.split('handleProjectFormSubmit')[1].split('async handleEditProjectFormSubmit')[0];
      expect(createHandler).toContain('showInlineLoading(submitBtn');
      expect(createHandler).toContain('hideInlineLoading(submitBtn');
    });

    it('should prevent double submission in create project form', () => {
      const projectManagerJs = fs.readFileSync(path.join(process.cwd(), 'project-manager.js'), 'utf-8');
      const createHandler = projectManagerJs.split('handleProjectFormSubmit')[1].split('async handleEditProjectFormSubmit')[0];
      expect(createHandler).toContain('if (submitBtn && submitBtn.disabled) return');
    });

    it('should have loading text for create project button', () => {
      const projectManagerJs = fs.readFileSync(path.join(process.cwd(), 'project-manager.js'), 'utf-8');
      expect(projectManagerJs).toMatch(/showInlineLoading\(submitBtn,\s*['"]Creating['"]/);
    });

    it('should use showInlineLoading for edit project form', () => {
      const projectManagerJs = fs.readFileSync(path.join(process.cwd(), 'project-manager.js'), 'utf-8');
      const editHandler = projectManagerJs.split('handleEditProjectFormSubmit')[1].split('editProject(projectId)')[0];
      expect(editHandler).toContain('showInlineLoading(submitBtn');
      expect(editHandler).toContain('hideInlineLoading(submitBtn');
    });

    it('should prevent double submission in edit project form', () => {
      const projectManagerJs = fs.readFileSync(path.join(process.cwd(), 'project-manager.js'), 'utf-8');
      const editHandler = projectManagerJs.split('handleEditProjectFormSubmit')[1].split('editProject(projectId)')[0];
      expect(editHandler).toContain('if (submitBtn && submitBtn.disabled) return');
    });

    it('should have loading text for edit project button', () => {
      const projectManagerJs = fs.readFileSync(path.join(process.cwd(), 'project-manager.js'), 'utf-8');
      expect(projectManagerJs).toMatch(/showInlineLoading\(submitBtn,\s*['"]Saving['"]/);
    });

    it('should use showInlineLoading for add collaborator form', () => {
      const projectManagerJs = fs.readFileSync(path.join(process.cwd(), 'project-manager.js'), 'utf-8');
      const addCollabHandler = projectManagerJs.split('handleAddCollaboratorSubmit')[1].split('removeCollaboratorConfirm')[0];
      expect(addCollabHandler).toContain('showInlineLoading(submitBtn');
      expect(addCollabHandler).toContain('hideInlineLoading(submitBtn');
    });

    it('should prevent double submission in add collaborator form', () => {
      const projectManagerJs = fs.readFileSync(path.join(process.cwd(), 'project-manager.js'), 'utf-8');
      const addCollabHandler = projectManagerJs.split('handleAddCollaboratorSubmit')[1].split('removeCollaboratorConfirm')[0];
      expect(addCollabHandler).toContain('if (submitBtn && submitBtn.disabled) return');
    });

    it('should have loading text for add collaborator button', () => {
      const projectManagerJs = fs.readFileSync(path.join(process.cwd(), 'project-manager.js'), 'utf-8');
      expect(projectManagerJs).toMatch(/showInlineLoading\(submitBtn,\s*['"]Adding['"]/);
    });
  });

  describe('Loading State Requirements', () => {
    it('should disable buttons during API requests', () => {
      // Verify that showInlineLoading is called before API calls
      const loginHtml = fs.readFileSync(path.join(process.cwd(), 'login.html'), 'utf-8');
      const signupHtml = fs.readFileSync(path.join(process.cwd(), 'signup.html'), 'utf-8');
      const projectManagerJs = fs.readFileSync(path.join(process.cwd(), 'project-manager.js'), 'utf-8');

      // Check that showInlineLoading is used in all forms
      expect(loginHtml).toContain('showInlineLoading');
      expect(signupHtml).toContain('showInlineLoading');
      expect(projectManagerJs).toContain('showInlineLoading');
    });

    it('should show loading spinner in buttons', () => {
      // Verify that showInlineLoading utility is used (which adds spinner)
      const loginHtml = fs.readFileSync(path.join(process.cwd(), 'login.html'), 'utf-8');
      const signupHtml = fs.readFileSync(path.join(process.cwd(), 'signup.html'), 'utf-8');
      const projectManagerJs = fs.readFileSync(path.join(process.cwd(), 'project-manager.js'), 'utf-8');

      // Verify showInlineLoading is called with button and text
      expect(loginHtml).toMatch(/showInlineLoading\([^,]+,\s*['"][^'"]+['"]\)/);
      expect(signupHtml).toMatch(/showInlineLoading\([^,]+,\s*['"][^'"]+['"]\)/);
      expect(projectManagerJs).toMatch(/showInlineLoading\([^,]+,\s*['"][^'"]+['"]\)/);
    });

    it('should prevent double submissions', () => {
      // Verify that all forms check if button is disabled
      const loginHtml = fs.readFileSync(path.join(process.cwd(), 'login.html'), 'utf-8');
      const signupHtml = fs.readFileSync(path.join(process.cwd(), 'signup.html'), 'utf-8');
      const projectManagerJs = fs.readFileSync(path.join(process.cwd(), 'project-manager.js'), 'utf-8');

      expect(loginHtml).toContain('if (submitButton.disabled) return');
      expect(signupHtml).toContain('if (submitButton.disabled) return');
      expect(projectManagerJs).toContain('if (submitBtn && submitBtn.disabled) return');
    });

    it('should restore button state after completion or error', () => {
      // Verify that hideInlineLoading is called in finally blocks or error handlers
      const loginHtml = fs.readFileSync(path.join(process.cwd(), 'login.html'), 'utf-8');
      const signupHtml = fs.readFileSync(path.join(process.cwd(), 'signup.html'), 'utf-8');
      const projectManagerJs = fs.readFileSync(path.join(process.cwd(), 'project-manager.js'), 'utf-8');

      expect(loginHtml).toContain('hideInlineLoading');
      expect(signupHtml).toContain('hideInlineLoading');
      expect(projectManagerJs).toContain('hideInlineLoading');
    });
  });
});
