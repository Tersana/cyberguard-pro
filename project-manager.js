/**
 * CyberGuard Pro Project Management System
 * Handles security project CRUD operations and collaborator management
 * Version: 1.0.1 - Fixed normalizeCollaboratorData conflicts
 */

console.log('[ProjectManager] Loading project-manager.js v1.0.1');

// Import normalizer functions (available globally in browser, imported in Node)
// In browser, these are already defined by data-normalizer.js
// In Node (testing), we need to require them
if (typeof window === 'undefined' && typeof require !== 'undefined') {
  // Node environment (testing) - require the module
  try {
    const normalizer = require('./data-normalizer.js');
    global.normalizeCollaboratorData = normalizer.normalizeCollaboratorData;
  } catch (e) {
    // Fallback if module not available
    console.warn('[ProjectManager] normalizeCollaboratorData not available');
  }
}

class ProjectManager {
  constructor(apiClient) {
    this.apiClient = apiClient;
    this.projects = [];
  }

  /**
   * Fetch all projects with optional pagination
   * @param {number} page - Page number (default: 1)
   * @param {number} limit - Items per page (default: 20)
   * @returns {Promise<Object>} Projects array and pagination info
   */
  async fetchProjects(page = 1, limit = 20) {
    try {
      // Show loading indicator
      if (typeof showContainerLoading !== 'undefined') {
        showContainerLoading('#projects-list', 'Loading projects...');
      }
      
      const endpoint = `/projects?page=${page}&limit=${limit}`;
      const response = await this.apiClient.get(endpoint);
      
      // Handle both paginated and non-paginated responses
      if (response.projects) {
        // Paginated response
        this.projects = response.projects;
        return {
          projects: response.projects,
          pagination: response.pagination || null
        };
      } else if (Array.isArray(response)) {
        // Non-paginated response (array of projects)
        this.projects = response;
        return {
          projects: response,
          pagination: null
        };
      } else {
        // Unexpected format
        this.projects = [];
        return {
          projects: [],
          pagination: null
        };
      }
    } catch (error) {
      console.error('[ProjectManager] Error fetching projects:', error);
      throw error;
    } finally {
      // Hide loading indicator
      if (typeof hideContainerLoading !== 'undefined') {
        hideContainerLoading('#projects-list');
      }
    }
  }

  /**
   * Fetch a single project by ID
   * @param {number} projectId - Project ID
   * @returns {Promise<Object>} Project details
   */
  async fetchProject(projectId) {
    try {
      const response = await this.apiClient.get(`/projects/${projectId}`);
      
      // Handle both wrapped and direct project responses
      return response.project || response;
    } catch (error) {
      console.error(`[ProjectManager] Error fetching project ${projectId}:`, error);
      throw error;
    }
  }

  /**
   * Create a new project
   * @param {Object} projectData - Project data (name, description, target, status)
   * @returns {Promise<Object>} Created project
   */
  async createProject(projectData) {
    try {
      // Show loading indicator
      if (typeof showLoading !== 'undefined') {
        showLoading('Creating project...');
      }
      
      // Validate required fields
      if (!projectData.name || !projectData.name.trim()) {
        throw new Error('Project name is required');
      }
      
      if (!projectData.target || !projectData.target.trim()) {
        throw new Error('Project target is required');
      }

      const response = await this.apiClient.post('/projects', projectData);
      
      // Handle both wrapped and direct project responses
      const newProject = response.project || response;
      
      // Add to local projects array
      this.projects.push(newProject);
      
      return newProject;
    } catch (error) {
      console.error('[ProjectManager] Error creating project:', error);
      throw error;
    } finally {
      // Hide loading indicator
      if (typeof hideLoading !== 'undefined') {
        hideLoading();
      }
    }
  }

  /**
   * Update an existing project
   * @param {number} projectId - Project ID
   * @param {Object} projectData - Updated project data
   * @returns {Promise<Object>} Updated project
   */
  async updateProject(projectId, projectData) {
    try {
      // Show loading indicator
      if (typeof showLoading !== 'undefined') {
        showLoading('Updating project...');
      }
      
      const response = await this.apiClient.put(`/projects/${projectId}`, projectData);
      
      // Handle both wrapped and direct project responses
      const updatedProject = response.project || response;
      
      // Update in local projects array
      const index = this.projects.findIndex(p => p.id === projectId);
      if (index !== -1) {
        this.projects[index] = updatedProject;
      }
      
      return updatedProject;
    } catch (error) {
      console.error(`[ProjectManager] Error updating project ${projectId}:`, error);
      throw error;
    } finally {
      // Hide loading indicator
      if (typeof hideLoading !== 'undefined') {
        hideLoading();
      }
    }
  }

  /**
   * Delete a project
   * @param {number} projectId - Project ID
   * @returns {Promise<Object>} Deletion confirmation
   */
  async deleteProject(projectId) {
    try {
      // Show loading indicator
      if (typeof showLoading !== 'undefined') {
        showLoading('Deleting project...');
      }
      
      const response = await this.apiClient.delete(`/projects/${projectId}`);
      
      // Remove from local projects array
      this.projects = this.projects.filter(p => p.id !== projectId);
      
      return response;
    } catch (error) {
      console.error(`[ProjectManager] Error deleting project ${projectId}:`, error);
      throw error;
    } finally {
      // Hide loading indicator
      if (typeof hideLoading !== 'undefined') {
        hideLoading();
      }
    }
  }

  /**
   * Fetch collaborators for a project
   * @param {number} projectId - Project ID
   * @returns {Promise<Array>} Array of collaborators
   */
  async fetchCollaborators(projectId) {
    try {
      const response = await this.apiClient.get(`/projects/${projectId}/collaborators`);
      
      // Handle both wrapped and direct array responses
      const collaborators = response.collaborators || response;
      
      // Normalize collaborator data to handle job_title/job_tittle inconsistency
      const normalizeFunc = typeof window !== 'undefined' ? window.normalizeCollaboratorData : normalizeCollaboratorData;
      return collaborators.map(collab => normalizeFunc(collab));
    } catch (error) {
      console.error(`[ProjectManager] Error fetching collaborators for project ${projectId}:`, error);
      throw error;
    }
  }

  /**
   * Add a collaborator to a project
   * @param {number} projectId - Project ID
   * @param {number} userId - User ID to add as collaborator
   * @returns {Promise<Object>} Added collaborator details
   */
  async addCollaborator(projectId, userId) {
    try {
      // Show loading indicator
      if (typeof showLoading !== 'undefined') {
        showLoading('Adding collaborator...');
      }
      
      const response = await this.apiClient.post(`/projects/${projectId}/collaborators`, { user_id: userId });
      
      // Handle both wrapped and direct collaborator responses
      const collaborator = response.collaborator || response;
      
      // Normalize collaborator data to handle job_title/job_tittle inconsistency
      const normalizeFunc = typeof window !== 'undefined' ? window.normalizeCollaboratorData : normalizeCollaboratorData;
      return normalizeFunc(collaborator);
    } catch (error) {
      console.error(`[ProjectManager] Error adding collaborator to project ${projectId}:`, error);
      throw error;
    } finally {
      // Hide loading indicator
      if (typeof hideLoading !== 'undefined') {
        hideLoading();
      }
    }
  }

  /**
   * Remove a collaborator from a project
   * @param {number} projectId - Project ID
   * @param {number} userId - User ID to remove
   * @returns {Promise<Object>} Removal confirmation
   */
  async removeCollaborator(projectId, userId) {
    try {
      // Show loading indicator
      if (typeof showLoading !== 'undefined') {
        showLoading('Removing collaborator...');
      }
      
      const response = await this.apiClient.delete(`/projects/${projectId}/collaborators/${userId}`);
      
      return response;
    } catch (error) {
      console.error(`[ProjectManager] Error removing collaborator from project ${projectId}:`, error);
      throw error;
    } finally {
      // Hide loading indicator
      if (typeof hideLoading !== 'undefined') {
        hideLoading();
      }
    }
  }

  /**
   * Show the create project modal
   */
  showCreateProjectModal() {
    const modal = document.getElementById('create-project-modal');
    if (modal) {
      // Reset form
      const form = document.getElementById('create-project-form');
      if (form) {
        form.reset();
        this.clearFormErrors();
      }
      
      // Show modal
      modal.classList.remove('hidden');
    }
  }

  /**
   * Hide the create project modal
   */
  hideCreateProjectModal() {
    const modal = document.getElementById('create-project-modal');
    if (modal) {
      modal.classList.add('hidden');
    }
  }

  /**
   * Clear all form validation errors
   */
  clearFormErrors() {
    const errorElements = [
      'project-name-error',
      'project-description-error',
      'project-target-error',
      'project-status-error'
    ];
    
    errorElements.forEach(id => {
      const el = document.getElementById(id);
      if (el) {
        el.textContent = '';
        el.classList.add('hidden');
      }
    });

    // Remove error styling from inputs
    const inputs = ['project-name', 'project-description', 'project-target', 'project-status'];
    inputs.forEach(id => {
      const input = document.getElementById(id);
      if (input) {
        input.classList.remove('border-red-500/50');
      }
    });
  }

  /**
   * Display validation error for a specific field
   * @param {string} fieldId - Field ID
   * @param {string} message - Error message
   */
  showFieldError(fieldId, message) {
    const input = document.getElementById(fieldId);
    const errorEl = document.getElementById(`${fieldId}-error`);
    
    if (input) {
      input.classList.add('border-red-500/50');
    }
    
    if (errorEl) {
      errorEl.textContent = message;
      errorEl.classList.remove('hidden');
    }
  }

  /**
   * Validate project form data
   * @param {Object} formData - Form data to validate
   * @returns {Object} Validation result { valid: boolean, errors: Object }
   */
  validateProjectForm(formData) {
    const errors = {};
    let valid = true;

    // Validate name (required)
    if (!formData.name || !formData.name.trim()) {
      errors.name = 'Project name is required';
      valid = false;
    } else if (formData.name.trim().length < 3) {
      errors.name = 'Project name must be at least 3 characters';
      valid = false;
    }

    // Validate target (required)
    if (!formData.target || !formData.target.trim()) {
      errors.target = 'Target is required';
      valid = false;
    }

    return { valid, errors };
  }

  /**
   * Handle project form submission
   * @param {Event} event - Form submit event
   */
  async handleProjectFormSubmit(event) {
    event.preventDefault();
    
    // Clear previous errors
    this.clearFormErrors();

    // Get form data
    const form = event.target;
    const formData = {
      name: form.name.value.trim(),
      description: form.description.value.trim(),
      target: form.target.value.trim(),
      status: form.status.value
    };

    // Validate form
    const validation = this.validateProjectForm(formData);
    if (!validation.valid) {
      // Display validation errors
      Object.keys(validation.errors).forEach(field => {
        this.showFieldError(`project-${field}`, validation.errors[field]);
      });
      return;
    }

    // Get submit button
    const submitBtn = document.getElementById('create-project-submit');
    
    // Prevent double submission
    if (submitBtn && submitBtn.disabled) return;
    
    // Show loading state on button
    if (submitBtn) {
      showInlineLoading(submitBtn, 'Creating');
    }

    try {
      // Create project via API
      const newProject = await this.createProject(formData);
      
      // Success: close modal and refresh project list
      this.hideCreateProjectModal();
      
      // Show success notification
      if (window.CyberNotify) {
        window.CyberNotify.alert('Project created successfully!', { type: 'success' });
      }
      
      // Refresh project list
      await this.renderProjectsList();
      
    } catch (error) {
      console.error('[ProjectManager] Error creating project:', error);
      
      // Handle validation errors from API (422)
      if (error.status === 422 && error.errors) {
        // Display inline validation errors
        error.errors.forEach(err => {
          const fieldId = `project-${err.field}`;
          this.showFieldError(fieldId, err.message);
        });
      } else {
        // Show generic error notification
        const errorMessage = error.message || 'Failed to create project. Please try again.';
        if (window.CyberNotify) {
          window.CyberNotify.alert(errorMessage, { type: 'error' });
        }
      }
    } finally {
      // Restore button state
      if (submitBtn) {
        hideInlineLoading(submitBtn);
      }
    }
  }

  /**
   * Render projects list in the UI
   */
  async renderProjectsList() {
    const listContainer = document.getElementById('projects-list');
    const emptyState = document.getElementById('projects-empty-state');
    
    if (!listContainer) return;

    try {
      // Fetch projects
      const { projects } = await this.fetchProjects();
      
      // Show/hide empty state
      if (projects.length === 0) {
        if (listContainer) listContainer.classList.add('hidden');
        if (emptyState) emptyState.classList.remove('hidden');
        return;
      }
      
      if (listContainer) listContainer.classList.remove('hidden');
      if (emptyState) emptyState.classList.add('hidden');
      
      // Render project cards
      listContainer.innerHTML = projects.map(project => this.renderProjectCard(project)).join('');
      
    } catch (error) {
      console.error('[ProjectManager] Error rendering projects list:', error);
      
      // Show error message
      if (window.CyberNotify) {
        window.CyberNotify.alert('Failed to load projects', { type: 'error' });
      }
    }
  }

  /**
   * Render a single project card
   * @param {Object} project - Project data
   * @returns {string} HTML string for project card
   */
  renderProjectCard(project) {
    const statusBadgeClass = {
      'active': 'cyber-badge-safe',
      'completed': 'cyber-badge-info',
      'archived': 'cyber-badge-warning'
    }[project.status] || 'cyber-badge-safe';

    const statusText = project.status.charAt(0).toUpperCase() + project.status.slice(1);
    
    return `
      <div class="cyber-card p-5 hover:border-purple-500/40 transition-all cursor-pointer" data-project-id="${project.id}">
        <div class="flex items-start justify-between mb-3">
          <div class="flex-1">
            <h3 class="text-base font-bold text-white mb-1">${this.escapeHtml(project.name)}</h3>
            <p class="text-xs text-slate-400 line-clamp-2">${this.escapeHtml(project.description || 'No description')}</p>
          </div>
          <span class="${statusBadgeClass} text-xs px-2 py-1 rounded">${statusText}</span>
        </div>
        
        <div class="flex items-center gap-2 text-xs text-slate-500 mb-3">
          <svg class="w-3.5 h-3.5" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" d="M15 10.5a3 3 0 1 1-6 0 3 3 0 0 1 6 0Z" />
            <path stroke-linecap="round" stroke-linejoin="round" d="M19.5 10.5c0 7.142-7.5 11.25-7.5 11.25S4.5 17.642 4.5 10.5a7.5 7.5 0 1 1 15 0Z" />
          </svg>
          <span class="font-mono">${this.escapeHtml(project.target)}</span>
        </div>
        
        <div class="flex items-center justify-between pt-3 border-t border-white/5">
          <div class="text-xs text-slate-500">
            Created ${this.formatDate(project.created_at)}
          </div>
          
          <div class="flex gap-1">
            <button class="cyber-btn-ghost text-xs px-2 py-1 rounded" onclick="projectManager.editProject(${project.id})" title="Edit project">
              <svg class="w-3.5 h-3.5" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" d="m16.862 4.487 1.687-1.688a1.875 1.875 0 1 1 2.652 2.652L10.582 16.07a4.5 4.5 0 0 1-1.897 1.13L6 18l.8-2.685a4.5 4.5 0 0 1 1.13-1.897l8.932-8.931Zm0 0L19.5 7.125M18 14v4.75A2.25 2.25 0 0 1 15.75 21H5.25A2.25 2.25 0 0 1 3 18.75V8.25A2.25 2.25 0 0 1 5.25 6H10" />
              </svg>
            </button>
            <button class="cyber-btn-danger text-xs px-2 py-1 rounded" onclick="projectManager.deleteProjectConfirm(${project.id})" title="Delete project">
              <svg class="w-3.5 h-3.5" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" d="m14.74 9-.346 9m-4.788 0L9.26 9m9.968-3.21c.342.052.682.107 1.022.166m-1.022-.165L18.16 19.673a2.25 2.25 0 0 1-2.244 2.077H8.084a2.25 2.25 0 0 1-2.244-2.077L4.772 5.79m14.456 0a48.108 48.108 0 0 0-3.478-.397m-12 .562c.34-.059.68-.114 1.022-.165m0 0a48.11 48.11 0 0 1 3.478-.397m7.5 0v-.916c0-1.18-.91-2.164-2.09-2.201a51.964 51.964 0 0 0-3.32 0c-1.18.037-2.09 1.022-2.09 2.201v.916m7.5 0a48.667 48.667 0 0 0-7.5 0" />
              </svg>
            </button>
          </div>
        </div>
      </div>
    `;
  }

  /**
   * Escape HTML to prevent XSS
   * @param {string} text - Text to escape
   * @returns {string} Escaped text
   */
  escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }

  /**
   * Format date for display
   * @param {string} dateString - ISO date string
   * @returns {string} Formatted date
   */
  formatDate(dateString) {
    if (!dateString) return 'Unknown';
    
    const date = new Date(dateString);
    const now = new Date();
    const diffMs = now - date;
    const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));
    
    if (diffDays === 0) return 'Today';
    if (diffDays === 1) return 'Yesterday';
    if (diffDays < 7) return `${diffDays} days ago`;
    if (diffDays < 30) return `${Math.floor(diffDays / 7)} weeks ago`;
    
    return date.toLocaleDateString();
  }

  /**
   * Show the edit project modal with pre-populated data
   * @param {number} projectId - Project ID to edit
   */
  async showEditProjectModal(projectId) {
    const modal = document.getElementById('edit-project-modal');
    if (!modal) return;

    try {
      // Fetch project details
      const project = await this.fetchProject(projectId);
      
      // Populate form fields
      document.getElementById('edit-project-id').value = project.id;
      document.getElementById('edit-project-name').value = project.name || '';
      document.getElementById('edit-project-description').value = project.description || '';
      document.getElementById('edit-project-target').value = project.target || '';
      document.getElementById('edit-project-status').value = project.status || 'active';
      
      // Clear any previous errors
      this.clearEditFormErrors();
      
      // Load collaborators
      await this.loadCollaborators(projectId);
      
      // Show modal
      modal.classList.remove('hidden');
      
    } catch (error) {
      console.error('[ProjectManager] Error loading project for edit:', error);
      
      if (window.CyberNotify) {
        window.CyberNotify.alert('Failed to load project details', { type: 'error' });
      }
    }
  }

  /**
   * Hide the edit project modal
   */
  hideEditProjectModal() {
    const modal = document.getElementById('edit-project-modal');
    if (modal) {
      modal.classList.add('hidden');
    }
  }

  /**
   * Clear all edit form validation errors
   */
  clearEditFormErrors() {
    const errorElements = [
      'edit-project-name-error',
      'edit-project-description-error',
      'edit-project-target-error',
      'edit-project-status-error'
    ];
    
    errorElements.forEach(id => {
      const el = document.getElementById(id);
      if (el) {
        el.textContent = '';
        el.classList.add('hidden');
      }
    });

    // Remove error styling from inputs
    const inputs = ['edit-project-name', 'edit-project-description', 'edit-project-target', 'edit-project-status'];
    inputs.forEach(id => {
      const input = document.getElementById(id);
      if (input) {
        input.classList.remove('border-red-500/50');
      }
    });
  }

  /**
   * Display validation error for a specific edit form field
   * @param {string} fieldId - Field ID
   * @param {string} message - Error message
   */
  showEditFieldError(fieldId, message) {
    const input = document.getElementById(fieldId);
    const errorEl = document.getElementById(`${fieldId}-error`);
    
    if (input) {
      input.classList.add('border-red-500/50');
    }
    
    if (errorEl) {
      errorEl.textContent = message;
      errorEl.classList.remove('hidden');
    }
  }

  /**
   * Handle edit project form submission
   * @param {Event} event - Form submit event
   */
  async handleEditProjectFormSubmit(event) {
    event.preventDefault();
    
    // Clear previous errors
    this.clearEditFormErrors();

    // Get form data
    const form = event.target;
    const projectId = parseInt(document.getElementById('edit-project-id').value);
    const formData = {
      name: form.name.value.trim(),
      description: form.description.value.trim(),
      target: form.target.value.trim(),
      status: form.status.value
    };

    // Validate form
    const validation = this.validateProjectForm(formData);
    if (!validation.valid) {
      // Display validation errors
      Object.keys(validation.errors).forEach(field => {
        this.showEditFieldError(`edit-project-${field}`, validation.errors[field]);
      });
      return;
    }

    // Get submit button
    const submitBtn = document.getElementById('edit-project-submit');
    
    // Prevent double submission
    if (submitBtn && submitBtn.disabled) return;
    
    // Show loading state on button
    if (submitBtn) {
      showInlineLoading(submitBtn, 'Saving');
    }

    try {
      // Update project via API
      await this.updateProject(projectId, formData);
      
      // Success: close modal and refresh project list
      this.hideEditProjectModal();
      
      // Show success notification
      if (window.CyberNotify) {
        window.CyberNotify.alert('Project updated successfully!', { type: 'success' });
      }
      
      // Refresh project list
      await this.renderProjectsList();
      
    } catch (error) {
      console.error('[ProjectManager] Error updating project:', error);
      
      // Handle validation errors from API (422)
      if (error.status === 422 && error.errors) {
        // Display inline validation errors
        error.errors.forEach(err => {
          const fieldId = `edit-project-${err.field}`;
          this.showEditFieldError(fieldId, err.message);
        });
      } else {
        // Show generic error notification
        const errorMessage = error.message || 'Failed to update project. Please try again.';
        if (window.CyberNotify) {
          window.CyberNotify.alert(errorMessage, { type: 'error' });
        }
      }
    } finally {
      // Restore button state
      if (submitBtn) {
        hideInlineLoading(submitBtn);
      }
    }
  }

  /**
   * Placeholder for edit project functionality
   * @param {number} projectId - Project ID
   */
  editProject(projectId) {
    console.log('[ProjectManager] Edit project:', projectId);
    this.showEditProjectModal(projectId);
  }

  /**
   * Load and render collaborators for a project
   * @param {number} projectId - Project ID
   */
  async loadCollaborators(projectId) {
    const listContainer = document.getElementById('collaborators-list');
    if (!listContainer) return;

    try {
      // Show loading state using container loading utility
      showContainerLoading('#collaborators-list', 'Loading collaborators...');
      
      // Fetch collaborators
      const collaborators = await this.fetchCollaborators(projectId);
      
      // Render collaborators
      if (collaborators.length === 0) {
        listContainer.innerHTML = '<div class="text-center py-4 text-xs text-slate-500">No collaborators yet</div>';
      } else {
        listContainer.innerHTML = collaborators.map(collab => this.renderCollaboratorItem(collab, projectId)).join('');
      }
      
    } catch (error) {
      console.error('[ProjectManager] Error loading collaborators:', error);
      listContainer.innerHTML = '<div class="text-center py-4 text-xs text-red-400">Failed to load collaborators</div>';
    } finally {
      // Hide loading state
      hideContainerLoading('#collaborators-list');
    }
  }

  /**
   * Render a single collaborator item
   * @param {Object} collaborator - Collaborator data (normalized)
   * @param {number} projectId - Project ID
   * @returns {string} HTML string for collaborator item
   */
  renderCollaboratorItem(collaborator, projectId) {
    const initials = this.getInitials(collaborator.fullName || 'User');
    const displayName = this.escapeHtml(collaborator.fullName || 'Unknown User');
    const role = this.escapeHtml(collaborator.role || 'Collaborator');
    const jobTitle = collaborator.jobTitle ? this.escapeHtml(collaborator.jobTitle) : role;
    
    return `
      <div class="cyber-card p-3 flex items-center justify-between">
        <div class="flex items-center gap-3">
          <div class="cyber-avatar-sm flex-shrink-0">
            <span class="text-xs font-bold text-white">${initials}</span>
          </div>
          <div>
            <p class="text-sm font-semibold text-white">${displayName}</p>
            <p class="text-xs text-slate-400">${jobTitle}</p>
          </div>
        </div>
        <button 
          class="cyber-btn-danger text-xs px-2 py-1 rounded flex items-center gap-1"
          onclick="projectManager.removeCollaboratorConfirm(${projectId}, ${collaborator.id})"
          title="Remove collaborator"
        >
          <svg class="w-3.5 h-3.5" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12" />
          </svg>
          Remove
        </button>
      </div>
    `;
  }

  /**
   * Get initials from a name
   * @param {string} name - Full name
   * @returns {string} Initials (max 2 characters)
   */
  getInitials(name) {
    if (!name) return 'U';
    
    const parts = name.trim().split(/\s+/);
    if (parts.length === 1) {
      return parts[0].charAt(0).toUpperCase();
    }
    
    return (parts[0].charAt(0) + parts[parts.length - 1].charAt(0)).toUpperCase();
  }

  /**
   * Show the add collaborator modal
   */
  showAddCollaboratorModal() {
    const modal = document.getElementById('add-collaborator-modal');
    if (modal) {
      // Reset form
      const form = document.getElementById('add-collaborator-form');
      if (form) {
        form.reset();
        this.clearAddCollaboratorErrors();
      }
      
      // Show modal
      modal.classList.remove('hidden');
    }
  }

  /**
   * Hide the add collaborator modal
   */
  hideAddCollaboratorModal() {
    const modal = document.getElementById('add-collaborator-modal');
    if (modal) {
      modal.classList.add('hidden');
    }
  }

  /**
   * Clear add collaborator form errors
   */
  clearAddCollaboratorErrors() {
    const errorEl = document.getElementById('collaborator-user-id-error');
    if (errorEl) {
      errorEl.textContent = '';
      errorEl.classList.add('hidden');
    }
    
    const input = document.getElementById('collaborator-user-id');
    if (input) {
      input.classList.remove('border-red-500/50');
    }
  }

  /**
   * Show add collaborator field error
   * @param {string} message - Error message
   */
  showAddCollaboratorError(message) {
    const errorEl = document.getElementById('collaborator-user-id-error');
    const input = document.getElementById('collaborator-user-id');
    
    if (input) {
      input.classList.add('border-red-500/50');
    }
    
    if (errorEl) {
      errorEl.textContent = message;
      errorEl.classList.remove('hidden');
    }
  }

  /**
   * Handle add collaborator form submission
   * @param {Event} event - Form submit event
   */
  async handleAddCollaboratorSubmit(event) {
    event.preventDefault();
    
    // Clear previous errors
    this.clearAddCollaboratorErrors();

    // Get form data
    const form = event.target;
    const userId = parseInt(form.user_id.value);
    const projectId = parseInt(document.getElementById('edit-project-id').value);

    // Validate user ID
    if (!userId || userId < 1) {
      this.showAddCollaboratorError('Please enter a valid user ID');
      return;
    }

    // Get submit button
    const submitBtn = document.getElementById('add-collaborator-submit');
    
    // Prevent double submission
    if (submitBtn && submitBtn.disabled) return;
    
    // Show loading state on button
    if (submitBtn) {
      showInlineLoading(submitBtn, 'Adding');
    }

    try {
      // Add collaborator via API
      await this.addCollaborator(projectId, userId);
      
      // Success: close modal and reload collaborators
      this.hideAddCollaboratorModal();
      
      // Show success notification
      if (window.CyberNotify) {
        window.CyberNotify.alert('Collaborator added successfully!', { type: 'success' });
      }
      
      // Reload collaborators list
      await this.loadCollaborators(projectId);
      
    } catch (error) {
      console.error('[ProjectManager] Error adding collaborator:', error);
      
      // Handle specific error messages
      let errorMessage = 'Failed to add collaborator. Please try again.';
      
      if (error.message) {
        if (error.message.includes('not found') || error.message.includes('User not found')) {
          errorMessage = 'User not found. Please check the user ID.';
        } else if (error.message.includes('already') || error.message.includes('Already a collaborator')) {
          errorMessage = 'This user is already a collaborator.';
        } else {
          errorMessage = error.message;
        }
      }
      
      // Show error
      if (window.CyberNotify) {
        window.CyberNotify.alert(errorMessage, { type: 'error' });
      }
      
      this.showAddCollaboratorError(errorMessage);
      
    } finally {
      // Restore button state
      if (submitBtn) {
        hideInlineLoading(submitBtn);
      }
    }
  }

  /**
   * Confirm and remove collaborator
   * @param {number} projectId - Project ID
   * @param {number} userId - User ID to remove
   */
  async removeCollaboratorConfirm(projectId, userId) {
    if (window.CyberNotify && window.CyberNotify.confirm) {
      // Use CyberNotify confirm dialog
      window.CyberNotify.confirm(
        'Are you sure you want to remove this collaborator from the project?',
        async (confirmed) => {
          if (confirmed) {
            await this.handleRemoveCollaborator(projectId, userId);
          }
        },
        {
          confirmText: 'Remove',
          cancelText: 'Cancel',
          type: 'warning'
        }
      );
    } else {
      // Fallback to native confirm
      const confirmed = confirm('Are you sure you want to remove this collaborator?');
      if (confirmed) {
        await this.handleRemoveCollaborator(projectId, userId);
      }
    }
  }

  /**
   * Handle collaborator removal
   * @param {number} projectId - Project ID
   * @param {number} userId - User ID to remove
   */
  async handleRemoveCollaborator(projectId, userId) {
    try {
      await this.removeCollaborator(projectId, userId);
      
      // Show success notification
      if (window.CyberNotify) {
        window.CyberNotify.alert('Collaborator removed successfully', { type: 'success' });
      }
      
      // Reload collaborators list
      await this.loadCollaborators(projectId);
      
    } catch (error) {
      console.error('[ProjectManager] Error removing collaborator:', error);
      
      // Display error message
      const errorMessage = error.message || 'Failed to remove collaborator. Please try again.';
      if (window.CyberNotify) {
        window.CyberNotify.alert(errorMessage, { type: 'error' });
      }
    }
  }

  /**
   * Confirm and delete project using CyberNotify
   * @param {number} projectId - Project ID
   */
  async deleteProjectConfirm(projectId) {
    if (window.CyberNotify && window.CyberNotify.confirm) {
      // Use CyberNotify confirm dialog (callback-based)
      window.CyberNotify.confirm(
        'Are you sure you want to delete this project? This action cannot be undone.',
        async (confirmed) => {
          if (confirmed) {
            await this.handleDeleteProject(projectId);
          }
        },
        {
          confirmText: 'Delete',
          cancelText: 'Cancel',
          type: 'danger'
        }
      );
    } else {
      // Fallback to native confirm
      const confirmed = confirm('Are you sure you want to delete this project?');
      if (confirmed) {
        await this.handleDeleteProject(projectId);
      }
    }
  }

  /**
   * Handle project deletion
   * @param {number} projectId - Project ID
   */
  async handleDeleteProject(projectId) {
    try {
      await this.deleteProject(projectId);
      
      // Show success notification
      if (window.CyberNotify) {
        window.CyberNotify.alert('Project deleted successfully', { type: 'success' });
      }
      
      // Remove project card from UI immediately
      const projectCard = document.querySelector(`[data-project-id="${projectId}"]`);
      if (projectCard) {
        projectCard.remove();
      }
      
      // Check if we need to show empty state
      const listContainer = document.getElementById('projects-list');
      const emptyState = document.getElementById('projects-empty-state');
      if (listContainer && listContainer.children.length === 0) {
        if (listContainer) listContainer.classList.add('hidden');
        if (emptyState) emptyState.classList.remove('hidden');
      }
      
    } catch (error) {
      console.error('[ProjectManager] Error deleting project:', error);
      
      // Display error message
      const errorMessage = error.message || 'Failed to delete project. Please try again.';
      if (window.CyberNotify) {
        window.CyberNotify.alert(errorMessage, { type: 'error' });
      }
    }
  }
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { ProjectManager };
}

// Initialize project manager when DOM is ready
if (typeof window !== 'undefined') {
  document.addEventListener('DOMContentLoaded', () => {
    // Initialize ProjectManager if APIClient is available
    if (window.apiClient) {
      window.projectManager = new ProjectManager(window.apiClient);
      
      // Set up modal event listeners
      const newProjectBtn = document.getElementById('new-project-btn');
      const createProjectClose = document.getElementById('create-project-close');
      const createProjectCancel = document.getElementById('create-project-cancel');
      const createProjectForm = document.getElementById('create-project-form');
      
      const editProjectClose = document.getElementById('edit-project-close');
      const editProjectCancel = document.getElementById('edit-project-cancel');
      const editProjectForm = document.getElementById('edit-project-form');
      
      // Open create modal
      if (newProjectBtn) {
        newProjectBtn.addEventListener('click', () => {
          window.projectManager.showCreateProjectModal();
        });
      }
      
      // Close create modal buttons
      if (createProjectClose) {
        createProjectClose.addEventListener('click', () => {
          window.projectManager.hideCreateProjectModal();
        });
      }
      
      if (createProjectCancel) {
        createProjectCancel.addEventListener('click', () => {
          window.projectManager.hideCreateProjectModal();
        });
      }
      
      // Handle create form submission
      if (createProjectForm) {
        createProjectForm.addEventListener('submit', (event) => {
          window.projectManager.handleProjectFormSubmit(event);
        });
      }
      
      // Close edit modal buttons
      if (editProjectClose) {
        editProjectClose.addEventListener('click', () => {
          window.projectManager.hideEditProjectModal();
        });
      }
      
      if (editProjectCancel) {
        editProjectCancel.addEventListener('click', () => {
          window.projectManager.hideEditProjectModal();
        });
      }
      
      // Handle edit form submission
      if (editProjectForm) {
        editProjectForm.addEventListener('submit', (event) => {
          window.projectManager.handleEditProjectFormSubmit(event);
        });
      }
      
      // Close modals on backdrop click
      const createModal = document.getElementById('create-project-modal');
      if (createModal) {
        createModal.addEventListener('click', (event) => {
          if (event.target === createModal) {
            window.projectManager.hideCreateProjectModal();
          }
        });
      }
      
      const editModal = document.getElementById('edit-project-modal');
      if (editModal) {
        editModal.addEventListener('click', (event) => {
          if (event.target === editModal) {
            window.projectManager.hideEditProjectModal();
          }
        });
      }
      
      // Add Collaborator Modal event listeners
      const addCollaboratorBtn = document.getElementById('add-collaborator-btn');
      const addCollaboratorClose = document.getElementById('add-collaborator-close');
      const addCollaboratorCancel = document.getElementById('add-collaborator-cancel');
      const addCollaboratorForm = document.getElementById('add-collaborator-form');
      const addCollaboratorModal = document.getElementById('add-collaborator-modal');
      
      if (addCollaboratorBtn) {
        addCollaboratorBtn.addEventListener('click', () => {
          window.projectManager.showAddCollaboratorModal();
        });
      }
      
      if (addCollaboratorClose) {
        addCollaboratorClose.addEventListener('click', () => {
          window.projectManager.hideAddCollaboratorModal();
        });
      }
      
      if (addCollaboratorCancel) {
        addCollaboratorCancel.addEventListener('click', () => {
          window.projectManager.hideAddCollaboratorModal();
        });
      }
      
      if (addCollaboratorForm) {
        addCollaboratorForm.addEventListener('submit', (event) => {
          window.projectManager.handleAddCollaboratorSubmit(event);
        });
      }
      
      if (addCollaboratorModal) {
        addCollaboratorModal.addEventListener('click', (event) => {
          if (event.target === addCollaboratorModal) {
            window.projectManager.hideAddCollaboratorModal();
          }
        });
      }
      
      // Load projects when Projects tab becomes active
      // Listen for custom tab switch event
      document.addEventListener('tabSwitched', (event) => {
        if (event.detail && event.detail.tabId === 'projects') {
          console.log('[ProjectManager] Projects tab activated, loading projects...');
          // Small delay to ensure tab is visible
          setTimeout(() => {
            window.projectManager.renderProjectsList();
          }, 100);
        }
      });
      
      // Also bind to sidebar link click
      const projectsSidebarLink = document.querySelector('a[onclick*="switchToTab(\'projects\')"]');
      if (projectsSidebarLink) {
        projectsSidebarLink.addEventListener('click', () => {
          console.log('[ProjectManager] Projects sidebar link clicked');
          setTimeout(() => {
            window.projectManager.renderProjectsList();
          }, 150);
        });
      }
      
      // Also bind to empty state button
      const emptyStateBtn = document.querySelector('#projects-empty-state button');
      if (emptyStateBtn) {
        emptyStateBtn.addEventListener('click', () => {
          window.projectManager.showCreateProjectModal();
        });
      }
      
      console.log('[ProjectManager] Initialized successfully');
    } else {
      console.warn('[ProjectManager] APIClient not available, skipping initialization');
    }
  });
}
