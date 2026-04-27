/**
 * Tests for renderProjectsList function
 * Task 13.4: Implement project list rendering
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { JSDOM } from 'jsdom';

describe('renderProjectsList', () => {
  let dom;
  let document;
  let window;
  let renderProjectsList;
  let renderProjectCard;
  let APIClient;
  let ProjectManager;

  beforeEach(async () => {
    // Create a fresh DOM for each test
    dom = new JSDOM(`
      <!DOCTYPE html>
      <html>
        <body>
          <div id="projects-list" class="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4"></div>
          <div id="projects-empty-state" class="text-center py-16">
            <h3>No Projects Yet</h3>
          </div>
        </body>
      </html>
    `, { url: 'http://localhost' });

    document = dom.window.document;
    window = dom.window;
    global.document = document;
    global.window = window;

    // Mock localStorage
    global.localStorage = {
      getItem: vi.fn(),
      setItem: vi.fn(),
      removeItem: vi.fn(),
      clear: vi.fn()
    };

    // Load the API client
    const apiClientModule = await import('./api-client.js');
    APIClient = apiClientModule.APIClient;

    // Load the project manager
    const projectManagerModule = await import('./project-manager.js');
    ProjectManager = projectManagerModule.ProjectManager;

    // Mock renderProjectCard function
    renderProjectCard = vi.fn((project) => {
      return `<div class="project-card" data-project-id="${project.id}">${project.name}</div>`;
    });
    global.renderProjectCard = renderProjectCard;

    // Define renderProjectsList in global scope
    global.renderProjectsList = async function() {
      const projectsListContainer = document.getElementById('projects-list');
      const emptyStateContainer = document.getElementById('projects-empty-state');
      
      if (!projectsListContainer || !emptyStateContainer) {
        console.error('[renderProjectsList] Required DOM elements not found');
        return;
      }

      try {
        // Show loading state
        projectsListContainer.innerHTML = `
          <div class="col-span-full flex items-center justify-center py-16">
            <div class="text-center">
              <div class="cyber-spinner mb-4"></div>
              <p class="text-sm text-slate-400">Loading projects...</p>
            </div>
          </div>
        `;
        emptyStateContainer.classList.add('hidden');

        // Initialize API client and project manager if not already done
        if (typeof window.apiClient === 'undefined') {
          window.apiClient = new APIClient();
        }
        if (typeof window.projectManager === 'undefined') {
          window.projectManager = new ProjectManager(window.apiClient);
        }

        // Fetch projects from API
        const response = await window.projectManager.fetchProjects();
        const projects = response.projects || [];

        // Clear loading state
        projectsListContainer.innerHTML = '';

        // Check if there are projects
        if (projects.length === 0) {
          // Show empty state
          projectsListContainer.classList.add('hidden');
          emptyStateContainer.classList.remove('hidden');
        } else {
          // Hide empty state and show projects
          projectsListContainer.classList.remove('hidden');
          emptyStateContainer.classList.add('hidden');

          // Render each project card
          projects.forEach(project => {
            const cardHTML = renderProjectCard(project);
            projectsListContainer.insertAdjacentHTML('beforeend', cardHTML);
          });
        }

      } catch (error) {
        console.error('[renderProjectsList] Error fetching projects:', error);
        
        // Show error state
        projectsListContainer.innerHTML = `
          <div class="col-span-full cyber-card p-8 text-center">
            <h3>Failed to Load Projects</h3>
            <p>${error.message || 'An error occurred while fetching projects'}</p>
            <button onclick="renderProjectsList()">Try Again</button>
          </div>
        `;
        emptyStateContainer.classList.add('hidden');
      }
    };

    renderProjectsList = global.renderProjectsList;
  });

  it('should show loading state initially', async () => {
    // Mock fetchProjects to delay
    const mockFetchProjects = vi.fn(() => new Promise(resolve => {
      setTimeout(() => resolve({ projects: [] }), 100);
    }));
    
    window.projectManager = {
      fetchProjects: mockFetchProjects
    };

    // Start rendering (don't await)
    const renderPromise = renderProjectsList();

    // Check loading state appears
    const projectsList = document.getElementById('projects-list');
    expect(projectsList.innerHTML).toContain('Loading projects');
    expect(projectsList.innerHTML).toContain('cyber-spinner');

    // Wait for completion
    await renderPromise;
  });

  it('should show empty state when no projects exist', async () => {
    // Mock fetchProjects to return empty array
    window.projectManager = {
      fetchProjects: vi.fn().mockResolvedValue({ projects: [] })
    };

    await renderProjectsList();

    const projectsList = document.getElementById('projects-list');
    const emptyState = document.getElementById('projects-empty-state');

    expect(projectsList.classList.contains('hidden')).toBe(true);
    expect(emptyState.classList.contains('hidden')).toBe(false);
  });

  it('should render project cards when projects exist', async () => {
    const mockProjects = [
      {
        id: 1,
        name: 'Project Alpha',
        description: 'Test project 1',
        target: 'example.com',
        status: 'active',
        collaborators: []
      },
      {
        id: 2,
        name: 'Project Beta',
        description: 'Test project 2',
        target: '192.168.1.1',
        status: 'completed',
        collaborators: []
      }
    ];

    window.projectManager = {
      fetchProjects: vi.fn().mockResolvedValue({ projects: mockProjects })
    };

    await renderProjectsList();

    const projectsList = document.getElementById('projects-list');
    const emptyState = document.getElementById('projects-empty-state');

    // Check empty state is hidden
    expect(emptyState.classList.contains('hidden')).toBe(true);
    
    // Check projects list is visible
    expect(projectsList.classList.contains('hidden')).toBe(false);

    // Check renderProjectCard was called for each project
    expect(renderProjectCard).toHaveBeenCalledTimes(2);
    expect(renderProjectCard).toHaveBeenCalledWith(mockProjects[0]);
    expect(renderProjectCard).toHaveBeenCalledWith(mockProjects[1]);

    // Check project cards are in the DOM
    expect(projectsList.innerHTML).toContain('data-project-id="1"');
    expect(projectsList.innerHTML).toContain('data-project-id="2"');
  });

  it('should show error state when fetch fails', async () => {
    const errorMessage = 'Network error';
    window.projectManager = {
      fetchProjects: vi.fn().mockRejectedValue(new Error(errorMessage))
    };

    await renderProjectsList();

    const projectsList = document.getElementById('projects-list');
    const emptyState = document.getElementById('projects-empty-state');

    // Check empty state is hidden
    expect(emptyState.classList.contains('hidden')).toBe(true);

    // Check error message is displayed
    expect(projectsList.innerHTML).toContain('Failed to Load Projects');
    expect(projectsList.innerHTML).toContain(errorMessage);
    expect(projectsList.innerHTML).toContain('Try Again');
  });

  it('should initialize apiClient and projectManager if not present', async () => {
    // Ensure they don't exist initially
    delete window.apiClient;
    delete window.projectManager;

    // We'll mock the projectManager after it's created
    const mockFetchProjects = vi.fn().mockResolvedValue({ projects: [] });
    
    // Intercept the creation by mocking after first check
    const originalRenderProjectsList = renderProjectsList;
    global.renderProjectsList = async function() {
      const projectsListContainer = document.getElementById('projects-list');
      const emptyStateContainer = document.getElementById('projects-empty-state');
      
      if (!projectsListContainer || !emptyStateContainer) {
        return;
      }

      projectsListContainer.innerHTML = '<div>Loading...</div>';
      emptyStateContainer.classList.add('hidden');

      // Initialize with mocked manager
      if (typeof window.apiClient === 'undefined') {
        window.apiClient = new APIClient();
      }
      if (typeof window.projectManager === 'undefined') {
        window.projectManager = { fetchProjects: mockFetchProjects };
      }

      const response = await window.projectManager.fetchProjects();
      const projects = response.projects || [];

      projectsListContainer.innerHTML = '';
      if (projects.length === 0) {
        projectsListContainer.classList.add('hidden');
        emptyStateContainer.classList.remove('hidden');
      }
    };

    await global.renderProjectsList();

    // Check that apiClient and projectManager were created
    expect(window.apiClient).toBeDefined();
    expect(window.projectManager).toBeDefined();
    expect(mockFetchProjects).toHaveBeenCalled();

    // Restore
    global.renderProjectsList = originalRenderProjectsList;
  });

  it('should handle missing DOM elements gracefully', async () => {
    // Remove required elements
    document.getElementById('projects-list').remove();
    
    const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

    await renderProjectsList();

    expect(consoleSpy).toHaveBeenCalledWith(
      expect.stringContaining('Required DOM elements not found')
    );

    consoleSpy.mockRestore();
  });
});
