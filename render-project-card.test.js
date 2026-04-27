/**
 * Tests for renderProjectCard function
 * Task 13.3: Implement project card component
 */

import { describe, it, expect } from 'vitest';
import fs from 'fs';
import path from 'path';

// Read main.js and extract just the renderProjectCard function
const mainJsPath = path.join(process.cwd(), 'main.js');
const mainJsContent = fs.readFileSync(mainJsPath, 'utf-8');

// Extract the renderProjectCard function using regex
const functionMatch = mainJsContent.match(/function renderProjectCard\(project\) \{[\s\S]*?\n\}/);
if (!functionMatch) {
  throw new Error('renderProjectCard function not found in main.js');
}

// Create the function in the global scope
const renderProjectCard = new Function('project', functionMatch[0].replace('function renderProjectCard(project) {', '').slice(0, -1));

describe('renderProjectCard', () => {
  it('should render a project card with all required elements', () => {
    const project = {
      id: 1,
      name: 'Test Security Project',
      description: 'A comprehensive security assessment for example.com',
      target: 'example.com',
      status: 'active',
      collaborators: [
        { id: 1, full_name: 'John Doe', email: 'john@example.com' },
        { id: 2, full_name: 'Jane Smith', email: 'jane@example.com' }
      ]
    };

    const html = renderProjectCard(project);

    // Verify HTML is returned
    expect(html).toBeTruthy();
    expect(typeof html).toBe('string');

    // Verify project name is displayed
    expect(html).toContain('Test Security Project');

    // Verify description is displayed
    expect(html).toContain('A comprehensive security assessment for example.com');

    // Verify target is displayed
    expect(html).toContain('example.com');

    // Verify status badge is displayed
    expect(html).toContain('Active');
    expect(html).toContain('cyber-badge-safe');

    // Verify collaborator count is displayed
    expect(html).toContain('2 collaborators');

    // Verify Edit and Delete buttons are present
    expect(html).toContain('editProject(1)');
    expect(html).toContain('deleteProject(1)');

    // Verify cyber-card class is applied
    expect(html).toContain('cyber-card');
  });

  it('should handle project with no collaborators', () => {
    const project = {
      id: 2,
      name: 'Solo Project',
      description: 'A project with no collaborators',
      target: '192.168.1.1',
      status: 'active',
      collaborators: []
    };

    const html = renderProjectCard(project);

    expect(html).toContain('0 collaborators');
    expect(html).not.toContain('cyber-avatar-sm');
  });

  it('should handle project with single collaborator', () => {
    const project = {
      id: 3,
      name: 'Single Collaborator Project',
      description: 'Test project',
      target: 'test.com',
      status: 'active',
      collaborators: [
        { id: 1, full_name: 'Alice Johnson', email: 'alice@example.com' }
      ]
    };

    const html = renderProjectCard(project);

    expect(html).toContain('1 collaborator');
    expect(html).toContain('AJ'); // Initials
  });

  it('should handle project with many collaborators (show max 3 + count)', () => {
    const project = {
      id: 4,
      name: 'Large Team Project',
      description: 'Project with many collaborators',
      target: 'bigproject.com',
      status: 'active',
      collaborators: [
        { id: 1, full_name: 'Alice Anderson', email: 'alice@example.com' },
        { id: 2, full_name: 'Bob Brown', email: 'bob@example.com' },
        { id: 3, full_name: 'Charlie Clark', email: 'charlie@example.com' },
        { id: 4, full_name: 'Diana Davis', email: 'diana@example.com' },
        { id: 5, full_name: 'Eve Evans', email: 'eve@example.com' }
      ]
    };

    const html = renderProjectCard(project);

    expect(html).toContain('5 collaborators');
    expect(html).toContain('+2'); // Remaining count indicator
  });

  it('should map status to correct badge class', () => {
    const activeProject = {
      id: 5,
      name: 'Active Project',
      description: 'Test',
      target: 'test.com',
      status: 'active',
      collaborators: []
    };

    const completedProject = {
      id: 6,
      name: 'Completed Project',
      description: 'Test',
      target: 'test.com',
      status: 'completed',
      collaborators: []
    };

    const archivedProject = {
      id: 7,
      name: 'Archived Project',
      description: 'Test',
      target: 'test.com',
      status: 'archived',
      collaborators: []
    };

    expect(renderProjectCard(activeProject)).toContain('cyber-badge-safe');
    expect(renderProjectCard(completedProject)).toContain('cyber-badge-info');
    expect(renderProjectCard(archivedProject)).toContain('cyber-badge-warning');
  });

  it('should handle missing or invalid project data gracefully', () => {
    const invalidProject = null;
    const html = renderProjectCard(invalidProject);
    expect(html).toBe('');
  });

  it('should use default values for missing fields', () => {
    const minimalProject = {
      id: 8
    };

    const html = renderProjectCard(minimalProject);

    expect(html).toContain('Untitled Project');
    expect(html).toContain('No description provided');
    expect(html).toContain('N/A');
    expect(html).toContain('Active');
  });

  it('should generate correct initials for collaborators', () => {
    const project = {
      id: 9,
      name: 'Test Project',
      description: 'Test',
      target: 'test.com',
      status: 'active',
      collaborators: [
        { id: 1, full_name: 'John Doe', email: 'john@example.com' },
        { id: 2, full_name: 'Mary Jane Watson', email: 'mary@example.com' }
      ]
    };

    const html = renderProjectCard(project);

    expect(html).toContain('JD'); // John Doe
    expect(html).toContain('MJ'); // Mary Jane Watson (first two initials)
  });

  it('should include hover effects and cyber-theme styling', () => {
    const project = {
      id: 10,
      name: 'Styled Project',
      description: 'Test styling',
      target: 'style.com',
      status: 'active',
      collaborators: []
    };

    const html = renderProjectCard(project);

    expect(html).toContain('hover:border-purple-500/40');
    expect(html).toContain('transition-all');
    expect(html).toContain('cyber-card');
  });

  it('should include data-project-id attribute', () => {
    const project = {
      id: 123,
      name: 'ID Test Project',
      description: 'Test',
      target: 'test.com',
      status: 'active',
      collaborators: []
    };

    const html = renderProjectCard(project);

    expect(html).toContain('data-project-id="123"');
  });

  it('should prevent event propagation on button clicks', () => {
    const project = {
      id: 11,
      name: 'Event Test Project',
      description: 'Test',
      target: 'test.com',
      status: 'active',
      collaborators: []
    };

    const html = renderProjectCard(project);

    expect(html).toContain('event.stopPropagation()');
  });
});
