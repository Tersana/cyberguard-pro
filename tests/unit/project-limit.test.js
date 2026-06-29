import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { JSDOM } from 'jsdom';

describe('Project Limit ValidationError UI Response', () => {
  let dom;
  let APIClient;
  let ProjectManager;

  beforeEach(async () => {
    dom = new JSDOM(`
      <!DOCTYPE html>
      <html>
        <body>
          <form id="create-project-form">
            <input name="name" id="project-name" value="Test Project" />
            <input name="description" id="project-description" value="Testing" />
            <span id="project-name-error" class="hidden"></span>
            <button id="create-project-submit">Submit</button>
          </form>

          <form id="edit-project-form">
            <input name="id" id="edit-project-id" value="123" />
            <input name="name" id="edit-project-name" value="Test Project Edit" />
            <input name="status" id="edit-project-status" value="active" />
            <span id="edit-project-name-error" class="hidden"></span>
            <button id="edit-project-submit">Save</button>
          </form>
        </body>
      </html>
    `, {
      url: 'http://localhost'
    });

    global.window = dom.window;
    global.document = dom.window.document;

    // Mock CyberNotify
    global.window.CyberNotify = {
      alert: vi.fn(),
    };

    // Load APIClient and ProjectManager
    const apiClientModule = await import('../../public/js/api-client.js');
    APIClient = apiClientModule.APIClient || apiClientModule.default?.APIClient;
    if (!APIClient && apiClientModule.default) {
      APIClient = apiClientModule.default.APIClient;
    }
    if (!APIClient) {
      APIClient = global.window.APIClient;
    }

    const pmModule = await import('../../public/js/project-manager.js');
    ProjectManager = pmModule.ProjectManager || pmModule.default?.ProjectManager;
    if (!ProjectManager && pmModule.default) {
      ProjectManager = pmModule.default.ProjectManager;
    }
    if (!ProjectManager) {
      ProjectManager = global.window.ProjectManager;
    }
  });

  afterEach(() => {
    vi.clearAllMocks();
    vi.resetModules();
    dom.window.close();
  });

  it('should display error toast on project creation ValidationError if limit error occurs', async () => {
    const apiClient = new APIClient();
    const projectManager = new ProjectManager(apiClient);

    // Mock form properties directly using Object.defineProperty to bypass read-only attribute constraints
    const form = global.document.getElementById("create-project-form");
    Object.defineProperty(form, 'name', { value: { value: "Test Project" }, configurable: true });
    Object.defineProperty(form, 'description', { value: { value: "Testing" }, configurable: true });

    // Mock apiClient.post to throw a ValidationError with a limit message
    const validationError = new global.window.ValidationError([
      { field: 'limit', message: 'You have reached the maximum limit of projects for your plan.' }
    ]);
    validationError.status = 422;
    vi.spyOn(apiClient, 'post').mockRejectedValue(validationError);

    // Mock validateProjectForm to return valid: true
    vi.spyOn(projectManager, 'validateProjectForm').mockReturnValue({ valid: true, errors: {} });

    // Call handleProjectFormSubmit
    await projectManager.handleProjectFormSubmit();

    // Verify: CyberNotify.alert was called with the limit message.
    expect(global.window.CyberNotify.alert).toHaveBeenCalledWith(
      'You have reached the maximum limit of projects for your plan.',
      { type: 'error' }
    );
  });

  it('should display error toast on project edit ValidationError if limit error occurs', async () => {
    const apiClient = new APIClient();
    const projectManager = new ProjectManager(apiClient);

    // Mock form properties directly
    const form = global.document.getElementById("edit-project-form");
    Object.defineProperty(form, 'name', { value: { value: "Test Project Edit" }, configurable: true });
    Object.defineProperty(form, 'status', { value: { value: "active" }, configurable: true });

    // Mock apiClient.patch to throw a ValidationError with a limit message
    const validationError = new global.window.ValidationError([
      { field: 'limit', message: 'Editing is limited under your plan.' }
    ]);
    validationError.status = 422;
    vi.spyOn(apiClient, 'patch').mockRejectedValue(validationError);

    // Mock validateProjectForm to return valid: true
    vi.spyOn(projectManager, 'validateProjectForm').mockReturnValue({ valid: true, errors: {} });

    // Call handleEditProjectFormSubmit
    await projectManager.handleEditProjectFormSubmit();

    // Verify: CyberNotify.alert was called with the limit message.
    expect(global.window.CyberNotify.alert).toHaveBeenCalledWith(
      'Editing is limited under your plan.',
      { type: 'error' }
    );
  });
});
