import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { JSDOM } from 'jsdom';

describe('Profile Settings & Avatar API Integration', () => {
  let dom;
  let mockStorage;
  
  beforeEach(async () => {
    dom = new JSDOM(`
      <!DOCTYPE html>
      <html>
        <body>
          <div id="navbar-avatar-container">
            <span id="navbarUserInitials">MG</span>
          </div>
          <div id="userName">User Name</div>
          <div id="userEmail">user@example.com</div>
          <div id="pane-profile"></div>
          <div id="settings-modal" class="hidden"></div>
        </body>
      </html>
    `, {
      url: 'http://localhost'
    });

    global.window = dom.window;
    global.document = dom.window.document;
    global.FormData = dom.window.FormData;
    global.File = dom.window.File;
    global.FileReader = dom.window.FileReader;
    global.CustomEvent = dom.window.CustomEvent;
    global.Event = dom.window.Event;

    // Mock localStorage
    const storage = {};
    mockStorage = {
      getItem: vi.fn((key) => storage[key] || null),
      setItem: vi.fn((key, val) => { storage[key] = val; }),
      removeItem: vi.fn((key) => { delete storage[key]; })
    };
    global.localStorage = mockStorage;

    // Mock CyberNotify
    global.CyberNotify = {
      alert: vi.fn(),
      confirm: vi.fn().mockImplementation((msg, callback) => callback(true))
    };

    // Mock global showLoading / hideLoading
    global.showLoading = vi.fn();
    global.hideLoading = vi.fn();
    global.window.showLoading = global.showLoading;
    global.window.hideLoading = global.hideLoading;

    // Mock escapeHtml
    global.escapeHtml = (str) => str || '';
    global.window.escapeHtml = global.escapeHtml;

    // Mock fetch
    global.fetch = vi.fn().mockImplementation(() => 
      Promise.resolve({
        ok: true,
        status: 200,
        json: () => Promise.resolve({ status: 'success' })
      })
    );

    // Mock AuthManager
    global.window.authManager = {
      getCurrentUser: vi.fn().mockReturnValue({
        fullName: 'Mohamed Gamal',
        email: 'mohamed@example.com',
        jobTitle: 'Security Engineer',
        phoneNumber: '+1 (555) 000-0000',
        avatar: ''
      }),
      updateUI: vi.fn()
    };

    // Mock SettingsPanel
    global.window.SettingsPanel = {
      updateNavbarTrigger: vi.fn()
    };

    // Load APIClient and ProfileSettings modules
    await import('../../public/js/api-client.js');
    global.window.apiClient = new global.window.APIClient();
    await import('../../public/js/profile-settings.js');
  });

  afterEach(() => {
    vi.clearAllMocks();
    vi.resetModules();
    dom.window.close();
  });

  describe('APIClient FormData support', () => {
    it('should not set Content-Type to application/json and pass FormData body directly', async () => {
      const client = global.window.apiClient;
      const formData = new FormData();
      formData.append('key', 'value');

      await client.post('/test-endpoint', formData);

      expect(global.fetch).toHaveBeenCalled();
      const [url, options] = global.fetch.mock.calls[0];
      
      // Should not have Content-Type: application/json
      expect(options.headers['Content-Type']).toBeUndefined();
      // Should pass FormData object directly as body
      expect(options.body).toBe(formData);
    });

    it('should set Content-Type to application/json and stringify body for plain objects', async () => {
      const client = global.window.apiClient;
      const payload = { key: 'value' };

      await client.post('/test-endpoint', payload);

      expect(global.fetch).toHaveBeenCalled();
      const [url, options] = global.fetch.mock.calls[0];
      
      expect(options.headers['Content-Type']).toBe('application/json');
      expect(options.body).toBe(JSON.stringify(payload));
    });
  });

  describe('ProfileSettings Save & Upload Flow', () => {
    it('should update name and job title via PUT /user/profile', async () => {
      const prof = global.window.ProfileSettings;
      prof.init();

      // Change name and job
      const nameInput = dom.window.document.getElementById('profile-name');
      const roleInput = dom.window.document.getElementById('profile-role');
      nameInput.value = 'New Mohamed Gamal';
      roleInput.value = 'Senior Security Analyst';
      
      // Dispatch input events
      nameInput.dispatchEvent(new dom.window.Event('input'));
      roleInput.dispatchEvent(new dom.window.Event('input'));

      // Mock fetch responses for profile update
      global.fetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: () => Promise.resolve({
          status: 'success',
          user: {
            full_name: 'New Mohamed Gamal',
            job_title: 'Senior Security Analyst'
          }
        })
      });

      const success = await prof.save();
      expect(success).toBe(true);

      // Verify fetch was called with PUT /user/profile
      expect(global.fetch).toHaveBeenCalled();
      const putCall = global.fetch.mock.calls.find(call => call[1].method === 'PUT');
      expect(putCall).toBeTruthy();
      expect(putCall[0]).toContain('/user/profile');
      expect(JSON.parse(putCall[1].body)).toEqual({
        full_name: 'New Mohamed Gamal',
        job_title: 'Senior Security Analyst'
      });

      // Verify local user was updated and saved
      expect(global.window.authManager.getCurrentUser).toHaveBeenCalled();
      expect(global.window.authManager.updateUI).toHaveBeenCalled();
    });

    it('should upload avatar via POST /user/profile/avatar when a file is selected', async () => {
      const prof = global.window.ProfileSettings;
      prof.init();

      // Mock file selection
      const mockFile = new dom.window.File(['content'], 'avatar.jpg', { type: 'image/jpeg' });
      prof.photoFile = mockFile;
      prof.currentState.avatar = 'data:image/jpeg;base64,mockdata';

      // Mock fetch responses:
      // First call is POST /user/profile/avatar
      global.fetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: () => Promise.resolve({
          status: 'success',
          avatar_url: 'https://cdn.cyberguard.pro/avatars/new-avatar.jpg'
        })
      });
      // Second call is PUT /user/profile
      global.fetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: () => Promise.resolve({ status: 'success' })
      });

      const success = await prof.save();
      expect(success).toBe(true);

      // Verify POST to upload avatar
      const postCall = global.fetch.mock.calls.find(call => call[1].method === 'POST');
      expect(postCall).toBeTruthy();
      expect(postCall[0]).toContain('/user/profile/avatar');
      expect(postCall[1].headers['Accept']).toBe('application/json');
      expect(postCall[1].body).toBeInstanceOf(FormData);
      expect(postCall[1].body.get('avatar')).toBe(mockFile);

      // Verify PUT to save profile
      const putCall = global.fetch.mock.calls.find(call => call[1].method === 'PUT');
      expect(putCall).toBeTruthy();
      expect(putCall[0]).toContain('/user/profile');

      // Verify local storage avatar url was updated
      expect(mockStorage.setItem).toHaveBeenCalledWith('cyberguard_user_avatar', 'https://cdn.cyberguard.pro/avatars/new-avatar.jpg');
      expect(prof.photoFile).toBeNull();
    });

    it('should handle API errors and show alert message', async () => {
      const prof = global.window.ProfileSettings;
      prof.init();

      // Force failure on fetch
      global.fetch.mockResolvedValueOnce({
        ok: false,
        status: 400,
        json: () => Promise.resolve({ message: 'Internal Server Error' })
      });

      const success = await prof.save();
      expect(success).toBe(false);
      expect(global.CyberNotify.alert).toHaveBeenCalledWith('Internal Server Error', { type: 'error' });
    });
  });
});
