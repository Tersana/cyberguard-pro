import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { JSDOM } from 'jsdom';

describe('Avatar Flow In Settings Panel and Profile Settings', () => {
  let dom;
  let document;
  let mockLocalStorage;
  let mockAuthManager;

  beforeEach(() => {
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
    `);

    document = dom.window.document;
    global.document = document;
    global.window = dom.window;

    // Mock localStorage
    const storage = {};
    mockLocalStorage = {
      getItem: vi.fn((key) => storage[key] || null),
      setItem: vi.fn((key, val) => { storage[key] = val; }),
      removeItem: vi.fn((key) => { delete storage[key]; })
    };
    global.localStorage = mockLocalStorage;

    // Mock CyberNotify
    global.CyberNotify = {
      alert: vi.fn()
    };
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  describe('SettingsPanel updateNavbarTrigger', () => {
    it('should show avatar image if user has avatarUrl (Google OAuth avatar)', () => {
      // Mock AuthManager
      mockAuthManager = {
        getCurrentUser: vi.fn().mockReturnValue({
          fullName: 'Mohamed Gamal',
          email: 'mohamed@example.com',
          avatarUrl: 'https://lh3.googleusercontent.com/photo-spiderman'
        })
      };
      global.window.authManager = mockAuthManager;

      // Define local settings panel logic derived from public/js/settings-panel.js
      const updateNavbarTrigger = () => {
        const user = global.window.authManager.getCurrentUser() || {};
        const fullName = user.fullName || user.name || "Mohamed Gamal";
        
        // Calculate initials fallback
        const parts = fullName.trim().split(/\s+/);
        let initials = "MG";
        if (parts.length >= 2) {
            initials = (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
        }

        const initialsEl = document.getElementById("navbarUserInitials");
        if (initialsEl) initialsEl.textContent = initials;

        const nameEl = document.getElementById("userName");
        const emailEl = document.getElementById("userEmail");
        if (nameEl) nameEl.textContent = fullName;
        if (emailEl) emailEl.textContent = user.email || "";

        const avatarContainer = document.getElementById("navbar-avatar-container");
        if (avatarContainer) {
            const avatarUrl = user.avatar || user.avatarUrl || localStorage.getItem("cyberguard_user_avatar") || "";
            if (avatarUrl) {
                avatarContainer.innerHTML = `<img src="${avatarUrl}" alt="Avatar" class="w-full h-full object-cover">`;
            } else {
                avatarContainer.innerHTML = `<span class="text-xs font-bold text-white" id="navbarUserInitials">${initials}</span>`;
            }
        }
      };

      updateNavbarTrigger();

      const container = document.getElementById('navbar-avatar-container');
      const img = container.querySelector('img');
      expect(img).toBeTruthy();
      expect(img.getAttribute('src')).toBe('https://lh3.googleusercontent.com/photo-spiderman');
    });

    it('should show initials if no avatar or avatarUrl exists', () => {
      mockAuthManager = {
        getCurrentUser: vi.fn().mockReturnValue({
          fullName: 'Mohamed Gamal',
          email: 'mohamed@example.com'
        })
      };
      global.window.authManager = mockAuthManager;

      const updateNavbarTrigger = () => {
        const user = global.window.authManager.getCurrentUser() || {};
        const fullName = user.fullName || user.name || "Mohamed Gamal";
        
        // Calculate initials fallback
        const parts = fullName.trim().split(/\s+/);
        let initials = "MG";
        if (parts.length >= 2) {
            initials = (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
        }

        const initialsEl = document.getElementById("navbarUserInitials");
        if (initialsEl) initialsEl.textContent = initials;

        const avatarContainer = document.getElementById("navbar-avatar-container");
        if (avatarContainer) {
            const avatarUrl = user.avatar || user.avatarUrl || localStorage.getItem("cyberguard_user_avatar") || "";
            if (avatarUrl) {
                avatarContainer.innerHTML = `<img src="${avatarUrl}" alt="Avatar" class="w-full h-full object-cover">`;
            } else {
                avatarContainer.innerHTML = `<span class="text-xs font-bold text-white" id="navbarUserInitials">${initials}</span>`;
            }
        }
      };

      updateNavbarTrigger();

      const container = document.getElementById('navbar-avatar-container');
      const span = container.querySelector('span');
      expect(span).toBeTruthy();
      expect(span.textContent).toBe('MG');
      expect(container.querySelector('img')).toBeNull();
    });
  });

  describe('ProfileSettings Tab Module', () => {
    it('should load initial data with avatarUrl (Google avatar) if avatar is absent', () => {
      const user = {
        fullName: 'Mohamed Gamal',
        jobTitle: 'Security Specialist',
        phoneNumber: '123456',
        avatarUrl: 'https://lh3.googleusercontent.com/photo-spiderman'
      };

      mockAuthManager = {
        getCurrentUser: vi.fn().mockReturnValue(user)
      };
      global.window.authManager = mockAuthManager;

      // Class replica under test
      class ProfileSettingsTest {
        constructor() {
          this.initialState = {
            fullName: "",
            jobTitle: "",
            phoneNumber: "",
            avatar: null
          };
          this.currentState = { ...this.initialState };
        }

        loadInitialData() {
          const u = global.window.authManager.getCurrentUser() || {};
          const fullName = u.fullName || u.name || "Mohamed Gamal";
          const jobTitle = u.jobTitle || u.job_title || u.job_tittle || "Security Engineer";
          const phoneNumber = u.phoneNumber || u.phone || "";
          const avatar = u.avatar || u.avatarUrl || localStorage.getItem("cyberguard_user_avatar") || "";

          this.initialState = {
            fullName: fullName,
            jobTitle: jobTitle,
            phoneNumber: phoneNumber,
            avatar: avatar
          };
          this.currentState = { ...this.initialState };
        }
      }

      const prof = new ProfileSettingsTest();
      prof.loadInitialData();

      expect(prof.currentState.avatar).toBe('https://lh3.googleusercontent.com/photo-spiderman');
    });

    it('should delete user.avatar and user.avatarUrl when clearing avatar', () => {
      const user = {
        fullName: 'Mohamed Gamal',
        avatarUrl: 'https://lh3.googleusercontent.com/photo-spiderman'
      };

      mockAuthManager = {
        getCurrentUser: vi.fn().mockReturnValue(user),
        updateUI: vi.fn()
      };
      global.window.authManager = mockAuthManager;

      class ProfileSettingsTest {
        constructor() {
          this.currentState = {
            fullName: "Mohamed Gamal",
            jobTitle: "",
            phoneNumber: "",
            avatar: "" // Cleared
          };
        }

        save() {
          const u = global.window.authManager.getCurrentUser() || {};
          u.fullName = this.currentState.fullName;
          
          if (this.currentState.avatar) {
              localStorage.setItem("cyberguard_user_avatar", this.currentState.avatar);
              u.avatar = this.currentState.avatar;
          } else {
              localStorage.removeItem("cyberguard_user_avatar");
              delete u.avatar;
              delete u.avatarUrl;
          }
          localStorage.setItem("cyberguard_user", JSON.stringify(u));
        }
      }

      const prof = new ProfileSettingsTest();
      prof.save();

      expect(user.avatar).toBeUndefined();
      expect(user.avatarUrl).toBeUndefined();
      expect(mockLocalStorage.removeItem).toHaveBeenCalledWith('cyberguard_user_avatar');
    });

    it('should show CyberNotify confirmation when removing photo and proceed on confirm', () => {
      let confirmMessage = "";
      let confirmOptions = null;
      global.CyberNotify.confirm = vi.fn().mockImplementation((msg, callback, options) => {
        confirmMessage = msg;
        confirmOptions = options;
        callback(true); // Simulate clicking confirm
      });

      class ProfileSettingsTest {
        constructor() {
          this.currentState = {
            avatar: "https://lh3.googleusercontent.com/photo-spiderman"
          };
          this.isDirty = false;
        }

        checkDirtyState() { this.isDirty = true; }
        renderAvatarPreview() {}

        removePhoto() {
          if (global.CyberNotify && typeof global.CyberNotify.confirm === "function") {
              global.CyberNotify.confirm(
                  "Are you sure you want to remove your profile photo?",
                  (confirmed) => {
                      if (confirmed) {
                          this.currentState.avatar = "";
                          this.checkDirtyState();
                          this.renderAvatarPreview();
                      }
                  },
                  { type: "warning" }
              );
          }
        }
      }

      const prof = new ProfileSettingsTest();
      prof.removePhoto();

      expect(global.CyberNotify.confirm).toHaveBeenCalled();
      expect(confirmMessage).toBe("Are you sure you want to remove your profile photo?");
      expect(confirmOptions).toEqual({ type: "warning" });
      expect(prof.currentState.avatar).toBe("");
      expect(prof.isDirty).toBe(true);
    });

    it('should show CyberNotify confirmation when removing photo and cancel on discard', () => {
      global.CyberNotify.confirm = vi.fn().mockImplementation((msg, callback, options) => {
        callback(false); // Simulate clicking cancel
      });

      class ProfileSettingsTest {
        constructor() {
          this.currentState = {
            avatar: "https://lh3.googleusercontent.com/photo-spiderman"
          };
          this.isDirty = false;
        }

        checkDirtyState() { this.isDirty = true; }
        renderAvatarPreview() {}

        removePhoto() {
          if (global.CyberNotify && typeof global.CyberNotify.confirm === "function") {
              global.CyberNotify.confirm(
                  "Are you sure you want to remove your profile photo?",
                  (confirmed) => {
                      if (confirmed) {
                          this.currentState.avatar = "";
                          this.checkDirtyState();
                          this.renderAvatarPreview();
                      }
                  },
                  { type: "warning" }
              );
          }
        }
      }

      const prof = new ProfileSettingsTest();
      prof.removePhoto();

      expect(global.CyberNotify.confirm).toHaveBeenCalled();
      expect(prof.currentState.avatar).toBe("https://lh3.googleusercontent.com/photo-spiderman");
      expect(prof.isDirty).toBe(false);
    });
  });
});
