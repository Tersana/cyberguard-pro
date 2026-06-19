import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { JSDOM } from 'jsdom';

describe('Settings Modal Dismissal on Tab Switch', () => {
  let dom;
  let document;
  let window;
  let DashboardTabManager;

  beforeEach(async () => {
    // Set up a minimal JSDOM environment
    dom = new JSDOM(`
      <!DOCTYPE html>
      <html>
        <body>
          <button class="tab-button active" data-tab="security-dashboard">Dashboard</button>
          <button class="tab-button" data-tab="osint">OSINT</button>
          
          <div id="security-dashboard" class="tab-pane"></div>
          <div id="osint" class="tab-pane hidden"></div>
        </body>
      </html>
    `, {
      url: 'http://localhost',
      runScripts: 'dangerously',
      resources: 'usable'
    });

    document = dom.window.document;
    window = dom.window;

    // Set up global environment
    global.document = document;
    global.window = window;
    global.CustomEvent = window.CustomEvent;
    
    // Mocks for globals expected by dashboard-tab-manager.js
    global.console = {
      log: vi.fn(),
      error: vi.fn(),
      warn: vi.fn()
    };
    
    // Reset/Mock SettingsPanel structure
    window.SettingsPanel = {
      isOpen: false,
      hasUnsavedChanges: vi.fn().mockReturnValue(false),
      forceClose: vi.fn()
    };

    // Reset/Mock CyberNotify structure
    window.CyberNotify = {
      confirm: vi.fn()
    };

    // Mock confirm
    window.confirm = vi.fn().mockReturnValue(true);
    global.confirm = window.confirm;

    // Load DashboardTabManager module
    const tabManagerModule = await import('../../public/js/dashboard-tab-manager.js');
    DashboardTabManager = tabManagerModule.default || tabManagerModule.DashboardTabManager || tabManagerModule;
    
    // Initialize with default state
    DashboardTabManager.currentTab = 'security-dashboard';
    DashboardTabManager.tabInitialized = {
      'security-dashboard': true,
      'osint': false
    };
  });

  afterEach(() => {
    vi.clearAllMocks();
    dom.window.close();
    // Reset global references
    delete global.window.SettingsPanel;
    delete global.window.CyberNotify;
    delete global.window.confirm;
    delete global.confirm;
  });

  it('should switch tab directly when SettingsPanel is not open', () => {
    window.SettingsPanel.isOpen = false;

    DashboardTabManager.switchTab('osint');

    // Should switch the tab successfully
    expect(DashboardTabManager.getCurrentTab()).toBe('osint');
    // Should not call forceClose since modal is not open
    expect(window.SettingsPanel.forceClose).not.toHaveBeenCalled();
  });

  it('should call forceClose and switch tab when SettingsPanel is open but has no unsaved changes', () => {
    window.SettingsPanel.isOpen = true;
    window.SettingsPanel.hasUnsavedChanges.mockReturnValue(false);

    DashboardTabManager.switchTab('osint');

    // Should close settings and switch tab
    expect(window.SettingsPanel.forceClose).toHaveBeenCalled();
    expect(DashboardTabManager.getCurrentTab()).toBe('osint');
    expect(window.CyberNotify.confirm).not.toHaveBeenCalled();
    expect(window.confirm).not.toHaveBeenCalled();
  });

  describe('With Unsaved Changes', () => {
    beforeEach(() => {
      window.SettingsPanel.isOpen = true;
      window.SettingsPanel.hasUnsavedChanges.mockReturnValue(true);
    });

    it('should use CyberNotify.confirm when available and switch tab on confirmation', () => {
      // Setup CyberNotify.confirm to execute success callback immediately
      window.CyberNotify.confirm.mockImplementation((message, onConfirm) => {
        onConfirm();
      });

      DashboardTabManager.switchTab('osint');

      expect(window.CyberNotify.confirm).toHaveBeenCalledWith(
        'You have unsaved changes. Discard changes and close settings?',
        expect.any(Function)
      );
      expect(window.SettingsPanel.forceClose).toHaveBeenCalled();
      expect(DashboardTabManager.getCurrentTab()).toBe('osint');
    });

    it('should use CyberNotify.confirm and NOT switch tab if confirmation is cancelled', () => {
      // Setup CyberNotify.confirm to NOT execute the callback (cancelled/closed)
      window.CyberNotify.confirm.mockImplementation(() => {});

      DashboardTabManager.switchTab('osint');

      expect(window.CyberNotify.confirm).toHaveBeenCalled();
      expect(window.SettingsPanel.forceClose).not.toHaveBeenCalled();
      // Should remain on the old tab
      expect(DashboardTabManager.getCurrentTab()).toBe('security-dashboard');
    });

    it('should fallback to window.confirm when CyberNotify is not available and switch tab on OK', () => {
      delete window.CyberNotify;
      window.confirm.mockReturnValue(true);

      DashboardTabManager.switchTab('osint');

      expect(window.confirm).toHaveBeenCalledWith('You have unsaved changes. Are you sure you want to discard them?');
      expect(window.SettingsPanel.forceClose).toHaveBeenCalled();
      expect(DashboardTabManager.getCurrentTab()).toBe('osint');
    });

    it('should fallback to window.confirm when CyberNotify is not available and NOT switch tab on Cancel', () => {
      delete window.CyberNotify;
      window.confirm.mockReturnValue(false);

      DashboardTabManager.switchTab('osint');

      expect(window.confirm).toHaveBeenCalled();
      expect(window.SettingsPanel.forceClose).not.toHaveBeenCalled();
      // Should remain on the old tab
      expect(DashboardTabManager.getCurrentTab()).toBe('security-dashboard');
    });
  });
});
