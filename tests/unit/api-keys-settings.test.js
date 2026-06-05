/**
 * Unit Tests for API Keys Settings Tab
 * Validates dynamic loading, dirty state triggers, bulk saving, deletion, and cache updates.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { JSDOM } from 'jsdom';
import fs from 'fs';
import path from 'path';

describe('API Keys Settings Module', () => {
  let dom;
  let window;
  let document;
  let dirtyEventCount = 0;
  let lastDirtyState = null;

  beforeEach(() => {
    // Setup JSDOM
    dom = new JSDOM(`
      <!DOCTYPE html>
      <html>
        <body>
          <div id="pane-api-keys"></div>
        </body>
      </html>
    `, {
      url: "http://localhost",
      runScripts: "dangerously",
      resources: "usable"
    });
    window = dom.window;
    document = window.document;

    // Set globals for test execution context
    global.window = window;
    global.document = document;
    global.localStorage = window.localStorage;
    global.CustomEvent = window.CustomEvent;

    // Mock global loaders on window
    window.showLoading = vi.fn();
    window.hideLoading = vi.fn();
    window.showContainerLoading = vi.fn();
    window.hideContainerLoading = vi.fn();

    global.showLoading = window.showLoading;
    global.hideLoading = window.hideLoading;
    global.showContainerLoading = window.showContainerLoading;
    global.hideContainerLoading = window.hideContainerLoading;

    // Mock CyberNotify on window
    window.CyberNotify = {
      alert: vi.fn(),
      confirm: vi.fn((msg, callback) => callback(true))
    };
    global.CyberNotify = window.CyberNotify;

    // Load source code
    const apiClientCode = fs.readFileSync(path.resolve(__dirname, '../../public/js/api-client.js'), 'utf8');
    const apiKeysSettingsCode = fs.readFileSync(path.resolve(__dirname, '../../public/js/api-keys-settings.js'), 'utf8');

    // Eval in JSDOM window context
    window.eval(apiClientCode);

    // Mock APIClient HTTP calls before executing api-keys-settings.js
    window.APIClient.prototype.get = vi.fn().mockImplementation(async (url) => {
      if (url === "user/api-keys") {
        return {
          virustotal: { has_key: true, key: "vtKeyReal", masked: "••••1234", id: "vt-id" },
          abuseipdb: { has_key: false, masked: "", id: null },
          whoisxml: { has_key: false, masked: "", id: null },
          shodan: { has_key: false, masked: "", id: null },
          urlscan: { has_key: false, masked: "", id: null },
          ai_assistant: { has_key: true, masked: "••••abcd", id: null }
        };
      }
      return {};
    });
    
    window.APIClient.prototype.post = vi.fn().mockResolvedValue({ message: "API Keys Saved Or Updated Successfuly." });
    window.APIClient.prototype.delete = vi.fn().mockResolvedValue({ message: "API Key deleted successfully" });
    window.APIClient.prototype.getToken = vi.fn().mockReturnValue("mock-token");

    // Instantiate apiClient
    window.apiClient = new window.APIClient();

    // Now load settings module
    window.eval(apiKeysSettingsCode);

    // Reset event tracker
    dirtyEventCount = 0;
    lastDirtyState = null;
    document.addEventListener("settingsTabDirtyChange", (e) => {
      dirtyEventCount++;
      lastDirtyState = e.detail;
    });
  });

  afterEach(() => {
    delete global.window;
    delete global.document;
    delete global.localStorage;
    delete global.CustomEvent;
    delete global.showLoading;
    delete global.hideLoading;
    delete global.showContainerLoading;
    delete global.hideContainerLoading;
    delete global.CyberNotify;
    vi.clearAllMocks();
  });

  it('should fetch API keys on init, populate form and cache transiently in window.userApiKeys', async () => {
    await window.ApiKeysSettings.init();

    // Verify GET request was called
    expect(window.APIClient.prototype.get).toHaveBeenCalledWith("user/api-keys");

    // Verify transient memory cache population
    expect(window.userApiKeys.virustotal).toBeDefined();
    expect(window.userApiKeys.virustotal.key).toBe("vtKeyReal");
    expect(window.userApiKeys.abuseipdb.has_key).toBe(false);

    // Verify window.getApiKey returns correct values
    expect(window.getApiKey("virustotal")).toBe("vtKeyReal");
    expect(window.getApiKey("vtApiKey")).toBe("vtKeyReal"); // Legacy normalization check
    expect(window.getApiKey("abuseipdb")).toBe("");

    // Verify DOM rendering
    const pane = document.getElementById("pane-api-keys");
    expect(pane.innerHTML).toContain("VirusTotal");
    expect(pane.innerHTML).toContain("AbuseIPDB");
    expect(pane.innerHTML).toContain("Configured");
    expect(pane.innerHTML).toContain("Not Configured");
    expect(pane.innerHTML).toContain("System Default"); // AI Assistant
  });

  it('should mark form as dirty when user modifies a key input', async () => {
    await window.ApiKeysSettings.init();

    const abuseInput = document.getElementById("api-input-abuseipdb");
    expect(abuseInput).toBeDefined();

    // Simulate input change
    abuseInput.value = "newAbuseIPDBKey";
    abuseInput.dispatchEvent(new window.Event('input'));

    // Verify dirty state
    expect(window.ApiKeysSettings.isDirty).toBe(true);
    expect(dirtyEventCount).toBe(2);
    expect(lastDirtyState).toEqual({ tabId: "api-keys", isDirty: true });
  });

  it('should submit bulk updates to POST /api/user/api-keys when save is called', async () => {
    await window.ApiKeysSettings.init();

    // Modify VirusTotal input and Shodan input
    const vtInput = document.getElementById("api-input-virustotal");
    const shodanInput = document.getElementById("api-input-shodan");

    vtInput.value = "newVTKey";
    vtInput.dispatchEvent(new window.Event('input'));

    shodanInput.value = "newShodanKey";
    shodanInput.dispatchEvent(new window.Event('input'));

    // Trigger save
    const success = await window.ApiKeysSettings.save();
    expect(success).toBe(true);

    // Verify POST payload
    expect(window.APIClient.prototype.post).toHaveBeenCalledWith("user/api-keys", {
      keys: {
        virustotal: "newVTKey",
        shodan: "newShodanKey"
      }
    });

    // Verify CyberNotify alert called
    expect(global.CyberNotify.alert).toHaveBeenCalledWith("API Keys Saved Or Updated Successfuly.", { type: "success" });
  });

  it('should request confirmation and send DELETE request for single key deletion', async () => {
    await window.ApiKeysSettings.init();

    const deleteBtn = document.querySelector("[data-delete='virustotal']");
    expect(deleteBtn).toBeDefined();
    expect(deleteBtn.getAttribute("data-id")).toBe("vt-id");

    // Simulate deletion click
    deleteBtn.dispatchEvent(new window.MouseEvent('click', { bubbles: true }));

    // Wait for the async delete process to complete
    await new Promise(resolve => setTimeout(resolve, 10));

    // Verify DELETE request was sent with the correct ID
    expect(window.APIClient.prototype.delete).toHaveBeenCalledWith("user/api-keys/vt-id");

    // Verify CyberNotify alert called
    expect(window.CyberNotify.alert).toHaveBeenCalledWith("API Key deleted successfully", { type: "success" });
  });

  it('should clean up legacy localStorage keys on key fetch', async () => {
    // Set legacy localStorage keys
    localStorage.setItem("vtApiKey", "legacyVT");
    localStorage.setItem("abuseipdbApiKey", "legacyAbuse");
    localStorage.setItem("abuseipdb_api_key", "legacyPlain1");

    // Trigger fetch
    await window.fetchUserApiKeys();

    // Verify keys were cleaned up
    expect(localStorage.getItem("vtApiKey")).toBeNull();
    expect(localStorage.getItem("abuseipdbApiKey")).toBeNull();
    expect(localStorage.getItem("abuseipdb_api_key")).toBeNull();
  });
});
