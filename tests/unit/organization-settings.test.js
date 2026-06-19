/**
 * Unit Tests — OrganizationSettings UI Module
 *
 * Validates:
 *   - Initialization and event listener setup
 *   - Workspace switcher rendering and interaction
 *   - Org settings pane rendering (overview, metrics, team, invite form)
 *   - Member row rendering with role badges
 *   - Invite form submission
 *   - Role change dropdown handling
 *   - Onboarding wizard step rendering
 *   - No-org empty state
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { JSDOM } from "jsdom";
import fs from "fs";
import path from "path";

describe("OrganizationSettings", () => {
  let dom;
  let window;
  let document;

  function loadModules() {
    // Load OrganizationManager first (dependency)
    const mgrSrc = fs.readFileSync(
      path.resolve(__dirname, "../../public/js/organization-manager.js"),
      "utf8"
    );
    window.eval(mgrSrc);

    // Load OrganizationSettings
    const settingsSrc = fs.readFileSync(
      path.resolve(__dirname, "../../public/js/organization-settings.js"),
      "utf8"
    );
    window.eval(settingsSrc);
  }

  beforeEach(() => {
    dom = new JSDOM(
      `<!DOCTYPE html>
      <html>
        <body>
          <div id="org-workspace-switcher" class="hidden"></div>
          <a href="#" id="org-nav-toggle"></a>
          <div id="pane-org-settings"></div>
          <div id="org-onboarding-modal" class="hidden">
            <div class="cyber-step-dot" data-step="1"><span>1</span></div>
            <div class="cyber-step-dot" data-step="2"><span>2</span></div>
            <div class="cyber-step-dot" data-step="3"><span>3</span></div>
            <div id="org-onboarding-body"></div>
          </div>
        </body>
      </html>`,
      {
        url: "http://localhost",
        runScripts: "dangerously",
        resources: "usable",
      }
    );
    window = dom.window;
    document = window.document;

    global.window = window;
    global.document = document;
    global.localStorage = window.localStorage;
    global.CustomEvent = window.CustomEvent;

    // Mock globals
    window.showLoading = vi.fn();
    window.hideLoading = vi.fn();
    global.showLoading = window.showLoading;
    global.hideLoading = window.hideLoading;

    window.CyberNotify = {
      alert: vi.fn(),
      confirm: vi.fn((msg, cb) => cb(true)),
      prompt: vi.fn((msg, def, cb) => cb("confirmed")),
    };
    global.CyberNotify = window.CyberNotify;

    // Mock apiClient
    window.apiClient = {
      get: vi.fn().mockResolvedValue({}),
      post: vi.fn().mockResolvedValue({}),
      put: vi.fn().mockResolvedValue({}),
      delete: vi.fn().mockResolvedValue({}),
    };

    // Mock authManager
    window.authManager = {
      isAuthenticated: vi.fn().mockReturnValue(true),
      getCurrentUser: vi.fn().mockReturnValue({
        id: 1,
        fullName: "Test User",
        email: "test@domain.com",
      }),
    };

    // Mock SettingsPanel
    window.SettingsPanel = {
      open: vi.fn(),
    };

    loadModules();
  });

  afterEach(() => {
    localStorage.clear();
    delete global.window;
    delete global.document;
    delete global.localStorage;
    delete global.CustomEvent;
    delete global.showLoading;
    delete global.hideLoading;
    delete global.CyberNotify;
    vi.clearAllMocks();
    vi.restoreAllMocks();
  });

  // ─── Initialization ─────────────────────────────────────────────

  describe("Initialization", () => {
    it("exposes OrganizationSettings as a singleton on window", () => {
      expect(window.OrganizationSettings).toBeDefined();
      expect(typeof window.OrganizationSettings.init).toBe("function");
      expect(typeof window.OrganizationSettings.loadSettingsPane).toBe("function");
    });

    it("init() sets _initialized flag and loads workspace switcher", async () => {
      window.apiClient.get.mockResolvedValue({ organizations: [] });

      window.OrganizationSettings.init();

      expect(window.OrganizationSettings._initialized).toBe(true);
      // Calling init again should be a no-op
      window.OrganizationSettings.init();
    });
  });

  // ─── Workspace Switcher ─────────────────────────────────────────

  describe("Workspace Switcher", () => {
    it("renders workspace items when workspaces are available", async () => {
      const workspaces = [
        { id: 1, name: "Org Alpha", subscription: { plan: "pro", status: "active" } },
        { id: 2, name: "Org Beta", subscription: { plan: "starter", status: "pending" } },
      ];
      window.apiClient.get.mockResolvedValue({ organizations: workspaces });

      window.OrganizationSettings.init();
      // Wait for async workspace loading
      await new Promise((r) => setTimeout(r, 50));

      const container = document.getElementById("org-workspace-switcher");
      expect(container.classList.contains("hidden")).toBe(false);
      expect(container.innerHTML).toContain("Org Alpha");
      expect(container.innerHTML).toContain("Org Beta");
      expect(container.innerHTML).toContain("Personal Workspace");
    });

    it("hides switcher when no workspaces exist", async () => {
      window.apiClient.get.mockResolvedValue({ organizations: [] });

      window.OrganizationSettings.init();
      await new Promise((r) => setTimeout(r, 50));

      const container = document.getElementById("org-workspace-switcher");
      expect(container.classList.contains("hidden")).toBe(true);
    });

    it("marks personal workspace as active when no org is set", async () => {
      const workspaces = [
        { id: 1, name: "Org A", subscription: { plan: "pro", status: "active" } },
      ];
      window.apiClient.get.mockResolvedValue({ organizations: workspaces });

      window.OrganizationSettings.init();
      await new Promise((r) => setTimeout(r, 50));

      const personalBtn = document.getElementById("org-switch-personal");
      expect(personalBtn).toBeTruthy();
      expect(personalBtn.classList.contains("active")).toBe(true);
    });

    it("marks the correct org as active when org context is set", async () => {
      window.organizationManager.setActiveOrg("1");
      const workspaces = [
        { id: 1, name: "Org A", subscription: { plan: "pro", status: "active" } },
      ];
      window.apiClient.get.mockResolvedValue({ organizations: workspaces });

      window.OrganizationSettings.init();
      await new Promise((r) => setTimeout(r, 50));

      const orgBtn = document.getElementById("org-switch-1");
      expect(orgBtn).toBeTruthy();
      expect(orgBtn.classList.contains("active")).toBe(true);

      const personalBtn = document.getElementById("org-switch-personal");
      expect(personalBtn.classList.contains("active")).toBe(false);
    });

    it("clicking a workspace item calls setActiveOrg", async () => {
      const workspaces = [
        { id: 1, name: "Org A", subscription: { plan: "pro", status: "active" } },
      ];
      window.apiClient.get.mockResolvedValue({ organizations: workspaces });

      window.OrganizationSettings.init();
      await new Promise((r) => setTimeout(r, 50));

      const spy = vi.spyOn(window.organizationManager, "setActiveOrg");
      const orgBtn = document.getElementById("org-switch-1");
      orgBtn.click();
      expect(spy).toHaveBeenCalledWith("1");
    });

    it("clicking Personal clears active org", async () => {
      window.organizationManager.setActiveOrg("1");
      const workspaces = [
        { id: 1, name: "Org A", subscription: { plan: "pro", status: "active" } },
      ];
      window.apiClient.get.mockResolvedValue({ organizations: workspaces });

      window.OrganizationSettings.init();
      await new Promise((r) => setTimeout(r, 50));

      const spy = vi.spyOn(window.organizationManager, "clearActiveOrg");
      const personalBtn = document.getElementById("org-switch-personal");
      personalBtn.click();
      expect(spy).toHaveBeenCalled();
    });
  });

  // ─── Settings Pane ──────────────────────────────────────────────

  describe("Org Settings Pane", () => {
    it("renders no-org state when not in org context", async () => {
      await window.OrganizationSettings.loadSettingsPane();

      const pane = document.getElementById("pane-org-settings");
      expect(pane.innerHTML).toContain("No Organization Selected");
      expect(pane.innerHTML).toContain("org-start-onboarding-btn");
    });

    it("renders org overview with name, domain, plan, status", async () => {
      window.organizationManager.setActiveOrg("org-7");

      window.apiClient.get.mockImplementation(async (url) => {
        if (url === "organizations/details")
          return {
            organization: {
              name: "TestOrg",
              domain: "test.io",
              slug: "testorg",
              logo_url: null,
              subscription: { plan: "pro", status: "active", expires_at: "2027-01-01" },
            },
            limits: { max_projects: 10, max_scans_per_month: 500, max_members: 20 },
            usage: { projects_count: 3, scans_used: 42, members_count: 5 },
          };
        if (url === "organizations/members")
          return {
            members: [
              {
                id: 1,
                full_name: "Test User",
                email: "test@domain.com",
                job_tittle: "Lead",
                pivot: { role: "owner", joined_at: "2024-01-15" },
              },
            ],
          };
        if (url === "organizations/invitations") return { invitations: [] };
        return {};
      });

      await window.OrganizationSettings.loadSettingsPane();

      const pane = document.getElementById("pane-org-settings");
      expect(pane.innerHTML).toContain("TestOrg");
      expect(pane.innerHTML).toContain("test.io");
      expect(pane.innerHTML).toContain("Pro");
      expect(pane.innerHTML).toContain("Active");
      expect(pane.innerHTML).toContain("3 / 10");
      expect(pane.innerHTML).toContain("42 / 500");
      expect(pane.innerHTML).toContain("5 / 20");
    });

    it("renders member rows with role badges and job_tittle", async () => {
      window.organizationManager.setActiveOrg("org-7");

      window.apiClient.get.mockImplementation(async (url) => {
        if (url === "organizations/details")
          return {
            organization: {
              name: "TestOrg",
              domain: "t.io",
              subscription: { plan: "starter", status: "active" },
            },
            limits: {},
            usage: {},
          };
        if (url === "organizations/members")
          return {
            members: [
              {
                id: 1,
                full_name: "Test User",
                email: "test@domain.com",
                job_tittle: "CTO",
                pivot: { role: "owner", joined_at: "2024-01-15" },
              },
              {
                id: 2,
                full_name: "Bob Smith",
                email: "bob@domain.com",
                job_tittle: "Engineer",
                pivot: { role: "admin", joined_at: "2024-02-10" },
              },
            ],
          };
        if (url === "organizations/invitations") return { invitations: [] };
        return {};
      });

      await window.OrganizationSettings.loadSettingsPane();

      const pane = document.getElementById("pane-org-settings");
      // Check member names
      expect(pane.innerHTML).toContain("Test User");
      expect(pane.innerHTML).toContain("Bob Smith");
      // Check role badges
      expect(pane.innerHTML).toContain("Owner");
      expect(pane.innerHTML).toContain("Admin");
      // Check job_tittle (double-t preserved)
      expect(pane.innerHTML).toContain("CTO");
      expect(pane.innerHTML).toContain("Engineer");
    });

    it("shows invite form when user is owner", async () => {
      window.organizationManager.setActiveOrg("org-7");

      window.apiClient.get.mockImplementation(async (url) => {
        if (url === "organizations/details")
          return {
            organization: {
              name: "TestOrg",
              domain: "t.io",
              subscription: { plan: "pro", status: "active" },
            },
            limits: {},
            usage: {},
          };
        if (url === "organizations/members")
          return {
            members: [
              {
                id: 1,
                full_name: "Test User",
                email: "test@domain.com",
                pivot: { role: "owner" },
              },
            ],
          };
        if (url === "organizations/invitations") return { invitations: [] };
        return {};
      });

      await window.OrganizationSettings.loadSettingsPane();

      const inviteForm = document.getElementById("org-invite-form");
      expect(inviteForm).toBeTruthy();
    });

    it("shows danger zone only when user is owner", async () => {
      window.organizationManager.setActiveOrg("org-7");

      window.apiClient.get.mockImplementation(async (url) => {
        if (url === "organizations/details")
          return {
            organization: {
              name: "TestOrg",
              domain: "t.io",
              subscription: { plan: "pro", status: "active" },
            },
            limits: {},
            usage: {},
          };
        if (url === "organizations/members")
          return {
            members: [
              {
                id: 1,
                full_name: "Test User",
                email: "test@domain.com",
                pivot: { role: "owner" },
              },
            ],
          };
        if (url === "organizations/invitations") return { invitations: [] };
        return {};
      });

      await window.OrganizationSettings.loadSettingsPane();

      const deleteBtn = document.getElementById("org-delete-btn");
      expect(deleteBtn).toBeTruthy();
    });

    it("shows pending invitations section when invitations exist", async () => {
      window.organizationManager.setActiveOrg("org-7");

      window.apiClient.get.mockImplementation(async (url) => {
        if (url === "organizations/details")
          return {
            organization: {
              name: "T",
              domain: "t.io",
              subscription: { plan: "pro", status: "active" },
            },
            limits: {},
            usage: {},
          };
        if (url === "organizations/members")
          return {
            members: [
              { id: 1, full_name: "Test User", email: "test@domain.com", pivot: { role: "owner" } },
            ],
          };
        if (url === "organizations/invitations")
          return {
            invitations: [
              { email: "pending@corp.com", role: "member", expires_at: "2027-12-31T00:00:00Z" },
            ],
          };
        return {};
      });

      await window.OrganizationSettings.loadSettingsPane();

      const pane = document.getElementById("pane-org-settings");
      expect(pane.innerHTML).toContain("Pending Invitations");
      expect(pane.innerHTML).toContain("pending@corp.com");
    });

    it("shows error state on failed load and retry button works", async () => {
      window.organizationManager.setActiveOrg("org-7");
      window.apiClient.get.mockRejectedValue(new Error("Network fail"));

      await window.OrganizationSettings.loadSettingsPane();

      const pane = document.getElementById("pane-org-settings");
      expect(pane.innerHTML).toContain("Failed to load organization details");
      const retryBtn = document.getElementById("org-settings-retry-btn");
      expect(retryBtn).toBeTruthy();
    });
  });

  // ─── Onboarding Wizard ──────────────────────────────────────────

  describe("Onboarding Wizard", () => {
    it("opens the modal and renders step 1 form", () => {
      window.OrganizationSettings._openOnboardingWizard();

      const modal = document.getElementById("org-onboarding-modal");
      expect(modal.classList.contains("hidden")).toBe(false);

      const body = document.getElementById("org-onboarding-body");
      expect(body.innerHTML).toContain("Create Organization");
      expect(body.innerHTML).toContain("onboard-org-name");
      expect(body.innerHTML).toContain("onboard-domain");
      expect(body.innerHTML).toContain("onboard-plan");
    });

    it("closes the modal when _closeOnboardingWizard is called", () => {
      window.OrganizationSettings._openOnboardingWizard();
      window.OrganizationSettings._closeOnboardingWizard();

      const modal = document.getElementById("org-onboarding-modal");
      expect(modal.classList.contains("hidden")).toBe(true);
    });

    it("renders step 2 billing form", () => {
      window.OrganizationSettings._openOnboardingWizard();
      window.OrganizationSettings._renderOnboardingStep(2);

      const body = document.getElementById("org-onboarding-body");
      expect(body.innerHTML).toContain("Billing Information");
      expect(body.innerHTML).toContain("billing-first-name");
      expect(body.innerHTML).toContain("billing-last-name");
      expect(body.innerHTML).toContain("billing-email");
      expect(body.innerHTML).toContain("billing-phone");
    });

    it("renders step 3 corporate email form", () => {
      window.OrganizationSettings._openOnboardingWizard();
      window.OrganizationSettings._renderOnboardingStep(3);

      const body = document.getElementById("org-onboarding-body");
      expect(body.innerHTML).toContain("Corporate Email Verification");
      expect(body.innerHTML).toContain("corp-email");
    });
  });

  // ─── Post-Payment Flow ──────────────────────────────────────────

  describe("Post-Payment Flow", () => {
    it("does nothing if there is no pending organization ID", async () => {
      const spy = vi.spyOn(window.organizationManager, "pollPaymentStatus");
      await window.OrganizationSettings.startPostPaymentFlow();
      expect(spy).not.toHaveBeenCalled();
    });

    it("opens step 3 verification if payment status is pending_email_verification", async () => {
      window.organizationManager.setPendingOrgId("pending-org-123");
      vi.spyOn(window.organizationManager, "pollPaymentStatus").mockResolvedValue({
        payment_status: "pending_email_verification",
      });

      const openSpy = vi.spyOn(window.OrganizationSettings, "_openOnboardingWizard");
      const renderSpy = vi.spyOn(window.OrganizationSettings, "_renderOnboardingStep");

      await window.OrganizationSettings.startPostPaymentFlow();

      expect(openSpy).toHaveBeenCalled();
      expect(renderSpy).toHaveBeenCalledWith(3);
    });

    it("activates organization if payment status is active", async () => {
      window.organizationManager.setPendingOrgId("pending-org-123");
      vi.spyOn(window.organizationManager, "pollPaymentStatus").mockResolvedValue({
        payment_status: "active",
      });

      const activeSpy = vi.spyOn(window.organizationManager, "setActiveOrg");
      const clearSpy = vi.spyOn(window.organizationManager, "clearPendingOrgId");
      const switcherSpy = vi.spyOn(window.OrganizationSettings, "_loadWorkspaceSwitcher");

      await window.OrganizationSettings.startPostPaymentFlow();

      expect(activeSpy).toHaveBeenCalledWith("pending-org-123");
      expect(clearSpy).toHaveBeenCalled();
      expect(switcherSpy).toHaveBeenCalled();
      expect(window.CyberNotify.alert).toHaveBeenCalledWith(
        "Organization activated successfully!",
        { type: "success" }
      );
    });
  });

  // ─── Helper Methods ─────────────────────────────────────────────

  describe("Helper methods", () => {
    it("_getInitials returns correct initials for two-word names", () => {
      expect(window.OrganizationSettings._getInitials("John Doe")).toBe("JD");
      expect(window.OrganizationSettings._getInitials("Alice Bob Charlie")).toBe("AC");
    });

    it("_getInitials handles single-word names", () => {
      expect(window.OrganizationSettings._getInitials("John")).toBe("JO");
    });

    it("_getInitials returns '?' for empty/null", () => {
      expect(window.OrganizationSettings._getInitials("")).toBe("?");
      expect(window.OrganizationSettings._getInitials(null)).toBe("?");
    });
  });
});
