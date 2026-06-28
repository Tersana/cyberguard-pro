/**
 * Unit Tests — OrganizationManager
 *
 * Validates every public method of the OrganizationManager class:
 *   - Context helpers (getActiveOrgId, setActiveOrg, clearActiveOrg, isOrgContext, getOrgHeaders)
 *   - Onboarding flow (initiate, checkout, payment polling, corporate email)
 *   - Invitation handling (fetchDetails, register, accept)
 *   - Workspace management (fetch, details, update, delete)
 *   - Team / IAM (fetchMembers, fetchOrgInvitations, inviteMember, changeRole, removeMember)
 *   - DNS verification (verifyDns)
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { JSDOM } from "jsdom";
import fs from "fs";
import path from "path";

describe("OrganizationManager", () => {
  let dom;
  let window;
  let document;

  beforeEach(() => {
    dom = new JSDOM(
      `<!DOCTYPE html><html><body></body></html>`,
      { url: "http://localhost", runScripts: "dangerously", resources: "usable" }
    );
    window = dom.window;
    document = window.document;

    global.window = window;
    global.document = document;
    global.localStorage = window.localStorage;
    global.CustomEvent = window.CustomEvent;

    // Mock loading helpers
    window.showLoading = vi.fn();
    window.hideLoading = vi.fn();
    global.showLoading = window.showLoading;
    global.hideLoading = window.hideLoading;

    // Mock apiClient
    window.apiClient = {
      get: vi.fn().mockResolvedValue({}),
      post: vi.fn().mockResolvedValue({}),
      put: vi.fn().mockResolvedValue({}),
      delete: vi.fn().mockResolvedValue({}),
    };

    // Load source
    const src = fs.readFileSync(
      path.resolve(__dirname, "../../public/js/organization-manager.js"),
      "utf8"
    );
    window.eval(src);
  });

  afterEach(() => {
    localStorage.clear();
    delete global.window;
    delete global.document;
    delete global.localStorage;
    delete global.CustomEvent;
    delete global.showLoading;
    delete global.hideLoading;
    vi.clearAllMocks();
    vi.restoreAllMocks();
  });

  // ─── Context Helpers ────────────────────────────────────────────

  describe("Context helpers", () => {
    it("getActiveOrgId returns null when no org is set", () => {
      expect(window.organizationManager.getActiveOrgId()).toBeNull();
    });

    it("setActiveOrg stores org ID in localStorage", () => {
      window.organizationManager.setActiveOrg("org-123");
      expect(localStorage.getItem("cyberguard_active_org_id")).toBe("org-123");
    });

    it("setActiveOrg dispatches cyberguard:orgContextChanged event", () => {
      let firedDetail = null;
      document.addEventListener("cyberguard:orgContextChanged", (e) => {
        firedDetail = e.detail;
      });
      window.organizationManager.setActiveOrg("org-abc");
      expect(firedDetail).toEqual({ organizationId: "org-abc" });
    });

    it("clearActiveOrg removes org ID and dispatches event", () => {
      localStorage.setItem("cyberguard_active_org_id", "org-123");
      let firedDetail = null;
      document.addEventListener("cyberguard:orgContextChanged", (e) => {
        firedDetail = e.detail;
      });
      window.organizationManager.clearActiveOrg();
      expect(localStorage.getItem("cyberguard_active_org_id")).toBeNull();
      expect(firedDetail).toEqual({ organizationId: null });
    });

    it("isOrgContext returns true when org is set, false otherwise", () => {
      expect(window.organizationManager.isOrgContext()).toBe(false);
      window.organizationManager.setActiveOrg("org-1");
      expect(window.organizationManager.isOrgContext()).toBe(true);
    });

    it("getOrgHeaders returns empty object when no org, header when set", () => {
      expect(window.organizationManager.getOrgHeaders()).toEqual({});
      window.organizationManager.setActiveOrg("org-42");
      expect(window.organizationManager.getOrgHeaders()).toEqual({
        "X-Organization-Id": "org-42",
      });
    });
  });

  // ─── Pending Org ────────────────────────────────────────────────

  describe("Pending org", () => {
    it("setPendingOrgId / getPendingOrgId / clearPendingOrgId round-trip", () => {
      expect(window.organizationManager.getPendingOrgId()).toBeNull();
      window.organizationManager.setPendingOrgId("pending-1");
      expect(window.organizationManager.getPendingOrgId()).toBe("pending-1");
      window.organizationManager.clearPendingOrgId();
      expect(window.organizationManager.getPendingOrgId()).toBeNull();
    });
  });

  // ─── Onboarding Flow ───────────────────────────────────────────

  describe("Onboarding flow", () => {
    it("initiateOnboarding sends correct payload and stores pending org ID", async () => {
      window.apiClient.post.mockResolvedValue({
        organization_id: "new-org-99",
        organization_name: "Acme",
        plan: "pro",
      });

      const result = await window.organizationManager.initiateOnboarding({
        org_name: "Acme",
        company_domain: "acme.com",
        plan: "pro",
        corporate_email: "admin@acme.com",
      });

      expect(window.apiClient.post).toHaveBeenCalledWith("organizations/initiate", {
        org_name: "Acme",
        company_domain: "acme.com",
        plan: "pro",
        corporate_email: "admin@acme.com",
      });
      expect(result.organization_id).toBe("new-org-99");
      expect(window.organizationManager.getPendingOrgId()).toBe("new-org-99");
      expect(window.showLoading).toHaveBeenCalled();
      expect(window.hideLoading).toHaveBeenCalled();
    });

    it("submitCheckout sends correct payload with plan and billing_data", async () => {
      const billingData = { first_name: "John", last_name: "Doe", email: "j@acme.com", phone_number: "+1" };
      window.apiClient.post.mockResolvedValue({ data: { iframe_url: "https://paymob.com/checkout" } });

      const result = await window.organizationManager.submitCheckout("org-99", {
        plan: "pro",
        billing_data: billingData,
      });

      expect(window.apiClient.post).toHaveBeenCalledWith(
        "organizations/org-99/payment/checkout",
        { plan: "pro", billing_data: billingData }
      );
      expect(result.data.iframe_url).toBe("https://paymob.com/checkout");
    });

    it("submitCorporateEmail sends correct payload to resend-verification", async () => {
      window.apiClient.post.mockResolvedValue({ message: "Verification email sent" });

      const result = await window.organizationManager.submitCorporateEmail("org-99", "admin@acme.com");

      expect(window.apiClient.post).toHaveBeenCalledWith(
        "organizations/org-99/resend-verification",
        { corporate_email: "admin@acme.com" }
      );
      expect(result.message).toBe("Verification email sent");
    });

    it("resendVerification sends correct payload to resend-verification", async () => {
      window.apiClient.post.mockResolvedValue({ message: "Resent" });

      const result = await window.organizationManager.resendVerification("org-99", "admin@acme.com");

      expect(window.apiClient.post).toHaveBeenCalledWith(
        "organizations/org-99/resend-verification",
        { corporate_email: "admin@acme.com" }
      );
      expect(result.message).toBe("Resent");
    });

    it("resumePayment sends correct payload to resume-payment", async () => {
      const billingData = { first_name: "John", last_name: "Doe" };
      window.apiClient.post.mockResolvedValue({ data: { iframe_url: "https://paymob.com/resume" } });

      const result = await window.organizationManager.resumePayment("org-99", {
        plan: "pro",
        billing_data: billingData,
      });

      expect(window.apiClient.post).toHaveBeenCalledWith(
        "organizations/org-99/resume-payment",
        { plan: "pro", billing_data: billingData }
      );
      expect(result.data.iframe_url).toBe("https://paymob.com/resume");
    });
  });

  // ─── Invitation Handling ────────────────────────────────────────

  describe("Invitation handling", () => {
    it("fetchInvitationDetails calls correct endpoint with skipAuth", async () => {
      window.apiClient.get.mockResolvedValue({
        is_exist: false,
        invitation: { email: "new@acme.com", role: "member", organization: { name: "Acme" } },
      });

      const result = await window.organizationManager.fetchInvitationDetails("tok-abc");

      expect(window.apiClient.get).toHaveBeenCalledWith("organizations/invitations/tok-abc", {
        skipAuth: true,
      });
      expect(result.is_exist).toBe(false);
    });

    it("registerViaInvitation sends registration data with skipAuth", async () => {
      window.apiClient.post.mockResolvedValue({ token: "jwt-xyz", user: { id: 1 } });

      const result = await window.organizationManager.registerViaInvitation("tok-abc", {
        full_name: "Jane Doe",
        password: "securePass1",
        password_confirmation: "securePass1",
        job_tittle: "Engineer",
      });

      expect(window.apiClient.post).toHaveBeenCalledWith(
        "organizations/invitations/tok-abc/register",
        {
          full_name: "Jane Doe",
          password: "securePass1",
          password_confirmation: "securePass1",
          job_tittle: "Engineer",
        },
        { skipAuth: true }
      );
      expect(result.token).toBe("jwt-xyz");
    });

    it("acceptInvitation sends POST to correct endpoint", async () => {
      window.apiClient.post.mockResolvedValue({ message: "Joined" });

      await window.organizationManager.acceptInvitation("tok-abc");

      expect(window.apiClient.post).toHaveBeenCalledWith("organizations/tok-abc/accept");
    });
  });

  // ─── Workspace Management ──────────────────────────────────────

  describe("Workspace management", () => {
    it("fetchMyWorkspaces stores workspaces and returns array (legacy format)", async () => {
      const mockWorkspaces = [
        { id: 1, name: "Org A", subscription: { plan: "pro" } },
        { id: 2, name: "Org B", subscription: { plan: "starter" } },
      ];
      window.apiClient.get.mockResolvedValue({ organizations: mockWorkspaces });

      const result = await window.organizationManager.fetchMyWorkspaces();

      expect(window.apiClient.get).toHaveBeenCalledWith("organizations/my-workspaces");
      expect(result).toHaveLength(2);
      expect(window.organizationManager.workspaces).toHaveLength(2);
    });

    it("fetchMyWorkspaces stores workspaces and returns combined array (new format)", async () => {
      const mockResponse = {
        status: "success",
        active: [{ id: 1, name: "Org Active" }],
        pending: [{ id: 2, name: "Org Pending" }],
        deleted: [{ id: 3, name: "Org Deleted" }],
      };
      window.apiClient.get.mockResolvedValue(mockResponse);

      const result = await window.organizationManager.fetchMyWorkspaces();

      expect(window.apiClient.get).toHaveBeenCalledWith("organizations/my-workspaces");
      expect(result).toHaveLength(2);
      expect(window.organizationManager.workspacesResponse).toEqual(mockResponse);
      expect(result[0].name).toBe("Org Active");
      expect(result[1].name).toBe("Org Pending");
    });

    it("fetchMyWorkspaces returns empty array on missing organizations/active/pending keys", async () => {
      window.apiClient.get.mockResolvedValue({});
      const result = await window.organizationManager.fetchMyWorkspaces();
      expect(result).toEqual([]);
    });

    it("fetchOrgDetails includes X-Organization-Id header", async () => {
      window.organizationManager.setActiveOrg("org-7");
      window.apiClient.get.mockResolvedValue({
        organization: { name: "Org 7" },
        limits: { max_projects: 10 },
        usage: { projects_count: 3 },
      });

      const result = await window.organizationManager.fetchOrgDetails();

      expect(window.apiClient.get).toHaveBeenCalledWith("organizations/details", {
        headers: { "X-Organization-Id": "org-7" },
      });
      expect(result.organization.name).toBe("Org 7");
    });

    it("updateOrganization sends PUT with org header", async () => {
      window.organizationManager.setActiveOrg("org-7");
      window.apiClient.put.mockResolvedValue({ message: "Updated" });

      await window.organizationManager.updateOrganization({ name: "New Name" });

      expect(window.apiClient.put).toHaveBeenCalledWith(
        "organizations",
        { name: "New Name" },
        { headers: { "X-Organization-Id": "org-7" } }
      );
    });

    it("deleteOrganization sends DELETE with org header and clears context", async () => {
      window.organizationManager.setActiveOrg("org-7");
      window.apiClient.delete.mockResolvedValue({ message: "Deleted" });

      await window.organizationManager.deleteOrganization();

      expect(window.apiClient.delete).toHaveBeenCalledWith("organizations", {
        headers: { "X-Organization-Id": "org-7" },
      });
      expect(window.organizationManager.getActiveOrgId()).toBeNull();
    });

    it("deleteOrganization accepts custom organizationId and sets header without clearing active context of another org", async () => {
      window.organizationManager.setActiveOrg("org-active");
      window.apiClient.delete.mockResolvedValue({ message: "Deleted" });

      await window.organizationManager.deleteOrganization("org-custom");

      expect(window.apiClient.delete).toHaveBeenCalledWith("organizations/org-custom", {
        headers: {},
      });
      expect(window.organizationManager.getActiveOrgId()).toBe("org-active");
    });

    it("forceDeleteOrganization sends DELETE to /force", async () => {
      window.apiClient.delete.mockResolvedValue({ message: "Force deleted" });

      const result = await window.organizationManager.forceDeleteOrganization("org-88");

      expect(window.apiClient.delete).toHaveBeenCalledWith("organizations/org-88/force");
      expect(result.message).toBe("Force deleted");
    });

    it("restoreOrganization sends POST to /restore", async () => {
      window.apiClient.post.mockResolvedValue({ message: "Restored" });

      const result = await window.organizationManager.restoreOrganization("org-88");

      expect(window.apiClient.post).toHaveBeenCalledWith("organizations/org-88/restore");
      expect(result.message).toBe("Restored");
    });
  });

  // ─── Team / IAM ────────────────────────────────────────────────

  describe("Team / IAM", () => {
    beforeEach(() => {
      window.organizationManager.setActiveOrg("org-100");
    });

    it("fetchMembers returns members array", async () => {
      const members = [
        { id: 1, full_name: "Alice", pivot: { role: "owner" } },
        { id: 2, full_name: "Bob", pivot: { role: "member" } },
      ];
      window.apiClient.get.mockResolvedValue({ members });

      const result = await window.organizationManager.fetchMembers();

      expect(window.apiClient.get).toHaveBeenCalledWith("organizations/members", {
        headers: { "X-Organization-Id": "org-100" },
      });
      expect(result).toHaveLength(2);
      expect(result[0].pivot.role).toBe("owner");
    });

    it("fetchOrgInvitations returns invitations array", async () => {
      window.apiClient.get.mockResolvedValue({
        invitations: [{ email: "new@corp.com", role: "admin" }],
      });

      const result = await window.organizationManager.fetchOrgInvitations();

      expect(result).toHaveLength(1);
      expect(result[0].role).toBe("admin");
    });

    it("inviteMember sends correct payload with org header", async () => {
      window.apiClient.post.mockResolvedValue({ message: "Sent" });

      await window.organizationManager.inviteMember({ email: "bob@corp.com", role: "admin" });

      expect(window.apiClient.post).toHaveBeenCalledWith(
        "organizations/members/invite",
        { email: "bob@corp.com", role: "admin" },
        { headers: { "X-Organization-Id": "org-100" } }
      );
    });

    it("changeMemberRole sends PUT with role and org header", async () => {
      window.apiClient.put.mockResolvedValue({ message: "Updated" });

      await window.organizationManager.changeMemberRole("user-5", "viewer");

      expect(window.apiClient.put).toHaveBeenCalledWith(
        "organizations/members/user-5/role",
        { role: "viewer" },
        { headers: { "X-Organization-Id": "org-100" } }
      );
    });

    it("removeMember sends DELETE with org header", async () => {
      window.apiClient.delete.mockResolvedValue({ message: "Removed" });

      await window.organizationManager.removeMember("user-5");

      expect(window.apiClient.delete).toHaveBeenCalledWith(
        "organizations/members/user-5",
        { headers: { "X-Organization-Id": "org-100" } }
      );
    });
  });

  // ─── DNS Verification ──────────────────────────────────────────

  describe("DNS verification", () => {
    it("verifyDns sends POST to /targets/{id}/verify-dns with org header", async () => {
      window.organizationManager.setActiveOrg("org-100");
      window.apiClient.post.mockResolvedValue({ message: "Verified", is_verified: true });

      const result = await window.organizationManager.verifyDns("target-55");

      expect(window.apiClient.post).toHaveBeenCalledWith(
        "targets/target-55/verify-dns",
        null,
        { headers: { "X-Organization-Id": "org-100" } }
      );
      expect(result.is_verified).toBe(true);
    });
  });

  // ─── Utility ───────────────────────────────────────────────────

  describe("Utility methods", () => {
    it("getWorkspace returns matching workspace from cached list", async () => {
      window.organizationManager.workspaces = [
        { id: 1, name: "Org A" },
        { id: 2, name: "Org B" },
      ];
      expect(window.organizationManager.getWorkspace(2)).toEqual({ id: 2, name: "Org B" });
      expect(window.organizationManager.getWorkspace(99)).toBeNull();
    });
  });

  // ─── Error Handling ────────────────────────────────────────────

  describe("Error handling", () => {
    it("initiateOnboarding re-throws API errors after hiding loading", async () => {
      const error = new Error("Validation failed");
      error.name = "ValidationError";
      window.apiClient.post.mockRejectedValue(error);

      await expect(
        window.organizationManager.initiateOnboarding({
          org_name: "X",
          company_domain: "x.com",
          plan: "pro",
        })
      ).rejects.toThrow("Validation failed");

      expect(window.hideLoading).toHaveBeenCalled();
    });

    it("fetchMyWorkspaces sets workspaces to [] on error and re-throws", async () => {
      window.apiClient.get.mockRejectedValue(new Error("Network error"));

      await expect(window.organizationManager.fetchMyWorkspaces()).rejects.toThrow("Network error");
      expect(window.organizationManager.workspaces).toEqual([]);
    });
  });
});
