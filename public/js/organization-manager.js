/**
 * Organization Manager — CyberGuard Multi-Tenancy API Layer
 *
 * Handles all organization-related API communication:
 *   - Onboarding (initiate, checkout, payment status, corporate email)
 *   - Workspace CRUD (list, details, update, delete)
 *   - Team / IAM (members, invitations, role changes)
 *   - DNS ownership verification for targets
 *   - Org context helpers (active org, header injection)
 *
 * Every org-scoped endpoint automatically includes the
 * X-Organization-Id header read from localStorage.
 *
 * Depends on: window.apiClient (APIClient instance from api-client.js)
 */
(() => {
  "use strict";

  // ─── Constants ──────────────────────────────────────────────────────────────
  const ORG_ID_KEY = "cyberguard_active_org_id";
  const PENDING_ORG_KEY = "cyberguard_pending_org_id";
  const PAYMENT_POLL_INTERVAL = 5000; // 5 seconds
  const PAYMENT_POLL_MAX_ATTEMPTS = 12; // 60 seconds total

  // ─── Class ──────────────────────────────────────────────────────────────────
  class OrganizationManager {
    constructor() {
      this.workspaces = [];
      this._paymentPollTimer = null;
      this._pendingDetailsRequest = null;
    }

    // ─── Context Helpers ────────────────────────────────────────────────────

    /**
     * Get the active organization ID from localStorage.
     * @returns {string|null}
     */
    getActiveOrgId() {
      return localStorage.getItem(ORG_ID_KEY) || null;
    }

    /**
     * Set the active organization context.
     * Stores the ID and dispatches a context-change event.
     * @param {string} orgId
     */
    setActiveOrg(orgId) {
      if (!orgId) return;
      localStorage.setItem(ORG_ID_KEY, orgId);
      document.dispatchEvent(
        new CustomEvent("cyberguard:orgContextChanged", {
          detail: { organizationId: orgId },
        })
      );
    }

    /**
     * Clear the active organization context (switch to personal workspace).
     */
    clearActiveOrg() {
      localStorage.removeItem(ORG_ID_KEY);
      document.dispatchEvent(
        new CustomEvent("cyberguard:orgContextChanged", {
          detail: { organizationId: null },
        })
      );
    }

    /**
     * Check whether the user is currently operating in an org context.
     * @returns {boolean}
     */
    isOrgContext() {
      return !!this.getActiveOrgId();
    }

    /**
     * Build the X-Organization-Id header object for org-scoped requests.
     * Returns an empty object when no org is active.
     * @returns {Object}
     */
    getOrgHeaders() {
      const orgId = this.getActiveOrgId();
      return orgId ? { "X-Organization-Id": orgId } : {};
    }

    /**
     * Get the pending org ID (set during onboarding before activation).
     * @returns {string|null}
     */
    getPendingOrgId() {
      return localStorage.getItem(PENDING_ORG_KEY) || null;
    }

    /**
     * Set the pending org ID during onboarding.
     * @param {string} orgId
     */
    setPendingOrgId(orgId) {
      if (orgId) {
        localStorage.setItem(PENDING_ORG_KEY, orgId);
      }
    }

    /**
     * Clear the pending org ID after onboarding completes.
     */
    clearPendingOrgId() {
      localStorage.removeItem(PENDING_ORG_KEY);
    }

    // ─── Section 1: Onboarding Flow ─────────────────────────────────────────

    /**
     * Step 1 — Initiate organization onboarding.
     * POST /api/organizations/initiate
     * @param {{ org_name: string, company_domain: string, plan: string }} data
     * @returns {Promise<Object>} { organization_id, organization_name, plan, ... }
     */
    async initiateOnboarding(data) {
      try {
        if (typeof showLoading === "function") showLoading("Creating organization…");
        const response = await window.apiClient.post("organizations/initiate", {
          org_name: data.org_name,
          company_domain: data.company_domain,
          plan: data.plan,
          corporate_email: data.corporate_email,
        });
        // Store the pending org ID for checkout
        if (response.organization_id) {
          this.setPendingOrgId(response.organization_id);
        }
        return response;
      } catch (error) {
        console.error("[OrganizationManager] initiateOnboarding error:", error);
        throw error;
      } finally {
        if (typeof hideLoading === "function") hideLoading();
      }
    }

    /**
     * Step 2 — Submit checkout billing data to Paymob.
     * POST /api/organizations/{organization_id}/payment/checkout
     * @param {string} organizationId
     * @param {{ plan: string, billing_data: Object }} data
     * @returns {Promise<Object>} { data: { iframe_url, billing_order_id, ... } }
     */
    async submitCheckout(organizationId, data) {
      try {
        if (typeof showLoading === "function") showLoading("Processing payment…");
        const endpoint = `organizations/${organizationId}/payment/checkout`;
        console.log("[OrganizationManager] submitCheckout called:");
        console.log("  organizationId:", organizationId);
        console.log("  endpoint:", endpoint);
        console.log("  full URL will be:", window.apiClient.baseURL + endpoint);
        console.log("  payload:", JSON.stringify(data));
        const response = await window.apiClient.post(endpoint, data);
        return response;
      } catch (error) {
        console.error("[OrganizationManager] submitCheckout error:", error);
        throw error;
      } finally {
        if (typeof hideLoading === "function") hideLoading();
      }
    }

    /**
     * Step 3a — Poll payment status until payment is confirmed.
     * GET /api/organizations/{organization_id}/payment/status
     * Polls every 5 seconds, max 12 attempts (60s total).
     * @param {string} organizationId
     * @returns {Promise<Object>} Final status response
     */
    async pollPaymentStatus(organizationId) {
      return new Promise((resolve, reject) => {
        let attempts = 0;

        const poll = async () => {
          attempts++;
          try {
            const response = await window.apiClient.get(
              `organizations/${organizationId}/payment/status`
            );
            const status = response.payment_status;

            if (status === "pending_email_verification" || status === "active") {
              this._clearPaymentPoll();
              resolve(response);
              return;
            }

            if (attempts >= PAYMENT_POLL_MAX_ATTEMPTS) {
              this._clearPaymentPoll();
              reject(new Error("Payment verification timed out. Please check your email or try again."));
              return;
            }
          } catch (error) {
            if (attempts >= PAYMENT_POLL_MAX_ATTEMPTS) {
              this._clearPaymentPoll();
              reject(error);
              return;
            }
          }
        };

        // Start polling
        poll();
        this._paymentPollTimer = setInterval(poll, PAYMENT_POLL_INTERVAL);
      });
    }

    /** @private */
    _clearPaymentPoll() {
      if (this._paymentPollTimer) {
        clearInterval(this._paymentPollTimer);
        this._paymentPollTimer = null;
      }
    }

    /**
     * Step 3b — Submit corporate email for verification.
     * POST /api/organizations/{organization_id}/corporate-email
     * @param {string} organizationId
     * @param {string} corporateEmail
     * @returns {Promise<Object>}
     */
    async submitCorporateEmail(organizationId, corporateEmail) {
      try {
        if (typeof showLoading === "function") showLoading("Sending verification…");
        const response = await window.apiClient.post(
          `organizations/${organizationId}/corporate-email`,
          { corporate_email: corporateEmail }
        );
        return response;
      } catch (error) {
        console.error("[OrganizationManager] submitCorporateEmail error:", error);
        throw error;
      } finally {
        if (typeof hideLoading === "function") hideLoading();
      }
    }

    // ─── Section 1B: Invitation Flows ───────────────────────────────────────

    /**
     * Fetch invitation details (public, no auth required).
     * GET /api/organizations/invitations/{token}
     * @param {string} token
     * @returns {Promise<Object>} { is_exist, invitation: { email, role, organization } }
     */
    async fetchInvitationDetails(token) {
      try {
        return await window.apiClient.get(
          `organizations/invitations/${token}`,
          { skipAuth: true }
        );
      } catch (error) {
        console.error("[OrganizationManager] fetchInvitationDetails error:", error);
        throw error;
      }
    }

    /**
     * Register a new user via an org invitation (no auth required).
     * POST /api/organizations/invitations/{token}/register
     * @param {string} token
     * @param {{ full_name: string, password: string, password_confirmation: string, job_tittle: string }} data
     * @returns {Promise<Object>} { token, user }
     */
    async registerViaInvitation(token, data) {
      try {
        if (typeof showLoading === "function") showLoading("Creating account…");
        const response = await window.apiClient.post(
          `organizations/invitations/${token}/register`,
          data,
          { skipAuth: true }
        );
        return response;
      } catch (error) {
        console.error("[OrganizationManager] registerViaInvitation error:", error);
        throw error;
      } finally {
        if (typeof hideLoading === "function") hideLoading();
      }
    }

    /**
     * Accept an org invitation (authenticated user).
     * POST /api/organizations/{token}/accept
     * @param {string} token
     * @returns {Promise<Object>}
     */
    async acceptInvitation(token) {
      try {
        if (typeof showLoading === "function") showLoading("Joining organization…");
        const response = await window.apiClient.post(
          `organizations/${token}/accept`
        );
        return response;
      } catch (error) {
        console.error("[OrganizationManager] acceptInvitation error:", error);
        throw error;
      } finally {
        if (typeof hideLoading === "function") hideLoading();
      }
    }

    // ─── Section 2: Workspace Management ────────────────────────────────────

    /**
     * Fetch all workspaces the current user belongs to.
     * GET /api/organizations/my-workspaces
     * @returns {Promise<Array>} Array of organization objects with subscriptions
     */
    async fetchMyWorkspaces() {
      try {
        const response = await window.apiClient.get("organizations/my-workspaces");
        this.workspaces = Array.isArray(response.organizations)
          ? response.organizations
          : [];
        return this.workspaces;
      } catch (error) {
        console.error("[OrganizationManager] fetchMyWorkspaces error:", error);
        this.workspaces = [];
        throw error;
      }
    }

    /**
     * Fetch details for the currently active organization.
     * GET /api/organizations/details
     * @returns {Promise<Object>} { organization, limits, usage }
     */
    async fetchOrgDetails() {
      // Deduplicate concurrent calls — return the in-flight promise if one exists
      if (this._pendingDetailsRequest) {
        return this._pendingDetailsRequest;
      }

      this._pendingDetailsRequest = (async () => {
        try {
          const response = await window.apiClient.get("organizations/details", {
            headers: this.getOrgHeaders(),
          });
          return response;
        } catch (error) {
          console.error("[OrganizationManager] fetchOrgDetails error:", error);
          throw error;
        } finally {
          this._pendingDetailsRequest = null;
        }
      })();

      return this._pendingDetailsRequest;
    }

    /**
     * Update organization details (Owner/Admin only).
     * PUT /api/organizations
     * @param {{ name?: string, logo_url?: string }} data — do NOT send domain
     * @returns {Promise<Object>}
     */
    async updateOrganization(data) {
      try {
        if (typeof showLoading === "function") showLoading("Saving…");
        const response = await window.apiClient.put("organizations", data, {
          headers: this.getOrgHeaders(),
        });
        return response;
      } catch (error) {
        console.error("[OrganizationManager] updateOrganization error:", error);
        throw error;
      } finally {
        if (typeof hideLoading === "function") hideLoading();
      }
    }

    /**
     * Delete organization (Owner only).
     * DELETE /api/organizations
     * @returns {Promise<Object>}
     */
    async deleteOrganization() {
      try {
        if (typeof showLoading === "function") showLoading("Deleting workspace…");
        const response = await window.apiClient.delete("organizations", {
          headers: this.getOrgHeaders(),
        });
        // Clear org context on successful deletion
        this.clearActiveOrg();
        return response;
      } catch (error) {
        console.error("[OrganizationManager] deleteOrganization error:", error);
        throw error;
      } finally {
        if (typeof hideLoading === "function") hideLoading();
      }
    }

    // ─── Section 3: Team / IAM ──────────────────────────────────────────────

    /**
     * Fetch all members of the active organization.
     * GET /api/organizations/members
     * @returns {Promise<Array>}
     */
    async fetchMembers() {
      try {
        const response = await window.apiClient.get("organizations/members", {
          headers: this.getOrgHeaders(),
        });
        return Array.isArray(response.members) ? response.members : [];
      } catch (error) {
        console.error("[OrganizationManager] fetchMembers error:", error);
        throw error;
      }
    }

    /**
     * Fetch pending invitations for the active organization.
     * GET /api/organizations/invitations
     * @returns {Promise<Array>}
     */
    async fetchOrgInvitations() {
      try {
        const response = await window.apiClient.get("organizations/invitations", {
          headers: this.getOrgHeaders(),
        });
        return Array.isArray(response.invitations) ? response.invitations : [];
      } catch (error) {
        console.error("[OrganizationManager] fetchOrgInvitations error:", error);
        throw error;
      }
    }

    /**
     * Invite a new member to the active organization.
     * POST /api/organizations/members/invite
     * @param {{ email: string, role: string }} data
     * @returns {Promise<Object>}
     */
    async inviteMember(data) {
      try {
        if (typeof showLoading === "function") showLoading("Sending invitation…");
        const response = await window.apiClient.post(
          "organizations/members/invite",
          { email: data.email, role: data.role },
          { headers: this.getOrgHeaders() }
        );
        return response;
      } catch (error) {
        console.error("[OrganizationManager] inviteMember error:", error);
        throw error;
      } finally {
        if (typeof hideLoading === "function") hideLoading();
      }
    }

    /**
     * Change a member's role in the active organization.
     * PUT /api/organizations/members/{userId}/role
     * @param {string} userId
     * @param {string} role — 'admin' | 'member' | 'viewer'
     * @returns {Promise<Object>}
     */
    async changeMemberRole(userId, role) {
      try {
        const response = await window.apiClient.put(
          `organizations/members/${userId}/role`,
          { role },
          { headers: this.getOrgHeaders() }
        );
        return response;
      } catch (error) {
        console.error("[OrganizationManager] changeMemberRole error:", error);
        throw error;
      }
    }

    /**
     * Remove a member from the active organization.
     * DELETE /api/organizations/members/{userId}
     * @param {string} userId
     * @returns {Promise<Object>}
     */
    async removeMember(userId) {
      try {
        if (typeof showLoading === "function") showLoading("Removing member…");
        const response = await window.apiClient.delete(
          `organizations/members/${userId}`,
          { headers: this.getOrgHeaders() }
        );
        return response;
      } catch (error) {
        console.error("[OrganizationManager] removeMember error:", error);
        throw error;
      } finally {
        if (typeof hideLoading === "function") hideLoading();
      }
    }

    // ─── Section 4: DNS Ownership Verification ──────────────────────────────

    /**
     * Trigger DNS TXT record verification for a target.
     * POST /api/targets/{target_id}/verify-dns
     * @param {string} targetId
     * @returns {Promise<Object>}
     */
    async verifyDns(targetId) {
      try {
        if (typeof showLoading === "function") showLoading("Verifying DNS…");
        const response = await window.apiClient.post(
          `targets/${targetId}/verify-dns`,
          null,
          { headers: this.getOrgHeaders() }
        );
        return response;
      } catch (error) {
        console.error("[OrganizationManager] verifyDns error:", error);
        throw error;
      } finally {
        if (typeof hideLoading === "function") hideLoading();
      }
    }

    // ─── Utilities ──────────────────────────────────────────────────────────

    /**
     * Get the user's role in the active organization from the cached workspaces.
     * @returns {string|null} 'owner' | 'admin' | 'member' | 'viewer' | null
     */
    getCurrentOrgRole() {
      const orgId = this.getActiveOrgId();
      if (!orgId) return null;
      // Role will be determined from the org details or members list
      // For now return null — OrganizationSettings will fetch and cache it
      return null;
    }

    /**
     * Find a workspace by ID from the cached list.
     * @param {string} orgId
     * @returns {Object|null}
     */
    getWorkspace(orgId) {
      return this.workspaces.find((w) => String(w.id) === String(orgId)) || null;
    }
  }

  // ─── Dual Export ────────────────────────────────────────────────────────────
  if (typeof module !== "undefined" && module.exports) {
    module.exports = { OrganizationManager };
  } else {
    window.OrganizationManager = OrganizationManager;
    window.organizationManager = new OrganizationManager();
  }
})();
