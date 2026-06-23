/**
 * Organization Settings — CyberGuard Multi-Tenancy UI Layer
 *
 * Renders and manages:
 *   - Workspace Switcher (sidebar dropdown)
 *   - Organization Settings pane (inside settings modal)
 *   - Team Management (members list, invitations, invite form)
 *   - Onboarding Wizard (3-step modal flow)
 *
 * Depends on:
 *   window.organizationManager  (OrganizationManager singleton)
 *   window.apiClient            (APIClient instance)
 *   window.authManager          (AuthManager instance)
 *   window.CyberNotify          (notification system)
 *   showLoading / hideLoading   (loading utilities)
 */
(() => {
  "use strict";

  // ─── Helpers ────────────────────────────────────────────────────────────────
  function escapeHtml(str) {
    if (!str) return "";
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function formatDate(dateString) {
    if (!dateString) return "—";
    const d = new Date(dateString);
    if (isNaN(d)) return "—";
    return d.toLocaleDateString("en-US", { year: "numeric", month: "short", day: "numeric" });
  }

  function timeUntil(dateString) {
    if (!dateString) return "—";
    const target = new Date(dateString);
    if (isNaN(target)) return "—";
    const diff = target - Date.now();
    if (diff <= 0) return "Expired";
    const hours = Math.floor(diff / 3600000);
    if (hours < 24) return `${hours}h remaining`;
    const days = Math.floor(hours / 24);
    return `${days}d remaining`;
  }

  // Role badge color mapping
  const ROLE_BADGES = {
    owner:  { cls: "cyber-badge-info",    label: "Owner" },
    admin:  { cls: "cyber-badge-purple",  label: "Admin" },
    member: { cls: "cyber-badge-slate",   label: "Member" },
    viewer: { cls: "cyber-badge-muted",   label: "Viewer" },
  };

  // Plan badge color mapping
  const PLAN_BADGES = {
    starter:    { cls: "cyber-badge-info",    label: "Starter" },
    pro:        { cls: "cyber-badge-success", label: "Pro" },
    enterprise: { cls: "cyber-badge-gold",    label: "Enterprise" },
  };

  // ─── Class ──────────────────────────────────────────────────────────────────
  class OrganizationSettingsManager {
    constructor() {
      this._initialized = false;
      this._orgDetails = null;
      this._members = [];
      this._invitations = [];
      this._currentUserOrgRole = null;
    }

    // ─── Initialization ─────────────────────────────────────────────────────

    init() {
      console.log("[OrgSettings] init() called. Initialized state:", this._initialized);
      if (this._initialized) return;
      this._initialized = true;

      // Listen for session restoration to load workspaces
      document.addEventListener("cyberguard:sessionRestored", () => {
        console.log("[OrgSettings] cyberguard:sessionRestored event received");
        this._loadWorkspaceSwitcher();
        this.startPostPaymentFlow();
      });

      // Listen for org context changes
      document.addEventListener("cyberguard:orgContextChanged", () => {
        console.log("[OrgSettings] cyberguard:orgContextChanged event received");
        this._onOrgContextChanged();
      });

      // If session already exists, load immediately
      if (window.authManager && window.authManager.isAuthenticated()) {
        console.log("[OrgSettings] Session already exists on init, loading workspaces and post-payment flow");
        this._loadWorkspaceSwitcher();
        this.startPostPaymentFlow();
      } else {
        console.log("[OrgSettings] No authenticated session found on init yet");
      }

      // Setup sidebar nav item click
      this._setupSidebarNav();
    }

    reset() {
      // Called when settings panel closes — no-op for now
    }

    // ─── Workspace Switcher ─────────────────────────────────────────────────

    async _loadWorkspaceSwitcher() {
      const om = window.organizationManager;
      if (!om) return;

      try {
        const workspaces = await om.fetchMyWorkspaces();
        this._renderWorkspaceSwitcher(workspaces);
      } catch (error) {
        console.warn("[OrgSettings] Failed to load workspaces:", error);
        this._renderWorkspaceSwitcher([]);
      }
    }

    _renderWorkspaceSwitcher(workspaces) {
      const container = document.getElementById("org-workspace-switcher");
      if (!container) return;

      if (!workspaces || workspaces.length === 0) {
        container.classList.add("hidden");
        return;
      }

      container.classList.remove("hidden");
      const activeOrgId = window.organizationManager.getActiveOrgId();

      const items = workspaces
        .map((ws) => {
          const isActive = String(ws.id) === String(activeOrgId);
          const plan = ws.subscription ? ws.subscription.plan : "starter";
          const status = ws.subscription ? ws.subscription.status : "pending";
          const planBadge = PLAN_BADGES[plan] || PLAN_BADGES.starter;
          const statusCls = status === "active" ? "cyber-status-active" : "cyber-status-pending";

          return `
            <button class="cyber-org-switcher-item ${isActive ? "active" : ""}"
                    data-org-id="${escapeHtml(ws.id)}"
                    id="org-switch-${escapeHtml(ws.id)}"
                    title="${escapeHtml(ws.name)}">
              <div class="cyber-org-switcher-info">
                <span class="cyber-org-switcher-name">${escapeHtml(ws.name)}</span>
                <div class="cyber-org-switcher-badges">
                  <span class="cyber-badge-xs ${escapeHtml(planBadge.cls)}">${escapeHtml(planBadge.label)}</span>
                  <span class="cyber-status-dot ${escapeHtml(statusCls)}"></span>
                </div>
              </div>
              ${isActive ? '<span class="material-symbols-outlined cyber-org-check">check_circle</span>' : ""}
            </button>`;
        })
        .join("");

      const personalActive = !activeOrgId;

      container.innerHTML = `
        <div class="cyber-org-switcher-dropdown">
          <button class="cyber-org-switcher-item ${personalActive ? "active" : ""}"
                  id="org-switch-personal"
                  data-org-id="">
            <div class="cyber-org-switcher-info">
              <span class="cyber-org-switcher-name">Personal Workspace</span>
              <div class="cyber-org-switcher-badges">
                <span class="cyber-badge-xs cyber-badge-slate">Personal</span>
              </div>
            </div>
            ${personalActive ? '<span class="material-symbols-outlined cyber-org-check">check_circle</span>' : ""}
          </button>
          <div class="cyber-org-switcher-divider"></div>
          ${items}
        </div>`;

      // Bind click handlers
      container.querySelectorAll(".cyber-org-switcher-item").forEach((btn) => {
        btn.addEventListener("click", () => {
          const orgId = btn.getAttribute("data-org-id");
          if (orgId) {
            window.organizationManager.setActiveOrg(orgId);
          } else {
            window.organizationManager.clearActiveOrg();
          }
          // Re-render the switcher
          this._renderWorkspaceSwitcher(window.organizationManager.workspaces);
        });
      });
    }

    _onOrgContextChanged() {
      // SidebarSystemHealth already listens for cyberguard:orgContextChanged
      // directly — no need to call it again here to avoid duplicate API requests.
    }

    // ─── Sidebar Nav ────────────────────────────────────────────────────────

    _setupSidebarNav() {
      const navItem = document.getElementById("org-nav-toggle");
      if (navItem) {
        navItem.addEventListener("click", (e) => {
          e.preventDefault();
          if (window.SettingsPanel) {
            window.SettingsPanel.open("org-settings");
          }
        });
      }
    }

    // ─── Settings Pane: Organization Details ─────────────────────────────────

    async loadSettingsPane() {
      const pane = document.getElementById("pane-org-settings");
      if (!pane) return;

      const om = window.organizationManager;
      if (!om || !om.isOrgContext()) {
        pane.innerHTML = this._renderNoOrgState();
        // Bind "Create Organization" button immediately
        const startBtn = document.getElementById("org-start-onboarding-btn");
        if (startBtn) {
          startBtn.addEventListener("click", () => this._openOnboardingWizard());
        }
        return;
      }

      pane.innerHTML = `
        <div class="flex items-center justify-center py-12">
          <div class="cyber-spinner"></div>
          <span class="text-slate-400 text-sm ml-3">Loading organization…</span>
        </div>`;

      try {
        const detailsRes = await om.fetchOrgDetails();
        const members = await om.fetchMembers();
        const invitations = await om.fetchOrgInvitations().catch(() => []);

        this._orgDetails = detailsRes;
        this._members = members;
        this._invitations = invitations;

        // Determine current user's role
        const currentUser = window.authManager ? window.authManager.getCurrentUser() : null;
        if (currentUser && members) {
          const me = members.find((m) => String(m.id) === String(currentUser.id));
          this._currentUserOrgRole = me ? me.pivot.role : null;
        }

        pane.innerHTML = this._renderOrgSettingsContent(detailsRes, members, invitations);
        this._bindOrgSettingsEvents();
      } catch (error) {
        console.error("[OrgSettings] loadSettingsPane error:", error);
        pane.innerHTML = `
          <div class="text-center py-12">
            <span class="material-symbols-outlined text-red-400 text-4xl mb-3 block">error</span>
            <p class="text-slate-400 text-sm">Failed to load organization details.</p>
            <button id="org-settings-retry-btn" class="cyber-btn-ghost text-xs mt-4 px-4 py-2 rounded-lg">Retry</button>
          </div>`;
        const retryBtn = document.getElementById("org-settings-retry-btn");
        if (retryBtn) retryBtn.addEventListener("click", () => this.loadSettingsPane());
      }
    }

    _renderNoOrgState() {
      return `
        <div class="text-center py-12 px-6">
          <span class="material-symbols-outlined text-slate-500 text-5xl mb-4 block">business</span>
          <h4 class="text-lg font-bold text-white mb-2">No Organization Selected</h4>
          <p class="text-sm text-slate-400 mb-6">
            Select an organization from the workspace switcher, or create a new one.
          </p>
          <button id="org-start-onboarding-btn"
                  class="cyber-btn-primary px-6 py-2.5 rounded-lg text-sm font-semibold inline-flex items-center gap-2">
            <span class="material-symbols-outlined" style="font-size:1rem;">add_business</span>
            Create Organization
          </button>
        </div>`;
    }

    _renderOrgSettingsContent(details, members, invitations) {
      const org = details.organization || {};
      const limits = details.limits || {};
      const usage = details.usage || {};
      const sub = org.subscription || {};
      const planBadge = PLAN_BADGES[sub.plan] || PLAN_BADGES.starter;
      const isOwnerOrAdmin = this._currentUserOrgRole === "owner" || this._currentUserOrgRole === "admin";
      const isOwner = this._currentUserOrgRole === "owner";

      return `
        <div class="space-y-8">
          ${this._renderOrgOverview(org, sub, planBadge)}
          ${this._renderUsageMetrics(limits, usage)}
          ${isOwnerOrAdmin ? this._renderEditForm(org) : ""}
          <div class="cyber-divider"></div>
          ${this._renderTeamSection(members, invitations, isOwnerOrAdmin)}
          ${isOwner ? this._renderDangerZone(org) : ""}
        </div>`;
    }

    _renderOrgOverview(org, sub, planBadge) {
      const statusLabel = sub.status === "active" ? "Active" : (sub.status || "Pending");
      const statusCls = sub.status === "active" ? "cyber-badge-success" : "cyber-badge-warning";
      const expiresAt = sub.expires_at ? formatDate(sub.expires_at) : "—";

      return `
        <div class="cyber-card p-5">
          <div class="flex items-start justify-between mb-4">
            <div class="flex items-center gap-3">
              <div class="cyber-org-avatar">
                ${org.logo_url
                  ? `<img src="${escapeHtml(org.logo_url)}" alt="Logo" class="w-full h-full object-cover rounded-lg">`
                  : `<span class="text-lg font-bold text-white">${escapeHtml((org.name || "O")[0].toUpperCase())}</span>`}
              </div>
              <div>
                <h4 class="text-base font-bold text-white">${escapeHtml(org.name)}</h4>
                <p class="text-xs text-slate-400">${escapeHtml(org.domain)}</p>
              </div>
            </div>
            <div class="flex items-center gap-2">
              <span class="cyber-badge-xs ${escapeHtml(planBadge.cls)}">${escapeHtml(planBadge.label)}</span>
              <span class="cyber-badge-xs ${escapeHtml(statusCls)}">${escapeHtml(statusLabel)}</span>
            </div>
          </div>
          <div class="text-xs text-slate-500">
            <span>Expires: ${escapeHtml(expiresAt)}</span>
            <span class="mx-2">·</span>
            <span>Slug: ${escapeHtml(org.slug || "—")}</span>
          </div>
        </div>`;
    }

    _renderUsageMetrics(limits, usage) {
      const metrics = [
        { label: "Projects", used: usage.projects_count || 0, max: limits.max_projects || 0, color: "from-blue-500 to-indigo-500" },
        { label: "Scans This Month", used: usage.scans_used || 0, max: limits.max_scans_per_month || 0, color: "from-blue-500 to-cyan-500" },
        { label: "Team Members", used: usage.members_count || 0, max: limits.max_members || 0, color: "from-violet-500 to-purple-500" },
      ];

      const bars = metrics
        .map((m) => {
          const pct = m.max ? Math.min(100, Math.round((m.used / m.max) * 100)) : 0;
          return `
            <div>
              <div class="flex justify-between text-xs mb-1.5">
                <span class="text-slate-400">${escapeHtml(m.label)}</span>
                <span class="text-slate-300 font-medium">${m.used} / ${m.max || "—"}</span>
              </div>
              <div class="w-full bg-slate-800/60 rounded-full h-1.5 overflow-hidden border border-slate-700/30">
                <div class="bg-gradient-to-r ${m.color} h-full rounded-full transition-all duration-500"
                     style="width:${pct}%"></div>
              </div>
            </div>`;
        })
        .join("");

      return `<div class="space-y-4">${bars}</div>`;
    }

    _renderEditForm(org) {
      return `
        <div class="cyber-card p-5">
          <h5 class="text-sm font-semibold text-white mb-4 flex items-center gap-2">
            <span class="material-symbols-outlined" style="font-size:1rem;">edit</span>
            Edit Organization
          </h5>
          <form id="org-edit-form" class="space-y-4">
            <div>
              <label class="block text-xs text-slate-400 mb-1.5" for="org-edit-name">Organization Name</label>
              <input type="text" id="org-edit-name" class="cyber-input w-full"
                     value="${escapeHtml(org.name || "")}" maxlength="255" autocomplete="off">
              <p class="cyber-field-error hidden" id="org-edit-name-error"></p>
            </div>
            <div>
              <label class="block text-xs text-slate-400 mb-1.5" for="org-edit-logo">Logo URL</label>
              <input type="url" id="org-edit-logo" class="cyber-input w-full"
                     value="${escapeHtml(org.logo_url || "")}" placeholder="https://cdn.example.com/logo.png" autocomplete="off">
              <p class="cyber-field-error hidden" id="org-edit-logo-error"></p>
            </div>
            <button type="submit" class="cyber-btn-primary text-xs px-4 py-2 rounded-lg font-semibold">
              Save Changes
            </button>
          </form>
        </div>`;
    }

    _renderTeamSection(members, invitations, isOwnerOrAdmin) {
      return `
        <div>
          <div class="flex items-center justify-between mb-4">
            <h5 class="text-sm font-semibold text-white flex items-center gap-2">
              <span class="material-symbols-outlined" style="font-size:1rem;">group</span>
              Team Members
            </h5>
            <span class="text-xs text-slate-500">${members.length} member${members.length !== 1 ? "s" : ""}</span>
          </div>

          ${isOwnerOrAdmin ? this._renderInviteForm() : ""}

          <div id="org-members-list" class="space-y-2 mb-6">
            ${members.map((m) => this._renderMemberRow(m, isOwnerOrAdmin)).join("")}
          </div>

          ${invitations.length > 0 ? this._renderInvitationsSection(invitations) : ""}
        </div>`;
    }

    _renderInviteForm() {
      return `
        <form id="org-invite-form" class="cyber-card p-4 mb-4">
          <div class="flex gap-3 items-end">
            <div class="flex-1">
              <label class="block text-xs text-slate-400 mb-1" for="org-invite-email">Email</label>
              <input type="email" id="org-invite-email" class="cyber-input w-full text-sm"
                     placeholder="colleague@domain.com" required autocomplete="off">
            </div>
            <div class="w-28">
              <label class="block text-xs text-slate-400 mb-1" for="org-invite-role">Role</label>
              <select id="org-invite-role" class="cyber-input w-full text-sm">
                <option value="admin">Admin</option>
                <option value="member" selected>Member</option>
                <option value="viewer">Viewer</option>
              </select>
            </div>
            <button type="submit" class="cyber-btn-primary text-xs px-4 py-2 rounded-lg font-semibold whitespace-nowrap"
                    id="org-invite-submit-btn">
              <span class="material-symbols-outlined" style="font-size:0.875rem;">send</span>
              Invite
            </button>
          </div>
          <p class="cyber-field-error hidden mt-2" id="org-invite-error"></p>
        </form>`;
    }

    _renderMemberRow(member, canManage) {
      const role = member.pivot ? member.pivot.role : "member";
      const badge = ROLE_BADGES[role] || ROLE_BADGES.member;
      const isOwner = role === "owner";
      const initials = this._getInitials(member.full_name);
      const joinedAt = member.pivot ? formatDate(member.pivot.joined_at) : "—";

      const actions = canManage && !isOwner
        ? `
          <div class="flex items-center gap-2">
            <select class="cyber-input cyber-input-xs org-role-select" data-user-id="${escapeHtml(member.id)}">
              <option value="admin" ${role === "admin" ? "selected" : ""}>Admin</option>
              <option value="member" ${role === "member" ? "selected" : ""}>Member</option>
              <option value="viewer" ${role === "viewer" ? "selected" : ""}>Viewer</option>
            </select>
            <button class="cyber-btn-ghost-danger cyber-btn-xs org-remove-member-btn"
                    data-user-id="${escapeHtml(member.id)}"
                    data-user-name="${escapeHtml(member.full_name)}"
                    title="Remove member">
              <span class="material-symbols-outlined" style="font-size:0.875rem;">person_remove</span>
            </button>
          </div>`
        : "";

      return `
        <div class="cyber-org-member-row" id="org-member-${escapeHtml(member.id)}">
          <div class="flex items-center gap-3 flex-1 min-w-0">
            <div class="cyber-avatar-sm">${escapeHtml(initials)}</div>
            <div class="min-w-0">
              <p class="text-sm font-medium text-white truncate">${escapeHtml(member.full_name)}</p>
              <p class="text-xs text-slate-500 truncate">${escapeHtml(member.email)}</p>
            </div>
          </div>
          <div class="flex items-center gap-3 flex-shrink-0">
            <span class="text-xs text-slate-600 hidden sm:inline">${escapeHtml(member.job_tittle || "")}</span>
            <span class="cyber-badge-xs ${escapeHtml(badge.cls)}">${escapeHtml(badge.label)}</span>
            <span class="text-xs text-slate-600 hidden md:inline">${escapeHtml(joinedAt)}</span>
            ${actions}
          </div>
        </div>`;
    }

    _renderInvitationsSection(invitations) {
      const rows = invitations
        .map((inv) => {
          const roleBadge = ROLE_BADGES[inv.role] || ROLE_BADGES.member;
          return `
            <div class="cyber-org-member-row cyber-org-pending-row">
              <div class="flex items-center gap-3 flex-1 min-w-0">
                <div class="cyber-avatar-sm cyber-avatar-pending">
                  <span class="material-symbols-outlined" style="font-size:0.875rem;">mail</span>
                </div>
                <div class="min-w-0">
                  <p class="text-sm font-medium text-slate-300 truncate">${escapeHtml(inv.email)}</p>
                  <p class="text-xs text-slate-600">${timeUntil(inv.expires_at)}</p>
                </div>
              </div>
              <div class="flex items-center gap-2">
                <span class="cyber-badge-xs ${escapeHtml(roleBadge.cls)}">${escapeHtml(roleBadge.label)}</span>
                <span class="cyber-badge-xs cyber-badge-warning">Pending</span>
              </div>
            </div>`;
        })
        .join("");

      return `
        <div class="mt-4">
          <p class="text-xs text-slate-500 font-semibold uppercase tracking-wider mb-2">Pending Invitations</p>
          <div class="space-y-2">${rows}</div>
        </div>`;
    }

    _renderDangerZone(org) {
      return `
        <div class="cyber-card cyber-card-danger p-5 mt-6">
          <h5 class="text-sm font-semibold text-red-400 mb-2 flex items-center gap-2">
            <span class="material-symbols-outlined" style="font-size:1rem;">warning</span>
            Danger Zone
          </h5>
          <p class="text-xs text-slate-400 mb-4">
            Permanently delete this organization and all its data. This action cannot be undone.
          </p>
          <button id="org-delete-btn" class="cyber-btn-danger text-xs px-4 py-2 rounded-lg font-semibold">
            Delete Workspace
          </button>
        </div>`;
    }

    // ─── Event Bindings ─────────────────────────────────────────────────────

    _bindOrgSettingsEvents() {
      // Edit form
      const editForm = document.getElementById("org-edit-form");
      if (editForm) {
        editForm.addEventListener("submit", (e) => {
          e.preventDefault();
          this._handleEditSave();
        });
      }

      // Invite form
      const inviteForm = document.getElementById("org-invite-form");
      if (inviteForm) {
        inviteForm.addEventListener("submit", (e) => {
          e.preventDefault();
          this._handleInvite();
        });
      }

      // Role change dropdowns
      document.querySelectorAll(".org-role-select").forEach((select) => {
        select.addEventListener("change", (e) => {
          const userId = e.target.getAttribute("data-user-id");
          const newRole = e.target.value;
          this._handleRoleChange(userId, newRole);
        });
      });

      // Remove member buttons
      document.querySelectorAll(".org-remove-member-btn").forEach((btn) => {
        btn.addEventListener("click", () => {
          const userId = btn.getAttribute("data-user-id");
          const userName = btn.getAttribute("data-user-name");
          this._handleRemoveMember(userId, userName);
        });
      });

      // Delete organization
      const deleteBtn = document.getElementById("org-delete-btn");
      if (deleteBtn) {
        deleteBtn.addEventListener("click", () => this._handleDeleteOrg());
      }

      // No-org start onboarding button
      const startBtn = document.getElementById("org-start-onboarding-btn");
      if (startBtn) {
        startBtn.addEventListener("click", () => this._openOnboardingWizard());
      }
    }

    // ─── Action Handlers ────────────────────────────────────────────────────

    async _handleEditSave() {
      const nameInput = document.getElementById("org-edit-name");
      const logoInput = document.getElementById("org-edit-logo");
      if (!nameInput) return;

      const payload = {};
      if (nameInput.value.trim()) payload.name = nameInput.value.trim();
      if (logoInput && logoInput.value.trim()) payload.logo_url = logoInput.value.trim();

      try {
        await window.organizationManager.updateOrganization(payload);
        window.CyberNotify.alert("Organization updated successfully.", { type: "success" });
        // Refresh
        this.loadSettingsPane();
        this._loadWorkspaceSwitcher();
      } catch (error) {
        if (error.name === "ValidationError" && error.errors) {
          const shown = this._showFieldErrors(error.errors);
          if (!shown) {
            let msg = error.message || "Failed to update organization.";
            if (error.errors && error.errors.length > 0) {
              const msgErr = error.errors.find(e => e.field === "message");
              if (msgErr) {
                msg = msgErr.message;
              } else {
                msg = error.errors
                  .filter(e => e.field !== "status")
                  .map(e => e.message)
                  .join(" ");
              }
            }
            window.CyberNotify.alert(msg, { type: "error" });
          }
        } else if (error.name !== "APIError") {
          window.CyberNotify.alert(error.message || "Failed to update organization.", { type: "error" });
        }
      }
    }

    async _handleInvite() {
      const emailInput = document.getElementById("org-invite-email");
      const roleSelect = document.getElementById("org-invite-role");
      const errorEl = document.getElementById("org-invite-error");
      if (!emailInput || !roleSelect) return;

      // Clear previous errors
      if (errorEl) {
        errorEl.classList.add("hidden");
        errorEl.textContent = "";
      }

      const email = emailInput.value.trim();
      const role = roleSelect.value;

      if (!email) {
        if (errorEl) {
          errorEl.textContent = "Email is required.";
          errorEl.classList.remove("hidden");
        }
        return;
      }

      try {
        await window.organizationManager.inviteMember({ email, role });
        window.CyberNotify.alert("Invitation sent successfully.", { type: "success" });
        emailInput.value = "";
        // Refresh invitations
        this.loadSettingsPane();
      } catch (error) {
        if (error.name === "ValidationError") {
          const msg = error.data?.message || (Array.isArray(error.errors) ? error.errors[0]?.message : "Validation failed.");
          if (errorEl) {
            errorEl.textContent = msg;
            errorEl.classList.remove("hidden");
          }
        } else if (error.name === "APIError") {
          // 422 threshold error comes as APIError with message
          const msg = error.data?.message || error.message || "Failed to send invitation.";
          window.CyberNotify.alert(msg, { type: "error" });
        }
      }
    }

    async _handleRoleChange(userId, newRole) {
      try {
        await window.organizationManager.changeMemberRole(userId, newRole);
        window.CyberNotify.alert("Member role updated.", { type: "success" });
      } catch (error) {
        if (error.name !== "APIError") {
          window.CyberNotify.alert(error.message || "Failed to update role.", { type: "error" });
        }
        // Revert the dropdown by reloading
        this.loadSettingsPane();
      }
    }

    async _handleRemoveMember(userId, userName) {
      window.CyberNotify.confirm(
        `Remove ${userName || "this member"} from the organization? Their sessions will be revoked.`,
        async (confirmed) => {
          if (!confirmed) return;
          try {
            await window.organizationManager.removeMember(userId);
            // Optimistic remove from DOM
            const row = document.getElementById(`org-member-${userId}`);
            if (row) row.remove();
            window.CyberNotify.alert("Member removed successfully.", { type: "success" });
          } catch (error) {
            if (error.name !== "APIError") {
              window.CyberNotify.alert(error.message || "Failed to remove member.", { type: "error" });
            }
          }
        },
        { type: "warning" }
      );
    }

    async _handleDeleteOrg() {
      const org = this._orgDetails?.organization;
      if (!org) return;

      window.CyberNotify.prompt(
        `Type "${org.name}" to confirm deletion:`,
        "",
        async (value) => {
          if (value === null) return; // cancelled
          if (value !== org.name) {
            window.CyberNotify.alert("Organization name does not match. Deletion cancelled.", { type: "error" });
            return;
          }
          try {
            await window.organizationManager.deleteOrganization();
            window.CyberNotify.alert("Organization deleted successfully.", { type: "success" });
            // Refresh workspace switcher and settings pane
            this._loadWorkspaceSwitcher();
            this.loadSettingsPane();
          } catch (error) {
            if (error.name !== "APIError") {
              window.CyberNotify.alert(error.message || "Failed to delete organization.", { type: "error" });
            }
          }
        }
      );
    }

    // ─── Onboarding Wizard ──────────────────────────────────────────────────

    _openOnboardingWizard() {
      const modal = document.getElementById("org-onboarding-modal");
      if (!modal) return;

      modal.classList.remove("hidden");
      document.body.style.overflow = "hidden";
      this._renderOnboardingStep(1);
    }

    _closeOnboardingWizard() {
      const modal = document.getElementById("org-onboarding-modal");
      if (modal) {
        modal.classList.add("hidden");
        document.body.style.overflow = "";
      }
      // Stop any payment polling
      window.organizationManager._clearPaymentPoll();
    }

    _renderOnboardingStep(step) {
      const body = document.getElementById("org-onboarding-body");
      if (!body) return;

      if (step === 1) {
        body.innerHTML = this._renderOnboardingStep1();
        this._bindOnboardingStep1();
      } else if (step === 2) {
        body.innerHTML = this._renderOnboardingStep2();
        this._bindOnboardingStep2();
      } else if (step === 3) {
        body.innerHTML = this._renderOnboardingStep3();
        this._bindOnboardingStep3();
      }

      // Update step indicators (backward compatible with tests)
      const stepItems = document.querySelectorAll(".cyber-step-item");
      if (stepItems.length > 0) {
        stepItems.forEach((item, i) => {
          const isActive = i < step;
          const isCurrent = i + 1 === step;
          const isCompleted = i + 1 < step;

          item.classList.toggle("active", isActive);
          item.classList.toggle("current", isCurrent);
          item.classList.toggle("completed", isCompleted);

          const dot = item.querySelector(".cyber-step-dot");
          if (dot) {
            dot.classList.toggle("active", isActive);
            dot.classList.toggle("current", isCurrent);
            dot.classList.toggle("completed", isCompleted);
            if (isCompleted) {
              dot.innerHTML = `<span class="material-symbols-outlined text-xs">check</span>`;
            } else {
              dot.innerHTML = `<span>${i + 1}</span>`;
            }
          }
        });
      } else {
        // Fallback for tests
        document.querySelectorAll(".cyber-step-dot").forEach((dot, i) => {
          dot.classList.toggle("active", i < step);
          dot.classList.toggle("current", i + 1 === step);
        });
      }

      // Update step lines
      document.querySelectorAll(".cyber-step-line").forEach((line, i) => {
        line.classList.toggle("active", i < step - 1);
        line.classList.toggle("completed", i + 1 < step);
      });
    }

    _renderOnboardingStep1() {
      return `
        <h4 class="text-base font-bold text-white mb-1">Create Organization</h4>
        <p class="text-xs text-slate-400 mb-5">Set up your corporate workspace</p>
        <form id="org-onboard-step1-form" class="space-y-4">
          <div>
            <label class="block text-xs text-slate-400 mb-1.5" for="onboard-org-name">Organization Name</label>
            <input type="text" id="onboard-org-name" class="cyber-input w-full py-2 px-3" required maxlength="255"
                   placeholder="Acme Corp" autocomplete="off">
            <p class="cyber-field-error hidden" id="onboard-org-name-error"></p>
          </div>
          <div>
            <label class="block text-xs text-slate-400 mb-1.5" for="onboard-domain">Company Domain</label>
            <input type="text" id="onboard-domain" class="cyber-input w-full py-2 px-3" required maxlength="255"
                   placeholder="acme.com" autocomplete="off">
            <p class="cyber-field-error hidden" id="onboard-domain-error"></p>
          </div>
          <div>
            <label class="block text-xs text-slate-400 mb-1.5" for="onboard-corp-email">Corporate Email Address</label>
            <input type="email" id="onboard-corp-email" class="cyber-input w-full py-2 px-3" required
                   placeholder="you@company.com" autocomplete="email">
            <p class="cyber-field-error hidden" id="onboard-corp-email-error"></p>
          </div>
          <div>
            <label class="block text-xs text-slate-400 mb-2">Plan</label>
            <select id="onboard-plan" class="hidden" required>
              <option value="starter">Starter</option>
              <option value="pro" selected>Pro</option>
              <option value="enterprise">Enterprise</option>
            </select>
            
            <div class="cyber-plans-grid">
              <div class="cyber-plan-card" data-plan-val="starter">
                <span class="material-symbols-outlined cyber-plan-icon">groups</span>
                <div class="cyber-plan-name">Starter</div>
                <div class="cyber-plan-price">$29<span>/mo</span></div>
                <div class="cyber-plan-features">Up to 5 members<br>10 projects</div>
              </div>
              <div class="cyber-plan-card selected" data-plan-val="pro">
                <span class="cyber-plan-badge">Popular</span>
                <span class="material-symbols-outlined cyber-plan-icon">shield_with_heart</span>
                <div class="cyber-plan-name">Pro</div>
                <div class="cyber-plan-price">$99<span>/mo</span></div>
                <div class="cyber-plan-features">Up to 20 members<br>50 projects</div>
              </div>
              <div class="cyber-plan-card" data-plan-val="enterprise">
                <span class="material-symbols-outlined cyber-plan-icon">domain</span>
                <div class="cyber-plan-name">Enterprise</div>
                <div class="cyber-plan-price">Custom</div>
                <div class="cyber-plan-features">Unlimited members<br>Dedicated support</div>
              </div>
            </div>
          </div>
          <button type="submit" class="cyber-btn-primary w-full py-2.5 rounded-lg text-sm font-semibold">
            Continue to Checkout
          </button>
        </form>`;
    }

    _bindOnboardingStep1() {
      const form = document.getElementById("org-onboard-step1-form");
      if (!form) return;

      const cards = form.querySelectorAll(".cyber-plan-card");
      const planSelect = document.getElementById("onboard-plan");

      cards.forEach((card) => {
        card.addEventListener("click", () => {
          cards.forEach((c) => c.classList.remove("selected"));
          card.classList.add("selected");
          const val = card.getAttribute("data-plan-val");
          if (planSelect) {
            planSelect.value = val;
            planSelect.dispatchEvent(new Event("change"));
          }
        });
      });

      form.addEventListener("submit", async (e) => {
        e.preventDefault();
        const orgName = document.getElementById("onboard-org-name").value.trim();
        const domain = document.getElementById("onboard-domain").value.trim();
        const corporateEmail = document.getElementById("onboard-corp-email").value.trim();
        const plan = planSelect ? planSelect.value : "pro";

        // Store email to display in Step 2 verification
        this._pendingCorpEmail = corporateEmail;

        try {
          await window.organizationManager.initiateOnboarding({
            org_name: orgName,
            company_domain: domain,
            plan: plan,
            corporate_email: corporateEmail,
          });
          this._renderOnboardingStep(2);
        } catch (error) {
          if (error.name === "ValidationError") {
            const shown = this._showFieldErrors(error.errors, "onboard-");
            if (!shown) {
              let msg = error.message || "Failed to create organization.";
              if (error.errors && error.errors.length > 0) {
                const msgErr = error.errors.find(e => e.field === "message");
                if (msgErr) {
                  msg = msgErr.message;
                } else {
                  msg = error.errors
                    .filter(e => e.field !== "status")
                    .map(e => e.message)
                    .join(" ");
                }
              }
              window.CyberNotify.alert(msg, { type: "error" });
            }
          } else if (error.name !== "APIError") {
            window.CyberNotify.alert(error.message || "Failed to create organization.", { type: "error" });
          }
        }
      });
    }

    _renderOnboardingStep2() {
      const email = this._pendingCorpEmail || "";
      return `
        <h4 class="text-base font-bold text-white mb-1">Corporate Email Verification</h4>
        <p class="text-xs text-slate-400 mb-5">Verify your identity with your corporate email address</p>
        <form id="org-onboard-step2-form" class="space-y-4">
          <div class="cyber-onboarding-form-section space-y-3">
            <div class="flex items-start gap-3 p-3 bg-blue-500/5 border border-blue-500/10 rounded-lg mb-3">
              <span class="material-symbols-outlined text-blue-400 mt-0.5 text-lg">info</span>
              <p class="text-xs text-slate-300 leading-relaxed">
                We have sent a security verification link to your corporate email. This email domain must match the company domain you set up. Please click the link to verify, then click "Continue to Billing" below.
              </p>
            </div>
            <div>
              <label class="block text-[11px] text-slate-400 mb-1" for="corp-email">Corporate Email Address</label>
              <input type="email" id="corp-email" class="cyber-input w-full py-2 px-3" required
                     value="${escapeHtml(email)}" placeholder="you@company.com" autocomplete="email">
              <p class="text-[11px] text-slate-500 mt-1">Example: you@company.com</p>
              <p class="cyber-field-error hidden" id="corp-email-error"></p>
            </div>
          </div>
          <div class="flex gap-3">
            <button type="submit" class="cyber-btn-ghost flex-1 py-2.5 rounded-lg text-sm font-semibold" style="justify-content: center;" id="org-onboard-resend-btn">
              Resend Verification
            </button>
            <button type="button" class="cyber-btn-primary flex-1 py-2.5 rounded-lg text-sm font-semibold" id="org-onboard-verify-continue-btn">
              Continue to Billing
            </button>
          </div>
        </form>`;
    }

    _bindOnboardingStep2() {
      const form = document.getElementById("org-onboard-step2-form");
      if (!form) return;

      form.addEventListener("submit", async (e) => {
        e.preventDefault();
        const orgId = window.organizationManager.getPendingOrgId();
        if (!orgId) {
          window.CyberNotify.alert("No pending organization found.", { type: "error" });
          return;
        }

        const corporateEmail = document.getElementById("corp-email").value.trim();
        if (!corporateEmail) return;
        this._pendingCorpEmail = corporateEmail;

        try {
          await window.organizationManager.submitCorporateEmail(orgId, corporateEmail);
          window.CyberNotify.alert("Verification email sent. Check your corporate inbox.", { type: "success" });
        } catch (error) {
          if (error.name === "ValidationError") {
            const shown = this._showFieldErrors(error.errors, "corp-");
            if (!shown) {
              let msg = error.message || "Failed to send verification email.";
              if (error.errors && error.errors.length > 0) {
                const msgErr = error.errors.find(e => e.field === "message");
                if (msgErr) {
                  msg = msgErr.message;
                } else {
                  msg = error.errors
                    .filter(e => e.field !== "status")
                    .map(e => e.message)
                    .join(" ");
                }
              }
              window.CyberNotify.alert(msg, { type: "error" });
            }
          } else if (error.name !== "APIError") {
            window.CyberNotify.alert(error.message || "Failed to send verification email.", { type: "error" });
          }
        }
      });

      const continueBtn = document.getElementById("org-onboard-verify-continue-btn");
      if (continueBtn) {
        continueBtn.addEventListener("click", () => {
          this._renderOnboardingStep(3);
        });
      }
    }

    _renderOnboardingStep3() {
      return `
        <h4 class="text-base font-bold text-white mb-1">Billing Information</h4>
        <p class="text-xs text-slate-400 mb-5">Enter your billing details for Paymob checkout</p>
        <form id="org-onboard-step3-form" class="space-y-4">
          <!-- Contact Info Section -->
          <div class="cyber-onboarding-form-section space-y-3">
            <h5 class="text-xs font-bold text-slate-300 uppercase tracking-wider mb-2">Contact Details</h5>
            <div class="grid grid-cols-2 gap-3">
              <div>
                <label class="block text-[11px] text-slate-400 mb-1" for="billing-first-name">First Name *</label>
                <input type="text" id="billing-first-name" class="cyber-input w-full text-sm py-2 px-3" required autocomplete="given-name">
                <p class="cyber-field-error hidden" id="billing-first-name-error"></p>
              </div>
              <div>
                <label class="block text-[11px] text-slate-400 mb-1" for="billing-last-name">Last Name *</label>
                <input type="text" id="billing-last-name" class="cyber-input w-full text-sm py-2 px-3" required autocomplete="family-name">
                <p class="cyber-field-error hidden" id="billing-last-name-error"></p>
              </div>
            </div>
            <div>
              <label class="block text-[11px] text-slate-400 mb-1" for="billing-email">Email *</label>
              <input type="email" id="billing-email" class="cyber-input w-full text-sm py-2 px-3" required autocomplete="email">
              <p class="cyber-field-error hidden" id="billing-email-error"></p>
            </div>
            <div>
              <label class="block text-[11px] text-slate-400 mb-1" for="billing-phone">Phone Number *</label>
              <input type="tel" id="billing-phone" class="cyber-input w-full text-sm py-2 px-3" required autocomplete="tel">
              <p class="cyber-field-error hidden" id="billing-phone-error"></p>
            </div>
          </div>
          
          <!-- Address Section -->
          <div class="cyber-onboarding-form-section space-y-3">
            <h5 class="text-xs font-bold text-slate-300 uppercase tracking-wider mb-2">Billing Address</h5>
            <div class="grid grid-cols-2 gap-3">
              <div>
                <label class="block text-[11px] text-slate-400 mb-1" for="billing-city">City *</label>
                <input type="text" id="billing-city" class="cyber-input w-full text-sm py-2 px-3" required autocomplete="address-level2">
              </div>
              <div>
                <label class="block text-[11px] text-slate-400 mb-1" for="billing-country">Country *</label>
                <input type="text" id="billing-country" class="cyber-input w-full text-sm py-2 px-3" required autocomplete="country-name">
              </div>
            </div>
            <div>
              <label class="block text-[11px] text-slate-400 mb-1" for="billing-street">Street</label>
              <input type="text" id="billing-street" class="cyber-input w-full text-sm py-2 px-3" autocomplete="street-address">
            </div>
            <div class="grid grid-cols-3 gap-3">
              <div>
                <label class="block text-[11px] text-slate-400 mb-1" for="billing-building">Building</label>
                <input type="text" id="billing-building" class="cyber-input w-full text-sm py-2 px-3">
              </div>
              <div>
                <label class="block text-[11px] text-slate-400 mb-1" for="billing-floor">Floor</label>
                <input type="text" id="billing-floor" class="cyber-input w-full text-sm py-2 px-3">
              </div>
              <div>
                <label class="block text-[11px] text-slate-400 mb-1" for="billing-apartment">Apt</label>
                <input type="text" id="billing-apartment" class="cyber-input w-full text-sm py-2 px-3">
              </div>
            </div>
            <div>
              <label class="block text-[11px] text-slate-400 mb-1" for="billing-postal">Postal Code</label>
              <input type="text" id="billing-postal" class="cyber-input w-full text-sm py-2 px-3" autocomplete="postal-code">
            </div>
          </div>
          <button type="submit" class="cyber-btn-primary w-full py-2.5 rounded-lg text-sm font-semibold mt-2">
            Proceed to Payment
          </button>
        </form>`;
    }

    _bindOnboardingStep3() {
      const form = document.getElementById("org-onboard-step3-form");
      if (!form) return;

      form.addEventListener("submit", async (e) => {
        e.preventDefault();
        const orgId = window.organizationManager.getPendingOrgId();
        if (!orgId) {
          window.CyberNotify.alert("No pending organization found. Please start over.", { type: "error" });
          return;
        }

        const planSelect = document.getElementById("onboard-plan");
        const plan = planSelect ? planSelect.value : "pro";

        const billingData = {
          first_name: document.getElementById("billing-first-name").value.trim(),
          last_name: document.getElementById("billing-last-name").value.trim(),
          email: document.getElementById("billing-email").value.trim(),
          phone_number: document.getElementById("billing-phone").value.trim(),
          city: document.getElementById("billing-city").value.trim(),
          country: document.getElementById("billing-country").value.trim(),
          street: document.getElementById("billing-street").value.trim() || undefined,
          building: document.getElementById("billing-building").value.trim() || undefined,
          floor: document.getElementById("billing-floor").value.trim() || undefined,
          apartment: document.getElementById("billing-apartment").value.trim() || undefined,
          postal_code: document.getElementById("billing-postal").value.trim() || undefined,
        };

        // Remove undefined fields
        Object.keys(billingData).forEach((k) => {
          if (billingData[k] === undefined) delete billingData[k];
        });

        try {
          const response = await window.organizationManager.submitCheckout(orgId, {
            plan: plan,
            billing_data: billingData,
          });

          const iframeUrl = response.data ? response.data.iframe_url : response.iframe_url;
          if (iframeUrl) {
            window.location.href = iframeUrl;
          } else {
            window.CyberNotify.alert("Payment URL not received. Please try again.", { type: "error" });
          }
        } catch (error) {
          if (error.name === "ValidationError") {
            const shown = this._showFieldErrors(error.errors, "billing-");
            if (!shown) {
              let msg = error.message || "Checkout failed.";
              if (error.errors && error.errors.length > 0) {
                const msgErr = error.errors.find(e => e.field === "message");
                if (msgErr) {
                  msg = msgErr.message;
                } else {
                  msg = error.errors
                    .filter(e => e.field !== "status")
                    .map(e => e.message)
                    .join(" ");
                }
              }
              window.CyberNotify.alert(msg, { type: "error" });
            }
          } else if (error.name !== "APIError") {
            window.CyberNotify.alert(error.message || "Checkout failed.", { type: "error" });
          }
        }
      });
    }

    /**
     * Start polling for payment status and advance to step 3 when ready.
     * Called after user returns from Paymob redirect.
     */
    async startPostPaymentFlow() {
      const orgId = window.organizationManager.getPendingOrgId();
      if (!orgId) return; // No pending onboarding — skip silently
      console.log("[OrgSettings] startPostPaymentFlow called. Pending org ID:", orgId);

      try {
        console.log("[OrgSettings] Polling payment status for pending org:", orgId);
        const statusRes = await window.organizationManager.pollPaymentStatus(orgId);
        console.log("[OrgSettings] Polling resolved. Response:", statusRes);
        if (statusRes.payment_status === "pending_email_verification") {
          console.log("[OrgSettings] Status is pending_email_verification, opening step 2 verification modal");
          // Open the onboarding wizard at step 2
          this._openOnboardingWizard();
          this._renderOnboardingStep(2);
        } else if (statusRes.payment_status === "active") {
          console.log("[OrgSettings] Status is active, setting context and activating organization workspace");
          // Already active — set context and refresh
          window.organizationManager.setActiveOrg(orgId);
          window.organizationManager.clearPendingOrgId();
          window.CyberNotify.alert("Organization activated successfully!", { type: "success" });
          this._loadWorkspaceSwitcher();
        } else {
          console.log("[OrgSettings] Unhandled payment status:", statusRes.payment_status);
        }
      } catch (error) {
        console.error("[OrgSettings] Payment verification failed:", error);
        window.CyberNotify.alert(error.message || "Payment verification timed out.", { type: "error" });
      }
    }

    // ─── Utilities ──────────────────────────────────────────────────────────

    _showFieldErrors(errors, prefix = "org-edit-") {
      if (!Array.isArray(errors)) return false;
      let shownAny = false;
      errors.forEach((err) => {
        // Map backend field names to DOM IDs
        const fieldMap = {
          org_name: "name",
          company_domain: "domain",
          name: "name",
          logo_url: "logo",
          email: "email",
          corporate_email: "email",
          first_name: "first-name",
          last_name: "last-name",
          phone_number: "phone",
          city: "city",
          country: "country",
        };
        const mappedField = fieldMap[err.field] || err.field;
        const errorEl = document.getElementById(`${prefix}${mappedField}-error`);
        if (errorEl) {
          errorEl.textContent = err.message;
          errorEl.classList.remove("hidden");
          shownAny = true;
        }
      });
      return shownAny;
    }

    _getInitials(name) {
      if (!name) return "?";
      const parts = name.trim().split(/\s+/);
      if (parts.length >= 2) return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
      return parts[0].substring(0, 2).toUpperCase();
    }
  }

  // ─── Dual Export ────────────────────────────────────────────────────────────
  if (typeof module !== "undefined" && module.exports) {
    module.exports = { OrganizationSettingsManager };
  } else {
    window.OrganizationSettings = new OrganizationSettingsManager();
  }
})();
