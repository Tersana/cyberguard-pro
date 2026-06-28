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
    starter:    { cls: "cyber-badge-slate",   label: "Starter" },
    pro:        { cls: "cyber-badge-info",    label: "Pro" },
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
        
        // Extract active workspaces (either from the legacy format, or the new format)
        let activeWorkspaces = [];
        const workspacesResponse = om.workspacesResponse || workspaces;
        if (Array.isArray(workspacesResponse)) {
          activeWorkspaces = workspacesResponse.filter((ws) => !ws.subscription || ws.subscription.status === "active");
        } else if (workspacesResponse) {
          if (Array.isArray(workspacesResponse.organizations)) {
            activeWorkspaces = workspacesResponse.organizations.filter((ws) => !ws.subscription || ws.subscription.status === "active");
          } else {
            activeWorkspaces = Array.isArray(workspacesResponse.active) ? workspacesResponse.active : [];
          }
        }

        // Proactively clear invalid active org ID (must be active, not pending/deleted)
        const activeOrgId = om.getActiveOrgId();
        if (activeOrgId) {
          const isValid = activeWorkspaces.some((ws) => String(ws.id) === String(activeOrgId));
          if (!isValid) {
            console.warn("[OrgSettings] Active organization ID is no longer valid or is pending. Clearing active organization.");
            om.clearActiveOrg();
            if (
              typeof window !== "undefined" &&
              window.location &&
              typeof window.location.reload === "function" &&
              (!window.navigator || !window.navigator.userAgent || !window.navigator.userAgent.includes("jsdom"))
            ) {
              window.location.reload();
              return;
            }
          }
        }

        this._renderWorkspaceSwitcher(om.workspacesResponse || workspaces);
      } catch (error) {
        console.warn("[OrgSettings] Failed to load workspaces:", error);
        this._renderWorkspaceSwitcher([]);
      }
    }

    _renderWorkspaceSwitcher(workspacesResponse) {
      const container = document.getElementById("org-workspace-switcher");
      if (!container) return;

      let active = [];
      let pending = [];
      let deleted = [];

      if (Array.isArray(workspacesResponse)) {
        active = workspacesResponse.filter((ws) => !ws.subscription || ws.subscription.status === "active");
        pending = workspacesResponse.filter((ws) => ws.subscription && ws.subscription.status !== "active");
      } else if (workspacesResponse) {
        if (Array.isArray(workspacesResponse.organizations)) {
          active = workspacesResponse.organizations.filter((ws) => !ws.subscription || ws.subscription.status === "active");
          pending = workspacesResponse.organizations.filter((ws) => ws.subscription && ws.subscription.status !== "active");
        } else {
          active = Array.isArray(workspacesResponse.active) ? workspacesResponse.active : [];
          pending = Array.isArray(workspacesResponse.pending) ? workspacesResponse.pending : [];
          deleted = Array.isArray(workspacesResponse.deleted) ? workspacesResponse.deleted : [];
        }
      }

      // Only count active and deleted (trash) workspaces; pending is hidden from switcher
      const totalCount = active.length + deleted.length;
      if (totalCount === 0) {
        container.classList.add("hidden");
        return;
      }

      container.classList.remove("hidden");
      const activeOrgId = window.organizationManager.getActiveOrgId();

      const combined = [...active];
      const items = combined
        .map((ws) => {
          const isActive = String(ws.id) === String(activeOrgId);
          const plan = ws.subscription ? ws.subscription.plan : "starter";
          const planBadge = PLAN_BADGES[plan] || PLAN_BADGES.starter;

          return `
            <button class="cyber-org-switcher-item ${isActive ? "active" : ""}"
                    data-org-id="${escapeHtml(ws.id)}"
                    id="org-switch-${escapeHtml(ws.id)}"
                    title="${escapeHtml(ws.name)}">
              <div class="flex items-center gap-3 flex-1 min-w-0">
                <div class="cyber-org-switcher-icon w-8 h-8 rounded-lg bg-white/5 border border-white/10 flex items-center justify-center text-slate-400 flex-shrink-0">
                  <span class="material-symbols-outlined" style="font-size: 1.1rem;">business</span>
                </div>
                <div class="cyber-org-switcher-info">
                  <span class="cyber-org-switcher-name">${escapeHtml(ws.name)}</span>
                  <div class="cyber-org-switcher-badges">
                    <span class="cyber-badge-xs ${escapeHtml(planBadge.cls)}">${escapeHtml(planBadge.label)}</span>
                  </div>
                </div>
              </div>
              ${isActive ? '<span class="material-symbols-outlined cyber-org-check">check_circle</span>' : ""}
            </button>`;
        })
        .join("");

      let deletedItems = "";
      if (deleted.length > 0) {
        const deletedList = deleted
          .map((ws) => {
            return `
              <div class="cyber-org-switcher-item opacity-60 hover:opacity-100 flex items-center justify-between gap-2 p-2 rounded-lg"
                   title="${escapeHtml(ws.name)} (Deleted)">
                <div class="flex items-center gap-3 min-w-0 flex-1">
                  <div class="cyber-org-switcher-icon w-8 h-8 rounded-lg bg-red-500/10 border border-red-500/20 flex items-center justify-center text-red-400 flex-shrink-0">
                    <span class="material-symbols-outlined" style="font-size: 1.1rem;">delete_outline</span>
                  </div>
                  <div class="cyber-org-switcher-info min-w-0">
                    <span class="cyber-org-switcher-name text-red-300 truncate block text-sm">${escapeHtml(ws.name)}</span>
                    <span class="text-[10px] text-slate-500 block font-mono">Deleted</span>
                  </div>
                </div>
                <div class="flex items-center gap-1 flex-shrink-0">
                  <button class="cyber-btn-ghost-success org-restore-btn w-7 h-7 p-0 flex items-center justify-center rounded-md"
                          data-org-id="${escapeHtml(ws.id)}"
                          data-org-name="${escapeHtml(ws.name)}"
                          title="Restore Organization">
                    <span class="material-symbols-outlined" style="font-size: 1.1rem;">restore</span>
                  </button>
                  <button class="cyber-btn-ghost-danger org-force-delete-btn w-7 h-7 p-0 flex items-center justify-center rounded-md"
                          data-org-id="${escapeHtml(ws.id)}"
                          data-org-name="${escapeHtml(ws.name)}"
                          title="Force Delete Organization">
                    <span class="material-symbols-outlined" style="font-size: 1.1rem;">delete_forever</span>
                  </button>
                </div>
              </div>`;
          })
          .join("");

        deletedItems = `
          <div class="cyber-org-switcher-divider"></div>
          <div class="px-3 py-1.5 text-[10px] font-bold text-red-400/80 uppercase tracking-wider flex items-center gap-1">
            <span class="material-symbols-outlined text-[12px]">delete</span>
            Trash
          </div>
          <div class="space-y-1 mt-1">
            ${deletedList}
          </div>
        `;
      }

      const personalActive = !activeOrgId;

      container.innerHTML = `
        <div class="cyber-org-switcher-dropdown">
          <button class="cyber-org-switcher-item ${personalActive ? "active" : ""}"
                  id="org-switch-personal"
                  data-org-id="">
            <div class="flex items-center gap-3 flex-1 min-w-0">
              <div class="cyber-org-switcher-icon w-8 h-8 rounded-lg bg-white/5 border border-white/10 flex items-center justify-center text-slate-400 flex-shrink-0">
                <span class="material-symbols-outlined" style="font-size: 1.1rem;">person</span>
              </div>
              <div class="cyber-org-switcher-info">
                <span class="cyber-org-switcher-name">Personal Workspace</span>
                <div class="cyber-org-switcher-badges">
                  <span class="cyber-badge-xs cyber-badge-slate">Personal</span>
                </div>
              </div>
            </div>
            ${personalActive ? '<span class="material-symbols-outlined cyber-org-check">check_circle</span>' : ""}
          </button>
          <div class="cyber-org-switcher-divider"></div>
          ${items}
          ${deletedItems}
        </div>`;

      // Bind click handlers
      container.querySelectorAll(".cyber-org-switcher-item[data-org-id]").forEach((btn) => {
        if (btn.classList.contains("opacity-60")) return;
        btn.addEventListener("click", () => {
          const orgId = btn.getAttribute("data-org-id");
          if (orgId) {
            window.organizationManager.setActiveOrg(orgId);
          } else {
            window.organizationManager.clearActiveOrg();
          }
          // Re-render the switcher
          this._renderWorkspaceSwitcher(window.organizationManager.workspacesResponse || window.organizationManager.workspaces);
          // Reload the page to refresh all context-specific data
          if (
            typeof window !== "undefined" &&
            window.location &&
            typeof window.location.reload === "function" &&
            (!window.navigator || !window.navigator.userAgent || !window.navigator.userAgent.includes("jsdom"))
          ) {
            window.location.reload();
          }
        });
      });

      // Bind restore buttons
      container.querySelectorAll(".org-restore-btn").forEach((btn) => {
        btn.addEventListener("click", (e) => {
          e.stopPropagation();
          const orgId = btn.getAttribute("data-org-id");
          const orgName = btn.getAttribute("data-org-name");
          window.CyberNotify.confirm(
            `Are you sure you want to restore the organization "${orgName}"?`,
            async (confirmed) => {
              if (!confirmed) return;
              try {
                await window.organizationManager.restoreOrganization(orgId);
                window.CyberNotify.alert("Organization restored successfully.", { type: "success" });
                this._loadWorkspaceSwitcher();
              } catch (err) {
                window.CyberNotify.alert(err.message || "Failed to restore organization.", { type: "error" });
              }
            }
          );
        });
      });

      // Bind force delete buttons
      container.querySelectorAll(".org-force-delete-btn").forEach((btn) => {
        btn.addEventListener("click", (e) => {
          e.stopPropagation();
          const orgId = btn.getAttribute("data-org-id");
          const orgName = btn.getAttribute("data-org-name");
          window.CyberNotify.prompt(
            `Type "${orgName}" to PERMANENTLY delete this organization:`,
            "",
            async (value) => {
              if (value === null) return;
              if (value !== orgName) {
                window.CyberNotify.alert("Organization name does not match. Action cancelled.", { type: "error" });
                return;
              }
              try {
                await window.organizationManager.forceDeleteOrganization(orgId);
                window.CyberNotify.alert("Organization permanently deleted.", { type: "success" });
                this._loadWorkspaceSwitcher();
              } catch (err) {
                window.CyberNotify.alert(err.message || "Failed to delete organization.", { type: "error" });
              }
            }
          );
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
        <div class="settings-section-card text-center py-16 px-6 max-w-xl mx-auto border-dashed border-white/10 bg-white/[0.01]">
          <span class="material-symbols-outlined text-slate-500 text-5xl mb-4 block">business</span>
          <h4 class="text-lg font-bold text-white mb-2">No Organization Selected</h4>
          <p class="text-sm text-slate-400 mb-6 leading-relaxed">
            Select an organization from the workspace switcher, or create a new one.
          </p>
          <div class="flex justify-center">
            <button id="org-start-onboarding-btn"
                    class="cyber-btn-primary px-6 py-2.5 rounded-lg text-sm font-semibold inline-flex items-center gap-2">
              <span class="material-symbols-outlined" style="font-size:1rem;">add_business</span>
              Create Organization
            </button>
          </div>
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
        <div class="space-y-6">
          <!-- Workspace Overview and Resource Usage Grid -->
          <div class="grid grid-cols-1 md:grid-cols-2 gap-6 items-stretch">
            ${this._renderOrgOverview(org, sub, planBadge)}
            ${this._renderUsageMetrics(limits, usage)}
          </div>
          
          ${isOwnerOrAdmin ? this._renderEditForm(org) : ""}
          ${this._renderTeamSection(members, invitations, isOwnerOrAdmin)}
          ${isOwner ? this._renderDangerZone(org) : ""}
        </div>`;
    }

    _renderOrgOverview(org, sub, planBadge) {
      const statusLabel = sub.status === "active" ? "Active" : (sub.status || "Pending");
      const statusCls = sub.status === "active" ? "cyber-badge-success" : "cyber-badge-warning";
      const expiresAt = sub.expires_at ? formatDate(sub.expires_at) : "—";
      const isOwnerOrAdmin = this._currentUserOrgRole === "owner" || this._currentUserOrgRole === "admin";

      let resumeBtnHtml = "";
      if (sub.status !== "active" && isOwnerOrAdmin) {
        resumeBtnHtml = `
          <div class="mt-4">
            <button id="org-resume-payment-btn" class="cyber-btn-primary w-full py-2 rounded-lg text-xs font-semibold flex items-center justify-center gap-2">
              <span class="material-symbols-outlined text-[14px]">payment</span>
              Resume Payment
            </button>
          </div>
        `;
      }

      return `
        <div class="settings-section-card flex flex-col justify-between mb-0 h-full">
          <div>
            <h5 class="settings-section-card-title">
              <span class="material-symbols-outlined text-blue-400">business</span>
              Workspace Overview
            </h5>
            <div class="flex items-center gap-4 mt-6">
              <div class="cyber-org-avatar w-14 h-14 rounded-xl border border-white/10 bg-white/5 flex items-center justify-center font-bold text-white text-xl shadow-lg overflow-hidden flex-shrink-0">
                ${org.logo_url
                  ? `<img src="${escapeHtml(org.logo_url)}" alt="Logo" class="w-full h-full object-cover">`
                  : `<span>${escapeHtml((org.name || "O")[0].toUpperCase())}</span>`}
              </div>
              <div class="min-w-0 flex-1">
                <h4 class="text-base font-bold text-white truncate">${escapeHtml(org.name)}</h4>
                <p class="text-xs text-slate-400 truncate mt-1 flex items-center gap-1">
                  <span class="material-symbols-outlined text-[12px]">link</span>
                  ${escapeHtml(org.domain)}
                </p>
              </div>
            </div>
            ${resumeBtnHtml}
          </div>
          <div class="mt-6 pt-4 border-t border-white/5 flex flex-wrap items-center justify-between gap-3">
            <div class="text-[11px] text-slate-500 font-mono">
              <span class="block">Expires: ${escapeHtml(expiresAt)}</span>
              <span class="block mt-0.5">Slug: ${escapeHtml(org.slug || "—")}</span>
            </div>
            <div class="flex items-center gap-2">
              <span class="cyber-badge-xs ${escapeHtml(planBadge.cls)}">${escapeHtml(planBadge.label)}</span>
              <span class="cyber-badge-xs ${escapeHtml(statusCls)}">${escapeHtml(statusLabel)}</span>
            </div>
          </div>
        </div>`;
    }

    _renderUsageMetrics(limits, usage) {
      const metrics = [
        { label: "Projects", used: usage.projects_count || 0, max: limits.max_projects || 0, color: "bg-blue-500" },
        { label: "Scans This Month", used: usage.scans_used || 0, max: limits.max_scans_per_month || 0, color: "bg-blue-500" },
        { label: "Team Members", used: usage.members_count || 0, max: limits.max_members || 0, color: "bg-blue-500" },
      ];

      const bars = metrics
        .map((m) => {
          const pct = m.max ? Math.min(100, Math.round((m.used / m.max) * 100)) : 0;
          return `
            <div>
              <div class="flex justify-between text-xs mb-1.5 font-mono">
                <span class="text-slate-400">${escapeHtml(m.label)}</span>
                <span class="text-slate-300 font-medium">${m.used} / ${m.max || "—"}</span>
              </div>
              <div class="w-full bg-[#0a0a0a] rounded-full h-2 overflow-hidden border border-white/5">
                <div class="${m.color} h-full rounded-full transition-all duration-500 shadow-[0_0_8px_rgba(59,130,246,0.3)]"
                     style="width:${pct}%"></div>
              </div>
            </div>`;
        })
        .join("");

      return `
        <div class="settings-section-card mb-0 h-full flex flex-col justify-between">
          <div>
            <h5 class="settings-section-card-title">
              <span class="material-symbols-outlined text-blue-400">monitoring</span>
              Resource Usage
            </h5>
            <div class="space-y-4 mt-5">
              ${bars}
            </div>
          </div>
        </div>`;
    }

    _renderEditForm(org) {
      return `
        <div class="settings-section-card">
          <h5 class="settings-section-card-title">
            <span class="material-symbols-outlined text-blue-400">edit</span>
            Workspace Settings
          </h5>
          <form id="org-edit-form" class="space-y-5 mt-4" onsubmit="return false;">
            <div class="settings-form-group mb-0">
              <label for="org-edit-name" class="block text-xs font-semibold text-slate-400 mb-2">Organization Name</label>
              <div class="input-wrapper">
                <input type="text" id="org-edit-name" class="cyber-input p-3 rounded-lg text-sm w-full"
                       value="${escapeHtml(org.name || "")}" maxlength="255" autocomplete="off" required>
              </div>
              <p class="cyber-field-error hidden" id="org-edit-name-error"></p>
            </div>
            <div class="settings-form-group mb-0">
              <label for="org-edit-logo" class="block text-xs font-semibold text-slate-400 mb-2">Logo URL</label>
              <div class="input-wrapper">
                <input type="url" id="org-edit-logo" class="cyber-input p-3 rounded-lg text-sm w-full"
                       value="${escapeHtml(org.logo_url || "")}" placeholder="https://cdn.example.com/logo.png" autocomplete="off">
              </div>
              <p class="cyber-field-error hidden" id="org-edit-logo-error"></p>
            </div>
            <div class="flex justify-end pt-2">
              <button type="button" id="org-edit-submit-btn" class="cyber-btn-primary py-2 px-4 rounded-lg font-semibold text-sm">
                Save Changes
              </button>
            </div>
          </form>
        </div>`;
    }

    _renderTeamSection(members, invitations, isOwnerOrAdmin) {
      return `
        <div class="settings-section-card">
          <div class="flex items-center justify-between mb-6 border-b border-white/5 pb-4">
            <h5 class="settings-section-card-title mb-0">
              <span class="material-symbols-outlined text-blue-400">group</span>
              Team Management
            </h5>
            <span class="text-xs text-slate-500 font-mono bg-white/5 px-2 py-1 rounded border border-white/5">${members.length} member${members.length !== 1 ? "s" : ""}</span>
          </div>

          ${isOwnerOrAdmin ? this._renderInviteForm() : ""}

          <div id="org-members-list" class="space-y-3 mb-6">
            ${members.map((m) => this._renderMemberRow(m, isOwnerOrAdmin)).join("")}
          </div>

          ${invitations.length > 0 ? this._renderInvitationsSection(invitations) : ""}
        </div>`;
    }

    _renderInviteForm() {
      return `
        <form id="org-invite-form" class="bg-white/5 border border-white/5 rounded-xl p-4 mb-6" onsubmit="return false;">
          <div class="grid grid-cols-1 sm:grid-cols-3 gap-4 items-end">
            <div class="sm:col-span-1">
              <label class="block text-xs text-slate-400 mb-1.5" for="org-invite-email">Invite Email Address</label>
              <div class="input-wrapper">
                <input type="email" id="org-invite-email" class="cyber-input p-3 rounded-lg text-sm w-full"
                       placeholder="colleague@domain.com" required autocomplete="off">
              </div>
            </div>
            <div class="sm:col-span-1">
              <label class="block text-xs text-slate-400 mb-1.5" for="org-invite-role">Assign Role</label>
              <div class="input-wrapper">
                <select id="org-invite-role" class="cyber-input p-3 rounded-lg text-sm w-full">
                  <option value="admin">Admin</option>
                  <option value="member" selected>Member</option>
                  <option value="viewer">Viewer</option>
                </select>
              </div>
            </div>
            <div class="sm:col-span-1">
              <button type="button" class="cyber-btn-primary py-3 px-4 rounded-lg font-semibold text-sm w-full flex items-center justify-center gap-2"
                      id="org-invite-submit-btn">
                <span class="material-symbols-outlined" style="font-size:1.1rem;">send</span>
                Send Invite
              </button>
            </div>
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
          <div class="flex items-center gap-2 flex-shrink-0">
            <select class="cyber-input py-1 px-2 text-xs rounded border border-white/10 bg-[#0a0a0a] text-slate-300 org-role-select" data-user-id="${escapeHtml(member.id)}">
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
        <div class="cyber-org-member-row flex items-center justify-between p-4 border border-white/5 bg-white/[0.01] hover:bg-white/[0.03] rounded-xl transition-all gap-4" id="org-member-${escapeHtml(member.id)}">
          <div class="flex items-center gap-3 min-w-0 flex-1">
            <div class="w-10 h-10 rounded-full border border-white/10 bg-white/5 flex items-center justify-center font-bold text-white text-sm flex-shrink-0">
              ${escapeHtml(initials)}
            </div>
            <div class="min-w-0 flex-1">
              <div class="flex items-center gap-2">
                <span class="text-sm font-semibold text-white truncate">${escapeHtml(member.full_name)}</span>
                <span class="cyber-badge-xs ${escapeHtml(badge.cls)}">${escapeHtml(badge.label)}</span>
              </div>
              <p class="text-xs text-slate-500 truncate mt-0.5">${escapeHtml(member.email)}</p>
            </div>
          </div>
          <div class="flex items-center gap-4 flex-shrink-0">
            <div class="text-right hidden sm:block">
              <p class="text-xs text-slate-400">${escapeHtml(member.job_tittle || "Member")}</p>
              <p class="text-[10px] text-slate-600 mt-0.5 font-mono">Joined: ${escapeHtml(joinedAt)}</p>
            </div>
            ${actions}
          </div>
        </div>`;
    }

    _renderInvitationsSection(invitations) {
      const rows = invitations
        .map((inv) => {
          const roleBadge = ROLE_BADGES[inv.role] || ROLE_BADGES.member;
          return `
            <div class="cyber-org-member-row cyber-org-pending-row flex items-center justify-between p-4 border border-dashed border-white/10 bg-white/[0.005] hover:bg-white/[0.015] rounded-xl transition-all gap-4">
              <div class="flex items-center gap-3 min-w-0 flex-1 opacity-70">
                <div class="w-10 h-10 rounded-full border border-dashed border-yellow-500/30 bg-yellow-500/5 flex items-center justify-center text-yellow-500 flex-shrink-0">
                  <span class="material-symbols-outlined" style="font-size:1.1rem;">mail</span>
                </div>
                <div class="min-w-0 flex-1">
                  <div class="flex items-center gap-2">
                    <span class="text-sm font-semibold text-slate-300 truncate">${escapeHtml(inv.email)}</span>
                    <span class="cyber-badge-xs ${escapeHtml(roleBadge.cls)}">${escapeHtml(roleBadge.label)}</span>
                  </div>
                  <p class="text-xs text-yellow-500/70 mt-0.5 font-mono">${timeUntil(inv.expires_at)}</p>
                </div>
              </div>
              <div class="flex items-center gap-2 flex-shrink-0">
                <span class="cyber-badge-xs cyber-badge-warning">Pending</span>
              </div>
            </div>`;
        })
        .join("");

      return `
        <div class="mt-6 border-t border-white/5 pt-6">
          <p class="text-xs font-bold text-slate-400 uppercase tracking-wider mb-3">Pending Invitations</p>
          <div class="space-y-3">${rows}</div>
        </div>`;
    }

    _renderDangerZone(org) {
      return `
        <div class="settings-section-card border-red-900/30 bg-red-950/5 mt-6">
          <h5 class="settings-section-card-title text-red-400 mb-2">
            <span class="material-symbols-outlined text-red-500">warning</span>
            Danger Zone
          </h5>
          <p class="text-xs text-slate-400 mb-4 leading-relaxed">
            Permanently delete this organization and all its data. <span class="text-red-400/80 font-semibold">This action cannot be undone.</span>
          </p>
          <div class="flex">
            <button id="org-delete-btn" class="cyber-btn-red text-xs px-4 py-2.5 rounded-lg font-semibold transition-all">
              Delete Workspace
            </button>
          </div>
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

      const editSubmitBtn = document.getElementById("org-edit-submit-btn");
      if (editSubmitBtn) {
        editSubmitBtn.addEventListener("click", () => {
          this._handleEditSave();
        });
      }

      const editNameInput = document.getElementById("org-edit-name");
      const editLogoInput = document.getElementById("org-edit-logo");
      const handleEditSave = (e) => {
        if (e.key === "Enter") {
          e.preventDefault();
          this._handleEditSave();
        }
      };
      if (editNameInput) editNameInput.addEventListener("keydown", handleEditSave);
      if (editLogoInput) editLogoInput.addEventListener("keydown", handleEditSave);

      // Invite form
      const inviteForm = document.getElementById("org-invite-form");
      if (inviteForm) {
        inviteForm.addEventListener("submit", (e) => {
          e.preventDefault();
          this._handleInvite();
        });
      }

      const inviteSubmitBtn = document.getElementById("org-invite-submit-btn");
      if (inviteSubmitBtn) {
        inviteSubmitBtn.addEventListener("click", () => {
          this._handleInvite();
        });
      }

      const inviteEmailInput = document.getElementById("org-invite-email");
      if (inviteEmailInput) {
        inviteEmailInput.addEventListener("keydown", (e) => {
          if (e.key === "Enter") {
            e.preventDefault();
            this._handleInvite();
          }
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

      // Resume payment button
      const resumeBtn = document.getElementById("org-resume-payment-btn");
      if (resumeBtn) {
        resumeBtn.addEventListener("click", () => {
          const org = this._orgDetails?.organization;
          if (org) {
            window.organizationManager.setPendingOrgId(org.id);
            this._openOnboardingWizard();
            this._isResumingPayment = true;
            this._renderOnboardingStep(3);
          }
        });
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
      this._isResumingPayment = false;
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
            <input type="text" id="onboard-org-name" class="cyber-input p-3 rounded-lg text-sm w-full" required maxlength="255"
                   placeholder="Acme Corp" autocomplete="off">
            <p class="cyber-field-error hidden" id="onboard-org-name-error"></p>
          </div>
          <div>
            <label class="block text-xs text-slate-400 mb-1.5" for="onboard-domain">Company Domain</label>
            <input type="text" id="onboard-domain" class="cyber-input p-3 rounded-lg text-sm w-full" required maxlength="255"
                   placeholder="acme.com" autocomplete="off">
            <p class="cyber-field-error hidden" id="onboard-domain-error"></p>
          </div>
          <div>
            <label class="block text-xs text-slate-400 mb-1.5" for="onboard-corp-email">Corporate Email Address</label>
            <input type="email" id="onboard-corp-email" class="cyber-input p-3 rounded-lg text-sm w-full" required
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
                <div class="cyber-plan-price">2,999<span> EGP/mo</span></div>
                <div class="cyber-plan-features">
                  <div class="cyber-plan-feature-item">Up to <strong>10</strong> members</div>
                  <div class="cyber-plan-feature-item"><strong>10</strong> projects</div>
                  <div class="cyber-plan-feature-item"><strong>20</strong> targets/proj</div>
                  <div class="cyber-plan-feature-item"><strong>50</strong> scans/mo</div>
                </div>
              </div>
              <div class="cyber-plan-card selected" data-plan-val="pro">
                <span class="cyber-plan-badge">Popular</span>
                <span class="material-symbols-outlined cyber-plan-icon">shield_with_heart</span>
                <div class="cyber-plan-name">Pro</div>
                <div class="cyber-plan-price">3,999<span> EGP/mo</span></div>
                <div class="cyber-plan-features">
                  <div class="cyber-plan-feature-item">Up to <strong>15</strong> members</div>
                  <div class="cyber-plan-feature-item"><strong>15</strong> projects</div>
                  <div class="cyber-plan-feature-item"><strong>25</strong> targets/proj</div>
                  <div class="cyber-plan-feature-item"><strong>100</strong> scans/mo</div>
                </div>
              </div>
              <div class="cyber-plan-card" data-plan-val="enterprise">
                <span class="material-symbols-outlined cyber-plan-icon">domain</span>
                <div class="cyber-plan-name">Enterprise</div>
                <div class="cyber-plan-price">5,999<span> EGP/mo</span></div>
                <div class="cyber-plan-features">
                  <div class="cyber-plan-feature-item">Up to <strong>50</strong> members</div>
                  <div class="cyber-plan-feature-item"><strong>50</strong> projects</div>
                  <div class="cyber-plan-feature-item"><strong>100</strong> targets/proj</div>
                  <div class="cyber-plan-feature-item"><strong>500</strong> scans/mo</div>
                </div>
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
              <label class="block text-[11px] text-slate-400 mb-1.5" for="corp-email">Corporate Email Address</label>
              <input type="email" id="corp-email" class="cyber-input p-3 rounded-lg text-sm w-full" required
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
                <label class="block text-[11px] text-slate-400 mb-1.5" for="billing-first-name">First Name *</label>
                <input type="text" id="billing-first-name" class="cyber-input p-3 rounded-lg text-sm w-full" required autocomplete="given-name">
                <p class="cyber-field-error hidden" id="billing-first-name-error"></p>
              </div>
              <div>
                <label class="block text-[11px] text-slate-400 mb-1.5" for="billing-last-name">Last Name *</label>
                <input type="text" id="billing-last-name" class="cyber-input p-3 rounded-lg text-sm w-full" required autocomplete="family-name">
                <p class="cyber-field-error hidden" id="billing-last-name-error"></p>
              </div>
            </div>
            <div>
              <label class="block text-[11px] text-slate-400 mb-1.5" for="billing-email">Email *</label>
              <input type="email" id="billing-email" class="cyber-input p-3 rounded-lg text-sm w-full" required autocomplete="email">
              <p class="cyber-field-error hidden" id="billing-email-error"></p>
            </div>
            <div>
              <label class="block text-[11px] text-slate-400 mb-1.5" for="billing-phone">Phone Number *</label>
              <input type="tel" id="billing-phone" class="cyber-input p-3 rounded-lg text-sm w-full" required autocomplete="tel">
              <p class="cyber-field-error hidden" id="billing-phone-error"></p>
            </div>
          </div>
          
          <!-- Address Section -->
          <div class="cyber-onboarding-form-section space-y-3">
            <h5 class="text-xs font-bold text-slate-300 uppercase tracking-wider mb-2">Billing Address</h5>
            <div class="grid grid-cols-2 gap-3">
              <div>
                <label class="block text-[11px] text-slate-400 mb-1.5" for="billing-city">City *</label>
                <input type="text" id="billing-city" class="cyber-input p-3 rounded-lg text-sm w-full" required autocomplete="address-level2">
              </div>
              <div>
                <label class="block text-[11px] text-slate-400 mb-1.5" for="billing-country">Country *</label>
                <input type="text" id="billing-country" class="cyber-input p-3 rounded-lg text-sm w-full" required autocomplete="country-name">
              </div>
            </div>
            <div>
              <label class="block text-[11px] text-slate-400 mb-1.5" for="billing-street">Street</label>
              <input type="text" id="billing-street" class="cyber-input p-3 rounded-lg text-sm w-full" autocomplete="street-address">
            </div>
            <div class="grid grid-cols-3 gap-3">
              <div>
                <label class="block text-[11px] text-slate-400 mb-1.5" for="billing-building">Building</label>
                <input type="text" id="billing-building" class="cyber-input p-3 rounded-lg text-sm w-full">
              </div>
              <div>
                <label class="block text-[11px] text-slate-400 mb-1.5" for="billing-floor">Floor</label>
                <input type="text" id="billing-floor" class="cyber-input p-3 rounded-lg text-sm w-full">
              </div>
              <div>
                <label class="block text-[11px] text-slate-400 mb-1.5" for="billing-apartment">Apt</label>
                <input type="text" id="billing-apartment" class="cyber-input p-3 rounded-lg text-sm w-full">
              </div>
            </div>
            <div>
              <label class="block text-[11px] text-slate-400 mb-1.5" for="billing-postal">Postal Code</label>
              <input type="text" id="billing-postal" class="cyber-input p-3 rounded-lg text-sm w-full" autocomplete="postal-code">
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
          let response;
          if (this._isResumingPayment) {
            response = await window.organizationManager.resumePayment(orgId, {
              plan: plan,
              billing_data: billingData,
            });
          } else {
            response = await window.organizationManager.submitCheckout(orgId, {
              plan: plan,
              billing_data: billingData,
            });
          }

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

      // Check query parameter to open Step 3 directly!
      const urlParams = new URLSearchParams(window.location.search);
      const stepParam = urlParams.get("org_onboarding_step");
      if (stepParam === "3") {
        // Clean the query parameter from URL
        const newUrl = window.location.pathname;
        window.history.replaceState({}, document.title, newUrl);
        
        this._openOnboardingWizard();
        this._renderOnboardingStep(3);
        return;
      }

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
