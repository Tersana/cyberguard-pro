/**
 * CyberGuard — Phishing Simulation Module
 * Version: 1.0.0
 *
 * Frontend for the consent-based phishing-simulation API documented in
 * docs/PHISHING_WORKFLOW_v2.md. Renders a tabbed "Phishing" workspace with six
 * sub-views (Campaigns, Templates, Employees, Domains, Reports, Permissions) and
 * talks to the hosted Laravel backend through the shared window.apiClient.
 *
 * Endpoints (all relative to APIClient baseURL, org context auto-injected):
 *   Campaigns   GET/POST /phishing/campaigns · GET/PUT /phishing/campaigns/{id}
 *               POST /phishing/campaigns/{id}/launch|cancel · GET .../report
 *   Templates   GET/POST /phishing/templates · GET/PUT/DELETE /phishing/templates/{id}
 *   Employees   GET/POST /phishing/employees · GET/DELETE /phishing/employees/{id}
 *               POST /phishing/employees/import (CSV, multipart)
 *   Domains     GET/POST /phishing/domains · GET .../dns-records · POST .../verify · DELETE
 *   Permissions GET /phishing/permissions · PUT/DELETE /phishing/permissions/{userId}
 *   Reports     GET /phishing/reports/overview|employees/risk|departments
 *
 * Mirrors the ProjectManager module conventions: an ES6 class instantiated as a
 * window singleton by an auto-bootstrap IIFE, dual-mode export for Vitest.
 */

console.log("[PhishingManager] Loading v1.0.0");

// Valid granular permission keys (spec §2)
const PHISHING_PERMISSION_KEYS = [
  "phishing.templates.manage",
  "phishing.campaigns.manage",
  "phishing.employees.manage",
  "phishing.reports.view",
];

const PHISHING_SUBVIEWS = [
  "campaigns",
  "templates",
  "employees",
  "domains",
  "reports",
  "permissions",
];

class PhishingManager {
  constructor(apiClient) {
    this.apiClient = apiClient;
    this.currentSubview = "campaigns";
    this._wired = false;
    this._initialized = {};
    // Cached datasets
    this.campaigns = [];
    this.templates = [];
    this.employees = [];
    this.domains = [];
    // Employee list state
    this.employeeFilters = { department: "", search: "", per_page: 50, page: 1 };
    this.employeePagination = null;
    // ApexCharts instances (destroyed/recreated on re-render)
    this._charts = {};
  }

  // ─── Lifecycle ─────────────────────────────────────────────────────────────

  /**
   * Called by the dashboard tab manager the first time the Phishing tab opens.
   * Wires delegated listeners (idempotent), reveals the Permissions sub-nav for
   * Owners, and renders the default Campaigns sub-view.
   */
  init() {
    this._wireListeners();
    this._applyRoleVisibility();
    this.switchSubview(this.currentSubview || "campaigns", true);
  }

  /** Re-fetch the active sub-view (used on org context change). */
  refreshActive() {
    if (!this.currentSubview) return;
    this._renderSubview(this.currentSubview);
  }

  // ─── Helpers ────────────────────────────────────────────────────────────────

  _qs(id) {
    return typeof document !== "undefined" ? document.getElementById(id) : null;
  }

  getCurrentUser() {
    try {
      if (typeof window !== "undefined" && window.authManager && window.authManager.currentUser) {
        return window.authManager.currentUser;
      }
      const raw = localStorage.getItem("cyberguard_user");
      return raw ? JSON.parse(raw) : null;
    } catch (_) {
      return null;
    }
  }

  /**
   * Best-effort resolution of the current user's role in the active org.
   * Returns a lowercase role string ('owner'/'admin'/'member'/'viewer') or null
   * when it can't be determined from client state.
   */
  currentOrgRole() {
    try {
      const om = typeof window !== "undefined" ? window.organizationManager : null;
      if (om) {
        if (typeof om.getActiveOrg === "function") {
          const org = om.getActiveOrg();
          if (org && (org.role || org.membership_role)) {
            return String(org.role || org.membership_role).toLowerCase();
          }
        }
        if (typeof om.getActiveRole === "function") {
          const r = om.getActiveRole();
          if (r) return String(r).toLowerCase();
        }
      }
      const user = this.getCurrentUser();
      const activeId = om && typeof om.getActiveOrgId === "function" ? om.getActiveOrgId() : null;
      if (user && Array.isArray(user.organizations) && activeId) {
        const match = user.organizations.find((o) => String(o.id) === String(activeId));
        if (match && match.role) return String(match.role).toLowerCase();
      }
      if (user && user.role) return String(user.role).toLowerCase();
    } catch (_) {}
    return null;
  }

  isOwner() {
    return this.currentOrgRole() === "owner";
  }

  /** Map a numeric risk score to its band per spec §5.1. */
  riskLevelFromScore(score) {
    const n = Number(score) || 0;
    if (n <= 0) return "safe";
    if (n <= 5) return "low";
    if (n <= 15) return "medium";
    return "high";
  }

  /** Percentage formatter — one decimal, divide-by-zero safe. */
  formatRate(count, total) {
    const t = Number(total) || 0;
    if (t <= 0) return 0;
    return Math.round((Number(count || 0) / t) * 1000) / 10;
  }

  /** Format a value that is already a rate/number to one decimal for display. */
  _pct(value) {
    const n = Number(value);
    if (!isFinite(n)) return "0.0";
    return n.toFixed(1);
  }

  escapeHtml(str) {
    if (str === null || str === undefined) return "";
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  _notify(message, type = "info") {
    if (typeof window !== "undefined" && window.CyberNotify && typeof window.CyberNotify.alert === "function") {
      window.CyberNotify.alert(message, { type });
    } else {
      console[type === "error" ? "error" : "log"]("[PhishingManager]", message);
    }
  }

  _confirm(message, onConfirm) {
    if (typeof window !== "undefined" && window.CyberNotify && typeof window.CyberNotify.confirm === "function") {
      window.CyberNotify.confirm(message, (ok) => {
        if (ok) onConfirm();
      });
    } else if (typeof window !== "undefined" && typeof window.confirm === "function") {
      if (window.confirm(message)) onConfirm();
    } else {
      onConfirm();
    }
  }

  /** Extract the most useful human-readable message from an API error. */
  _errorMessage(error, fallback = "Something went wrong. Please try again.") {
    if (window.organizationManager && typeof window.organizationManager.isOrgContext === "function" && !window.organizationManager.isOrgContext()) {
      return "Phishing Simulation is only available within an Organization Workspace. Please switch to an Organization Workspace or create one to get started.";
    }
    if (!error) return fallback;
    if (error.data && error.data.message) return error.data.message;
    if (Array.isArray(error.errors) && error.errors.length && error.errors[0].message) {
      return error.errors[0].message;
    }
    if (error.message) return error.message;
    return fallback;
  }

  _handleError(error, fallback) {
    console.error("[PhishingManager]", error);
    // ErrorHandler (when present) already surfaces validation/api errors; still
    // show a concise toast so failures are never silent.
    this._notify(this._errorMessage(error, fallback), "error");
  }

  // ─── API wrappers ────────────────────────────────────────────────────────────
  // Thin, individually testable methods. Each returns the parsed JSON body.

  // Campaigns
  listCampaigns() { return this.apiClient.get("/phishing/campaigns"); }
  getCampaign(id) { return this.apiClient.get(`/phishing/campaigns/${id}`); }
  createCampaign(payload) { return this.apiClient.post("/phishing/campaigns", payload); }
  updateCampaign(id, payload) { return this.apiClient.put(`/phishing/campaigns/${id}`, payload); }
  launchCampaign(id) { return this.apiClient.post(`/phishing/campaigns/${id}/launch`, {}); }
  cancelCampaign(id) { return this.apiClient.post(`/phishing/campaigns/${id}/cancel`, {}); }
  getCampaignReport(id) { return this.apiClient.get(`/phishing/campaigns/${id}/report`); }

  // Templates
  listTemplates(type) {
    const q = type ? `?type=${encodeURIComponent(type)}` : "";
    return this.apiClient.get(`/phishing/templates${q}`);
  }
  getTemplate(id) { return this.apiClient.get(`/phishing/templates/${id}`); }
  createTemplate(payload) { return this.apiClient.post("/phishing/templates", payload); }
  updateTemplate(id, payload) { return this.apiClient.put(`/phishing/templates/${id}`, payload); }
  deleteTemplate(id) { return this.apiClient.delete(`/phishing/templates/${id}`); }

  // Employees
  listEmployees(filters = {}) {
    const params = new URLSearchParams();
    if (filters.department) params.set("department", filters.department);
    if (filters.search) params.set("search", filters.search);
    if (filters.per_page) params.set("per_page", filters.per_page);
    if (filters.page) params.set("page", filters.page);
    const q = params.toString();
    return this.apiClient.get(`/phishing/employees${q ? `?${q}` : ""}`);
  }
  getEmployee(id) { return this.apiClient.get(`/phishing/employees/${id}`); }
  createEmployee(payload) { return this.apiClient.post("/phishing/employees", payload); }
  deleteEmployee(id) { return this.apiClient.delete(`/phishing/employees/${id}`); }
  importEmployees(file) {
    const fd = new FormData();
    fd.append("file", file);
    return this.apiClient.post("/phishing/employees/import", fd);
  }

  // Domains
  listDomains() { return this.apiClient.get("/phishing/domains"); }
  addDomain(domain) { return this.apiClient.post("/phishing/domains", { domain }); }
  getDomainDns(id) { return this.apiClient.get(`/phishing/domains/${id}/dns-records`); }
  verifyDomain(id) { return this.apiClient.post(`/phishing/domains/${id}/verify`, {}); }
  deleteDomain(id) { return this.apiClient.delete(`/phishing/domains/${id}`); }

  // Permissions (Owner only)
  listPermissions() { return this.apiClient.get("/phishing/permissions"); }
  grantPermissions(userId, permissions) {
    return this.apiClient.put(`/phishing/permissions/${userId}`, { permissions });
  }
  revokePermission(userId, permission) {
    // apiClient.delete() sends no body; use _request so the { permission } body is included.
    return this.apiClient._request("DELETE", `/phishing/permissions/${userId}`, { permission });
  }

  // Reports
  reportOverview() { return this.apiClient.get("/phishing/reports/overview"); }
  reportEmployeesRisk() { return this.apiClient.get("/phishing/reports/employees/risk"); }
  reportDepartments() { return this.apiClient.get("/phishing/reports/departments"); }

  // ─── Sub-view navigation ──────────────────────────────────────────────────────

  _wireListeners() {
    if (this._wired) return;
    const root = this._qs("phishing");
    if (!root) return;

    root.addEventListener("click", (e) => {
      const navBtn = e.target.closest(".phishing-subnav-btn[data-subview]");
      if (navBtn) {
        e.preventDefault();
        this.switchSubview(navBtn.dataset.subview);
        return;
      }
      const actionEl = e.target.closest("[data-phishing-action]");
      if (actionEl) {
        e.preventDefault();
        this._handleAction(actionEl.dataset.phishingAction, actionEl.dataset);
      }
    });

    // Employee search / filter (live)
    root.addEventListener("input", (e) => {
      if (e.target && e.target.id === "phishing-employee-search") {
        this.employeeFilters.search = e.target.value.trim();
        this.employeeFilters.page = 1;
        this._debounceEmployees();
      }
    });
    root.addEventListener("change", (e) => {
      if (e.target && e.target.id === "phishing-employee-department") {
        this.employeeFilters.department = e.target.value.trim();
        this.employeeFilters.page = 1;
        this.renderEmployees();
      }
      if (e.target && e.target.id === "phishing-employee-file") {
        const file = e.target.files && e.target.files[0];
        if (file) this._doImportEmployees(file);
      }
    });

    this._wired = true;
  }

  _debounceEmployees() {
    clearTimeout(this._empTimer);
    this._empTimer = setTimeout(() => this._reloadEmployeesResults(), 300);
  }

  /** Hide the Owner-only Permissions sub-nav item for non-owners. */
  _applyRoleVisibility() {
    const permBtn = this._qs("phishing-subnav-permissions");
    if (!permBtn) return;
    const role = this.currentOrgRole();
    // Show for Owner, or when role can't be determined (fall back to backend 403).
    const show = role === null || role === "owner";
    permBtn.style.display = show ? "" : "none";
  }

  switchSubview(name, force = false) {
    if (!PHISHING_SUBVIEWS.includes(name)) return;
    if (!force && this.currentSubview === name && this._initialized[name]) {
      return;
    }
    this.currentSubview = name;

    // Toggle sub-nav active state
    const buttons = document.querySelectorAll(".phishing-subnav-btn[data-subview]");
    buttons.forEach((btn) => {
      btn.classList.toggle("active", btn.dataset.subview === name);
    });

    // Toggle sub-panes
    PHISHING_SUBVIEWS.forEach((view) => {
      const pane = this._qs(`phishing-view-${view}`);
      if (pane) pane.classList.toggle("hidden", view !== name);
    });

    this._renderSubview(name);
  }

  _renderSubview(name) {
    this._initialized[name] = true;
    switch (name) {
      case "campaigns": return this.renderCampaigns();
      case "templates": return this.renderTemplates();
      case "employees": return this.renderEmployees();
      case "domains": return this.renderDomains();
      case "reports": return this.renderReports();
      case "permissions": return this.renderPermissions();
    }
  }

  _handleAction(action, data) {
    switch (action) {
      // Campaigns
      case "campaign-refresh": return this.renderCampaigns();
      case "campaign-new": return this.openCampaignModal();
      case "campaign-edit": return this.openCampaignModal(data.id);
      case "campaign-launch": return this._doLaunchCampaign(data.id, data.name);
      case "campaign-cancel": return this._doCancelCampaign(data.id, data.name);
      case "campaign-report": return this.openCampaignReport(data.id);
      // Templates
      case "template-refresh": return this.renderTemplates();
      case "template-new": return this.openTemplateModal();
      case "template-edit": return this.openTemplateModal(data.id);
      case "template-delete": return this._doDeleteTemplate(data.id, data.name);
      // Employees
      case "employee-refresh": return this.renderEmployees();
      case "employee-new": return this.openEmployeeModal();
      case "employee-import": return this._triggerEmployeeImport();
      case "employee-view": return this.openEmployeeDetail(data.id);
      case "employee-delete": return this._doDeleteEmployee(data.id, data.name);
      case "employee-page": return this._gotoEmployeePage(Number(data.page));
      // Domains
      case "domain-refresh": return this.renderDomains();
      case "domain-new": return this.openDomainModal();
      case "domain-dns": return this.openDomainDns(data.id);
      case "domain-verify": return this._doVerifyDomain(data.id);
      case "domain-delete": return this._doDeleteDomain(data.id, data.name);
      // Reports
      case "report-refresh": return this.renderReports();
      // Permissions
      case "perm-refresh": return this.renderPermissions();
      case "perm-grant": return this.openPermissionModal(data.userId, data.name);
      case "perm-revoke": return this._doRevokePermission(data.userId, data.key, data.name);
      // Modals
      case "modal-close": return this.closeModal();
    }
  }

  // ─── Rendering: shared skeletons ──────────────────────────────────────────────

  _loadingHtml(label = "Loading…") {
    return `<div class="phishing-loading text-center py-8 text-sm" style="color: var(--cg-text-3);">${this.escapeHtml(label)}</div>`;
  }

  /** Wrap a sub-view's content in a themed panel so it sits on a surface. */
  _panel(innerHtml, extraClass = "") {
    return `<div class="cyber-card phishing-panel ${extraClass}">${innerHtml}</div>`;
  }

  _emptyHtml(title, subtitle, actionHtml = "") {
    return `
      <div class="phishing-empty">
        <div class="phishing-empty-icon" aria-hidden="true">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
            <path stroke-linecap="round" stroke-linejoin="round" d="M21.75 6.75v10.5a2.25 2.25 0 0 1-2.25 2.25h-15a2.25 2.25 0 0 1-2.25-2.25V6.75m19.5 0A2.25 2.25 0 0 0 19.5 4.5h-15a2.25 2.25 0 0 0-2.25 2.25m19.5 0v.243a2.25 2.25 0 0 1-1.07 1.916l-7.5 4.615a2.25 2.25 0 0 1-2.36 0L3.32 8.91a2.25 2.25 0 0 1-1.07-1.916V6.75"/>
          </svg>
        </div>
        <p class="phishing-empty-title">${this.escapeHtml(title)}</p>
        ${subtitle ? `<p class="phishing-empty-sub">${this.escapeHtml(subtitle)}</p>` : ""}
        ${actionHtml ? `<div class="phishing-empty-action">${actionHtml}</div>` : ""}
      </div>`;
  }

  _errorHtml(message, retryAction) {
    return `
      <div class="phishing-empty">
        <p class="phishing-empty-title" style="color: var(--cg-danger);">${this.escapeHtml(message)}</p>
        ${retryAction ? `<div class="phishing-empty-action"><button class="cyber-btn-secondary px-4 py-2 text-sm" data-phishing-action="${retryAction}">Retry</button></div>` : ""}
      </div>`;
  }

  _chartEmpty(label = "No data to display yet") {
    return `<div class="phishing-chart-empty">${this.escapeHtml(label)}</div>`;
  }

  _sectionHeader(title, subtitle, actionsHtml = "") {
    return `
      <div class="phishing-section-header flex items-center justify-between gap-3 mb-4 flex-wrap">
        <div>
          <h3 class="text-base font-semibold" style="color: var(--cg-text-1);">${this.escapeHtml(title)}</h3>
          ${subtitle ? `<p class="text-xs mt-0.5" style="color: var(--cg-text-3);">${this.escapeHtml(subtitle)}</p>` : ""}
        </div>
        <div class="phishing-header-actions flex items-center gap-2">${actionsHtml}</div>
      </div>`;
  }

  _statusBadge(status) {
    const MAP = {
      draft: "text-slate-400 bg-slate-500/10 border-slate-500/20",
      scheduled: "text-amber-400 bg-amber-500/10 border-amber-500/20",
      running: "text-blue-400 bg-blue-500/10 border-blue-500/20",
      completed: "text-emerald-400 bg-emerald-500/10 border-emerald-500/20",
      cancelled: "text-zinc-400 bg-zinc-500/10 border-zinc-500/20",
    };
    const cls = MAP[status] || MAP.draft;
    return `<span class="phishing-badge inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium border ${cls}">${this.escapeHtml(status || "draft")}</span>`;
  }

  _riskBadge(level) {
    const MAP = {
      safe: "text-emerald-400 bg-emerald-500/10 border-emerald-500/20",
      low: "text-blue-400 bg-blue-500/10 border-blue-500/20",
      medium: "text-amber-400 bg-amber-500/10 border-amber-500/20",
      high: "text-red-400 bg-red-500/10 border-red-500/20",
    };
    const cls = MAP[level] || MAP.safe;
    return `<span class="phishing-badge inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium border ${cls}">${this.escapeHtml(level)}</span>`;
  }

  // ─── Campaigns ─────────────────────────────────────────────────────────────

  async renderCampaigns() {
    const host = this._qs("phishing-view-campaigns");
    if (!host) return;
    host.innerHTML = this._loadingHtml("Loading campaigns…");
    try {
      const res = await this.listCampaigns();
      this.campaigns = (res && res.campaigns) || [];
      const actions = `<button class="cyber-btn-primary px-4 py-2 text-sm" data-phishing-action="campaign-new">+ New Campaign</button>`;
      let inner = this._sectionHeader("Campaigns", "Create, launch, and track phishing simulations.", actions);
      if (this.campaigns.length === 0) {
        inner += this._emptyHtml("No campaigns yet", "Create your first simulation to get started.",
          `<button class="cyber-btn-primary px-4 py-2 text-sm" data-phishing-action="campaign-new">+ New Campaign</button>`);
      } else {
        inner += `<div class="phishing-list">${this.campaigns.map((c) => this._campaignCard(c)).join("")}</div>`;
      }
      host.innerHTML = this._panel(inner);
    } catch (error) {
      host.innerHTML = this._panel(
        this._sectionHeader("Campaigns", "", "") +
        this._errorHtml(this._errorMessage(error, "Failed to load campaigns."), "campaign-refresh"));
    }
  }

  _campaignCard(c) {
    const tpl = c.template || {};
    const targets = c.targets_count != null ? c.targets_count : "—";
    const clicks = c.clicks_count != null ? c.clicks_count : "—";
    const status = c.status || "draft";
    const canEdit = status === "draft";
    const canLaunch = status === "draft";
    const canCancel = ["draft", "scheduled", "running"].includes(status);
    const canReport = ["running", "completed", "cancelled"].includes(status);
    const targetLabel = c.target_type === "department"
      ? `Dept: ${this.escapeHtml(c.target_department || "—")}`
      : (c.target_type || "all");
    return `
      <div class="phishing-row">
        <div class="phishing-row-main">
          <div class="phishing-row-title">
            <span class="phishing-row-name">${this.escapeHtml(c.name || "Untitled")}</span>
            ${this._statusBadge(status)}
          </div>
          <p class="phishing-row-meta">
            ${this.escapeHtml(tpl.name || "No template")} · ${this.escapeHtml(targetLabel)} · Targets: ${this.escapeHtml(targets)} · Clicks: ${this.escapeHtml(clicks)}
          </p>
        </div>
        <div class="phishing-row-actions">
          ${canEdit ? `<button class="cyber-btn-secondary px-2.5 py-1 text-xs" data-phishing-action="campaign-edit" data-id="${this.escapeHtml(c.id)}">Edit</button>` : ""}
          ${canLaunch ? `<button class="cyber-btn-primary px-2.5 py-1 text-xs" data-phishing-action="campaign-launch" data-id="${this.escapeHtml(c.id)}" data-name="${this.escapeHtml(c.name)}">Launch</button>` : ""}
          ${canReport ? `<button class="cyber-btn-secondary px-2.5 py-1 text-xs" data-phishing-action="campaign-report" data-id="${this.escapeHtml(c.id)}">Report</button>` : ""}
          ${canCancel ? `<button class="phishing-btn-danger px-2.5 py-1 text-xs" data-phishing-action="campaign-cancel" data-id="${this.escapeHtml(c.id)}" data-name="${this.escapeHtml(c.name)}">Cancel</button>` : ""}
        </div>
      </div>`;
  }

  async openCampaignModal(id = null) {
    // Load templates + employees for the pickers
    let templates = this.templates;
    let employees = this.employees;
    try {
      if (!templates || !templates.length) {
        const tr = await this.listTemplates("email");
        templates = (tr && tr.templates) || [];
        this.templates = templates;
      }
      const er = await this.listEmployees({ per_page: 500 });
      const edata = er && er.employees;
      employees = (edata && edata.data) || (Array.isArray(edata) ? edata : []) || [];
    } catch (error) {
      this._handleError(error, "Failed to load campaign form data.");
      return;
    }

    let existing = null;
    if (id) {
      try {
        const res = await this.getCampaign(id);
        existing = (res && res.campaign) || null;
      } catch (error) {
        this._handleError(error, "Failed to load campaign.");
        return;
      }
    }

    const tplOptions = templates
      .map((t) => `<option value="${this.escapeHtml(t.id)}" ${existing && existing.template_id === t.id ? "selected" : ""}>${this.escapeHtml(t.name)}</option>`)
      .join("");
    const empOptions = employees
      .map((e) => `<option value="${this.escapeHtml(e.id)}">${this.escapeHtml(e.name)} — ${this.escapeHtml(e.email)}</option>`)
      .join("");
    const cur = existing || {};

    const body = `
      <form id="phishing-campaign-form" class="space-y-3">
        <label class="phishing-field">
          <span>Campaign name</span>
          <input type="text" name="name" class="cyber-input" required maxlength="255" value="${this.escapeHtml(cur.name || "")}" />
        </label>
        <label class="phishing-field">
          <span>Template</span>
          <select name="template_id" class="cyber-input" required>${tplOptions || '<option value="">No templates available</option>'}</select>
        </label>
        <label class="phishing-field">
          <span>Target type</span>
          <select name="target_type" id="phishing-target-type" class="cyber-input" required>
            <option value="all" ${cur.target_type === "all" ? "selected" : ""}>All employees</option>
            <option value="department" ${cur.target_type === "department" ? "selected" : ""}>By department</option>
            <option value="individual" ${cur.target_type === "individual" ? "selected" : ""}>Specific employees</option>
          </select>
        </label>
        <label class="phishing-field ${cur.target_type === "department" ? "" : "hidden"}" id="phishing-target-department-field">
          <span>Department</span>
          <input type="text" name="target_department" class="cyber-input" maxlength="100" value="${this.escapeHtml(cur.target_department || "")}" />
        </label>
        <label class="phishing-field ${cur.target_type === "individual" ? "" : "hidden"}" id="phishing-target-individual-field">
          <span>Employees</span>
          <select name="employee_ids" class="cyber-input" multiple size="5">${empOptions}</select>
        </label>
        <label class="phishing-field">
          <span>Redirect URL (optional)</span>
          <input type="url" name="redirect_url" class="cyber-input" maxlength="500" value="${this.escapeHtml(cur.redirect_url || "")}" placeholder="https://company.com" />
        </label>
      </form>`;

    this.openModal(id ? "Edit Campaign" : "New Campaign", body, () => this._submitCampaign(id));

    // Toggle conditional fields
    const typeSel = this._qs("phishing-target-type");
    if (typeSel) {
      typeSel.addEventListener("change", () => {
        const deptField = this._qs("phishing-target-department-field");
        const indField = this._qs("phishing-target-individual-field");
        if (deptField) deptField.classList.toggle("hidden", typeSel.value !== "department");
        if (indField) indField.classList.toggle("hidden", typeSel.value !== "individual");
      });
    }
  }

  _readCampaignForm() {
    const form = this._qs("phishing-campaign-form");
    if (!form) return null;
    const payload = {
      name: form.name.value.trim(),
      template_id: form.template_id.value,
      target_type: form.target_type.value,
    };
    if (payload.target_type === "department") {
      payload.target_department = form.target_department.value.trim();
    } else if (payload.target_type === "individual") {
      payload.employee_ids = Array.from(form.employee_ids.selectedOptions || []).map((o) => o.value);
    }
    const redirect = form.redirect_url.value.trim();
    if (redirect) payload.redirect_url = redirect;
    return payload;
  }

  async _submitCampaign(id) {
    const payload = this._readCampaignForm();
    if (!payload) return;
    if (!payload.name) return this._notify("Campaign name is required.", "warning");
    if (!payload.template_id) return this._notify("Please select a template.", "warning");
    if (payload.target_type === "department" && !payload.target_department) {
      return this._notify("Department is required for department targeting.", "warning");
    }
    if (payload.target_type === "individual" && (!payload.employee_ids || !payload.employee_ids.length)) {
      return this._notify("Select at least one employee.", "warning");
    }
    try {
      if (id) {
        await this.updateCampaign(id, payload);
        this._notify("Campaign updated successfully.", "info");
      } else {
        await this.createCampaign(payload);
        this._notify("Campaign created successfully.", "info");
      }
      this.closeModal();
      this.renderCampaigns();
    } catch (error) {
      this._handleError(error, "Failed to save campaign.");
    }
  }

  _doLaunchCampaign(id, name) {
    this._confirm(`Launch campaign "${name || ""}"? Emails will be sent to all resolved targets.`, async () => {
      try {
        await this.launchCampaign(id);
        this._notify("Campaign launched. Emails are being sent.", "info");
        this.renderCampaigns();
      } catch (error) {
        this._handleError(error, "Failed to launch campaign.");
      }
    });
  }

  _doCancelCampaign(id, name) {
    this._confirm(`Cancel campaign "${name || ""}"?`, async () => {
      try {
        await this.cancelCampaign(id);
        this._notify("Campaign cancelled.", "info");
        this.renderCampaigns();
      } catch (error) {
        this._handleError(error, "Failed to cancel campaign.");
      }
    });
  }

  async openCampaignReport(id) {
    this.openModal("Campaign Report", this._loadingHtml("Loading report…"), null, { wide: true });
    try {
      const res = await this.getCampaignReport(id);
      const r = (res && res.report) || {};
      const body = document.querySelector("#phishing-modal-body");
      if (body) body.innerHTML = this._campaignReportHtml(r);
      // Render a chart after the DOM is present
      this._renderCampaignReportChart(r);
    } catch (error) {
      const body = document.querySelector("#phishing-modal-body");
      if (body) body.innerHTML = this._errorHtml(this._errorMessage(error, "Failed to load report."));
    }
  }

  _campaignReportHtml(r) {
    const rows = Object.entries(r.department_breakdown || {})
      .map(([dept, d]) => `
        <tr>
          <td>${this.escapeHtml(dept)}</td>
          <td>${this.escapeHtml(d.total)}</td>
          <td>${this.escapeHtml(d.clicks)}</td>
          <td>${this.escapeHtml(d.submissions)}</td>
          <td>${this.escapeHtml(d.reported)}</td>
          <td>${this._pct(d.click_rate)}%</td>
        </tr>`)
      .join("");
    return `
      <div class="space-y-4">
        <div>
          <h4 class="text-sm font-semibold" style="color: var(--cg-text-1);">${this.escapeHtml(r.campaign_name || "Campaign")}</h4>
          <p class="text-xs" style="color: var(--cg-text-3);">Status: ${this.escapeHtml(r.status || "—")}</p>
        </div>
        <div class="phishing-stat-grid">
          ${this._statTile("Sent", r.total_sent)}
          ${this._statTile("Clicks", `${r.clicks} (${this._pct(r.click_rate)}%)`)}
          ${this._statTile("Submissions", `${r.submissions} (${this._pct(r.submission_rate)}%)`)}
          ${this._statTile("Reported", `${r.reported} (${this._pct(r.report_rate)}%)`)}
        </div>
        <div id="phishing-report-chart" class="phishing-chart"></div>
        <div>
          <h5 class="text-xs font-semibold mb-2" style="color: var(--cg-text-2);">Department breakdown</h5>
          <div class="phishing-table-wrap">
            <table class="phishing-table">
              <thead><tr><th>Department</th><th>Total</th><th>Clicks</th><th>Submissions</th><th>Reported</th><th>Click rate</th></tr></thead>
              <tbody>${rows || '<tr><td colspan="6" style="text-align:center;color:var(--cg-text-3);">No data</td></tr>'}</tbody>
            </table>
          </div>
        </div>
      </div>`;
  }

  _renderCampaignReportChart(r) {
    if (typeof ApexCharts === "undefined") return;
    const el = document.querySelector("#phishing-report-chart");
    if (!el) return;
    try {
      const chart = new ApexCharts(el, {
        chart: { type: "bar", height: 220, toolbar: { show: false } },
        series: [{ name: "Employees", data: [Number(r.clicks) || 0, Number(r.submissions) || 0, Number(r.reported) || 0] }],
        xaxis: { categories: ["Clicked", "Submitted", "Reported"] },
        colors: ["#38BDF8"],
        dataLabels: { enabled: true },
        plotOptions: { bar: { borderRadius: 4, distributed: true } },
        legend: { show: false },
      });
      chart.render();
      this._charts.report = chart;
    } catch (_) {}
  }

  _statTile(label, value) {
    return `
      <div class="phishing-stat">
        <div class="phishing-stat-value">${this.escapeHtml(value != null ? value : "—")}</div>
        <div class="phishing-stat-label">${this.escapeHtml(label)}</div>
      </div>`;
  }

  // ─── Templates ─────────────────────────────────────────────────────────────

  async renderTemplates() {
    const host = this._qs("phishing-view-templates");
    if (!host) return;
    host.innerHTML = this._loadingHtml("Loading templates…");
    try {
      const res = await this.listTemplates("email");
      this.templates = (res && res.templates) || [];
      const actions = `<button class="cyber-btn-primary px-4 py-2 text-sm" data-phishing-action="template-new">+ New Template</button>`;
      let inner = this._sectionHeader("Templates", "Global templates are read-only; create your own custom ones.", actions);
      if (this.templates.length === 0) {
        inner += this._emptyHtml("No templates available", "Create a custom email template to run a campaign.",
          `<button class="cyber-btn-primary px-4 py-2 text-sm" data-phishing-action="template-new">+ New Template</button>`);
      } else {
        inner += `<div class="phishing-list">${this.templates.map((t) => this._templateCard(t)).join("")}</div>`;
      }
      host.innerHTML = this._panel(inner);
    } catch (error) {
      host.innerHTML = this._panel(
        this._sectionHeader("Templates", "", "") +
        this._errorHtml(this._errorMessage(error, "Failed to load templates."), "template-refresh"));
    }
  }

  _templateCard(t) {
    const isGlobal = !t.organization_id;
    const domain = t.domain || {};
    return `
      <div class="phishing-row">
        <div class="phishing-row-main">
          <div class="phishing-row-title">
            <span class="phishing-row-name">${this.escapeHtml(t.name || "Untitled")}</span>
            <span class="phishing-badge inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium border ${isGlobal ? "text-purple-400 bg-purple-500/10 border-purple-500/20" : "text-blue-400 bg-blue-500/10 border-blue-500/20"}">${isGlobal ? "Global" : "Custom"}</span>
            ${t.difficulty ? `<span class="phishing-badge text-xs" style="color: var(--cg-text-3);">${this.escapeHtml(t.difficulty)}</span>` : ""}
          </div>
          <p class="phishing-row-meta">
            ${this.escapeHtml(t.category || "Uncategorized")} · ${this.escapeHtml(t.sender_email || "")} ${domain.domain ? `· ${this.escapeHtml(domain.domain)}` : ""}
          </p>
          <p class="phishing-row-meta">${this.escapeHtml(t.subject || "")}</p>
        </div>
        <div class="phishing-row-actions">
          ${isGlobal ? `<span class="text-xs" style="color: var(--cg-text-3);">Read-only</span>` : `
            <button class="cyber-btn-secondary px-2.5 py-1 text-xs" data-phishing-action="template-edit" data-id="${this.escapeHtml(t.id)}">Edit</button>
            <button class="phishing-btn-danger px-2.5 py-1 text-xs" data-phishing-action="template-delete" data-id="${this.escapeHtml(t.id)}" data-name="${this.escapeHtml(t.name)}">Delete</button>`}
        </div>
      </div>`;
  }

  async openTemplateModal(id = null) {
    // Load domains for the sender-domain picker
    let domains = this.domains;
    try {
      if (!domains || !domains.length) {
        const dr = await this.listDomains();
        domains = (dr && dr.domains) || [];
        this.domains = domains;
      }
    } catch (_) {
      domains = [];
    }

    let existing = null;
    if (id) {
      try {
        const res = await this.getTemplate(id);
        existing = (res && res.template) || null;
      } catch (error) {
        this._handleError(error, "Failed to load template.");
        return;
      }
    }
    const cur = existing || {};
    const domainOptions = domains
      .map((d) => `<option value="${this.escapeHtml(d.id)}" ${cur.domain_id === d.id ? "selected" : ""}>${this.escapeHtml(d.domain)}${d.is_verified ? " ✓" : ""}</option>`)
      .join("");

    const body = `
      <form id="phishing-template-form" class="space-y-3">
        <label class="phishing-field"><span>Name</span>
          <input type="text" name="name" class="cyber-input" required maxlength="255" value="${this.escapeHtml(cur.name || "")}" /></label>
        <label class="phishing-field"><span>Category</span>
          <input type="text" name="category" class="cyber-input" maxlength="100" value="${this.escapeHtml(cur.category || "")}" /></label>
        <div class="phishing-field-row">
          <label class="phishing-field"><span>Difficulty</span>
            <select name="difficulty" class="cyber-input">
              <option value="easy" ${cur.difficulty === "easy" ? "selected" : ""}>Easy</option>
              <option value="medium" ${!cur.difficulty || cur.difficulty === "medium" ? "selected" : ""}>Medium</option>
              <option value="hard" ${cur.difficulty === "hard" ? "selected" : ""}>Hard</option>
            </select></label>
          <label class="phishing-field"><span>Language</span>
            <select name="language" class="cyber-input">
              <option value="en" ${!cur.language || cur.language === "en" ? "selected" : ""}>English</option>
              <option value="ar" ${cur.language === "ar" ? "selected" : ""}>Arabic</option>
            </select></label>
        </div>
        ${domainOptions ? `<label class="phishing-field"><span>Sending domain</span>
          <select name="domain_id" class="cyber-input"><option value="">— none —</option>${domainOptions}</select></label>` : ""}
        <label class="phishing-field"><span>Sender name</span>
          <input type="text" name="sender_name" class="cyber-input" required value="${this.escapeHtml(cur.sender_name || "")}" /></label>
        <label class="phishing-field"><span>Sender email</span>
          <input type="email" name="sender_email" class="cyber-input" value="${this.escapeHtml(cur.sender_email || "")}" placeholder="it-support@yourdomain.com" /></label>
        <label class="phishing-field"><span>Subject</span>
          <input type="text" name="subject" class="cyber-input" required maxlength="500" value="${this.escapeHtml(cur.subject || "")}" /></label>
        <label class="phishing-field"><span>Landing page type</span>
          <select name="landing_page_type" class="cyber-input" required>
            <option value="fake_login" ${cur.landing_page_type === "fake_login" ? "selected" : ""}>Fake login</option>
            <option value="awareness" ${cur.landing_page_type === "awareness" ? "selected" : ""}>Awareness</option>
          </select></label>
        <label class="phishing-field"><span>Email body (HTML — use {tracking_url})</span>
          <textarea name="body" class="cyber-input" rows="5" required>${this.escapeHtml(cur.body || "")}</textarea></label>
        <label class="phishing-field"><span>Awareness content (HTML, optional)</span>
          <textarea name="awareness_content" class="cyber-input" rows="3">${this.escapeHtml(cur.awareness_content || "")}</textarea></label>
      </form>`;

    this.openModal(id ? "Edit Template" : "New Template", body, () => this._submitTemplate(id), { wide: true });
  }

  _readTemplateForm() {
    const form = this._qs("phishing-template-form");
    if (!form) return null;
    const val = (n) => (form[n] ? form[n].value.trim() : "");
    const payload = {
      name: val("name"),
      category: val("category"),
      difficulty: val("difficulty"),
      language: val("language"),
      sender_name: val("sender_name"),
      sender_email: val("sender_email"),
      subject: val("subject"),
      body: form.body ? form.body.value : "",
      landing_page_type: val("landing_page_type"),
      awareness_content: form.awareness_content ? form.awareness_content.value : "",
      type: "email", // Phase 1 — forced email
    };
    if (form.domain_id && form.domain_id.value) payload.domain_id = form.domain_id.value;
    return payload;
  }

  async _submitTemplate(id) {
    const payload = this._readTemplateForm();
    if (!payload) return;
    if (!payload.name) return this._notify("Template name is required.", "warning");
    if (!payload.sender_name) return this._notify("Sender name is required.", "warning");
    if (!payload.subject) return this._notify("Subject is required.", "warning");
    if (!payload.body) return this._notify("Email body is required.", "warning");
    try {
      if (id) {
        await this.updateTemplate(id, payload);
        this._notify("Template updated successfully.", "info");
      } else {
        await this.createTemplate(payload);
        this._notify("Template created successfully.", "info");
      }
      this.closeModal();
      this.renderTemplates();
    } catch (error) {
      this._handleError(error, "Failed to save template.");
    }
  }

  _doDeleteTemplate(id, name) {
    this._confirm(`Delete template "${name || ""}"? This cannot be undone.`, async () => {
      try {
        await this.deleteTemplate(id);
        this._notify("Template deleted successfully.", "info");
        this.renderTemplates();
      } catch (error) {
        this._handleError(error, "Failed to delete template.");
      }
    });
  }

  // ─── Employees ─────────────────────────────────────────────────────────────

  async renderEmployees() {
    const host = this._qs("phishing-view-employees");
    if (!host) return;
    if (!host.querySelector("#phishing-employee-search")) {
      host.innerHTML = this._panel(
        this._sectionHeader("Employees", "The people your simulations target.", "") +
        this._loadingHtml("Loading employees…"));
    }
    try {
      const data = await this._fetchEmployees();
      host.innerHTML = this._employeesHtml(data);
    } catch (error) {
      host.innerHTML = this._panel(
        this._sectionHeader("Employees", "", "") +
        this._errorHtml(this._errorMessage(error, "Failed to load employees."), "employee-refresh"));
    }
  }

  async _fetchEmployees() {
    const res = await this.listEmployees(this.employeeFilters);
    const paged = (res && res.employees) || {};
    const data = paged.data || (Array.isArray(paged) ? paged : []) || [];
    this.employees = data;
    this.employeePagination = {
      current_page: paged.current_page || 1,
      last_page: paged.last_page || 1,
      total: paged.total != null ? paged.total : data.length,
      per_page: paged.per_page || this.employeeFilters.per_page,
    };
    return data;
  }

  /** Refresh only the results area so the search box keeps focus while typing. */
  async _reloadEmployeesResults() {
    try {
      const data = await this._fetchEmployees();
      const container = this._qs("phishing-employees-results");
      if (container) container.innerHTML = this._employeesResultsHtml(data);
    } catch (error) {
      const container = this._qs("phishing-employees-results");
      if (container) container.innerHTML = this._errorHtml(this._errorMessage(error, "Failed to load employees."), "employee-refresh");
    }
  }

  _employeesHtml(data) {
    const actions = `
      <input type="text" id="phishing-employee-search" class="cyber-input phishing-search" placeholder="Search name or email…" value="${this.escapeHtml(this.employeeFilters.search)}" />
      <input type="text" id="phishing-employee-department" class="cyber-input phishing-search" placeholder="Department" value="${this.escapeHtml(this.employeeFilters.department)}" />
      <button class="cyber-btn-secondary px-3 py-2 text-sm" data-phishing-action="employee-import">Import CSV</button>
      <button class="cyber-btn-primary px-3 py-2 text-sm" data-phishing-action="employee-new">+ Add</button>
      <input type="file" id="phishing-employee-file" accept=".csv" class="hidden" />`;
    const header = this._sectionHeader("Employees", "The people your simulations target.", actions);
    return this._panel(header + `<div id="phishing-employees-results">${this._employeesResultsHtml(data)}</div>`);
  }

  _employeesResultsHtml(data) {
    if (!data.length) {
      return this._emptyHtml("No employees found", "Add employees individually or import a CSV.",
        `<button class="cyber-btn-primary px-4 py-2 text-sm" data-phishing-action="employee-new">+ Add Employee</button>`);
    }
    const rows = data.map((e) => {
      const level = e.risk_level || this.riskLevelFromScore(e.risk_score);
      return `
        <tr>
          <td>${this.escapeHtml(e.name)}</td>
          <td>${this.escapeHtml(e.email)}</td>
          <td>${this.escapeHtml(e.department || "—")}</td>
          <td>${this.escapeHtml(e.risk_score != null ? e.risk_score : 0)} ${this._riskBadge(level)}</td>
          <td class="phishing-row-actions">
            <button class="cyber-btn-secondary px-2 py-1 text-xs" data-phishing-action="employee-view" data-id="${this.escapeHtml(e.id)}">View</button>
            <button class="phishing-btn-danger px-2 py-1 text-xs" data-phishing-action="employee-delete" data-id="${this.escapeHtml(e.id)}" data-name="${this.escapeHtml(e.name)}">Delete</button>
          </td>
        </tr>`;
    }).join("");
    return `
      <div class="phishing-table-wrap">
        <table class="phishing-table">
          <thead><tr><th>Name</th><th>Email</th><th>Department</th><th>Risk</th><th></th></tr></thead>
          <tbody>${rows}</tbody>
        </table>
      </div>
      ${this._paginationHtml()}`;
  }

  _paginationHtml() {
    const p = this.employeePagination;
    if (!p || p.last_page <= 1) return "";
    const prev = p.current_page > 1
      ? `<button class="cyber-btn-secondary px-3 py-1 text-xs" data-phishing-action="employee-page" data-page="${p.current_page - 1}">Prev</button>` : "";
    const next = p.current_page < p.last_page
      ? `<button class="cyber-btn-secondary px-3 py-1 text-xs" data-phishing-action="employee-page" data-page="${p.current_page + 1}">Next</button>` : "";
    return `
      <div class="phishing-pagination flex items-center justify-center gap-3 mt-4">
        ${prev}
        <span class="text-xs" style="color: var(--cg-text-3);">Page ${p.current_page} of ${p.last_page} · ${p.total} total</span>
        ${next}
      </div>`;
  }

  _gotoEmployeePage(page) {
    if (!page || page < 1) return;
    this.employeeFilters.page = page;
    this.renderEmployees();
  }

  openEmployeeModal() {
    const body = `
      <form id="phishing-employee-form" class="space-y-3">
        <label class="phishing-field"><span>Name</span>
          <input type="text" name="name" class="cyber-input" required maxlength="255" /></label>
        <label class="phishing-field"><span>Email</span>
          <input type="email" name="email" class="cyber-input" required maxlength="255" /></label>
        <label class="phishing-field"><span>Phone (optional)</span>
          <input type="text" name="phone" class="cyber-input" maxlength="50" /></label>
        <label class="phishing-field"><span>Department (optional)</span>
          <input type="text" name="department" class="cyber-input" maxlength="100" /></label>
      </form>`;
    this.openModal("Add Employee", body, () => this._submitEmployee());
  }

  async _submitEmployee() {
    const form = this._qs("phishing-employee-form");
    if (!form) return;
    const payload = {
      name: form.name.value.trim(),
      email: form.email.value.trim(),
      phone: form.phone.value.trim(),
      department: form.department.value.trim(),
    };
    if (!payload.name) return this._notify("Name is required.", "warning");
    if (!payload.email) return this._notify("Email is required.", "warning");
    try {
      await this.createEmployee(payload);
      this._notify("Employee added successfully.", "info");
      this.closeModal();
      this.renderEmployees();
    } catch (error) {
      this._handleError(error, "Failed to add employee.");
    }
  }

  _triggerEmployeeImport() {
    const input = this._qs("phishing-employee-file");
    if (input) input.click();
  }

  async _doImportEmployees(file) {
    if (file.size > 5 * 1024 * 1024) {
      return this._notify("CSV file must be under 5 MB.", "warning");
    }
    try {
      const res = await this.importEmployees(file);
      const stats = (res && res.stats) || {};
      this._notify(res.message || `Import complete: ${stats.created_or_updated || 0} processed, ${stats.skipped || 0} skipped.`, "info");
      const fileInput = this._qs("phishing-employee-file");
      if (fileInput) fileInput.value = "";
      this.renderEmployees();
    } catch (error) {
      this._handleError(error, "CSV import failed.");
    }
  }

  async openEmployeeDetail(id) {
    this.openModal("Employee Details", this._loadingHtml("Loading…"), null);
    try {
      const res = await this.getEmployee(id);
      const emp = (res && res.employee) || {};
      const history = (res && res.event_history) || [];
      const level = emp.risk_level || this.riskLevelFromScore(emp.risk_score);
      const rows = history.map((h) => `
        <tr>
          <td>${this.escapeHtml(h.event_type)}</td>
          <td>${this.escapeHtml(h.campaign || "—")}</td>
          <td>${this.escapeHtml(h.ip_address || "—")}</td>
          <td>${this.escapeHtml(h.occurred_at || "—")}</td>
        </tr>`).join("");
      const html = `
        <div class="space-y-3">
          <div>
            <p class="text-sm font-semibold" style="color: var(--cg-text-1);">${this.escapeHtml(emp.name)}</p>
            <p class="text-xs" style="color: var(--cg-text-3);">${this.escapeHtml(emp.email)} · Risk ${this.escapeHtml(emp.risk_score != null ? emp.risk_score : 0)} ${this._riskBadge(level)}</p>
          </div>
          <h5 class="text-xs font-semibold" style="color: var(--cg-text-2);">Event history</h5>
          <div class="phishing-table-wrap">
            <table class="phishing-table">
              <thead><tr><th>Event</th><th>Campaign</th><th>IP</th><th>When</th></tr></thead>
              <tbody>${rows || '<tr><td colspan="4" style="text-align:center;color:var(--cg-text-3);">No events yet</td></tr>'}</tbody>
            </table>
          </div>
        </div>`;
      const body = document.querySelector("#phishing-modal-body");
      if (body) body.innerHTML = html;
    } catch (error) {
      const body = document.querySelector("#phishing-modal-body");
      if (body) body.innerHTML = this._errorHtml(this._errorMessage(error, "Failed to load employee."));
    }
  }

  _doDeleteEmployee(id, name) {
    this._confirm(`Remove employee "${name || ""}"?`, async () => {
      try {
        await this.deleteEmployee(id);
        this._notify("Employee removed successfully.", "info");
        this.renderEmployees();
      } catch (error) {
        this._handleError(error, "Failed to remove employee.");
      }
    });
  }

  // ─── Domains ───────────────────────────────────────────────────────────────

  async renderDomains() {
    const host = this._qs("phishing-view-domains");
    if (!host) return;
    host.innerHTML = this._loadingHtml("Loading domains…");
    try {
      const res = await this.listDomains();
      this.domains = (res && res.domains) || [];
      const actions = `<button class="cyber-btn-primary px-4 py-2 text-sm" data-phishing-action="domain-new">+ Add Domain</button>`;
      let inner = this._sectionHeader("Custom Domains", "Send simulations from your own verified domain.", actions);
      inner += `<div class="phishing-notice">Domain verification depends on the Brevo integration, which is under optimization. DNS propagation can take 24–48 hours.</div>`;
      if (this.domains.length === 0) {
        inner += this._emptyHtml("No custom domains", "Add a domain and configure its DNS records to send from your brand.",
          `<button class="cyber-btn-primary px-4 py-2 text-sm" data-phishing-action="domain-new">+ Add Domain</button>`);
      } else {
        inner += `<div class="phishing-list">${this.domains.map((d) => this._domainCard(d)).join("")}</div>`;
      }
      host.innerHTML = this._panel(inner);
    } catch (error) {
      host.innerHTML = this._panel(
        this._sectionHeader("Custom Domains", "", "") +
        this._errorHtml(this._errorMessage(error, "Failed to load domains."), "domain-refresh"));
    }
  }

  _domainCard(d) {
    const verified = d.is_verified;
    return `
      <div class="phishing-row">
        <div class="phishing-row-main">
          <div class="phishing-row-title">
            <span class="phishing-row-name">${this.escapeHtml(d.domain)}</span>
            <span class="phishing-badge inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium border ${verified ? "text-emerald-400 bg-emerald-500/10 border-emerald-500/20" : "text-amber-400 bg-amber-500/10 border-amber-500/20"}">${verified ? "Verified" : "Pending"}</span>
          </div>
          <p class="phishing-row-meta">SPF: ${d.spf_configured ? "✓" : "✗"} · DKIM: ${d.dkim_configured ? "✓" : "✗"}</p>
        </div>
        <div class="phishing-row-actions">
          <button class="cyber-btn-secondary px-2.5 py-1 text-xs" data-phishing-action="domain-dns" data-id="${this.escapeHtml(d.id)}">DNS records</button>
          ${!verified ? `<button class="cyber-btn-primary px-2.5 py-1 text-xs" data-phishing-action="domain-verify" data-id="${this.escapeHtml(d.id)}">Verify</button>` : ""}
          <button class="phishing-btn-danger px-2.5 py-1 text-xs" data-phishing-action="domain-delete" data-id="${this.escapeHtml(d.id)}" data-name="${this.escapeHtml(d.domain)}">Delete</button>
        </div>
      </div>`;
  }

  openDomainModal() {
    const body = `
      <form id="phishing-domain-form" class="space-y-3">
        <label class="phishing-field"><span>Domain</span>
          <input type="text" name="domain" class="cyber-input" required maxlength="255" placeholder="acme-phish.com" /></label>
        <p class="text-xs" style="color: var(--cg-text-3);">After adding, configure the returned DNS records, then verify.</p>
      </form>`;
    this.openModal("Add Domain", body, () => this._submitDomain());
  }

  async _submitDomain() {
    const form = this._qs("phishing-domain-form");
    if (!form) return;
    const domain = form.domain.value.trim();
    if (!domain) return this._notify("Domain is required.", "warning");
    try {
      const res = await this.addDomain(domain);
      this.closeModal();
      this._notify(res.message || "Domain added. Configure the DNS records, then verify.", "info");
      // Show DNS records immediately if returned
      if (res.dns_records) {
        this._showDnsRecords(res.domain ? res.domain.domain : domain, res.dns_records, false);
      }
      this.renderDomains();
    } catch (error) {
      this._handleError(error, "Failed to add domain.");
    }
  }

  async openDomainDns(id) {
    this.openModal("DNS Records", this._loadingHtml("Loading DNS records…"), null, { wide: true });
    try {
      const res = await this.getDomainDns(id);
      const body = document.querySelector("#phishing-modal-body");
      if (body) body.innerHTML = this._dnsRecordsHtml(res.domain, res.dns_records || [], res.is_verified);
    } catch (error) {
      const body = document.querySelector("#phishing-modal-body");
      if (body) body.innerHTML = this._errorHtml(this._errorMessage(error, "Failed to load DNS records."));
    }
  }

  _showDnsRecords(domain, records, verified) {
    this.openModal("DNS Records", this._dnsRecordsHtml(domain, records, verified), null, { wide: true });
  }

  _dnsRecordsHtml(domain, records, verified) {
    const rows = (records || []).map((r) => {
      // records may be objects or plain strings (verify reference form)
      if (typeof r === "string") {
        return `<tr><td colspan="4"><code>${this.escapeHtml(r)}</code></td></tr>`;
      }
      return `
        <tr>
          <td>${this.escapeHtml(r.type)}</td>
          <td><code>${this.escapeHtml(r.name)}</code></td>
          <td><code class="phishing-code-value">${this.escapeHtml(r.value)}</code></td>
          <td>${this.escapeHtml(r.purpose || "")}</td>
        </tr>`;
    }).join("");
    return `
      <div class="space-y-3">
        <p class="text-sm" style="color: var(--cg-text-2);">${this.escapeHtml(domain || "")} ${verified ? "· Verified" : "· Pending verification"}</p>
        <div class="phishing-table-wrap">
          <table class="phishing-table">
            <thead><tr><th>Type</th><th>Name</th><th>Value</th><th>Purpose</th></tr></thead>
            <tbody>${rows || '<tr><td colspan="4" style="text-align:center;color:var(--cg-text-3);">No records</td></tr>'}</tbody>
          </table>
        </div>
      </div>`;
  }

  async _doVerifyDomain(id) {
    try {
      const res = await this.verifyDomain(id);
      this._notify(res.message || "Domain verified successfully.", "info");
      this.renderDomains();
    } catch (error) {
      // 422 = DNS not propagated yet — surface the backend's guidance clearly.
      this._notify(this._errorMessage(error, "Verification failed. DNS propagation can take 24–48 hours."), "warning");
    }
  }

  _doDeleteDomain(id, name) {
    this._confirm(`Delete domain "${name || ""}"?`, async () => {
      try {
        await this.deleteDomain(id);
        this._notify("Domain removed successfully.", "info");
        this.renderDomains();
      } catch (error) {
        // 422 when templates depend on the domain
        this._handleError(error, "Failed to delete domain.");
      }
    });
  }

  // ─── Reports & Analytics ──────────────────────────────────────────────────────

  async renderReports() {
    const host = this._qs("phishing-view-reports");
    if (!host) return;
    host.innerHTML = this._loadingHtml("Loading analytics…");
    try {
      const [ovRes, riskRes, deptRes] = await Promise.all([
        this.reportOverview(),
        this.reportEmployeesRisk(),
        this.reportDepartments(),
      ]);
      const ov = (ovRes && ovRes.overview) || {};
      const risky = (riskRes && riskRes.employees) || [];
      const depts = (deptRes && deptRes.departments) || [];
      host.innerHTML = this._reportsHtml(ov, risky, depts);
      this._renderOverviewCharts(ov, depts);
    } catch (error) {
      host.innerHTML = this._panel(
        this._sectionHeader("Reports & Analytics", "", "") +
        this._errorHtml(this._errorMessage(error, "Failed to load analytics."), "report-refresh"));
    }
  }

  _reportsHtml(ov, risky, depts) {
    const riskRows = risky.map((e) => {
      const level = e.risk_level || this.riskLevelFromScore(e.risk_score);
      return `
        <tr>
          <td>${this.escapeHtml(e.name)}</td>
          <td>${this.escapeHtml(e.department || "—")}</td>
          <td>${this.escapeHtml(e.risk_score != null ? e.risk_score : 0)} ${this._riskBadge(level)}</td>
          <td>${this.escapeHtml(e.last_interaction || "—")}</td>
        </tr>`;
    }).join("");
    const deptRows = depts.map((d) => `
      <tr>
        <td>${this.escapeHtml(d.department || d.name || "—")}</td>
        <td>${this.escapeHtml(d.total_employees != null ? d.total_employees : "—")}</td>
        <td>${this.escapeHtml(d.total_targets != null ? d.total_targets : "—")}</td>
        <td>${this._pct(d.click_rate)}%</td>
        <td>${this._pct(d.submission_rate)}%</td>
        <td>${this.escapeHtml(d.average_risk_score != null ? d.average_risk_score : "—")}</td>
      </tr>`).join("");
    return `
      <div class="phishing-reports-container">
        <div class="phishing-reports-header-section">
          ${this._sectionHeader("Reports & Analytics", "Organization-wide phishing posture and simulation response trends.", `<button class="cyber-btn-secondary phishing-refresh-btn" data-phishing-action="report-refresh"><span class="material-symbols-outlined" aria-hidden="true">refresh</span><span>Refresh</span></button>`)}
          <div class="phishing-stat-grid phishing-report-stat-grid">
            ${this._statTile("Campaigns", ov.total_campaigns)}
            ${this._statTile("Targets", ov.total_targets)}
            ${this._statTile("Click rate", `${this._pct(ov.click_rate)}%`)}
            ${this._statTile("Submission rate", `${this._pct(ov.submission_rate)}%`)}
            ${this._statTile("Report rate", `${this._pct(ov.report_rate)}%`)}
            ${this._statTile("Susceptibility", `${this._pct(ov.susceptibility_rate)}%`)}
          </div>
        </div>
        <div class="phishing-report-charts">
          <div class="cyber-card phishing-report-card phishing-chart-card"><h5>Risk distribution</h5><div id="phishing-risk-chart" class="phishing-chart">${this._chartEmpty()}</div></div>
          <div class="cyber-card phishing-report-card phishing-chart-card"><h5>Department click rate</h5><div id="phishing-dept-chart" class="phishing-chart">${this._chartEmpty()}</div></div>
        </div>
        <div class="cyber-card phishing-report-card">
          <h5>Highest-risk employees</h5>
          <div class="phishing-table-wrap">
            <table class="phishing-table">
              <thead><tr><th>Name</th><th>Department</th><th>Risk</th><th>Last interaction</th></tr></thead>
              <tbody>${riskRows || '<tr><td colspan="4" style="text-align:center;color:var(--cg-text-3);">No data</td></tr>'}</tbody>
            </table>
          </div>
        </div>
        <div class="cyber-card phishing-report-card">
          <h5>Department vulnerability</h5>
          <div class="phishing-table-wrap">
            <table class="phishing-table">
              <thead><tr><th>Department</th><th>Employees</th><th>Targets</th><th>Click rate</th><th>Submission rate</th><th>Avg risk</th></tr></thead>
              <tbody>${deptRows || '<tr><td colspan="6" style="text-align:center;color:var(--cg-text-3);">No data</td></tr>'}</tbody>
            </table>
          </div>
        </div>
      </div>`;
  }

  _renderOverviewCharts(ov, depts) {
    if (typeof ApexCharts === "undefined") return;
    // Risk distribution donut
    try {
      const el = document.querySelector("#phishing-risk-chart");
      const dist = ov.risk_distribution || {};
      const total = (Number(dist.safe) || 0) + (Number(dist.low) || 0) + (Number(dist.medium) || 0) + (Number(dist.high) || 0);
      if (el && total > 0) {
        el.innerHTML = "";
        if (this._charts.risk) { this._charts.risk.destroy(); }
        this._charts.risk = new ApexCharts(el, {
          chart: { type: "donut", height: 240 },
          series: [Number(dist.safe) || 0, Number(dist.low) || 0, Number(dist.medium) || 0, Number(dist.high) || 0],
          labels: ["Safe", "Low", "Medium", "High"],
          colors: ["#34D399", "#38BDF8", "#FBBF24", "#F87171"],
          legend: { position: "bottom" },
        });
        this._charts.risk.render();
      }
    } catch (_) {}
    // Department click-rate bar
    try {
      const el = document.querySelector("#phishing-dept-chart");
      if (el && Array.isArray(depts) && depts.length) {
        el.innerHTML = "";
        if (this._charts.dept) { this._charts.dept.destroy(); }
        this._charts.dept = new ApexCharts(el, {
          chart: { type: "bar", height: 240, toolbar: { show: false } },
          series: [{ name: "Click rate", data: depts.map((d) => Number(d.click_rate) || 0) }],
          xaxis: { categories: depts.map((d) => d.department || d.name || "—") },
          colors: ["#F87171"],
          plotOptions: { bar: { borderRadius: 4, horizontal: true } },
          dataLabels: { enabled: true, formatter: (v) => `${v}%` },
        });
        this._charts.dept.render();
      }
    } catch (_) {}
  }

  // ─── Permissions (Owner only) ─────────────────────────────────────────────────

  async renderPermissions() {
    const host = this._qs("phishing-view-permissions");
    if (!host) return;
    host.innerHTML = this._loadingHtml("Loading permissions…");
    try {
      const res = await this.listPermissions();
      const admins = (res && res.permissions) || [];
      let inner = this._sectionHeader("Permission Delegation", "Grant admins granular phishing permissions.", `<button class="cyber-btn-secondary px-4 py-2 text-sm" data-phishing-action="perm-refresh">Refresh</button>`);
      if (!admins.length) {
        inner += this._emptyHtml("No admins to manage", "Invite admins to your organization to delegate phishing permissions.");
      } else {
        inner += `<div class="phishing-list">${admins.map((a) => this._permissionCard(a)).join("")}</div>`;
      }
      host.innerHTML = this._panel(inner);
    } catch (error) {
      host.innerHTML = this._panel(
        this._sectionHeader("Permission Delegation", "", "") +
        this._errorHtml(this._errorMessage(error, "Failed to load permissions."), "perm-refresh"));
    }
  }

  _permissionCard(a) {
    const user = a.user || {};
    const keys = a.permissions || [];
    const chips = keys.length
      ? keys.map((k) => `
          <span class="phishing-perm-chip">${this.escapeHtml(k.replace("phishing.", ""))}
            <button data-phishing-action="perm-revoke" data-user-id="${this.escapeHtml(user.id)}" data-key="${this.escapeHtml(k)}" data-name="${this.escapeHtml(user.full_name || user.name)}" title="Revoke">×</button>
          </span>`).join("")
      : `<span class="text-xs" style="color: var(--cg-text-3);">No permissions granted</span>`;
    return `
      <div class="phishing-row">
        <div class="phishing-row-main">
          <p class="phishing-row-name">${this.escapeHtml(user.full_name || user.name || "Admin")}</p>
          <p class="phishing-row-meta">${this.escapeHtml(user.email || "")}</p>
          <div class="phishing-perm-chips mt-2">${chips}</div>
        </div>
        <div class="phishing-row-actions">
          <button class="cyber-btn-secondary px-2.5 py-1 text-xs" data-phishing-action="perm-grant" data-user-id="${this.escapeHtml(user.id)}" data-name="${this.escapeHtml(user.full_name || user.name)}">Grant</button>
        </div>
      </div>`;
  }

  openPermissionModal(userId, name) {
    const checks = PHISHING_PERMISSION_KEYS.map((k) => `
      <label class="phishing-check">
        <input type="checkbox" name="perm" value="${this.escapeHtml(k)}" />
        <span>${this.escapeHtml(k.replace("phishing.", ""))}</span>
      </label>`).join("");
    const body = `
      <form id="phishing-permission-form" class="space-y-2">
        <p class="text-xs" style="color: var(--cg-text-3);">Grant permissions to ${this.escapeHtml(name || "this admin")}.</p>
        ${checks}
      </form>`;
    this.openModal("Grant Permissions", body, () => this._submitPermissions(userId));
  }

  async _submitPermissions(userId) {
    const form = this._qs("phishing-permission-form");
    if (!form) return;
    const permissions = Array.from(form.querySelectorAll('input[name="perm"]:checked')).map((c) => c.value);
    if (!permissions.length) return this._notify("Select at least one permission.", "warning");
    try {
      await this.grantPermissions(userId, permissions);
      this._notify("Phishing permissions updated successfully.", "info");
      this.closeModal();
      this.renderPermissions();
    } catch (error) {
      this._handleError(error, "Failed to grant permissions.");
    }
  }

  _doRevokePermission(userId, key, name) {
    this._confirm(`Revoke "${(key || "").replace("phishing.", "")}" from ${name || "this admin"}?`, async () => {
      try {
        await this.revokePermission(userId, key);
        this._notify("Phishing permission revoked.", "info");
        this.renderPermissions();
      } catch (error) {
        this._handleError(error, "Failed to revoke permission.");
      }
    });
  }

  // ─── Modal host ───────────────────────────────────────────────────────────────

  openModal(title, bodyHtml, onSubmit, options = {}) {
    const host = this._qs("phishing-modal-host");
    if (!host) return;
    const wide = options.wide ? "phishing-modal-wide" : "";
    // type="button" on every control so the global submit-prevention handler in
    // cyber-notify.js (which targets `button:not([type])`) never intercepts them.
    const footer = onSubmit
      ? `<button type="button" class="cyber-btn-secondary px-4 py-2 text-sm" data-phishing-action="modal-close">Cancel</button>
         <button type="button" class="cyber-btn-primary px-4 py-2 text-sm" id="phishing-modal-submit">Save</button>`
      : `<button type="button" class="cyber-btn-secondary px-4 py-2 text-sm" data-phishing-action="modal-close">Close</button>`;
    host.innerHTML = `
      <div class="phishing-modal-overlay">
        <div class="phishing-modal ${wide}" role="dialog" aria-modal="true">
          <div class="phishing-modal-header">
            <h3 class="text-sm font-semibold" style="color: var(--cg-text-1);">${this.escapeHtml(title)}</h3>
            <button type="button" class="phishing-modal-x" data-phishing-action="modal-close" aria-label="Close">×</button>
          </div>
          <div class="phishing-modal-body" id="phishing-modal-body">${bodyHtml}</div>
          <div class="phishing-modal-footer">${footer}</div>
        </div>
      </div>`;

    // Self-contained wiring — do NOT rely on the delegated #phishing listener,
    // which the modal's fixed overlay/dialog can sit above.
    const overlay = host.querySelector(".phishing-modal-overlay");
    if (overlay) {
      overlay.addEventListener("click", (e) => {
        if (e.target === overlay) this.closeModal(); // click outside the dialog
      });
    }
    host.querySelectorAll('[data-phishing-action="modal-close"]').forEach((btn) => {
      btn.addEventListener("click", (e) => {
        e.preventDefault();
        this.closeModal();
      });
    });
    const submitBtn = this._qs("phishing-modal-submit");
    if (submitBtn && typeof onSubmit === "function") {
      submitBtn.addEventListener("click", (e) => {
        e.preventDefault();
        onSubmit();
      });
    }
  }

  closeModal() {
    const host = this._qs("phishing-modal-host");
    if (host) host.innerHTML = "";
  }
}

// ─── Dual-mode export + auto-bootstrap ───────────────────────────────────────
if (typeof module !== "undefined" && module.exports) {
  module.exports = { PhishingManager, PHISHING_PERMISSION_KEYS, PHISHING_SUBVIEWS };
}

if (typeof window !== "undefined") {
  window.PhishingManager = PhishingManager;

  function _bootstrapPhishing() {
    // Respect the shared auth guard when present.
    if (typeof window.runAuthGuard === "function" && !window.runAuthGuard()) {
      return;
    }
    if (!window.apiClient && typeof APIClient !== "undefined") {
      window.apiClient = new APIClient();
    }
    if (!window.phishingManager && window.apiClient) {
      window.phishingManager = new PhishingManager(window.apiClient);
      console.log("[PhishingManager] instance created");
    }
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", _bootstrapPhishing);
  } else {
    setTimeout(_bootstrapPhishing, 0);
  }
}
