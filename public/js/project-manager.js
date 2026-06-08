/**
 * CyberGuard Pro — Project Management System
 * Version: 2.0.0
 * Full Projects & Collaborators/Invitations API integration
 *
 * Covers:
 *  GET/POST /api/projects
 *  GET/PATCH/DELETE /api/projects/{id}
 *  POST /api/projects/{id}/invite
 *  GET/PATCH/DELETE /api/projects/{id}/collaborators/{user}
 */

console.log("[ProjectManager] Loading v2.0.0");

// ---------------------------------------------------------------------------
// Normalizer bootstrap (browser: window.normalizeCollaboratorData; Node: require)
// ---------------------------------------------------------------------------
if (typeof window === "undefined" && typeof require !== "undefined") {
  try {
    const norm = require("./data-normalizer.js");
    global.normalizeCollaboratorData = norm.normalizeCollaboratorData;
  } catch (_) {}
}

// ---------------------------------------------------------------------------
// ProjectManager class
// ---------------------------------------------------------------------------
class ProjectManager {
  constructor(apiClient) {
    this.apiClient = apiClient;
    this.projects = []; // all projects (merged)
    this.ownedProjects = []; // owned[]
    this.collaboratingProjects = []; // collaborating[]
    this.currentProjectsTab = "owned";
    this.projectMetricCache = new Map();
  }

  // ─── Helpers ───────────────────────────────────────────────────────────────

  /**
   * Return the authenticated user object from authManager or localStorage.
   * @returns {Object|null}
   */
  getCurrentUser() {
    try {
      if (window.authManager && window.authManager.currentUser) {
        return window.authManager.currentUser;
      }
      const raw = localStorage.getItem("cyberguard_user");
      return raw ? JSON.parse(raw) : null;
    } catch (_) {
      return null;
    }
  }

  /**
   * Determine user's role in a project.
   * @param {string|number} projectId
   * @returns {'owner'|'editor'|'viewer'}
   */
  getUserProjectRole(projectId) {
    const project = this.projects.find((p) => String(p.id) === String(projectId));
    if (!project) return "viewer";
    const currentUser = this.getCurrentUser();
    const isOwner =
      currentUser &&
      project.owner_id &&
      String(project.owner_id) === String(currentUser.id);
    if (isOwner) return "owner";
    return project.role || "viewer";
  }

  /**
   * Check if user has edit access (owner or editor).
   * @param {string|number} projectId
   * @returns {boolean}
   */
  canEdit(projectId) {
    const role = this.getUserProjectRole(projectId);
    return role === "owner" || role === "editor";
  }

  /**
   * Check if user is the owner of the project.
   * @param {string|number} projectId
   * @returns {boolean}
   */
  isOwner(projectId) {
    return this.getUserProjectRole(projectId) === "owner";
  }

  /** XSS-safe HTML escape for text content. */
  escapeHtml(text) {
    if (text == null) return "";
    const d = document.createElement("div");
    d.textContent = String(text);
    return d.innerHTML;
  }

  /** Escape a value for use inside an HTML attribute (single or double quotes). */
  escapeAttr(text) {
    if (text == null) return "";
    return String(text)
      .replace(/&/g, "&amp;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#x27;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;");
  }

  /**
   * Human-readable relative date ("Today", "3 days ago", "Jan 15, 2025").
   * @param {string} dateString — ISO date/datetime string
   */
  formatDate(dateString) {
    if (!dateString) return "Unknown";
    const date = new Date(dateString);
    if (isNaN(date)) return "Unknown";
    const diffDays = Math.floor((Date.now() - date) / 86_400_000);
    if (diffDays === 0) return "Today";
    if (diffDays === 1) return "Yesterday";
    if (diffDays < 7) return `${diffDays}d ago`;
    if (diffDays < 30) return `${Math.floor(diffDays / 7)}w ago`;
    return date.toLocaleDateString("en-US", {
      year: "numeric",
      month: "short",
      day: "numeric",
    });
  }

  /**
   * Readable absolute date for a YYYY-MM-DD string.
   * @param {string} dateString
   * @returns {string|null}
   */
  formatDateReadable(dateString) {
    if (!dateString) return null;
    // Append time so Date() parses as local, not UTC midnight shifted
    const date = new Date(
      dateString.includes("T") ? dateString : `${dateString}T00:00:00`,
    );
    if (isNaN(date)) return dateString;
    return date.toLocaleDateString("en-US", {
      year: "numeric",
      month: "short",
      day: "numeric",
    });
  }

  /** Extract initials (max 2 chars) from a display name. */
  getInitials(name) {
    if (!name) return "U";
    const parts = name.trim().split(/\s+/);
    return parts.length === 1
      ? parts[0][0].toUpperCase()
      : (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
  }

  // ─── API: Projects ─────────────────────────────────────────────────────────

  /**
   * GET /api/projects → { owned, collaborating }
   * Populates this.ownedProjects, this.collaboratingProjects, this.projects.
   */
  async fetchProjects() {
    try {
      const response = await this.apiClient.get("/projects");

      this.ownedProjects = Array.isArray(response.owned) ? response.owned : [];
      this.collaboratingProjects = Array.isArray(response.collaborating)
        ? response.collaborating
        : [];

      // Deduplicated merge for backward compat
      const map = new Map();
      this.ownedProjects.forEach((p) => map.set(String(p.id), p));
      this.collaboratingProjects.forEach((p) => {
        if (!map.has(String(p.id))) map.set(String(p.id), p);
      });
      this.projects = Array.from(map.values());

      return {
        owned: this.ownedProjects,
        collaborating: this.collaboratingProjects,
        projects: this.projects,
      };
    } catch (error) {
      console.error("[ProjectManager] fetchProjects error:", error);
      throw error;
    }
  }

  /**
   * GET /api/projects/{id}
   * @param {string|number} projectId
   */
  async fetchProject(projectId) {
    try {
      const response = await this.apiClient.get(`/projects/${projectId}`);
      return response.project || response;
    } catch (error) {
      console.error("[ProjectManager] fetchProject error:", error);
      throw error;
    }
  }

  /**
   * POST /api/projects
   * @param {Object} data — { name, description?, start_date?, end_date? }
   */
  async createProject(data) {
    try {
      if (typeof showLoading !== "undefined") showLoading("Creating project…");

      if (!data.name || !data.name.trim())
        throw new Error("Project name is required");

      const payload = { name: data.name.trim() };
      if (data.description) payload.description = data.description.trim();
      if (data.start_date) payload.start_date = data.start_date;
      if (data.end_date) payload.end_date = data.end_date;

      const response = await this.apiClient.post("/projects", payload);
      const newProject = response.project || response;

      this.ownedProjects.push(newProject);
      this.projects.push(newProject);
      return newProject;
    } catch (error) {
      console.error("[ProjectManager] createProject error:", error);
      throw error;
    } finally {
      if (typeof hideLoading !== "undefined") hideLoading();
    }
  }

  /**
   * PATCH /api/projects/{id}
   * @param {string|number} projectId
   * @param {Object} data — partial update fields
   */
  async updateProject(projectId, data) {
    try {
      if (typeof showLoading !== "undefined") showLoading("Saving project…");

      const response = await this.apiClient.patch(
        `/projects/${projectId}`,
        data,
      );
      const updated = response.project || response;
      const pid = String(projectId);

      const oi = this.ownedProjects.findIndex((p) => String(p.id) === pid);
      if (oi !== -1) this.ownedProjects[oi] = updated;

      const ai = this.projects.findIndex((p) => String(p.id) === pid);
      if (ai !== -1) this.projects[ai] = updated;

      return updated;
    } catch (error) {
      console.error("[ProjectManager] updateProject error:", error);
      throw error;
    } finally {
      if (typeof hideLoading !== "undefined") hideLoading();
    }
  }

  /**
   * DELETE /api/projects/{id}
   * @param {string|number} projectId
   */
  async deleteProject(projectId) {
    try {
      if (typeof showLoading !== "undefined") showLoading("Deleting project…");
      const pid = String(projectId);
      const response = await this.apiClient.delete(`/projects/${pid}`);

      this.ownedProjects = this.ownedProjects.filter(
        (p) => String(p.id) !== pid,
      );
      this.collaboratingProjects = this.collaboratingProjects.filter(
        (p) => String(p.id) !== pid,
      );
      this.projects = this.projects.filter((p) => String(p.id) !== pid);

      return response;
    } catch (error) {
      console.error("[ProjectManager] deleteProject error:", error);
      throw error;
    } finally {
      if (typeof hideLoading !== "undefined") hideLoading();
    }
  }

  // ─── API: Collaborators ────────────────────────────────────────────────────

  /**
   * GET /api/projects/{id}/collaborators
   */
  async fetchCollaborators(projectId) {
    try {
      const response = await this.apiClient.get(
        `/projects/${projectId}/collaborators`,
      );
      const list = Array.isArray(response.collaborators)
        ? response.collaborators
        : Array.isArray(response)
          ? response
          : [];
      const norm =
        typeof window !== "undefined" && window.normalizeCollaboratorData
          ? window.normalizeCollaboratorData
          : (x) => x;
      return list.map((c) => norm(c));
    } catch (error) {
      console.error("[ProjectManager] fetchCollaborators error:", error);
      throw error;
    }
  }

  /**
   * POST /api/projects/{id}/invite  →  { invite_link, expires_at }
   * @param {string|number} projectId
   * @param {string} role  — 'editor' | 'viewer'
   * @param {string} [email]
   */
  async inviteCollaborator(projectId, role) {
    try {
      if (typeof showLoading !== "undefined")
        showLoading("Generating invite link…");
      // Send role as JSON body (backend expects application/json)
      return await this.apiClient.post(
        `/projects/${projectId}/invite`,
        { role }
      );
    } catch (error) {
      console.error("[ProjectManager] inviteCollaborator error:", error);
      throw error;
    } finally {
      if (typeof hideLoading !== "undefined") hideLoading();
    }
  }

  /**
   * PATCH /api/projects/{id}/collaborators/{user}
   */
  async changeCollaboratorRole(projectId, userId, role) {
    try {
      return await this.apiClient.patch(
        `/projects/${projectId}/collaborators/${userId}`,
        { role },
      );
    } catch (error) {
      console.error("[ProjectManager] changeCollaboratorRole error:", error);
      throw error;
    }
  }

  /**
   * DELETE /api/projects/{id}/collaborators/{user}
   */
  async removeCollaborator(projectId, userId) {
    try {
      if (typeof showLoading !== "undefined") showLoading("Removing member…");
      return await this.apiClient.delete(
        `/projects/${projectId}/collaborators/${userId}`,
      );
    } catch (error) {
      console.error("[ProjectManager] removeCollaborator error:", error);
      throw error;
    } finally {
      if (typeof hideLoading !== "undefined") hideLoading();
    }
  }

  // ─── Targets API Methods ──────────────────────────────────────────────────

  /**
   * GET /api/projects/{id}/targets
   * @param {string|number} projectId
   * @returns {Promise<Array>} Array of target objects
   */
  async fetchTargets(projectId) {
    try {
      const response = await this.apiClient.get(
        `/projects/${projectId}/targets`,
      );
      return Array.isArray(response.targets)
        ? response.targets
        : Array.isArray(response)
          ? response
          : [];
    } catch (error) {
      console.error("[ProjectManager] fetchTargets error:", error);
      throw error;
    }
  }

  /**
   * POST /api/projects/{id}/targets
   * @param {string|number} projectId
   * @param {Object} data - { type, label, value }
   * @returns {Promise<Object>} Created target object
   */
  async createTarget(projectId, data) {
    try {
      if (typeof showLoading !== "undefined") showLoading("Adding target…");
      const response = await this.apiClient.post(
        `/projects/${projectId}/targets`,
        data,
      );
      return response.target || response;
    } catch (error) {
      console.error("[ProjectManager] createTarget error:", error);
      throw error;
    } finally {
      if (typeof hideLoading !== "undefined") hideLoading();
    }
  }

  /**
   * GET /api/targets/{id}
   * @param {string|number} targetId
   * @returns {Promise<Object>} Target detail object
   */
  async fetchTarget(targetId) {
    try {
      const response = await this.apiClient.get(`/targets/${targetId}`);
      return response.target || response;
    } catch (error) {
      console.error("[ProjectManager] fetchTarget error:", error);
      throw error;
    }
  }

  /**
   * PATCH /api/projects/{id}/targets/{targetId}
   * @param {string|number} projectId
   * @param {string|number} targetId
   * @param {Object} data - { label?, value? }
   * @returns {Promise<Object>} Updated target object
   */
  async updateTarget(projectId, targetId, data) {
    try {
      if (typeof showLoading !== "undefined") showLoading("Updating target…");
      const response = await this.apiClient.patch(
        `/projects/${projectId}/targets/${targetId}`,
        data,
      );
      return response.target || response;
    } catch (error) {
      console.error("[ProjectManager] updateTarget error:", error);
      throw error;
    } finally {
      if (typeof hideLoading !== "undefined") hideLoading();
    }
  }

  /**
   * DELETE /api/projects/{id}/targets/{targetId}
   * @param {string|number} projectId
   * @param {string|number} targetId
   * @returns {Promise<Object>} Deletion confirmation
   */
  async deleteTarget(projectId, targetId) {
    try {
      if (typeof showLoading !== "undefined") showLoading("Deleting target…");
      return await this.apiClient.delete(
        `/projects/${projectId}/targets/${targetId}`,
      );
    } catch (error) {
      console.error("[ProjectManager] deleteTarget error:", error);
      throw error;
    } finally {
      if (typeof hideLoading !== "undefined") hideLoading();
    }
  }

  // ─── UI: Projects Tab Sub-navigation ──────────────────────────────────────

  /**
   * Switch between "My Projects" (owned) and "Collaborating" panes.
   * @param {'owned'|'collaborating'} tab
   */
  switchProjectsTab(tab) {
    this.currentProjectsTab = tab;

    const ownedBtn = document.getElementById("projects-tab-owned");
    const collabBtn = document.getElementById("projects-tab-collaborating");
    const ownedPane = document.getElementById("owned-projects-pane");
    const collabPane = document.getElementById("collaborating-projects-pane");

    if (ownedBtn) ownedBtn.classList.toggle("active", tab === "owned");
    if (collabBtn)
      collabBtn.classList.toggle("active", tab === "collaborating");
    if (ownedPane) ownedPane.classList.toggle("hidden", tab !== "owned");
    if (collabPane)
      collabPane.classList.toggle("hidden", tab !== "collaborating");
  }

  // ─── UI: Render Projects List ──────────────────────────────────────────────

  /**
   * Main entry point: fetch & render all projects into both panes.
   */
  async renderProjectsList() {
    try {
      const { owned, collaborating } = await this.fetchProjects();
      const currentUser = this.getCurrentUser();

      this._renderPane(
        document.getElementById("owned-projects-list"),
        document.getElementById("owned-projects-empty"),
        owned,
        "owner",
        currentUser,
      );
      this._renderPane(
        document.getElementById("collaborating-projects-list"),
        document.getElementById("collaborating-projects-empty"),
        collaborating,
        "member",
        currentUser,
      );

      // Update count badges
      const ownedCountEl = document.getElementById("owned-count");
      const collabCountEl = document.getElementById("collaborating-count");
      if (ownedCountEl) ownedCountEl.textContent = owned.length;
      if (collabCountEl) collabCountEl.textContent = collaborating.length;

      // Lazy load actual metrics (targets, findings, scans) from right API endpoints
      const allProjects = [...owned, ...collaborating];
      this.projectMetricCache.clear();
      allProjects.forEach((p) => {
        this.projectMetricCache.set(String(p.id), {
          targets: Number(p.targets_count ?? 0),
          findings: Number(p.findings_count ?? 0),
          scans: Number(p.scans_count ?? 0),
        });
      });
      this._updateProjectsWorkspaceSummary(allProjects.length);
      allProjects.forEach((p) => this.lazyLoadProjectMetrics(p.id));

      // Dispatch custom event for project changes
      document.dispatchEvent(new CustomEvent("cyberguard:projectsUpdated", {
        detail: { projects: allProjects }
      }));
    } catch (error) {
      console.error("[ProjectManager] renderProjectsList error:", error);
      if (window.CyberNotify) {
        window.CyberNotify.alert("Failed to load projects. Please try again.", {
          type: "error",
        });
      }
    }
  }

  _updateProjectsWorkspaceSummary(projectCount = this.projects.length) {
    const totals = Array.from(this.projectMetricCache.values()).reduce(
      (acc, item) => {
        acc.targets += Number(item.targets || 0);
        acc.findings += Number(item.findings || 0);
        acc.scans += Number(item.scans || 0);
        return acc;
      },
      { targets: 0, findings: 0, scans: 0 },
    );

    const setText = (id, value) => {
      const el = document.getElementById(id);
      if (el) el.textContent = String(value);
    };

    setText("projects-total-count", projectCount);
    setText("projects-total-targets", totals.targets);
    setText("projects-total-findings", totals.findings);
    setText("projects-total-scans", totals.scans);
  }

  /**
   * Asynchronously fetch correct targets, findings, and scans counts from the right endpoints,
   * then dynamically update card values and re-calculate/render Risk Score in real time.
   * @param {string} projectId
   */
  async lazyLoadProjectMetrics(projectId) {
    console.log("[ProjectManager] lazyLoadProjectMetrics starting for project:", projectId);
    try {
      // 1. Fetch correct targets count
      const targetsRes = await this.apiClient.get(`/projects/${projectId}/targets`)
        .then(res => {
          console.log(`[ProjectManager] Fetch targets success for ${projectId}:`, res);
          return res;
        })
        .catch((err) => {
          console.error(`[ProjectManager] Fetch targets failed for ${projectId}:`, err);
          return { targets: [] };
        });
      const targets = Array.isArray(targetsRes.targets) ? targetsRes.targets : (Array.isArray(targetsRes) ? targetsRes : []);
      
      const targetsEls = document.querySelectorAll(`.project-targets-count-val[data-project-id="${projectId}"]`);
      console.log(`[ProjectManager] Found ${targetsEls.length} targetsEls for ${projectId}. Updating to: ${targets.length}`);
      targetsEls.forEach(el => {
        const txt = el.textContent || "";
        if (txt.includes("target")) {
          el.textContent = `${targets.length} ${targets.length === 1 ? 'target' : 'targets'}`;
        } else {
          el.textContent = `${targets.length}`;
        }
      });

      // 2. Fetch correct scans count
      const scansRes = await this.apiClient.get(`/projects/${projectId}/scans`)
        .then(res => {
          console.log(`[ProjectManager] Fetch scans success for ${projectId}:`, res);
          return res;
        })
        .catch((err) => {
          console.error(`[ProjectManager] Fetch scans failed for ${projectId}:`, err);
          return { scans: [] };
        });
      const scans = Array.isArray(scansRes.scans) ? scansRes.scans : (Array.isArray(scansRes) ? scansRes : []);
      
      const scansEls = document.querySelectorAll(`.project-scans-count-val[data-project-id="${projectId}"]`);
      console.log(`[ProjectManager] Found ${scansEls.length} scansEls for ${projectId}. Updating to: ${scans.length}`);
      scansEls.forEach(el => {
        const txt = el.textContent || "";
        if (txt.includes("scan")) {
          el.textContent = `${scans.length} ${scans.length === 1 ? 'scan' : 'scans'}`;
        } else {
          el.textContent = `${scans.length}`;
        }
      });

      // 3. Fetch correct findings count for the project in a paginated loop
      let allFindings = [];
      let page = 1;
      let lastPage = 1;

      while (page <= lastPage) {
        try {
          console.log(`[ProjectManager] Fetching findings for project ${projectId} page ${page}`);
          const res = await this.apiClient.get(`/projects/${projectId}/findings?page=${page}`);
          console.log(`[ProjectManager] Fetch findings success for project ${projectId} page ${page}:`, res);
          let arr = [];
          let currentPageVal = page;
          let lastPageVal = page;

          if (Array.isArray(res)) {
            arr = res;
            currentPageVal = 1;
            lastPageVal = 1;
          } else if (res && res.findings) {
            const findingsObj = res.findings;
            if (Array.isArray(findingsObj.data)) {
              arr = findingsObj.data;
              currentPageVal = findingsObj.current_page || page;
              lastPageVal = findingsObj.last_page || page;
            } else if (Array.isArray(findingsObj)) {
              arr = findingsObj;
              currentPageVal = 1;
              lastPageVal = 1;
            }
          } else if (res && res.data) {
            arr = Array.isArray(res.data) ? res.data : [];
            currentPageVal = res.current_page || page;
            lastPageVal = res.last_page || page;
          }

          allFindings = allFindings.concat(arr);

          if (lastPageVal > lastPage) {
            lastPage = lastPageVal;
          }

          if (page >= lastPage) {
            break;
          }
          page++;
        } catch (err) {
          console.error(`[ProjectManager] Fetch findings failed for project ${projectId} page ${page}:`, err);
          break;
        }
      }

      const findingsEls = document.querySelectorAll(`.project-findings-count-val[data-project-id="${projectId}"]`);
      console.log(`[ProjectManager] Found ${findingsEls.length} findingsEls for ${projectId}. Updating to: ${allFindings.length}`);
      findingsEls.forEach(el => {
        const txt = el.textContent || "";
        if (txt.includes("finding")) {
          el.textContent = `${allFindings.length} ${allFindings.length === 1 ? 'finding' : 'findings'}`;
        } else {
          el.textContent = `${allFindings.length}`;
        }
      });

      // 4. Calculate Risk Score dynamically using exact details page metrics formula
      let openCritical = 0;
      let openHigh = 0;
      let openMedium = 0;
      let openLow = 0;
      let totalOpen = 0;

      allFindings.forEach(f => {
        if ((f.status || "open").toLowerCase() === "open") {
          totalOpen++;
          const sev = (f.severity || "info").toLowerCase();
          if (sev === "critical") openCritical++;
          else if (sev === "high") openHigh++;
          else if (sev === "medium") openMedium++;
          else if (sev === "low") openLow++;
        }
      });

      let riskScore = (openCritical * 10 + openHigh * 7 + openMedium * 4 + openLow * 1) / 10;
      riskScore = Math.max(0, Math.min(100.0, riskScore));

      const riskScoreStr = riskScore.toFixed(1);
      const fillWidth = Math.round((riskScore / 100) * 100);

      let scoreColor = "#34D399"; // green
      if (riskScore > 70.0) {
        scoreColor = "#f87171"; // red
      } else if (riskScore > 30.0) {
        scoreColor = "#fbbf24"; // orange/yellow
      }

      console.log(`[ProjectManager] Calculated Risk Score for ${projectId}:`, {
        openCritical, openHigh, openMedium, openLow, totalOpen, riskScore, riskScoreStr, fillWidth
      });

      // Update risk score text value in DOM
      const scoreEls = document.querySelectorAll(`.project-risk-score-value[data-project-id="${projectId}"]`);
      scoreEls.forEach(el => {
        el.textContent = `${riskScoreStr} / 100`;
        el.style.color = scoreColor;
        el.style.background = `${scoreColor}15`;
        el.style.borderColor = `${scoreColor}30`;
      });

      // Update progress fill width and background in DOM
      const fillEls = document.querySelectorAll(`.project-progress-fill[data-progress-project-id="${projectId}"]`);
      fillEls.forEach(el => {
        el.style.width = `${fillWidth}%`;
        el.style.background = scoreColor;
      });

      this.projectMetricCache.set(String(projectId), {
        targets: targets.length,
        findings: allFindings.length,
        scans: scans.length,
      });
      this._updateProjectsWorkspaceSummary(this.projects.length);
    } catch (error) {
      console.error(`[ProjectManager] Failed to lazy load metrics for project ${projectId}:`, error);
    }
  }

  /**
   * Render projects into a list container + toggle its empty state.
   * @private
   */
  _renderPane(listEl, emptyEl, projects, defaultRole, currentUser) {
    if (!listEl) return;
    if (!projects || projects.length === 0) {
      listEl.innerHTML = "";
      listEl.classList.add("hidden");
      if (emptyEl) emptyEl.classList.remove("hidden");
      return;
    }
    listEl.classList.remove("hidden");
    if (emptyEl) emptyEl.classList.add("hidden");
    listEl.innerHTML = projects
      .map((p) => this.renderProjectCard(p, defaultRole, currentUser))
      .join("");
  }

  /**
   * Render a single project card HTML string.
   * @param {Object} project
   * @param {'owner'|'member'|'editor'|'viewer'} defaultRole
   * @param {Object|null} currentUser
   */
  renderProjectCard(project, defaultRole, currentUser) {
    // Ownership — true when this project is in the owned list OR owner_id matches
    const isOwner =
      defaultRole === "owner" ||
      (currentUser &&
        project.owner_id &&
        String(project.owner_id) === String(currentUser.id));

    const role = isOwner ? "owner" : project.role || defaultRole || "member";

    // Status badge
    const STATUS = {
      active: {
        cls: "text-blue-400 bg-blue-500/10 border-blue-500/20",
        label: "Active",
      },
      completed: {
        cls: "text-emerald-400 bg-emerald-500/10 border-emerald-500/20",
        label: "Completed",
      },
      archived: {
        cls: "text-zinc-400 bg-zinc-500/10 border-zinc-500/20",
        label: "Archived",
      },
    };
    const { cls: statusCls, label: statusLabel } =
      STATUS[project.status] || STATUS.active;

    // Role badge
    const ROLE = {
      owner: {
        cls: "text-zinc-300 bg-zinc-500/10 border-zinc-500/20",
        label: "Owner",
      },
      editor: {
        cls: "text-sky-400 bg-sky-500/10 border-sky-500/20",
        label: "Editor",
      },
      viewer: {
        cls: "text-amber-400 bg-amber-500/10 border-amber-500/20",
        label: "Viewer",
      },
      member: {
        cls: "text-zinc-400 bg-zinc-500/10 border-zinc-500/20",
        label: "Member",
      },
    };
    const { cls: roleCls, label: roleLabel } = ROLE[role] || ROLE.member;

    // Date range row
    const startStr = project.start_date
      ? this.formatDateReadable(project.start_date)
      : null;
    const endStr = project.end_date
      ? this.formatDateReadable(project.end_date)
      : null;
    const dateRow =
      startStr || endStr
        ? `
      <span class="project-date-range">
        ${
          startStr
            ? `<span>
          <svg class="w-3 h-3 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" d="M6.75 3v2.25M17.25 3v2.25M3 18.75V7.5a2.25 2.25 0 0 1 2.25-2.25h13.5A2.25 2.25 0 0 1 21 7.5v11.25m-18 0A2.25 2.25 0 0 0 5.25 21h13.5A2.25 2.25 0 0 0 21 18.75m-18 0v-7.5A2.25 2.25 0 0 1 5.25 9h13.5A2.25 2.25 0 0 1 21 11.25v7.5"/>
          </svg>${startStr}</span>`
            : ""
        }
        ${startStr && endStr ? '<span class="text-slate-600">→</span>' : ""}
        ${endStr ? `<span>${endStr}</span>` : ""}
      </span>`
        : "";

    // === RISK SCORE calculation ===
    const targetsCount = project.targets_count ?? 0;
    const findingsCount = project.findings_count ?? 0;
    const scansCount = project.scans_count ?? 0;

    let riskScore = 0;
    if (project.risk_score !== undefined && project.risk_score !== null) {
      riskScore = Number(project.risk_score);
    } else if (findingsCount > 0) {
      riskScore = (1.0 + Math.log2(findingsCount) * 1.5) * 10;
      riskScore = Math.min(100.0, Math.max(0.0, riskScore));
    }

    const riskScoreStr = riskScore.toFixed(1);
    const fillWidth = Math.round((riskScore / 100) * 100);

    let scoreColor = "#34D399"; // green
    if (riskScore > 70.0) {
      scoreColor = "#f87171"; // red
    } else if (riskScore > 30.0) {
      scoreColor = "#fbbf24"; // orange/yellow
    }

    // === METADATA ROW ===
    const metadataRow = `
      <div class="flex items-center gap-4 text-xs text-slate-400 mb-3.5 font-semibold">
        <span class="flex items-center gap-1.5" title="Targets inside project">
          <svg class="w-3.5 h-3.5 text-blue-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <circle cx="12" cy="12" r="10"/>
            <circle cx="12" cy="12" r="6"/>
            <circle cx="12" cy="12" r="2"/>
          </svg>
          <span class="project-targets-count-val" data-project-id="${project.id}">${targetsCount} targets</span>
        </span>
        <span class="flex items-center gap-1.5" title="Total findings">
          <svg class="w-3.5 h-3.5 text-blue-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <rect width="8" height="14" x="8" y="6" rx="4"/>
            <path d="m19 7-3 2M5 7l3 2M19 19l-3-2M5 19l3-2M20 13h-4M4 13h4M10 4l1-2M14 4l-1-2"/>
          </svg>
          <span class="project-findings-count-val" data-project-id="${project.id}">${findingsCount} findings</span>
        </span>
        <span class="flex items-center gap-1.5" title="Total scans done">
          <svg class="w-3.5 h-3.5 text-blue-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            <path d="m9 12 2 2 4-4"/>
          </svg>
          <span class="project-scans-count-val" data-project-id="${project.id}">${scansCount} scans</span>
        </span>
      </div>`;

    // === RISK SCORE BAR ===
    const riskScoreBar = `
      <div class="mb-4">
        <div class="flex items-center justify-between mb-1.5">
          <span class="text-xs text-slate-400 font-medium">Risk Score</span>
          <span class="text-xs font-bold px-2 py-0.5 rounded project-risk-score-value" data-project-id="${project.id}" style="color: ${scoreColor}; background: ${scoreColor}15; border: 1px solid ${scoreColor}30">${riskScoreStr} / 100</span>
        </div>
        <div class="project-progress-track" style="background: rgba(255, 255, 255, 0.05); height: 6px; border-radius: 999px; overflow: hidden; position: relative;">
          <div class="project-progress-fill" data-progress-project-id="${project.id}" style="width: ${fillWidth}%; height: 100%; border-radius: 999px; background: ${scoreColor}; transition: width 0.9s cubic-bezier(0.4, 0, 0.2, 1);"></div>
        </div>
      </div>`;

    // Owner-only action buttons (edit / delete)
    const ownerBtns = isOwner
      ? `
      <button class="cyber-btn-ghost text-xs px-2 py-1.5 rounded flex items-center gap-1"
        onclick="window.projectManager && window.projectManager.editProject('${this.escapeAttr(String(project.id))}')"
        title="Edit project">
        <svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor">
          <path stroke-linecap="round" stroke-linejoin="round" d="m16.862 4.487 1.687-1.688a1.875 1.875 0 1 1 2.652 2.652L10.582 16.07a4.5 4.5 0 0 1-1.897 1.13L6 18l.8-2.685a4.5 4.5 0 0 1 1.13-1.897l8.932-8.931Zm0 0L19.5 7.125M18 14v4.75A2.25 2.25 0 0 1 15.75 21H5.25A2.25 2.25 0 0 1 3 18.75V8.25A2.25 2.25 0 0 1 5.25 6H10"/>
        </svg>
      </button>
      <button class="btn-clear-history text-xs px-2 py-1.5 rounded flex items-center gap-1"
        onclick="window.projectManager && window.projectManager.showDeleteConfirmModal('${this.escapeAttr(String(project.id))}', '${this.escapeAttr(project.name)}')"
        title="Delete project">
        <svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor">
          <path stroke-linecap="round" stroke-linejoin="round" d="m14.74 9-.346 9m-4.788 0L9.26 9m9.968-3.21c.342.052.682.107 1.022.166m-1.022-.165L18.16 19.673a2.25 2.25 0 0 1-2.244 2.077H8.084a2.25 2.25 0 0 1-2.244-2.077L4.772 5.79m14.456 0a48.108 48.108 0 0 0-3.478-.397m-12 .562c.34-.059.68-.114 1.022-.165m0 0a48.11 48.11 0 0 1 3.478-.397m7.5 0v-.916c0-1.18-.91-2.164-2.09-2.201a51.964 51.964 0 0 0-3.32 0c-1.18.037-2.09 1.022-2.09 2.201v.916m7.5 0a48.667 48.667 0 0 0-7.5 0"/>
        </svg>
      </button>`
      : "";

    const detailUrl = `/project-detail?id=${this.escapeAttr(String(project.id))}${isOwner ? "&owned=true" : ""}`;
    const projectInitials = String(project.name || "CG")
      .split(/\s+/)
      .filter(Boolean)
      .slice(0, 2)
      .map((part) => part[0])
      .join("")
      .toUpperCase();
    const riskLevelLabel =
      riskScore > 70.0 ? "Critical" : riskScore > 30.0 ? "Elevated" : "Controlled";

    return `
      <div class="project-card-item"
           data-project-id="${this.escapeAttr(String(project.id))}"
           data-project-name="${this.escapeAttr(project.name)}"
           data-project-status="${this.escapeAttr(project.status || 'active')}"
           data-project-created="${this.escapeAttr(project.created_at || '')}">
        <div class="project-card-head">
          <div class="project-avatar" aria-hidden="true">${this.escapeHtml(projectInitials || "CG")}</div>
          <div class="project-title-block">
            <div class="project-title-row">
              <h3>${this.escapeHtml(project.name)}</h3>
              <span class="project-status-pill ${statusCls}">${statusLabel}</span>
            </div>
            <p>${this.escapeHtml(project.description || "No description")}</p>
          </div>
        </div>

        <div class="project-card-meta">
          <span class="project-role-pill ${roleCls}">${roleLabel}</span>
          ${dateRow || `<span class="project-date-muted">No assessment window</span>`}
        </div>

        <div class="project-metric-grid">
          <div class="project-metric" title="Targets inside project">
            <span class="project-metric-label">Targets</span>
            <strong class="project-targets-count-val" data-project-id="${project.id}">${targetsCount}</strong>
          </div>
          <div class="project-metric" title="Total findings">
            <span class="project-metric-label">Findings</span>
            <strong class="project-findings-count-val" data-project-id="${project.id}">${findingsCount}</strong>
          </div>
          <div class="project-metric" title="Total scans done">
            <span class="project-metric-label">Scans</span>
            <strong class="project-scans-count-val" data-project-id="${project.id}">${scansCount}</strong>
          </div>
        </div>

        <div class="project-risk-panel">
          <div class="project-risk-topline">
            <span>Risk posture</span>
            <span class="project-risk-level">${riskLevelLabel}</span>
          </div>
          <div class="project-progress-track">
            <div class="project-progress-fill" data-progress-project-id="${project.id}" style="width: ${fillWidth}%; background: ${scoreColor};"></div>
          </div>
          <span class="project-risk-score-value" data-project-id="${project.id}" style="color: ${scoreColor}; background: ${scoreColor}15; border-color: ${scoreColor}30">${riskScoreStr} / 100</span>
        </div>

        <div class="project-card-footer">
          <span class="project-created">Created ${this.formatDate(project.created_at)}</span>
          <div class="project-actions">
            <a href="${detailUrl}" class="project-action primary" title="Open project">
              Open
              <svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke-width="1.8" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" d="M13.5 4.5H19.5V10.5M19.5 4.5 10 14M6 6h5M6 18h12" />
              </svg>
            </a>
            ${ownerBtns}
          </div>
        </div>
      </div>`;
  }

  // ─── UI: Create Project Modal ──────────────────────────────────────────────

  showCreateProjectModal() {
    const modal = document.getElementById("create-project-modal");
    if (!modal) return;
    const form = document.getElementById("create-project-form");
    if (form) {
      form.reset();
      this.clearFormErrors();
    }
    modal.classList.remove("hidden");
    document.getElementById("project-name")?.focus();
  }

  hideCreateProjectModal() {
    document.getElementById("create-project-modal")?.classList.add("hidden");
  }

  clearFormErrors() {
    [
      "project-name",
      "project-description",
      "project-start-date",
      "project-end-date",
    ].forEach((id) => {
      const errEl = document.getElementById(`${id}-error`);
      if (errEl) {
        errEl.textContent = "";
        errEl.classList.add("hidden");
      }
      const inp = document.getElementById(id);
      if (inp) inp.classList.remove("border-red-500/50");
    });
  }

  showFieldError(fieldId, message) {
    const inp = document.getElementById(fieldId);
    const errEl = document.getElementById(`${fieldId}-error`);
    if (inp) inp.classList.add("border-red-500/50");
    if (errEl) {
      errEl.textContent = message;
      errEl.classList.remove("hidden");
    }
  }

  /** Client-side validation for create/edit forms. */
  validateProjectForm(data) {
    const errors = {};
    let valid = true;

    if (!data.name || !data.name.trim()) {
      errors.name = "Project name is required";
      valid = false;
    } else if (data.name.trim().length < 2) {
      errors.name = "Project name must be at least 2 characters";
      valid = false;
    } else if (data.name.trim().length > 255) {
      errors.name = "Project name must not exceed 255 characters";
      valid = false;
    }

    if (data.start_date && data.end_date) {
      if (new Date(data.end_date) <= new Date(data.start_date)) {
        errors["end-date"] = "End date must be after start date";
        valid = false;
      }
    }
    return { valid, errors };
  }

  async handleProjectFormSubmit(event) {
    event.preventDefault();
    this.clearFormErrors();

    const form = event.target;
    const data = {
      name: (form.name?.value || "").trim(),
      description: (form.description?.value || "").trim(),
      start_date: form.start_date?.value || "",
      end_date: form.end_date?.value || "",
    };

    const { valid, errors } = this.validateProjectForm(data);
    if (!valid) {
      Object.entries(errors).forEach(([field, msg]) =>
        this.showFieldError(`project-${field}`, msg),
      );
      return;
    }

    const submitBtn = document.getElementById("create-project-submit");
    if (submitBtn?.disabled) return;
    if (submitBtn && typeof showInlineLoading !== "undefined")
      showInlineLoading(submitBtn, "Creating");

    try {
      const project = await this.createProject(data);
      this.hideCreateProjectModal();
      if (window.CyberNotify)
        window.CyberNotify.alert(
          `Project "${project.name}" created successfully.`,
          { type: "success" },
        );
      await this.renderProjectsList();
    } catch (error) {
      if (error.status === 422 && error.errors) {
        error.errors.forEach((e) =>
          this.showFieldError(`project-${e.field}`, e.message),
        );
      } else {
        if (window.CyberNotify)
          window.CyberNotify.alert(
            error.message || "Failed to create project.",
            { type: "error" },
          );
      }
    } finally {
      if (submitBtn && typeof hideInlineLoading !== "undefined")
        hideInlineLoading(submitBtn);
    }
  }

  // ─── UI: Edit Project Modal ────────────────────────────────────────────────

  async showEditProjectModal(projectId) {
    const modal = document.getElementById("edit-project-modal");
    if (!modal) return;

    try {
      const project = await this.fetchProject(projectId);

      const f = (id) => document.getElementById(id);
      if (f("edit-project-id"))
        f("edit-project-id").value = project.id || projectId;
      if (f("edit-project-name"))
        f("edit-project-name").value = project.name || "";
      if (f("edit-project-description"))
        f("edit-project-description").value = project.description || "";
      if (f("edit-project-status"))
        f("edit-project-status").value = project.status || "active";
      if (f("edit-project-start-date"))
        f("edit-project-start-date").value = project.start_date || "";
      if (f("edit-project-end-date"))
        f("edit-project-end-date").value = project.end_date || "";

      this.clearEditFormErrors();
      await this.loadCollaborators(projectId);
      modal.classList.remove("hidden");
    } catch (error) {
      if (window.CyberNotify)
        window.CyberNotify.alert("Failed to load project details.", {
          type: "error",
        });
    }
  }

  hideEditProjectModal() {
    document.getElementById("edit-project-modal")?.classList.add("hidden");
  }

  clearEditFormErrors() {
    [
      "edit-project-name",
      "edit-project-description",
      "edit-project-status",
      "edit-project-start-date",
      "edit-project-end-date",
    ].forEach((id) => {
      const errEl = document.getElementById(`${id}-error`);
      if (errEl) {
        errEl.textContent = "";
        errEl.classList.add("hidden");
      }
      const inp = document.getElementById(id);
      if (inp) inp.classList.remove("border-red-500/50");
    });
  }

  showEditFieldError(fieldId, message) {
    const inp = document.getElementById(fieldId);
    const errEl = document.getElementById(`${fieldId}-error`);
    if (inp) inp.classList.add("border-red-500/50");
    if (errEl) {
      errEl.textContent = message;
      errEl.classList.remove("hidden");
    }
  }

  async handleEditProjectFormSubmit(event) {
    event.preventDefault();
    this.clearEditFormErrors();

    const form = event.target;
    const projectId = document.getElementById("edit-project-id")?.value;

    const data = {
      name: (form.name?.value || "").trim(),
      description: (form.description?.value || "").trim(),
      status: form.status?.value || "active",
    };
    const startDate = document.getElementById("edit-project-start-date")?.value;
    const endDate = document.getElementById("edit-project-end-date")?.value;
    if (startDate) data.start_date = startDate;
    if (endDate) data.end_date = endDate;

    const { valid, errors } = this.validateProjectForm(data);
    if (!valid) {
      Object.entries(errors).forEach(([field, msg]) => {
        this.showEditFieldError(
          `edit-project-${field.replace(/_/g, "-")}`,
          msg,
        );
      });
      return;
    }

    const submitBtn = document.getElementById("edit-project-submit");
    if (submitBtn?.disabled) return;
    if (submitBtn && typeof showInlineLoading !== "undefined")
      showInlineLoading(submitBtn, "Saving");

    try {
      const updated = await this.updateProject(projectId, data);
      this.hideEditProjectModal();
      if (window.CyberNotify)
        window.CyberNotify.alert(
          `Project "${updated.name}" updated successfully.`,
          { type: "success" },
        );
      await this.renderProjectsList();
    } catch (error) {
      if (error.status === 422 && error.errors) {
        error.errors.forEach((e) =>
          this.showEditFieldError(
            `edit-project-${e.field.replace(/_/g, "-")}`,
            e.message,
          ),
        );
      } else if (error.status === 403) {
        if (window.CyberNotify)
          window.CyberNotify.alert(
            "Only the project owner can edit this project.",
            { type: "error" },
          );
      } else {
        if (window.CyberNotify)
          window.CyberNotify.alert(
            error.message || "Failed to update project.",
            { type: "error" },
          );
      }
    } finally {
      if (submitBtn && typeof hideInlineLoading !== "undefined")
        hideInlineLoading(submitBtn);
    }
  }

  /** Alias called from project card Edit button. */
  editProject(projectId) {
    this.showEditProjectModal(projectId);
  }

  // ─── UI: Delete Confirmation Modal ────────────────────────────────────────

  showDeleteConfirmModal(projectId, projectName) {
    const modal = document.getElementById("delete-project-modal");
    if (!modal) {
      // Fallback if modal isn't in the DOM
      this.deleteProjectConfirm(projectId);
      return;
    }
    const idInput = document.getElementById("delete-project-id");
    const nameHint = document.getElementById("delete-project-name-hint");
    const nameInput = document.getElementById("delete-project-name-input");
    const confirmBtn = document.getElementById("delete-project-confirm-btn");
    const errEl = document.getElementById("delete-project-name-error");

    if (idInput) idInput.value = projectId;
    if (nameHint) nameHint.textContent = projectName;
    if (nameInput) {
      nameInput.value = "";
    }
    if (confirmBtn) confirmBtn.disabled = true;
    if (errEl) errEl.classList.add("hidden");

    modal.classList.remove("hidden");
    if (nameInput) nameInput.focus();
  }

  hideDeleteConfirmModal() {
    document.getElementById("delete-project-modal")?.classList.add("hidden");
  }

  async handleDeleteConfirm() {
    const projectId = document.getElementById("delete-project-id")?.value;
    if (!projectId) return;

    const confirmBtn = document.getElementById("delete-project-confirm-btn");
    if (confirmBtn && typeof showInlineLoading !== "undefined")
      showInlineLoading(confirmBtn, "Deleting");

    try {
      await this.deleteProject(projectId);
      this.hideDeleteConfirmModal();
      if (window.CyberNotify)
        window.CyberNotify.alert("Project deleted successfully.", {
          type: "success",
        });
      await this.renderProjectsList();
    } catch (error) {
      if (error.status === 403) {
        if (window.CyberNotify)
          window.CyberNotify.alert(
            "Only the project owner can delete this project.",
            { type: "error" },
          );
      } else {
        if (window.CyberNotify)
          window.CyberNotify.alert(
            error.message || "Failed to delete project.",
            { type: "error" },
          );
      }
    } finally {
      if (confirmBtn && typeof hideInlineLoading !== "undefined")
        hideInlineLoading(confirmBtn);
    }
  }

  /** Legacy entry point — called from old delete buttons. */
  async deleteProjectConfirm(projectId) {
    const project = this.projects.find(
      (p) => String(p.id) === String(projectId),
    );
    if (project) {
      this.showDeleteConfirmModal(projectId, project.name);
    } else {
      // Name unknown — use simple confirm fallback
      if (window.CyberNotify && window.CyberNotify.confirm) {
        window.CyberNotify.confirm(
          "Delete this project? This action cannot be undone.",
          async (confirmed) => {
            if (confirmed) await this.handleDeleteProject(projectId);
          },
          { confirmText: "Delete", cancelText: "Cancel", type: "danger" },
        );
      } else if (confirm("Delete this project?")) {
        await this.handleDeleteProject(projectId);
      }
    }
  }

  async handleDeleteProject(projectId) {
    try {
      await this.deleteProject(projectId);
      if (window.CyberNotify)
        window.CyberNotify.alert("Project deleted successfully.", {
          type: "success",
        });
      await this.renderProjectsList();
    } catch (error) {
      if (window.CyberNotify)
        window.CyberNotify.alert(error.message || "Failed to delete project.", {
          type: "error",
        });
    }
  }

  // ─── UI: Collaborators List ────────────────────────────────────────────────

  async loadCollaborators(projectId) {
    const listEl = document.getElementById("collaborators-list");
    if (!listEl) return;

    listEl.innerHTML = `<div class="text-center py-4 text-xs text-slate-400">Loading team…</div>`;

    try {
      const collaborators = await this.fetchCollaborators(projectId);
      const currentUser = this.getCurrentUser();

      if (collaborators.length === 0) {
        listEl.innerHTML = `<div class="text-center py-4 text-xs text-slate-500">No collaborators yet. Invite someone to collaborate.</div>`;
      } else {
        listEl.innerHTML = collaborators
          .map((c) => this.renderCollaboratorItem(c, projectId, currentUser))
          .join("");
      }
    } catch (error) {
      listEl.innerHTML = `<div class="text-center py-4 text-xs text-[var(--cg-danger)]">Failed to load team members.</div>`;
    }
  }

  renderCollaboratorItem(collaborator, projectId, currentUser) {
    // Normalise — handle nested user object or flat fields
    const norm =
      typeof window !== "undefined" && window.normalizeCollaboratorData
        ? window.normalizeCollaboratorData(collaborator)
        : collaborator;

    const userId =
      norm.id || norm.user_id || (collaborator.user && collaborator.user.id);
    const displayName = this.escapeHtml(
      norm.fullName ||
        norm.full_name ||
        norm.name ||
        (collaborator.user &&
          (collaborator.user.full_name || collaborator.user.name)) ||
        "Unknown User",
    );
    const email = this.escapeHtml(
      norm.email || (collaborator.user && collaborator.user.email) || "",
    );
    const jobTitle = this.escapeHtml(
      norm.jobTitle ||
        norm.job_title ||
        norm.job_tittle ||
        (collaborator.user &&
          (collaborator.user.job_title || collaborator.user.job_tittle)) ||
        "",
    );
    const role = norm.role || collaborator.role || "viewer";
    const initials = this.getInitials(
      norm.fullName || norm.full_name || norm.name || "U",
    );
    const isSelf =
      currentUser && userId && String(userId) === String(currentUser.id);

    const ROLE_BADGE = {
      owner:
        "text-zinc-300 bg-zinc-500/10 border-zinc-500/20",
      editor:
        "text-sky-400 bg-sky-500/10 border-sky-500/20",
      viewer:
        "text-amber-400 bg-amber-500/10 border-amber-500/20",
    };
    const roleBadgeCls = ROLE_BADGE[role] || ROLE_BADGE.viewer;

    // Inline role selector (owner sees this; viewer/editor sees badge only for their own row)
    const roleControl = !isSelf
      ? `<select
           class="cyber-input text-xs px-2 py-1 rounded-lg min-w-[80px]"
           onchange="window.projectManager && window.projectManager.handleRoleChange('${this.escapeAttr(String(projectId))}','${this.escapeAttr(String(userId))}',this.value)"
         >
           <option value="editor" ${role === "editor" ? "selected" : ""}>Editor</option>
           <option value="viewer" ${role === "viewer" ? "selected" : ""}>Viewer</option>
         </select>`
      : `<span class="text-xs px-2 py-0.5 rounded-full border font-semibold ${roleBadgeCls}">${role.charAt(0).toUpperCase() + role.slice(1)}</span>`;

    // Remove button — disabled + tooltip for self
    const removeBtn = isSelf
      ? `<button class="cyber-btn-ghost text-xs px-2 py-1.5 rounded opacity-40 cursor-not-allowed" disabled
           title="You cannot remove yourself from the project">
           <svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor">
             <path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12"/>
           </svg>
         </button>`
      : `<button class="cyber-btn-danger text-xs px-2 py-1.5 rounded flex items-center gap-1"
           onclick="window.projectManager && window.projectManager.removeCollaboratorConfirm('${this.escapeAttr(String(projectId))}','${this.escapeAttr(String(userId))}')"
           title="Remove member">
           <svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor">
             <path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12"/>
           </svg>
         </button>`;

    return `
      <div class="cyber-card p-3 flex items-center gap-3" data-collaborator-id="${this.escapeAttr(String(userId))}">
        <div class="cyber-avatar-sm flex-shrink-0 flex items-center justify-center">
          <span class="text-xs font-bold text-white">${initials}</span>
        </div>
        <div class="flex-1 min-w-0">
          <p class="text-sm font-semibold text-white truncate">
            ${displayName}${isSelf ? ' <span class="text-xs text-slate-400 font-normal">(you)</span>' : ""}
          </p>
          <p class="text-xs text-slate-400 truncate">${email || jobTitle || role}</p>
        </div>
        <div class="flex items-center gap-2 flex-shrink-0">
          ${roleControl}
          ${removeBtn}
        </div>
      </div>`;
  }

  async handleRoleChange(projectId, userId, newRole) {
    try {
      await this.changeCollaboratorRole(projectId, userId, newRole);
      if (window.CyberNotify)
        window.CyberNotify.alert("Role updated successfully.", {
          type: "success",
        });
    } catch (error) {
      const msg =
        error.status === 403
          ? "Only the project owner can change roles."
          : error.message || "Failed to change role.";
      if (window.CyberNotify) window.CyberNotify.alert(msg, { type: "error" });
      // Re-render to reset the select back to previous value
      const projectId2 =
        document.getElementById("edit-project-id")?.value || projectId;
      await this.loadCollaborators(projectId2);
    }
  }

  async removeCollaboratorConfirm(projectId, userId) {
    if (window.CyberNotify && window.CyberNotify.confirm) {
      window.CyberNotify.confirm(
        "Remove this team member from the project?",
        async (confirmed) => {
          if (confirmed) await this.handleRemoveCollaborator(projectId, userId);
        },
        { confirmText: "Remove", cancelText: "Cancel", type: "warning" },
      );
    } else if (confirm("Remove this team member?")) {
      await this.handleRemoveCollaborator(projectId, userId);
    }
  }

  async handleRemoveCollaborator(projectId, userId) {
    try {
      await this.removeCollaborator(projectId, userId);
      if (window.CyberNotify)
        window.CyberNotify.alert("Team member removed successfully.", {
          type: "success",
        });
      await this.loadCollaborators(projectId);
    } catch (error) {
      const msg =
        error.status === 400
          ? "You cannot remove yourself from the project."
          : error.status === 403
            ? "Only the project owner can remove members."
            : error.message || "Failed to remove member.";
      if (window.CyberNotify) window.CyberNotify.alert(msg, { type: "error" });
    }
  }

  // ─── UI: Invite Modal ──────────────────────────────────────────────────────

  showInviteModal(projectId) {
    const modal = document.getElementById("invite-collaborator-modal");
    if (!modal) return;

    modal.dataset.projectId = projectId;

    // Reset to form state
    document.getElementById("invite-form-section")?.classList.remove("hidden");
    document.getElementById("invite-link-section")?.classList.add("hidden");

    const form = document.getElementById("invite-collaborator-form");
    if (form) form.reset();

    // invite-email-error removed (email field no longer in UI)

    modal.classList.remove("hidden");
  }

  hideInviteModal() {
    document
      .getElementById("invite-collaborator-modal")
      ?.classList.add("hidden");
  }

  async handleInviteSubmit(event) {
    event.preventDefault();

    const modal = document.getElementById("invite-collaborator-modal");
    const projectId = modal?.dataset.projectId;
    if (!projectId) return;

    const role = document.getElementById("invite-role")?.value || "viewer";
    // email removed from UI — API only requires 'role' (email is truly optional and not surfaced)

    const submitBtn = document.getElementById("invite-submit-btn");
    if (submitBtn && typeof showInlineLoading !== "undefined")
      showInlineLoading(submitBtn, "Generating");

    try {
      const result = await this.inviteCollaborator(projectId, role, "");
      const inviteLink = result.invite_link || result.inviteLink || "";
      const expiresAt = result.expires_at || result.expiresAt || "";

      // Switch to link display section
      document.getElementById("invite-form-section")?.classList.add("hidden");
      document
        .getElementById("invite-link-section")
        ?.classList.remove("hidden");

      const linkEl = document.getElementById("invite-link-display");
      const expiryEl = document.getElementById("invite-expiry-display");
      if (linkEl) linkEl.textContent = inviteLink;
      if (expiryEl) {
        const expDate = expiresAt
          ? this.formatDateReadable(expiresAt.split("T")[0])
          : null;
        expiryEl.textContent = expDate ? `Expires: ${expDate}` : "";
      }
    } catch (error) {
      const msg =
        error.status === 403
          ? "Only the project owner can invite collaborators."
          : error.message ||
            "Failed to generate invite link. Please try again.";
      if (window.CyberNotify) window.CyberNotify.alert(msg, { type: "error" });
    } finally {
      if (submitBtn && typeof hideInlineLoading !== "undefined")
        hideInlineLoading(submitBtn);
    }
  }

  copyInviteLink() {
    const linkEl = document.getElementById("invite-link-display");
    if (!linkEl) return;
    const text = linkEl.textContent || "";
    if (!text) return;

    const btn = document.getElementById("copy-invite-link-btn");

    const onSuccess = () => {
      if (window.CyberNotify)
        window.CyberNotify.alert("Invite link copied to clipboard!", {
          type: "success",
        });
      if (btn) {
        const origHTML = btn.innerHTML;
        btn.innerHTML = `
            <svg class="w-3.5 h-3.5 text-emerald-400" fill="none" viewBox="0 0 24 24" stroke-width="2.5" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" d="M4.5 12.75l6 6 9-13.5" />
            </svg>
            <span class="text-emerald-400 font-semibold">Copied!</span>
        `;
        btn.style.borderColor = "rgba(52, 211, 153, 0.4)";
        btn.style.background = "rgba(52, 211, 153, 0.08)";
        setTimeout(() => {
          btn.innerHTML = origHTML;
          btn.style.borderColor = "";
          btn.style.background = "";
        }, 2500);
      }
    };

    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard
        .writeText(text)
        .then(onSuccess)
        .catch(() => this._fallbackCopy(text));
    } else {
      this._fallbackCopy(text);
    }
  }

  _fallbackCopy(text) {
    const ta = document.createElement("textarea");
    ta.value = text;
    ta.style.cssText = "position:fixed;opacity:0;pointer-events:none;";
    document.body.appendChild(ta);
    ta.select();
    try {
      document.execCommand("copy");
      if (window.CyberNotify)
        window.CyberNotify.alert("Invite link copied!", { type: "success" });
      const btn = document.getElementById("copy-invite-link-btn");
      if (btn) {
        const origHTML = btn.innerHTML;
        btn.innerHTML = `
            <svg class="w-3.5 h-3.5 text-emerald-400" fill="none" viewBox="0 0 24 24" stroke-width="2.5" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" d="M4.5 12.75l6 6 9-13.5" />
            </svg>
            <span class="text-emerald-400 font-semibold">Copied!</span>
        `;
        btn.style.borderColor = "rgba(52, 211, 153, 0.4)";
        btn.style.background = "rgba(52, 211, 153, 0.08)";
        setTimeout(() => {
          btn.innerHTML = origHTML;
          btn.style.borderColor = "";
          btn.style.background = "";
        }, 2500);
      }
    } catch (_) {
      if (window.CyberNotify)
        window.CyberNotify.alert(
          "Unable to copy automatically. Please copy the link manually.",
          { type: "warning" },
        );
    }
    document.body.removeChild(ta);
  }

  // ─── Backward-compat stubs for old add-collaborator API ───────────────────
  showAddCollaboratorModal() {
    const projectId = document.getElementById("edit-project-id")?.value;
    if (projectId) this.showInviteModal(projectId);
  }
  hideAddCollaboratorModal() {
    this.hideInviteModal();
  }
  clearAddCollaboratorErrors() {}
  showAddCollaboratorError(msg) {
    if (window.CyberNotify) window.CyberNotify.alert(msg, { type: "error" });
  }
  async handleAddCollaboratorSubmit(event) {
    event.preventDefault();
  }
}

// ---------------------------------------------------------------------------
// CommonJS export (for Jest / Node test environments)
// ---------------------------------------------------------------------------
if (typeof module !== "undefined" && module.exports) {
  module.exports = { ProjectManager };
}

// ---------------------------------------------------------------------------
// Browser bootstrap — event listeners
// ---------------------------------------------------------------------------
if (typeof window !== "undefined") {
  /**
   * Wire up all ProjectManager-related DOM event listeners.
   * Called once apiClient + projectManager are on window.
   */
  function _setupProjectManagerListeners() {
    if (!window.projectManager) return;
    const pm = window.projectManager;

    // ── Create modal ────────────────────────────────────────────────────────
    document
      .getElementById("new-project-btn")
      ?.addEventListener("click", () => pm.showCreateProjectModal());

    document
      .getElementById("create-project-close")
      ?.addEventListener("click", () => pm.hideCreateProjectModal());

    document
      .getElementById("create-project-cancel")
      ?.addEventListener("click", () => pm.hideCreateProjectModal());

    document
      .getElementById("create-project-form")
      ?.addEventListener("submit", (e) => pm.handleProjectFormSubmit(e));

    document
      .getElementById("create-project-modal")
      ?.addEventListener("click", (e) => {
        if (e.target === e.currentTarget) pm.hideCreateProjectModal();
      });

    document
      .getElementById("empty-state-create-btn")
      ?.addEventListener("click", () => pm.showCreateProjectModal());

    // ── Edit modal ──────────────────────────────────────────────────────────
    document
      .getElementById("edit-project-close")
      ?.addEventListener("click", () => pm.hideEditProjectModal());

    document
      .getElementById("edit-project-cancel")
      ?.addEventListener("click", () => pm.hideEditProjectModal());

    document
      .getElementById("edit-project-form")
      ?.addEventListener("submit", (e) => pm.handleEditProjectFormSubmit(e));

    document
      .getElementById("edit-project-modal")
      ?.addEventListener("click", (e) => {
        if (e.target === e.currentTarget) pm.hideEditProjectModal();
      });

    // ── Invite modal ────────────────────────────────────────────────────────
    document
      .getElementById("invite-collab-btn")
      ?.addEventListener("click", () => {
        const projectId = document.getElementById("edit-project-id")?.value;
        if (projectId) pm.showInviteModal(projectId);
      });

    document
      .getElementById("invite-collaborator-close")
      ?.addEventListener("click", () => pm.hideInviteModal());

    document
      .getElementById("invite-collaborator-cancel")
      ?.addEventListener("click", () => pm.hideInviteModal());

    document
      .getElementById("invite-collaborator-form")
      ?.addEventListener("submit", (e) => pm.handleInviteSubmit(e));

    document
      .getElementById("invite-collaborator-modal")
      ?.addEventListener("click", (e) => {
        if (e.target === e.currentTarget) pm.hideInviteModal();
      });

    document
      .getElementById("copy-invite-link-btn")
      ?.addEventListener("click", () => pm.copyInviteLink());

    document
      .getElementById("invite-done-btn")
      ?.addEventListener("click", () => pm.hideInviteModal());

    // ── Delete confirm modal ────────────────────────────────────────────────
    document
      .getElementById("delete-project-cancel-btn")
      ?.addEventListener("click", () => pm.hideDeleteConfirmModal());

    document
      .getElementById("delete-project-modal")
      ?.addEventListener("click", (e) => {
        if (e.target === e.currentTarget) pm.hideDeleteConfirmModal();
      });

    document
      .getElementById("delete-project-confirm-btn")
      ?.addEventListener("click", () => pm.handleDeleteConfirm());

    // Enable/disable confirm button as user types
    document
      .getElementById("delete-project-name-input")
      ?.addEventListener("input", function () {
        const hint =
          document.getElementById("delete-project-name-hint")?.textContent ||
          "";
        const confirmBtn = document.getElementById(
          "delete-project-confirm-btn",
        );
        if (confirmBtn) confirmBtn.disabled = this.value !== hint;
      });

    // ── Tab switching events ────────────────────────────────────────────────
    // Load projects when the Projects tab becomes active
    document.addEventListener("tabSwitched", (e) => {
      if (e.detail?.tabId === "projects") {
        setTimeout(() => pm.renderProjectsList(), 100);
      }
    });

    // Also respond to sidebar link click
    const projectsLink = document.querySelector(
      "a[onclick*=\"switchToTab('projects')\"]",
    );
    if (projectsLink) {
      projectsLink.addEventListener("click", () => {
        setTimeout(() => pm.renderProjectsList(), 150);
      });
    }

    console.log("[ProjectManager] v2.0.0 — listeners registered");
  }

  // Expose helper globally so main.js / DOMContentLoaded can call it
  window._setupProjectManagerListeners = _setupProjectManagerListeners;

  // Auto-bootstrap on DOM ready
  function _bootstrap() {
    // === AUTHENTICATION CHECK ===
    if (typeof window.runAuthGuard === 'function' && !window.runAuthGuard()) {
      return; // Stop initialization if not authenticated
    }

    // Ensure APIClient + ProjectManager are initialised
    if (!window.apiClient && typeof APIClient !== "undefined") {
      window.apiClient = new APIClient();
      console.log("[ProjectManager] Created APIClient (early bootstrap)");
    }
    if (!window.projectManager && window.apiClient) {
      window.projectManager = new ProjectManager(window.apiClient);
      console.log("[ProjectManager] Created ProjectManager (bootstrap)");
    }
    // Wire listeners (idempotent check inside if needed)
    if (window.projectManager) {
      _setupProjectManagerListeners();
    }
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", _bootstrap);
  } else {
    // DOM already parsed — defer to next tick so main.js can run first
    setTimeout(_bootstrap, 0);
  }
}
