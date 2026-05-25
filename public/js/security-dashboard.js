/**
 * Security Dashboard Controller — CyberGuard Pro
 * 
 * Manages parallel API fetches across all projects, aggregates targets and scans,
 * processes finding severities, renders high-fidelity custom circular gauges and conic-gradient doughnut charts,
 * lists running processes with 30s auto-refresh, and implements robust skeleton states.
 * 
 * Strict compliance: NO emojis used in HTML templates or logic. Fully integrated with theme variables.
 */

(function () {
  "use strict";

  // Dashboard in-memory cache/state
  let dashboardState = {
    projects: [],
    targets: [],
    scans: [],
    findings: [],
    isLoading: false,
    refreshInterval: null
  };

  // Theme-compliant colors matching HSL vars
  const SEVERITY_CONFIG = {
    critical: { color: "#ef4444", label: "Critical" },
    high:     { color: "#f97316", label: "High" },
    medium:   { color: "#eab308", label: "Medium" },
    low:      { color: "#22c55e", label: "Low" },
    info:     { color: "#38bdf8", label: "Info" }
  };

  /**
   * Main loader: Called when tab is activated or refreshed
   */
  async function loadSecurityDashboard() {
    if (dashboardState.isLoading) return;
    dashboardState.isLoading = true;

    showDashboardSkeleton();

    try {
      // 1. Fetch all projects first
      if (!window.projectManager) {
        throw new Error("ProjectManager module not available");
      }

      const projectsRes = await window.projectManager.fetchProjects();
      const projects = projectsRes?.projects || window.projectManager.projects || [];
      dashboardState.projects = projects;

      if (projects.length === 0) {
        renderEmptyState();
        dashboardState.isLoading = false;
        return;
      }

      // 2. Fetch targets & scans for all projects in parallel
      const targetsPromises = projects.map(p => 
        window.projectManager.fetchTargets(p.id).catch(() => [])
      );

      const scansPromises = projects.map(p => 
        window.scannerAPI ? window.scannerAPI.getProjectScans(p.id).catch(() => []) : []
      );

      const [targetsResults, scansResults] = await Promise.all([
        Promise.all(targetsPromises),
        Promise.all(scansPromises)
      ]);

      // Flatten and annotate targets
      const allTargets = [];
      projects.forEach((proj, idx) => {
        const tList = targetsResults[idx] || [];
        tList.forEach(t => {
          allTargets.push({
            ...t,
            project_id: proj.id,
            project_name: proj.name
          });
        });
      });
      dashboardState.targets = allTargets;

      // Flatten scans
      const allScans = [];
      projects.forEach((proj, idx) => {
        const sList = scansResults[idx] || [];
        sList.forEach(s => {
          allScans.push({
            ...s,
            project_id: proj.id,
            project_name: proj.name
          });
        });
      });
      dashboardState.scans = allScans;

      // 3. Fetch findings for all targets in parallel
      if (allTargets.length === 0) {
        dashboardState.findings = [];
      } else {
        const findingsPromises = allTargets.map(t =>
          window.apiClient.get(`/targets/${t.id}/findings`)
            .then(res => Array.isArray(res.findings) ? res.findings : (Array.isArray(res) ? res : []))
            .catch(() => [])
        );

        const findingsResults = await Promise.all(findingsPromises);

        const allFindings = [];
        allTargets.forEach((target, idx) => {
          const fList = findingsResults[idx] || [];
          fList.forEach(f => {
            allFindings.push({
              ...f,
              target_id: target.id,
              target_name: target.name || target.url || "Unknown Target",
              project_id: target.project_id,
              project_name: target.project_name
            });
          });
        });
        dashboardState.findings = allFindings;
      }

      // 4. Render all dashboard views
      renderDashboardViews();

      // 5. Start active scans auto-refresh
      startActiveScansPolling();

    } catch (error) {
      console.error("[SecurityDashboard] Loader failed:", error);
      showDashboardError(error.message);
    } finally {
      dashboardState.isLoading = false;
      hideDashboardSkeleton();
    }
  }

  /**
   * Render all dashboard sections using the loaded state
   */
  function renderDashboardViews() {
    const { projects, targets, scans, findings } = dashboardState;

    // Subtitle & Header metadata
    const subtitleText = document.getElementById("dashboard-subtitle-text");
    if (subtitleText) {
      subtitleText.textContent = `Overview of ${projects.length} active security project assessments`;
    }

    const dateRangeEl = document.getElementById("dashboard-date-range-display");
    if (dateRangeEl) {
      dateRangeEl.textContent = formatDashboardDateRange(projects);
    }

    // Process scans running count
    const activeScans = scans.filter(s => 
      ["running", "active", "in_progress"].includes((s.status || "").toLowerCase())
    );

    // 1. Render Stat Cards
    renderStatCards(findings, targets, scans, activeScans);

    // 2. Render Findings by Severity Donut Chart & List
    renderFindingsBySeverityChart(findings);

    // 3. Render Risk Score Circle & Target List
    renderRiskScoreSection(findings, targets);

    // 4. Render Active Scans List
    renderActiveScans(activeScans);

    // 5. Render Recent Findings Table
    renderRecentFindings(findings);
  }

  /**
   * Render Stat Counter Cards
   */
  function renderStatCards(findings, targets, scans, activeScans) {
    const oneWeekAgo = new Date();
    oneWeekAgo.setDate(oneWeekAgo.getDate() - 7);

    // Card 1: Critical Findings
    const criticalFindings = findings.filter(f => 
      (f.severity || "").toLowerCase() === "critical"
    );
    const criticalThisWeek = criticalFindings.filter(f => 
      new Date(f.created_at || f.timestamp) >= oneWeekAgo
    ).length;

    updateCounter("critical-findings-value", criticalFindings.length);
    const critSubtext = document.getElementById("critical-findings-subtext");
    if (critSubtext) {
      critSubtext.textContent = `+${criticalThisWeek} this week`;
      critSubtext.className = `stat-card-subtext ${criticalThisWeek > 0 ? "text-rose-400" : "text-slate-400"}`;
    }

    // Card 2: Total Findings
    const newThisWeek = findings.filter(f => 
      new Date(f.created_at || f.timestamp) >= oneWeekAgo
    ).length;

    updateCounter("total-findings-value", findings.length);
    const totalSubtext = document.getElementById("total-findings-subtext");
    if (totalSubtext) {
      totalSubtext.textContent = `+${newThisWeek} new`;
      totalSubtext.className = `stat-card-subtext ${newThisWeek > 0 ? "text-blue-400" : "text-slate-400"}`;
    }

    // Card 3: Resolved
    const resolved = findings.filter(f => 
      ["resolved", "fixed"].includes((f.status || "").toLowerCase())
    );
    const resolvedPercent = findings.length > 0
      ? Math.round((resolved.length / findings.length) * 100)
      : 0;

    updateCounter("resolved-value", resolved.length);
    const resolvedSubtext = document.getElementById("resolved-subtext");
    if (resolvedSubtext) {
      resolvedSubtext.textContent = `${resolvedPercent}% resolved`;
      resolvedSubtext.className = `stat-card-subtext ${resolvedPercent >= 75 ? "text-emerald-400" : resolvedPercent >= 40 ? "text-amber-400" : "text-rose-400"}`;
    }

    // Card 4: Targets / Scans
    const targetValueEl = document.getElementById("targets-scans-value");
    if (targetValueEl) {
      targetValueEl.textContent = `${targets.length} / ${scans.length}`;
    }
    const scansSubtext = document.getElementById("targets-scans-subtext");
    if (scansSubtext) {
      scansSubtext.textContent = `${activeScans.length} active process`;
      scansSubtext.className = `stat-card-subtext ${activeScans.length > 0 ? "text-purple-400" : "text-slate-400"}`;
    }
  }

  /**
   * Render Findings by Severity conic-gradient donut chart and bar rows
   */
  function renderFindingsBySeverityChart(findings) {
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    findings.forEach(f => {
      const sev = (f.severity || "").toLowerCase();
      if (sev === "critical") counts.critical++;
      else if (sev === "high") counts.high++;
      else if (sev === "medium" || sev === "moderate") counts.medium++;
      else if (sev === "low") counts.low++;
      else if (sev === "info" || sev === "informational") counts.info++;
    });

    const total = Object.values(counts).reduce((a, b) => a + b, 0);

    // Update donut count
    const totalCountEl = document.getElementById("donut-total-findings-count");
    if (totalCountEl) totalCountEl.textContent = total;

    // Render dynamic conic-gradient donut chart
    const donutEl = document.getElementById("severity-donut-chart");
    if (donutEl) {
      if (total === 0) {
        donutEl.style.background = "rgba(255, 255, 255, 0.05)";
      } else {
        const critPct = (counts.critical / total) * 100;
        const highPct = (counts.high / total) * 100;
        const medPct = (counts.medium / total) * 100;
        const lowPct = (counts.low / total) * 100;
        const infoPct = (counts.info / total) * 100;

        let cur = 0;
        const cS = cur; const cE = cur + critPct; cur = cE;
        const hS = cur; const hE = cur + highPct; cur = hE;
        const mS = cur; const mE = cur + medPct; cur = mE;
        const lS = cur; const lE = cur + lowPct; cur = lE;
        const iS = cur; const iE = 100;

        donutEl.style.background = `conic-gradient(
          #ef4444 ${cS}% ${cE}%,
          #f97316 ${hS}% ${hE}%,
          #eab308 ${mS}% ${mE}%,
          #22c55e ${lS}% ${lE}%,
          #38bdf8 ${iS}% ${iE}%
        )`;
      }
    }

    // Render severity bars
    const barList = document.getElementById("severity-bar-list");
    if (barList) {
      barList.innerHTML = Object.keys(counts).map(sev => {
        const count = counts[sev];
        const pct = total > 0 ? Math.round((count / total) * 100) : 0;
        const cfg = SEVERITY_CONFIG[sev];

        return `
          <div class="severity-bar-row">
            <span class="severity-label" style="color: ${cfg.color}">${cfg.label}</span>
            <div class="severity-bar-track">
              <div class="severity-bar-fill" style="width: ${pct}%; background-color: ${cfg.color}"></div>
            </div>
            <span class="severity-count">${count}</span>
          </div>
        `;
      }).join("");
    }
  }

  /**
   * Render circular SVG Risk Score and target score list
   */
  function renderRiskScoreSection(findings, targets) {
    const displayContainer = document.getElementById("risk-score-display-container");
    const targetsContainer = document.getElementById("risk-targets-list-container");
    if (!displayContainer || !targetsContainer) return;

    // Calculate synthetic target risk scores
    // Start at a perfect score of 10.0 and reduce based on open findings severity
    const targetsWithScores = targets.map(t => {
      const targetFindings = findings.filter(f => 
        String(f.target_id) === String(t.id) && (f.status || "").toLowerCase() === "open"
      );

      let criticalCount = 0;
      let highCount = 0;
      let mediumCount = 0;
      let lowCount = 0;

      targetFindings.forEach(f => {
        const sev = (f.severity || "").toLowerCase();
        if (sev === "critical") criticalCount++;
        else if (sev === "high") highCount++;
        else if (sev === "medium" || sev === "moderate") mediumCount++;
        else if (sev === "low") lowCount++;
      });

      // Standard weights to calculate penalty
      const penalty = (criticalCount * 2.5) + (highCount * 1.5) + (mediumCount * 0.6) + (lowCount * 0.1);
      const score = Math.max(0.0, Math.min(10.0, Math.round((10.0 - penalty) * 10) / 10));

      // Map score to color
      let color = "#22c55e"; // low risk green
      if (score < 4.0) color = "#ef4444"; // critical risk red
      else if (score < 6.0) color = "#f97316"; // high risk orange
      else if (score < 8.0) color = "#eab308"; // moderate risk yellow

      return {
        ...t,
        risk_score: score.toFixed(1),
        risk_color: color
      };
    });

    // Determine overall/average risk score
    let overallScore = 10.0;
    if (targetsWithScores.length > 0) {
      const totalScore = targetsWithScores.reduce((sum, t) => sum + parseFloat(t.risk_score), 0);
      overallScore = Math.round((totalScore / targetsWithScores.length) * 10) / 10;
    }

    // Overall color
    let overallColor = "#22c55e";
    if (overallScore < 4.0) overallColor = "#ef4444";
    else if (overallScore < 6.0) overallColor = "#f97316";
    else if (overallScore < 8.0) overallColor = "#eab308";

    // Circular gauge geometry
    const RADIUS = 50;
    const CIRCUMFERENCE = 2 * Math.PI * RADIUS; // ≈ 314.16
    const offset = CIRCUMFERENCE - (overallScore / 10) * CIRCUMFERENCE;

    // Render circular gauge SVG
    displayContainer.innerHTML = `
      <div class="relative flex items-center justify-center w-[130px] height-[130px]">
        <svg class="risk-circle-svg-container" width="120" height="120" viewBox="0 0 120 120">
          <circle class="risk-circle-bg" cx="60" cy="60" r="50"></circle>
          <circle class="risk-circle-value" cx="60" cy="60" r="50" 
            stroke="${overallColor}" 
            stroke-dasharray="${CIRCUMFERENCE.toFixed(2)}" 
            stroke-dashoffset="${offset.toFixed(2)}">
          </circle>
        </svg>
        <div class="risk-score-inner-text-container absolute">
          <span class="text-3xl font-extrabold text-white font-mono" id="overall-risk-score">${overallScore}</span>
          <span class="text-[9px] text-slate-400 font-bold uppercase tracking-wider mt-0.5">/ 10</span>
        </div>
      </div>
    `;

    // Render per-target list (top 4 for aesthetic elegance)
    const displayList = targetsWithScores.slice(0, 4);
    if (displayList.length === 0) {
      targetsContainer.innerHTML = `
        <div class="text-center py-4 text-xs text-slate-500">
          No targets registered
        </div>
      `;
    } else {
      targetsContainer.innerHTML = displayList.map(t => `
        <div class="risk-target-row">
          <span class="risk-target-name" title="${t.name || t.url}">${t.name || t.url}</span>
          <div class="risk-mini-bar bg-white/5">
            <div class="risk-mini-fill" style="width: ${parseFloat(t.risk_score) * 10}%; background-color: ${t.risk_color}"></div>
          </div>
          <span class="risk-score-value font-mono" style="color: ${t.risk_color}">${t.risk_score}</span>
        </div>
      `).join("");
    }
  }

  /**
   * Render Active/Running Scans List
   */
  function renderActiveScans(activeScans) {
    const container = document.getElementById("active-scans-container");
    if (!container) return;

    if (activeScans.length === 0) {
      container.innerHTML = `
        <div class="empty-state">
          <span class="material-symbols-outlined empty-icon-text">visibility</span>
          <div class="empty-title">All clear</div>
          <div class="empty-sub">No scans are currently running</div>
        </div>
      `;
      return;
    }

    container.innerHTML = activeScans.map(scan => {
      const progress = scan.progress ?? 35;
      const scanType = scan.driver_id || scan.type || "Analysis";
      const startText = scan.created_at || scan.timestamp || new Date().toISOString();

      return `
        <div class="active-scan-row bg-white/[0.01]">
          <div class="scan-info">
            <div class="scan-target-name">${scan.target_name || scan.target?.name || "Local Scan"}</div>
            <div class="scan-meta">
              <span class="scan-type font-mono text-[10px]">${scanType}</span>
              <span class="scan-started font-mono">Started ${formatRelativeTime(startText)}</span>
            </div>
          </div>
          <div class="scan-progress">
            <div class="scan-progress-bar bg-white/5">
              <div class="scan-progress-fill" style="width: ${progress}%"></div>
            </div>
            <span class="scan-progress-text font-mono">${progress}%</span>
          </div>
          <div class="scan-status-badge">
            <span class="scan-pulse-dot"></span>
            Running
          </div>
        </div>
      `;
    }).join("");
  }

  /**
   * Render Recent Findings List
   */
  function renderRecentFindings(findings) {
    const container = document.getElementById("recent-findings-container");
    if (!container) return;

    // Filter open/active findings, sort newest first, limit to 5 rows
    const openFindings = findings
      .filter(f => (f.status || "").toLowerCase() !== "resolved" && (f.status || "").toLowerCase() !== "fixed")
      .sort((a, b) => new Date(b.created_at || b.timestamp) - new Date(a.created_at || a.timestamp))
      .slice(0, 5);

    if (openFindings.length === 0) {
      container.innerHTML = `
        <div class="empty-state">
          <span class="material-symbols-outlined empty-icon-text">gpp_good</span>
          <div class="empty-title">Secured</div>
          <div class="empty-sub">No active vulnerabilities identified</div>
        </div>
      `;
      return;
    }

    container.innerHTML = openFindings.map(f => {
      const sev = (f.severity || "info").toLowerCase();
      const cfg = SEVERITY_CONFIG[sev] || SEVERITY_CONFIG.info;
      const timeStr = f.created_at || f.timestamp || new Date().toISOString();
      const status = (f.status || "open").toLowerCase();

      return `
        <div class="recent-finding-row flex justify-between items-center py-2.5">
          <span class="finding-severity-badge text-[10px] py-0.5" 
                style="background: ${cfg.color}15; color: ${cfg.color}; border: 1px solid ${cfg.color}30;">
            ${cfg.label}
          </span>
          <div class="finding-info">
            <div class="finding-title" title="${f.title || f.name || "Vulnerability Alert"}">
              ${f.title || f.name || "Vulnerability Alert"}
            </div>
            <div class="finding-meta font-mono text-[10px]">
              <span>${f.target_name}</span>
              <span class="text-slate-600">•</span>
              <span>${formatRelativeTime(timeStr)}</span>
            </div>
          </div>
          <span class="finding-status-badge ${status}">${status}</span>
        </div>
      `;
    }).join("");
  }

  /* ── Auto-refresh / polling logic ────────────────────────────────────── */

  function startActiveScansPolling() {
    stopActiveScansPolling();

    // Poll every 30 seconds
    dashboardState.refreshInterval = setInterval(async () => {
      // Check if current tab is still Security Dashboard
      if (typeof switchToTab === "function" && document.querySelector(".cyber-nav-item.cyber-nav-active")?.textContent.includes("Security Dashboard")) {
        try {
          const projects = dashboardState.projects;
          const scansPromises = projects.map(p => 
            window.scannerAPI ? window.scannerAPI.getProjectScans(p.id).catch(() => []) : []
          );
          const scansResults = await Promise.all(scansPromises);

          const allScans = [];
          projects.forEach((proj, idx) => {
            const sList = scansResults[idx] || [];
            sList.forEach(s => {
              allScans.push({
                ...s,
                project_id: proj.id,
                project_name: proj.name
              });
            });
          });
          dashboardState.scans = allScans;

          const activeScans = allScans.filter(s => 
            ["running", "active", "in_progress"].includes((s.status || "").toLowerCase())
          );

          renderActiveScans(activeScans);
        } catch (e) {
          console.warn("[SecurityDashboard] Auto-refresh scans query failed:", e);
        }
      } else {
        stopActiveScansPolling();
      }
    }, 30000);
  }

  function stopActiveScansPolling() {
    if (dashboardState.refreshInterval) {
      clearInterval(dashboardState.refreshInterval);
      dashboardState.refreshInterval = null;
    }
  }

  /* ── Skeleton Loading States ─────────────────────────────────────────── */

  function showDashboardSkeleton() {
    const el = document.getElementById("security-dashboard");
    if (!el) return;

    // Apply pulsing placeholders inside value text fields
    const valuePlaceholders = ["critical-findings-value", "total-findings-value", "resolved-value", "targets-scans-value"];
    valuePlaceholders.forEach(id => {
      const node = document.getElementById(id);
      if (node) {
        node.classList.add("dashboard-skeleton", "w-16", "h-8");
        node.textContent = "";
      }
    });

    const displayContainer = document.getElementById("risk-score-display-container");
    if (displayContainer) {
      displayContainer.innerHTML = `<div class="dashboard-skeleton w-24 h-24 rounded-full"></div>`;
    }

    const targetsContainer = document.getElementById("risk-targets-list-container");
    if (targetsContainer) {
      targetsContainer.innerHTML = Array(3).fill(0).map(() => `
        <div class="flex items-center gap-3">
          <div class="dashboard-skeleton w-24 h-4"></div>
          <div class="dashboard-skeleton flex-1 h-2 rounded-full"></div>
          <div class="dashboard-skeleton w-8 h-4"></div>
        </div>
      `).join("");
    }

    const barList = document.getElementById("severity-bar-list");
    if (barList) {
      barList.innerHTML = Array(5).fill(0).map(() => `
        <div class="flex items-center gap-3">
          <div class="dashboard-skeleton w-16 h-4"></div>
          <div class="dashboard-skeleton flex-1 h-2 rounded-full"></div>
          <div class="dashboard-skeleton w-8 h-4"></div>
        </div>
      `).join("");
    }

    const activeScansEl = document.getElementById("active-scans-container");
    if (activeScansEl) {
      activeScansEl.innerHTML = Array(2).fill(0).map(() => `
        <div class="flex justify-between items-center p-3 border border-white/5 rounded-lg mb-2">
          <div class="space-y-2 flex-1">
            <div class="dashboard-skeleton w-36 h-4"></div>
            <div class="dashboard-skeleton w-24 h-3"></div>
          </div>
          <div class="dashboard-skeleton w-28 h-2 rounded-full mx-4"></div>
          <div class="dashboard-skeleton w-16 h-6 rounded-full"></div>
        </div>
      `).join("");
    }

    const recentFindingsEl = document.getElementById("recent-findings-container");
    if (recentFindingsEl) {
      recentFindingsEl.innerHTML = Array(3).fill(0).map(() => `
        <div class="flex justify-between items-center py-2 border-b border-white/5">
          <div class="dashboard-skeleton w-16 h-5 rounded"></div>
          <div class="space-y-1.5 flex-1 mx-4">
            <div class="dashboard-skeleton w-48 h-4"></div>
            <div class="dashboard-skeleton w-32 h-3"></div>
          </div>
          <div class="dashboard-skeleton w-12 h-5 rounded"></div>
        </div>
      `).join("");
    }
  }

  function hideDashboardSkeleton() {
    const valuePlaceholders = ["critical-findings-value", "total-findings-value", "resolved-value", "targets-scans-value"];
    valuePlaceholders.forEach(id => {
      const node = document.getElementById(id);
      if (node) node.classList.remove("dashboard-skeleton", "w-16", "h-8");
    });
  }

  function renderEmptyState() {
    renderStatCards([], [], [], []);
    renderFindingsBySeverityChart([]);
    renderRiskScoreSection([], []);
    renderActiveScans([]);
    renderRecentFindings([]);
  }

  function showDashboardError(message) {
    const container = document.getElementById("security-dashboard");
    if (container) {
      container.innerHTML = `
        <div class="flex flex-col items-center justify-center text-center p-12 border border-rose-500/20 bg-rose-500/5 rounded-xl">
          <span class="material-symbols-outlined text-rose-500 text-4xl mb-4">error</span>
          <h3 class="text-lg font-bold text-white mb-2">Dashboard Assessment Offline</h3>
          <p class="text-sm text-slate-400 max-w-md">${message || "An unexpected error occurred while loading assessment telemetry. Please try reloading."}</p>
          <button class="cyber-btn-primary text-xs px-4 py-2 mt-6 rounded-lg" onclick="loadSecurityDashboard(); return false;">
            Retry Telemetry
          </button>
        </div>
      `;
    }
  }

  /* ── Utility Helpers ─────────────────────────────────────────────────── */

  function updateCounter(id, targetVal) {
    const el = document.getElementById(id);
    if (!el) return;
    el.textContent = targetVal;
  }

  function formatDashboardDateRange(projects) {
    if (!projects || projects.length === 0) return "No active assessment";
    
    let earliest = null;
    let latest = null;
    
    projects.forEach(p => {
      const start = p.start_date ? new Date(p.start_date) : null;
      const end = p.end_date ? new Date(p.end_date) : null;
      
      if (start && (!earliest || start < earliest)) earliest = start;
      if (end && (!latest || end > latest)) latest = end;
    });
    
    if (!earliest) earliest = new Date();
    if (!latest) {
      latest = new Date();
      latest.setDate(latest.getDate() + 30);
    }
    
    const options = { month: "short", day: "numeric" };
    return `${earliest.toLocaleDateString("en-US", options)} - ${latest.toLocaleDateString("en-US", options)}, ${latest.getFullYear()}`;
  }

  function formatRelativeTime(dateString) {
    if (!dateString) return "";
    
    const date = new Date(dateString);
    const now = new Date();
    const diffMs = now - date;
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMs / 3600000);
    const diffDays = Math.floor(diffMs / 86400000);
    
    if (diffMins < 1) return "just now";
    if (diffMins < 60) return `${diffMins}m ago`;
    if (diffHours < 24) return `${diffHours}h ago`;
    if (diffDays < 7) return `${diffDays}d ago`;
    
    return date.toLocaleDateString("en-US", { 
      month: "short", day: "numeric" 
    });
  }

  // Expose loadSecurityDashboard to window globally
  window.loadSecurityDashboard = loadSecurityDashboard;
  window.stopActiveScansPolling = stopActiveScansPolling;

})();
