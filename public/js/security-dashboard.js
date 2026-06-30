/**
 * Security Dashboard Controller — CyberGuard
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
    refreshInterval: null,
    activeChannels: {}
  };

  // Third-party chart and animation states
  let severityDonutChart = null;
  let lastOverallScore = null;

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
      // 1. Fetch all projects first to populate projects state & header metadata
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

      // 2. Fetch single metrics endpoint and all targets in parallel
      const [metricsRes, targetsRes] = await Promise.all([
        window.apiClient.get("/dashboard/metrics"),
        window.apiClient.get("/targets").catch(() => ({ targets: [] }))
      ]);

      if (metricsRes.status !== "success" || !metricsRes.data) {
        throw new Error(metricsRes.message || "Failed to retrieve dashboard metrics");
      }

      dashboardState.metrics = metricsRes.data;
      dashboardState.targets = targetsRes?.targets || [];

      // 3. Render all dashboard views
      renderDashboardViews();

      // 4. Start active scans auto-refresh
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
    const { projects, metrics, targets } = dashboardState;
    if (!metrics) return;

    // Subtitle & Header metadata
    const subtitleText = document.getElementById("dashboard-subtitle-text");
    if (subtitleText) {
      subtitleText.textContent = `Overview of ${projects.length} active security project assessments`;
    }

    const dateRangeEl = document.getElementById("dashboard-date-range-display");
    if (dateRangeEl) {
      dateRangeEl.textContent = formatDashboardDateRange(projects);
    }

    // 1. Render Stat Cards
    renderStatCards(metrics.findings_summary, metrics.infrastructure, metrics.active_scans, metrics.recent_findings);

    // 2. Render Findings by Severity Donut Chart & List
    renderFindingsBySeverityChart(metrics.findings_by_severity, metrics.findings_summary.total);

    // 3. Render Risk Score Circle & Target List
    renderRiskScoreSection(metrics.risk_score, targets);

    // 4. Render Active Scans List
    renderActiveScans(metrics.active_scans);

    // 5. Render Recent Findings Table
    renderRecentFindings(metrics.recent_findings);
  }

  /**
   * Render Stat Counter Cards
   */
  function renderStatCards(findings_summary, infrastructure, active_scans, recent_findings) {
    const oneWeekAgo = new Date();
    oneWeekAgo.setDate(oneWeekAgo.getDate() - 7);

    const recentList = recent_findings?.findings || [];
    const criticalThisWeek = recentList.filter(f => 
      (f.severity || "").toLowerCase() === "critical" && new Date(f.created_at || f.timestamp) >= oneWeekAgo
    ).length;

    updateCounter("critical-findings-value", findings_summary.critical || 0);
    const critSubtext = document.getElementById("critical-findings-subtext");
    if (critSubtext) {
      critSubtext.textContent = `+${criticalThisWeek} this week`;
      critSubtext.className = `stat-card-subtext ${criticalThisWeek > 0 ? "text-red-400" : "text-slate-400"}`;
    }

    const newThisWeek = recentList.filter(f => 
      new Date(f.created_at || f.timestamp) >= oneWeekAgo
    ).length;

    updateCounter("total-findings-value", findings_summary.total || 0);
    const totalSubtext = document.getElementById("total-findings-subtext");
    if (totalSubtext) {
      totalSubtext.textContent = `+${newThisWeek} new`;
      totalSubtext.className = `stat-card-subtext text-slate-400`;
    }

    const resolvedCount = findings_summary.resolved || 0;
    const totalCount = findings_summary.total || 0;
    const resolvedPercent = totalCount > 0
      ? Math.round((resolvedCount / totalCount) * 100)
      : 0;

    updateCounter("resolved-value", resolvedCount);
    const resolvedSubtext = document.getElementById("resolved-subtext");
    if (resolvedSubtext) {
      resolvedSubtext.textContent = `${resolvedPercent}% resolved`;
      resolvedSubtext.className = `stat-card-subtext text-slate-400`;
    }

    const targetValueEl = document.getElementById("targets-scans-value");
    if (targetValueEl) {
      targetValueEl.textContent = `${infrastructure.total_targets || 0} / ${infrastructure.total_scans || 0}`;
    }
    const scansSubtext = document.getElementById("targets-scans-subtext");
    if (scansSubtext) {
      const activeCount = active_scans.count ?? (active_scans.scans?.length || 0);
      scansSubtext.textContent = `${activeCount} active process`;
      scansSubtext.className = `stat-card-subtext ${activeCount > 0 ? "text-blue-400" : "text-slate-400"}`;
    }
  }

  /**
   * Render Findings by Severity conic-gradient donut chart and bar rows
   */
  function renderFindingsBySeverityChart(findings_by_severity, total) {
    const counts = {
      critical: findings_by_severity.critical?.count || 0,
      high: findings_by_severity.high?.count || 0,
      medium: findings_by_severity.medium?.count || 0,
      low: findings_by_severity.low?.count || 0,
      info: findings_by_severity.info?.count || 0
    };

    // Update donut count
    const totalCountEl = document.getElementById("donut-total-findings-count");
    if (totalCountEl) totalCountEl.textContent = total;

    // Render dynamic ApexCharts donut chart
    const donutEl = document.getElementById("severity-donut-chart");
    if (donutEl) {
      donutEl.style.background = "none";
      donutEl.style.boxShadow = "none";
      
      const series = total === 0 
        ? [1] 
        : [counts.critical, counts.high, counts.medium, counts.low, counts.info];
      const colors = total === 0 
        ? ["rgba(255, 255, 255, 0.05)"] 
        : ["#ef4444", "#f97316", "#eab308", "#22c55e", "#38bdf8"];
      const labels = total === 0 
        ? ["No findings"] 
        : ["Critical", "High", "Medium", "Low", "Info"];

      if (typeof ApexCharts !== "undefined") {
        if (!severityDonutChart) {
          // Initialize ApexCharts
          const options = {
            chart: {
              type: "donut",
              width: 140,
              height: 140,
              sparkline: { enabled: true },
              animations: {
                enabled: true,
                easing: "easeinout",
                speed: 800
              }
            },
            series: series,
            labels: labels,
            colors: colors,
            stroke: {
              show: true,
              width: 2,
              colors: ["#111827"] // Match --cg-bg-surface
            },
            plotOptions: {
              pie: {
                donut: {
                  size: "72%"
                }
              }
            },
            tooltip: {
              enabled: true,
              theme: "dark",
              y: {
                formatter: function (val) {
                  return total === 0 ? "0 findings" : val + " findings";
                }
              }
            },
            legend: { show: false },
            dataLabels: { enabled: false }
          };
          severityDonutChart = new ApexCharts(donutEl, options);
          severityDonutChart.render();
        } else {
          // Update existing chart
          severityDonutChart.updateOptions({
            series: series,
            labels: labels,
            colors: colors,
            tooltip: {
              y: {
                formatter: function (val) {
                  return total === 0 ? "0 findings" : val + " findings";
                }
              }
            }
          });
        }
      } else {
        // Fallback to static gradient if ApexCharts not loaded
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
          const iS = 100;

          donutEl.style.background = `conic-gradient(
            #ef4444 ${cS}% ${cE}%,
            #f97316 ${hS}% ${hE}%,
            #eab308 ${mS}% ${mE}%,
            #22c55e ${lS}% ${lE}%,
            #38bdf8 ${iS}% ${iE}%
          )`;
        }
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
  function renderRiskScoreSection(risk_score, targets) {
    const displayContainer = document.getElementById("risk-score-display-container");
    const targetsContainer = document.getElementById("risk-targets-list-container");
    if (!displayContainer || !targetsContainer) return;

    let overallScore = parseFloat(risk_score.global_score || 0.0);
    let riskLevel = (risk_score.risk_level || "Low").toLowerCase();

    // Map overall risk level to color
    let overallColor = "#22c55e"; // Green
    if (riskLevel === "critical") overallColor = "#ef4444";
    else if (riskLevel === "high") overallColor = "#f97316";
    else if (riskLevel === "medium" || riskLevel === "moderate") overallColor = "#eab308";

    // Circular gauge geometry
    const RADIUS = 50;
    const CIRCUMFERENCE = 2 * Math.PI * RADIUS; // ≈ 314.16
    const offset = CIRCUMFERENCE - (overallScore / 100) * CIRCUMFERENCE;

    // Check if the SVG gauge structure is already in place
    const existingCircleValue = document.querySelector("#risk-score-display-container .risk-circle-value");
    const existingScoreText = document.getElementById("overall-risk-score");

    if (existingCircleValue && existingScoreText) {
      // SVG is already built, run smooth GSAP transitions on the existing elements
      if (typeof gsap !== "undefined") {
        // Animate the circle properties
        gsap.to(existingCircleValue, {
          attr: { "stroke-dashoffset": offset.toFixed(2) },
          stroke: overallColor,
          duration: 1.2,
          ease: "power2.out"
        });

        // Animate the text score count-up
        const startVal = parseFloat(existingScoreText.textContent) || 0.0;
        const scoreObj = { val: startVal };
        gsap.to(scoreObj, {
          val: overallScore,
          duration: 1.2,
          ease: "power2.out",
          onUpdate: function () {
            existingScoreText.textContent = scoreObj.val.toFixed(1);
          }
        });
      } else {
        // Fallback if GSAP is not present
        existingCircleValue.setAttribute("stroke-dashoffset", offset.toFixed(2));
        existingCircleValue.setAttribute("stroke", overallColor);
        existingScoreText.textContent = overallScore.toFixed(1);
      }
    } else {
      // SVG not found (first load, empty state, or skeleton override), render it
      displayContainer.innerHTML = `
        <div class="relative flex items-center justify-center w-[130px] height-[130px]">
          <svg class="risk-circle-svg-container" width="120" height="120" viewBox="0 0 120 120">
            <circle class="risk-circle-bg" cx="60" cy="60" r="50"></circle>
            <circle class="risk-circle-value" cx="60" cy="60" r="50" 
              stroke="${overallColor}" 
              stroke-dasharray="${CIRCUMFERENCE.toFixed(2)}" 
              stroke-dashoffset="${CIRCUMFERENCE.toFixed(2)}">
            </circle>
          </svg>
          <div class="risk-score-inner-text-container absolute">
            <span class="text-3xl font-extrabold text-white font-mono" id="overall-risk-score">0.0</span>
            <span class="text-[9px] text-slate-400 font-bold uppercase tracking-wider mt-0.5">/ 100</span>
          </div>
        </div>
      `;

      // Animate it immediately from empty to current value
      const newCircleValue = document.querySelector("#risk-score-display-container .risk-circle-value");
      const newScoreText = document.getElementById("overall-risk-score");

      if (newCircleValue && newScoreText && typeof gsap !== "undefined") {
        gsap.to(newCircleValue, {
          attr: { "stroke-dashoffset": offset.toFixed(2) },
          duration: 1.2,
          ease: "power2.out"
        });

        const scoreObj = { val: 0.0 };
        gsap.to(scoreObj, {
          val: overallScore,
          duration: 1.2,
          ease: "power2.out",
          onUpdate: function () {
            newScoreText.textContent = scoreObj.val.toFixed(1);
          }
        });
      } else if (newCircleValue && newScoreText) {
        newCircleValue.setAttribute("stroke-dashoffset", offset.toFixed(2));
        newScoreText.textContent = overallScore.toFixed(1);
      }
    }

    // Celebration: Confetti burst on a perfect 100.0 score (LOW RISK / healthy)
    if (overallScore === 100.0 && lastOverallScore !== 100.0 && targets.length > 0) {
      if (typeof confetti === "function") {
        confetti({
          particleCount: 50,
          angle: 60,
          spread: 55,
          origin: { x: 0, y: 0.9 },
          colors: ["#3b82f6", "#34d399", "#38bdf8"]
        });
        confetti({
          particleCount: 50,
          angle: 120,
          spread: 55,
          origin: { x: 1, y: 0.9 },
          colors: ["#3b82f6", "#34d399", "#38bdf8"]
        });
      }
    }
    lastOverallScore = overallScore;

    // Render per-target list (top 4 for aesthetic elegance) using real risk scores from /targets API
    const targetsWithScores = targets.map(t => {
      const score = parseFloat(t.risk_score || 0.0);
      
      // Color-coding:
      // 0-30: Green, 31-60: Yellow, 61-80: Orange, 81-100: Red
      let color = "#22c55e"; // Low (Green)
      if (score > 80) color = "#ef4444"; // Critical (Red)
      else if (score > 60) color = "#f97316"; // High (Orange)
      else if (score > 30) color = "#eab308"; // Medium (Yellow)

      return {
        ...t,
        risk_color: color,
        risk_score_display: score.toFixed(0)
      };
    });

    // Sort by risk score descending so most risky are at the top
    targetsWithScores.sort((a, b) => parseFloat(b.risk_score || 0) - parseFloat(a.risk_score || 0));

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
          <span class="risk-target-name" title="${t.name || t.value}">${t.name || t.value}</span>
          <div class="risk-mini-bar bg-white/5">
            <div class="risk-mini-fill" style="width: ${parseFloat(t.risk_score || 0)}%; background-color: ${t.risk_color}"></div>
          </div>
          <span class="risk-score-value font-mono" style="color: ${t.risk_color}">${t.risk_score_display}</span>
        </div>
      `).join("");
    }
  }

  /**
   * Render Active/Running Scans List
   */
  function renderActiveScans(activeScansPayload) {
    const container = document.getElementById("active-scans-container");
    if (!container) return;

    const activeScans = activeScansPayload?.scans || [];

    // Sync WebSocket subscriptions
    const newActiveScanIds = new Set(activeScans.map(s => String(s.id)));
    
    // Unsubscribe from channels that are no longer active
    Object.keys(dashboardState.activeChannels).forEach(scanId => {
      if (!newActiveScanIds.has(scanId)) {
        unsubscribeFromScanWS(scanId);
      }
    });

    // Subscribe to new active scans
    activeScans.forEach(scan => {
      if (scan.id && !dashboardState.activeChannels[scan.id]) {
        subscribeToScanWS(scan.id);
      }
    });

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
        <div class="active-scan-row bg-white/[0.01]" data-scan-id="${scan.id}">
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
  function renderRecentFindings(recentFindingsPayload) {
    const container = document.getElementById("recent-findings-container");
    if (!container) return;

    const findings = recentFindingsPayload?.findings || [];

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
      const targetName = f.target_name || (f.target?.name || f.target?.url || "Unknown Target");

      return `
        <div class="recent-finding-row flex justify-between items-center py-2.5">
          <span class="finding-severity-badge severity-tooltip text-[10px] py-0.5" 
                data-severity="${sev}"
                data-title="${escapeHtml(f.title || f.name || 'Vulnerability Alert')}"
                data-target="${escapeHtml(targetName)}"
                style="background: ${cfg.color}15; color: ${cfg.color}; border: 1px solid ${cfg.color}30; cursor: help;">
            ${cfg.label}
          </span>
          <div class="finding-info">
            <div class="finding-title severity-tooltip" 
                 data-severity="${sev}"
                 data-title="${escapeHtml(f.title || f.name || 'Vulnerability Alert')}"
                 data-target="${escapeHtml(targetName)}"
                 style="cursor: help;">
              ${f.title || f.name || "Vulnerability Alert"}
            </div>
            <div class="finding-meta font-mono text-[10px]">
              <span>${targetName}</span>
              <span class="text-slate-600">•</span>
              <span>${formatRelativeTime(timeStr)}</span>
            </div>
          </div>
          <span class="finding-status-badge ${status}">${status}</span>
        </div>
      `;
    }).join("");

    // Initialize Tippy tooltips for the rendered findings
    if (typeof tippy !== "undefined") {
      tippy(".severity-tooltip", {
        theme: "translucent",
        allowHTML: true,
        placement: "top",
        animation: "shift-away",
        content(reference) {
          const sev = reference.getAttribute("data-severity");
          const title = reference.getAttribute("data-title");
          const target = reference.getAttribute("data-target");
          
          let desc = "";
          if (sev === "critical") {
            desc = "Allows immediate system compromise, remote code execution (RCE), or complete database takeover. Immediate remediation required.";
          } else if (sev === "high") {
            desc = "High risk of privilege escalation, data exfiltration, or unauthorized action execution. Needs urgent mitigation.";
          } else if (sev === "medium" || sev === "moderate") {
            desc = "Exposes security settings, intermediate keys, or application configurations (e.g. CSRF, SSRF, session hijacking). Schedule mitigation.";
          } else if (sev === "low") {
            desc = "Exposes metadata details, version numbers, or non-critical headers. Low exploitability but should be resolved.";
          } else {
            desc = "Informational check. Posture inspection with no active security threat detected.";
          }
          
          return `
            <div class="p-2 max-w-[260px] text-xs leading-relaxed font-sans text-left">
              <div class="font-extrabold uppercase tracking-wide mb-1" style="color: ${SEVERITY_CONFIG[sev]?.color || '#ffffff'}">${sev} Severity</div>
              <div class="font-semibold text-slate-100 mb-1.5">${title}</div>
              <div class="text-slate-300 mb-1">${desc}</div>
              <div class="text-[10px] text-slate-400 font-mono mt-1 pt-1 border-t border-white/10">Target: ${target}</div>
            </div>
          `;
        }
      });
    }

    // Helper helper to escape HTML inside data attributes safely
    function escapeHtml(str) {
      if (!str) return "";
      return str
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
    }
  }

  /* ── WebSocket Real-Time Active Scans ────────────────────────────────── */

  function subscribeToScanWS(scanId) {
    if (!window.echoInstance || dashboardState.activeChannels[scanId]) return;
    
    console.log(`[SecurityDashboardWS] Subscribing to scan.${scanId}`);
    try {
      const channelName = `scan.${scanId}`;
      const channel = window.echoInstance.channel(channelName);
      dashboardState.activeChannels[scanId] = channel;

      const pusher = window.echoInstance.connector?.pusher;
      if (pusher) {
        _attachDashboardGlobalHandler(pusher, channelName, scanId, 0);
      }
    } catch (err) {
      console.warn(`[SecurityDashboardWS] Error subscribing to scan.${scanId}:`, err);
    }
  }

  function _attachDashboardGlobalHandler(pusher, channelName, scanId, attempt) {
    if (attempt > 10) return;
    const ch = pusher.channel(channelName);
    if (!ch) {
      setTimeout(() => _attachDashboardGlobalHandler(pusher, channelName, scanId, attempt + 1), 500);
      return;
    }

    ch.bind_global((eventName, eventData) => {
      if (eventName.startsWith("pusher:") || eventName.startsWith("pusher_internal:")) return;

      const normalized = eventName.replace(/^\./, "").toLowerCase();
      console.log(`[SecurityDashboardWS] Event for scan.${scanId}: "${eventName}"`, eventData);

      if (normalized === "scan.status") {
        const progress = eventData?.progress || eventData?.scan_session?.progress;
        if (progress !== undefined) {
          updateScanProgressInUI(scanId, progress);
        }
        const status = eventData?.status || eventData?.scan_session?.status;
        if (status === "completed" || status === "failed" || status === "cancelled") {
          handleWSScanComplete(scanId);
        }
      } else if (
        normalized === "scan-completed" ||
        normalized === "scan-finished" ||
        normalized === "scan-done" ||
        normalized === "job-completed"
      ) {
        handleWSScanComplete(scanId);
      }
    });
  }

  function updateScanProgressInUI(scanId, progress) {
    const row = document.querySelector(`.active-scan-row[data-scan-id="${scanId}"]`);
    if (row) {
      const fill = row.querySelector('.scan-progress-fill');
      const text = row.querySelector('.scan-progress-text');
      if (fill) fill.style.width = `${progress}%`;
      if (text) text.textContent = `${progress}%`;
    }
  }

  function handleWSScanComplete(scanId) {
    console.log(`[SecurityDashboardWS] Scan completed: ${scanId}. Triggering metrics reload.`);
    unsubscribeFromScanWS(scanId);
    
    // Trigger dynamic reload of the entire security dashboard metrics
    if (typeof loadSecurityDashboard === "function") {
      loadSecurityDashboard();
    }
  }

  function unsubscribeFromScanWS(scanId) {
    if (dashboardState.activeChannels[scanId]) {
      console.log(`[SecurityDashboardWS] Unsubscribing from scan.${scanId}`);
      try {
        window.echoInstance.leaveChannel(`scan.${scanId}`);
      } catch (_) {}
      delete dashboardState.activeChannels[scanId];
    }
  }

  function unsubscribeAllScanWS() {
    Object.keys(dashboardState.activeChannels).forEach(scanId => {
      unsubscribeFromScanWS(scanId);
    });
  }

  /* ── Auto-refresh / polling logic ────────────────────────────────────── */

  function startActiveScansPolling() {
    stopActiveScansPolling();

    // Poll every 30 seconds
    dashboardState.refreshInterval = setInterval(async () => {
      // Check if current tab is still Security Dashboard
      if (typeof switchToTab === "function" && document.querySelector(".cyber-nav-item.cyber-nav-active")?.textContent.includes("Security Dashboard")) {
        try {
          const metricsRes = await window.apiClient.get("/dashboard/metrics");
          if (metricsRes.status === "success" && metricsRes.data) {
            dashboardState.metrics = metricsRes.data;
            renderActiveScans(metricsRes.data.active_scans);
          }
        } catch (e) {
          console.warn("[SecurityDashboard] Auto-refresh metrics query failed:", e);
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
    unsubscribeAllScanWS();
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
