/**
 * scan-progress.js — CyberGuard
 * Handles all logic for /scan/{scanJobId} progress page.
 *
 * Depends on (loaded via script tags in scan-progress.html):
 *   - api-client.js  → window.scannerAPI
 *   - echo-config.js → window.echoInstance
 *   - cyber-notify.js → window.CyberNotify
 */
(function () {
  "use strict";

  /* ─── Config ──────────────────────────────────────────────────────────── */
  const STATUS_POLL_MS      = 5_000;   // poll every 5 s (fallback)
  const STATUS_POLL_WS_MS   = 30_000;  // poll every 30 s when WS active
  const FINDINGS_POLL_MS    = 5_000;   // poll findings every 5 s while running
  const TERMINAL_MAX_LINES  = 2000;    // keep terminal trim

  /* ─── State ───────────────────────────────────────────────────────────── */
  let scanJobId        = null;
  let currentStatus    = null;   // "running"|"pending"|"cancelled"|"completed"
  let scanSession      = null;   // full session object from API
  let allFindings      = [];
  let seenFindingIds   = new Set();
  let terminalLines    = 0;

  // Polling handles
  let statusPollHandle   = null;
  let findingsPollHandle = null;

  // WebSocket
  let echoChannel    = null;
  let wsConnected    = false;

  function getPendingScanContext() {
    try {
      const pendingRaw = sessionStorage.getItem("cg_pending_scan");
      const pending = pendingRaw ? JSON.parse(pendingRaw) : null;
      return pending && pending.sessionId === scanJobId ? pending : {};
    } catch (_) {
      return {};
    }
  }

  function getCurrentScanContext(extra = {}) {
    const pending = getPendingScanContext();
    const session = scanSession || {};
    return {
      ...session,
      ...extra,
      id: session.id || scanJobId,
      target_id: session.target_id || session.target?.id || pending.targetId,
      project_id: session.project_id || session.project?.id || pending.projectId,
      target_value: session.target?.value || pending.targetValue,
      driver_ids: session.driver_id || pending.selectedBackendDrivers,
      started_at: session.started_at || pending.startedAt,
    };
  }

  function publishScanEvent(name, detail = {}) {
    const scan = getCurrentScanContext(detail.scan || {});
    if (window.scannerAPI && typeof window.scannerAPI.rememberScanSession === "function") {
      window.scannerAPI.rememberScanSession(scan, { source: scan.source || "api" });
    }
    document.dispatchEvent(new CustomEvent(`cyberguard:${name}`, {
      detail: {
        scanId: scanJobId,
        scan,
        projectId: scan.project_id,
        targetId: scan.target_id,
        findings: allFindings,
        ...detail,
      }
    }));
  }

  function rememberAndPublishFindings(findings) {
    const scan = getCurrentScanContext();
    if (window.scannerAPI && typeof window.scannerAPI.rememberScanFindings === "function") {
      window.scannerAPI.rememberScanFindings(scanJobId, findings, scan);
    }
    publishScanEvent("scanFindingsUpdated", { scan, findings });
  }

  /* ─── Boot ────────────────────────────────────────────────────────────── */
  document.addEventListener("DOMContentLoaded", async function () {
    // Read scan job ID from URL: /scan/{scanJobId}
    const pathParts = window.location.pathname.split("/scan/");
    scanJobId = pathParts[1] ? pathParts[1].split("/")[0] : null;

    if (!scanJobId) {
      showPageError("No scan ID in URL", "Please navigate from a project's scan.");
      return;
    }

    // Auth guard
    const token = localStorage.getItem("cyberguard_jwt");
    if (!token) {
      window.location.href = `/login?redirect=${encodeURIComponent(window.location.href)}`;
      return;
    }

    await initPage();
  });

  async function initPage() {
    showSkeleton(true);
    try {
      // Load initial status
      scanSession = await window.scannerAPI.getScanStatus(scanJobId);
      currentStatus = scanSession.status;
      publishScanEvent("scanUpdated", { scan: scanSession });

      renderHeader(scanSession);
      renderControlButtons(currentStatus);

      // Update Back Button to return to project targets tab
      try {
        let projectId = scanSession.project_id || (scanSession.project && scanSession.project.id);
        
        // Fallback 1: check cg_frontend_scans in localStorage
        if (!projectId && typeof scanJobId === "string" && scanJobId.startsWith("frontend_")) {
          const storedScansRaw = localStorage.getItem("cg_frontend_scans");
          if (storedScansRaw) {
            const storedScans = JSON.parse(storedScansRaw);
            const foundScan = storedScans.find(s => s.id === scanJobId);
            if (foundScan) {
              projectId = foundScan.project_id;
            }
          }
        }

        // Fallback 2: check cg_pending_scan in sessionStorage
        if (!projectId) {
          const pendingRaw = sessionStorage.getItem("cg_pending_scan");
          if (pendingRaw) {
            const pending = JSON.parse(pendingRaw);
            if (pending.sessionId === scanJobId) {
              projectId = pending.projectId;
            }
          }
        }

        if (projectId) {
          const backBtn = document.getElementById("sp-back-btn");
          if (backBtn) {
            backBtn.href = `/project-detail?id=${projectId}&tab=targets`;
          }
        }
      } catch (err) {
        console.warn("[ScanProgress] Failed to set back button href:", err);
      }
      hideSkeleton();

      // Load initial findings
      await loadFindings();
      if (currentStatus === "completed" || currentStatus === "cancelled") {
        publishScanEvent("scanCompleted", { scan: scanSession, status: currentStatus });
      }

      // Load historical logs if any exist
      if (scanSession && Array.isArray(scanSession.logs) && scanSession.logs.length > 0) {
        const terminal = document.getElementById("sp-terminal");
        if (terminal) {
          terminal.innerHTML = "";
          terminalLines = 0;
        }
        scanSession.logs.forEach(line => {
          appendTerminalLineRaw(line);
        });
      }

      // Connect WebSocket & Polling only for active scans
      if (currentStatus === "running" || currentStatus === "pending") {
        connectWebSocket();
        startStatusPolling();
        startFindingsPolling();
      }

      // Check if there are any pending frontend tools to execute
      let launchedFrontendScan = false;
      try {
        const pendingRaw = sessionStorage.getItem("cg_pending_scan");
        if (pendingRaw) {
          const pending = JSON.parse(pendingRaw);
          if (pending.sessionId === scanJobId && pending.selectedFrontendTools?.length > 0) {
            launchedFrontendScan = true;
            const toolsToRun = pending.selectedFrontendTools;
            // Remove them from sessionStorage so they don't execute again on page refresh
            pending.selectedFrontendTools = [];
            sessionStorage.setItem("cg_pending_scan", JSON.stringify(pending));

            // Acquire lock and execute
            acquireProgressPageLock(scanJobId);

            // Execute the tools asynchronously
            setTimeout(() => {
              runFrontendTools(toolsToRun, pending.targetValue);
            }, 1000);
          }
        }
      } catch (err) {
        console.error("[ScanProgress] Failed to run pending frontend tools:", err);
      }

      if (!launchedFrontendScan && typeof scanJobId === "string" && scanJobId.startsWith("frontend_") && currentStatus === "running") {
        // Check if a background tab is actively running (fresh heartbeat from another tab)
        const now = Date.now();
        const lastHb = (scanSession && scanSession.last_heartbeat) || 0;
        const activeTabId = scanSession && scanSession.active_tab_id;
        const isBackgroundActivelyRunning =
          activeTabId &&
          activeTabId !== window.scannerAPI.tabId &&
          (now - lastHb) < 6000;

        if (isBackgroundActivelyRunning) {
          // Background tab is running — just watch it. Start a live log refresh
          // so the terminal displays logs being written to localStorage by the background.
          appendTerminalSystem("Scan is running in background — displaying live progress…");
          startBackgroundLogPolling(scanJobId);
        } else {
          // No active background tab (stale heartbeat). Take over execution.
          acquireProgressPageLock(scanJobId);

          const targetValue = (scanSession && scanSession.target && scanSession.target.value) || "unknown";
          const selectedTools = (scanSession && scanSession.selected_frontend_tools) || [];
          const completedTools = (scanSession && scanSession.completed_frontend_tools) || [];
          const remainingTools = selectedTools.filter(t => !completedTools.includes(t));

          if (remainingTools.length > 0) {
            appendTerminalSystem("Resuming remaining network analysis tools…");
            setTimeout(() => {
              runFrontendTools(remainingTools, targetValue, true);
            }, 1000);
          } else {
            // All tools done — mark completed
            if (window.scannerAPI && typeof window.scannerAPI.completeFrontendScan === "function") {
              window.scannerAPI.completeFrontendScan(scanJobId);
            }
            onScanComplete({ status: "completed" });
          }
        }
      }

    } catch (err) {
      hideSkeleton();
      if (err.status === 404) {
        showPageError("Scan Not Found",
          "This scan job doesn't exist or has been deleted.");
      } else if (err.status === 403) {
        showPageError("Access Denied",
          "You don't have permission to view this scan.");
      } else {
        showPageError("Error Loading Scan",
          err.message || "Could not load scan data. Please try again.");
      }
    }
  }

  // Execute selected network analysis tools
  async function runFrontendTools(selectedTools, targetValue, isResume = false) {
    if (!isResume) {
      appendTerminalSystem("Starting selected network analysis tools…");
    } else {
      appendTerminalSystem("Resuming remaining network analysis tools…");
    }

    // Define custom hooks to route tools' outputs into the progress page UI
    window.onFrontendToolLog = function (msg, scanner) {
      appendTerminalLine(`[INFO] [${scanner}] ${msg}`);
    };

    window.onFrontendToolResult = function ({ timestamp, feature, message, status, details }) {
      let badge = "[INFO]";
      if (status === "danger" || status === "threat") {
        badge = message.includes("[SCAN COMPLETE]") ? "[LIVE]" : "[ERROR]";
      }
      else if (status === "warning") badge = "[WARN]";
      else if (status === "success" || status === "safe") badge = "[LIVE]";

      appendTerminalLine(`${badge} [${feature}] ${message}`);

      // Record final report as finding
      if (status === "danger" || status === "threat" || status === "success" || status === "safe" || message.includes("COMPLETE") || message.includes("Detailed")) {
        const severity = (status === "danger" || status === "threat") ? "high" : (status === "warning" ? "medium" : "info");
        const finding = {
          id: `net-${feature.toLowerCase().replace(/\s+/g, "-")}-${Date.now()}`,
          title: `${feature}: Analysis Complete`,
          severity: severity,
          status: "open",
          driver_id: feature.toUpperCase().replace(/\s+/g, "_"),
          description: message,
          created_at: new Date().toISOString()
        };
        // Save to mock database so polling loadFindings() doesn't overwrite it
        if (window.scannerAPI && typeof window.scannerAPI.addFrontendFinding === "function") {
          window.scannerAPI.addFrontendFinding(scanJobId, finding);
        }
        handleNewFinding(finding);
      }
    };

    window.onFrontendToolStatus = function (statusText) {
      appendTerminalLine(`[SYS] ${statusText}`);
    };

    // Run them sequentially
    const totalTools = selectedTools.length;
    const originalSelectedTools = (scanSession && scanSession.selected_frontend_tools) || selectedTools;
    const completedCount = originalSelectedTools.length - selectedTools.length;

    for (let i = 0; i < totalTools; i++) {
      // Check if the scan was cancelled or paused before running next tool
      const currentScanState = await window.scannerAPI.getScanStatus(scanJobId);
      if (currentScanState.status !== "running") {
        break;
      }

      const toolId = selectedTools[i];
      const progressPercent = Math.round(((completedCount + i) / originalSelectedTools.length) * 100);
      if (window.scannerAPI && typeof window.scannerAPI.updateFrontendScanProgress === "function") {
        window.scannerAPI.updateFrontendScanProgress(scanJobId, progressPercent);
      }

      appendTerminalSystem(`Initialising ${toolId.replace("net-", "").replace("frontend-", "").toUpperCase().replace("-", " ")}…`);
      try {
        if (toolId === "net-port-scanner" || toolId === "frontend-port-scanner") {
          await window.portScan(targetValue);
        } else if (toolId === "net-tcp-connectivity" || toolId === "frontend-tcp-connectivity") {
          await window.realTcpPortScan(targetValue);
        } else if (toolId === "net-udp-services" || toolId === "frontend-udp-services") {
          await window.realUdpConnectivityTest(targetValue);
        } else if (toolId === "net-ip-geolocation" || toolId === "frontend-ip-geolocation") {
          await window.ipGeolocation(targetValue);
        } else if (toolId === "net-reverse-dns" || toolId === "frontend-reverse-dns") {
          await window.reverseDns(targetValue);
        } else if (toolId === "net-whois-lookup" || toolId === "frontend-whois-lookup") {
          await window.whoisLookup(targetValue);
        }
      } catch (err) {
        console.error(`[Tool Error] ${toolId}:`, err);
        appendTerminalLine(`[ERROR] [${toolId}] Execution failed: ${err.message}`);
      }

      // Mark tool completed
      if (window.scannerAPI && typeof window.scannerAPI.addCompletedFrontendTool === "function") {
        window.scannerAPI.addCompletedFrontendTool(scanJobId, toolId);
      }
    }

    // Verify if all tools completed and mark the scan done
    const finalScanState = await window.scannerAPI.getScanStatus(scanJobId);
    if (finalScanState.status === "running") {
      const updatedCompleted = finalScanState.completed_frontend_tools || [];
      const stillRemaining = originalSelectedTools.filter(t => !updatedCompleted.includes(t));
      if (stillRemaining.length === 0) {
        if (window.scannerAPI && typeof window.scannerAPI.updateFrontendScanProgress === "function") {
          window.scannerAPI.updateFrontendScanProgress(scanJobId, 100);
        }

        appendTerminalSystem("All selected network analysis tools completed.");

        if (typeof scanJobId === "string" && scanJobId.startsWith("frontend_")) {
          if (window.scannerAPI && typeof window.scannerAPI.completeFrontendScan === "function") {
            window.scannerAPI.completeFrontendScan(scanJobId);
          }
          onScanComplete({ status: "completed" });
        }
      }
    }
  }

  let progressHeartbeatInterval = null;

  function acquireProgressPageLock(scanJobId) {
    try {
      const storedScansRaw = localStorage.getItem("cg_frontend_scans");
      if (storedScansRaw) {
        const storedScans = JSON.parse(storedScansRaw);
        const scan = storedScans.find(s => s.id === scanJobId);
        if (scan) {
          scan.active_tab_id = window.scannerAPI.tabId;
          scan.last_heartbeat = Date.now();
          localStorage.setItem("cg_frontend_scans", JSON.stringify(storedScans));
        }
      }
    } catch (_) {}

    if (progressHeartbeatInterval) clearInterval(progressHeartbeatInterval);
    progressHeartbeatInterval = setInterval(() => {
      try {
        const storedScansRaw = localStorage.getItem("cg_frontend_scans");
        if (!storedScansRaw) return;
        const storedScans = JSON.parse(storedScansRaw);
        const scan = storedScans.find(s => s.id === scanJobId);
        if (scan && scan.status === "running") {
          scan.active_tab_id = window.scannerAPI.tabId;
          scan.last_heartbeat = Date.now();
          localStorage.setItem("cg_frontend_scans", JSON.stringify(storedScans));
        } else {
          clearInterval(progressHeartbeatInterval);
        }
      } catch (_) {}
    }, 2000);
  }

  /* ═══════════════════════════════════════════════════════════════════════
     HEADER RENDERING
  ═══════════════════════════════════════════════════════════════════════ */
  function renderHeader(session) {
    const s = session || {};
    const target = s.target || {};

    _set("sp-target-name", target.value || "Unknown Target");
    
    const displayId = s.id || scanJobId || "";
    const shortId = window.scannerAPI && typeof window.scannerAPI.formatScanShortId === "function"
      ? window.scannerAPI.formatScanShortId(s)
      : displayId.substring(0, 8).toUpperCase();
    _set("sp-scan-id-short", shortId);

    // Started at
    if (s.started_at) {
      _set("sp-started-at", fmtDateTime(s.started_at));
    }

    // Driver chips
    const driversEl = document.getElementById("sp-drivers");
    if (driversEl) {
      const ids = Array.isArray(s.driver_id) ? s.driver_id : (s.driver_id ? [s.driver_id] : []);
      if (ids.length > 0) {
        driversEl.innerHTML = ids.map(id =>
          `<span class="sp-driver-chip">${escHtml(id)}</span>`
        ).join("");
      } else {
        driversEl.innerHTML = `<span class="sp-driver-chip sp-driver-chip--muted">—</span>`;
      }
    }

    renderStatusBadge(s.status);

    // Update document title
    document.title = `Scan ${(s.id || "").substring(0, 8)} — CyberGuard`;
  }

  function renderStatusBadge(status) {
    const el = document.getElementById("sp-status-badge");
    if (!el) return;

    const STATUS_MAP = {
      running  : { cls: "sp-badge--running",   label: "Running",   pulse: true  },
      pending  : { cls: "sp-badge--pending",   label: "Pausing…",  pulse: false },
      cancelled: { cls: "sp-badge--cancelled", label: "Cancelled", pulse: false },
      completed: { cls: "sp-badge--completed", label: "Completed", pulse: false },
    };
    const cfg = STATUS_MAP[status] || { cls: "sp-badge--pending", label: status || "Unknown", pulse: false };

    el.className = `sp-status-badge ${cfg.cls}`;
    el.innerHTML = cfg.pulse
      ? `<span class="sp-badge-pulse"></span>${escHtml(cfg.label)}`
      : escHtml(cfg.label);
  }

  /* ═══════════════════════════════════════════════════════════════════════
     CONTROL BUTTONS — status lifecycle
  ═══════════════════════════════════════════════════════════════════════ */
  function renderControlButtons(status) {
    const container = document.getElementById("sp-controls");
    const noteEl    = document.getElementById("sp-controls-note");
    if (!container) return;

    container.innerHTML = "";
    if (noteEl) noteEl.textContent = "";

    if (status === "running") {
      container.innerHTML = `
        <button id="sp-pause-btn" class="sp-btn sp-btn--warning" onclick="window._scanProgress.handlePause()">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="6" y="4" width="4" height="16"/><rect x="14" y="4" width="4" height="16"/></svg>
          Pause
        </button>
        <button id="sp-cancel-btn" class="sp-btn sp-btn--danger" onclick="window._scanProgress.handleCancel()">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
          Cancel
        </button>`;

    } else if (status === "pending") {
      container.innerHTML = `
        <button id="sp-resume-btn" class="sp-btn sp-btn--success" onclick="window._scanProgress.handleResume()">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="5 3 19 12 5 21 5 3"/></svg>
          Resume
        </button>
        <button id="sp-cancel-btn" class="sp-btn sp-btn--danger" onclick="window._scanProgress.handleCancel()">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
          Cancel
        </button>`;
      if (noteEl) noteEl.textContent = "Scan is pausing… container stops within 3 seconds.";

    } else if (status === "cancelled") {
      container.innerHTML = "";
      if (noteEl) noteEl.innerHTML =
        `<span class="sp-note sp-note--danger">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>
          This scan has been permanently cancelled.
        </span>`;

    } else if (status === "completed") {
      container.innerHTML = "";
      if (noteEl) noteEl.innerHTML =
        `<span class="sp-note sp-note--success">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>
          Scan completed successfully.
        </span>`;
    }

    renderStatusBadge(status);
    currentStatus = status;
  }

  /* ═══════════════════════════════════════════════════════════════════════
     BUTTON ACTION HANDLERS
  ═══════════════════════════════════════════════════════════════════════ */
  async function handlePause() {
    const btn = document.getElementById("sp-pause-btn");
    btnLoading(btn, "Pausing…");
    try {
      await window.scannerAPI.pauseScan(scanJobId);
      renderControlButtons("pending");
      notify("Pause signal sent — container will stop within 3 seconds.", "info");
    } catch (err) {
      notify(`Action failed — ${err.message || "please try again"}`, "error");
      renderControlButtons("running"); // revert
    }
  }

  async function handleResume() {
    const btn = document.getElementById("sp-resume-btn");
    btnLoading(btn, "Resuming…");
    try {
      await window.scannerAPI.continueScan(scanJobId);
      renderControlButtons("running");
      notify("Scan resumed successfully.", "success");
    } catch (err) {
      notify(`Action failed — ${err.message || "please try again"}`, "error");
      renderControlButtons("pending"); // revert
    }
  }

  function handleCancel() {
    // Show confirmation dialog
    const dialog = document.getElementById("sp-cancel-dialog");
    if (dialog) {
      dialog.classList.remove("hidden");
    } else {
      // Fallback — inline confirm
      if (confirm("Are you sure? This will permanently stop the scan and cannot be undone.")) {
        doCancel();
      }
    }
  }

  async function doCancel() {
    const confirmBtn = document.getElementById("sp-cancel-confirm-btn");
    btnLoading(confirmBtn, "Cancelling…");
    try {
      await window.scannerAPI.cancelScan(scanJobId);
      closeCancelDialog();
      renderControlButtons("cancelled");
      stopAllPolling();
      teardownWebSocket();
      appendTerminalSystem("Scan cancelled.");
      notify("Scan cancelled.", "warning");
    } catch (err) {
      closeCancelDialog();
      notify(`Failed to cancel — ${err.message || "please try again"}`, "error");
    }
  }

  function closeCancelDialog() {
    const dialog = document.getElementById("sp-cancel-dialog");
    if (dialog) dialog.classList.add("hidden");
  }

  /* ═══════════════════════════════════════════════════════════════════════
     STATUS POLLING
  ═══════════════════════════════════════════════════════════════════════ */
  function startStatusPolling() {
    stopStatusPolling();
    const interval = wsConnected ? STATUS_POLL_WS_MS : STATUS_POLL_MS;
    statusPollHandle = setInterval(pollStatus, interval);
  }

  function stopStatusPolling() {
    if (statusPollHandle) { clearInterval(statusPollHandle); statusPollHandle = null; }
  }

  async function pollStatus() {
    if (currentStatus === "completed" || currentStatus === "cancelled") {
      stopStatusPolling();
      return;
    }
    try {
      const session = await window.scannerAPI.getScanStatus(scanJobId);
      scanSession = session;
      publishScanEvent("scanUpdated", { scan: session });
      if (session.status !== currentStatus) {
        // Status changed
        renderControlButtons(session.status);
        if (session.status === "completed" || session.status === "cancelled") {
          stopAllPolling();
          teardownWebSocket();
          appendTerminalSystem(`Scan session ended (${session.status}).`);
          await loadFindings();
          publishScanEvent("scanCompleted", { scan: session, status: session.status });
        }
      }
      currentStatus = session.status;
    } catch (err) {
      console.warn("[ScanProgress] Status poll error:", err.message);
    }
  }

  /* ═══════════════════════════════════════════════════════════════════════
     FINDINGS
  ═══════════════════════════════════════════════════════════════════════ */
  async function loadFindings() {
    const container = document.getElementById("sp-findings-body");
    const countEl   = document.getElementById("sp-findings-count");
    if (!container) return;

    // Don't show spinner on background polls — only on first load
    if (allFindings.length === 0) {
      container.innerHTML = `<tr><td colspan="4" class="sp-table-empty">
        <span class="cyber-spinner-sm"></span> Loading findings…
      </td></tr>`;
    }

    try {
      const findings = await window.scannerAPI.getScanFindings(scanJobId);
      allFindings = findings;
      seenFindingIds.clear();
      findings.forEach(f => {
        const id = f.id || `${f.title}::${f.severity}`;
        seenFindingIds.add(id);
      });
      renderFindingsTable(findings);
      rememberAndPublishFindings(findings);
      if (countEl) {
        countEl.textContent = `${findings.length} finding${findings.length !== 1 ? "s" : ""} discovered`;
      }
    } catch (err) {
      if (allFindings.length === 0) {
        container.innerHTML = `<tr><td colspan="4" class="sp-table-empty sp-table-error">
          Could not load findings.
          <button class="sp-retry-btn" onclick="window._scanProgress.loadFindings()">Retry</button>
        </td></tr>`;
      }
    }
  }

  function renderFindingsTable(findings) {
    const container = document.getElementById("sp-findings-body");
    if (!container) return;

    if (findings.length === 0) {
      const msg = (currentStatus === "running" || currentStatus === "pending")
        ? "No findings yet — scan is in progress…"
        : "No findings were discovered.";
      container.innerHTML = `<tr><td colspan="4" class="sp-table-empty">${escHtml(msg)}</td></tr>`;
      return;
    }

    const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    const sorted = [...findings].sort((a, b) =>
      (SEV_ORDER[(a.severity || "").toLowerCase()] ?? 5) -
      (SEV_ORDER[(b.severity || "").toLowerCase()] ?? 5)
    );

    container.innerHTML = sorted.map(f => {
      const sev = (f.severity || "info").toLowerCase();
      const date = f.created_at
        ? new Date(f.created_at).toLocaleDateString("en-US", {
            year: "numeric", month: "short", day: "numeric",
          })
        : "—";
      const fId = f.id || `${f.title}::${f.severity}`;
      const escapedFId = fId.replace(/'/g, "\\'");

      let title = f.title || "Untitled Finding";
      // Remove repetitive "Severity Risk Endpoint: " or "Severity Risk Parameter: " prefixes to make it clean & organized
      const cleanRegex = /^(critical|high|medium|low|info)\s+risk\s+(endpoint|parameter|vulnerability):\s*/i;
      if (cleanRegex.test(title)) {
        const cleaned = title.replace(cleanRegex, "").trim();
        if (cleaned !== "") {
          title = cleaned;
        } else {
          // If the cleaned title is empty, try to extract the URL or description to avoid a blank title
          if (f.affected_url && f.affected_url.trim() !== "") {
            title = f.affected_url.trim();
          } else if (f.description && f.description.trim() !== "") {
            const descLine = f.description.split("\n")[0].trim();
            title = descLine !== "" ? descLine : f.title;
          } else {
            title = f.title;
          }
        }
      }

      return `<tr class="sp-table-row cursor-pointer" onclick="window.showFindingDetailModal('${escapedFId}')">
        <td class="sp-td sp-td--title">${escHtml(title)}</td>
        <td class="sp-td"><span class="sp-sev-badge sp-sev-${sev}">${escHtml(sev.toUpperCase())}</span></td>
        <td class="sp-td"><span class="sp-status-pill sp-status-${escHtml(f.status || "open")}">${escHtml((f.status || "open").toUpperCase())}</span></td>
        <td class="sp-td sp-td--mono">${escHtml(date)}</td>
      </tr>`;
    }).join("");
  }

  function startFindingsPolling() {
    stopFindingsPolling();
    if (currentStatus === "running" || currentStatus === "pending") {
      findingsPollHandle = setInterval(() => {
        if (currentStatus === "running" || currentStatus === "pending") {
          loadFindings();
        } else {
          stopFindingsPolling();
        }
      }, FINDINGS_POLL_MS);
    }
  }

  function stopFindingsPolling() {
    if (findingsPollHandle) { clearInterval(findingsPollHandle); findingsPollHandle = null; }
  }

  function stopAllPolling() {
    stopStatusPolling();
    stopFindingsPolling();
    stopBackgroundLogPolling();
  }

  /* ─── Background Log Polling (for when background tab is executing) ─── */
  let bgLogPollHandle = null;
  let bgLogSeenCount = 0;

  function startBackgroundLogPolling(jobId) {
    stopBackgroundLogPolling();
    bgLogSeenCount = terminalLines; // don't re-show logs already displayed
    bgLogPollHandle = setInterval(async () => {
      try {
        // Refresh the scan record from localStorage
        const storedScansRaw = localStorage.getItem("cg_frontend_scans");
        if (!storedScansRaw) return;
        const storedScans = JSON.parse(storedScansRaw);
        const scan = storedScans.find(s => s.id === jobId);
        if (!scan) return;

        // Display any new logs written by the background tab
        const logs = Array.isArray(scan.logs) ? scan.logs : [];
        if (logs.length > bgLogSeenCount) {
          const newLogs = logs.slice(bgLogSeenCount);
          newLogs.forEach(line => appendTerminalLineRaw(line));
          bgLogSeenCount = logs.length;
        }

        // If the background tab finishes, stop polling and update UI
        if (scan.status !== "running") {
          stopBackgroundLogPolling();
          renderControlButtons(scan.status);
          stopAllPolling();
          await loadFindings();
        }

        // If the background tab's heartbeat goes stale mid-run, take over
        const now = Date.now();
        const lastHb = scan.last_heartbeat || 0;
        const activeTabId = scan.active_tab_id;
        const isStale = !activeTabId || (activeTabId !== window.scannerAPI.tabId && (now - lastHb) > 6000);
        if (isStale && scan.status === "running") {
          stopBackgroundLogPolling();
          acquireProgressPageLock(jobId);
          const selectedTools = scan.selected_frontend_tools || [];
          const completedTools = scan.completed_frontend_tools || [];
          const remaining = selectedTools.filter(t => !completedTools.includes(t));
          const targetValue = (scan.target && scan.target.value) || "unknown";
          if (remaining.length > 0) {
            appendTerminalSystem("Background tab stopped — resuming here…");
            runFrontendTools(remaining, targetValue, true);
          } else {
            if (window.scannerAPI && typeof window.scannerAPI.completeFrontendScan === "function") {
              window.scannerAPI.completeFrontendScan(jobId);
            }
            onScanComplete({ status: "completed" });
          }
        }
      } catch (e) {
        console.warn("[ScanProgress] Background log poll error:", e);
      }
    }, 2000);
  }

  function stopBackgroundLogPolling() {
    if (bgLogPollHandle) { clearInterval(bgLogPollHandle); bgLogPollHandle = null; }
  }

  /* ═══════════════════════════════════════════════════════════════════════
     WEBSOCKET — LIVE TERMINAL VIA LARAVEL ECHO
  ═══════════════════════════════════════════════════════════════════════ */
  function connectWebSocket() {
    appendTerminalSystem("Connecting to scan stream…");

    if (!window.echoInstance) {
      showWsUnavailable();
      return;
    }

    const channelName = `scan.${scanJobId}`;
    try {
      echoChannel = window.echoInstance.channel(channelName);

      // Lifecycle
      if (echoChannel.subscribed) {
        echoChannel.subscribed(() => {
          wsConnected = true;
          appendTerminalSystem("[OK] Live channel connected.");
          hideWsUnavailable();
          // Slow down status polling when WS is available
          startStatusPolling();
        });
      }
      if (echoChannel.error) {
        echoChannel.error(() => {
          wsConnected = false;
          showWsUnavailable();
          startStatusPolling(); // ensure fast polling fallback
        });
      }

      // Event routing via bind_global
      const pusher = window.echoInstance.connector?.pusher;
      if (pusher) {
        _attachGlobalHandler(pusher, channelName, 0);
      }
    } catch (err) {
      console.error("[ScanProgress] WebSocket error:", err);
      showWsUnavailable();
    }
  }

  function _attachGlobalHandler(pusher, channelName, attempt) {
    if (attempt > 10) { showWsUnavailable(); return; }
    const ch = pusher.channel(channelName);
    if (!ch) {
      setTimeout(() => _attachGlobalHandler(pusher, channelName, attempt + 1), 500);
      return;
    }

    ch.bind_global((eventName, eventData) => {
      if (eventName.startsWith("pusher:") || eventName.startsWith("pusher_internal:")) return;

      const normalized = eventName.replace(/^\./, "").toLowerCase();
      switch (normalized) {
        case "terminal-log":
          handleTerminalLog(eventData);
          break;
        case "scan-results":
        case "scan.finding":
          handleNewFinding(eventData?.finding || eventData);
          break;
        case "scan.status": {
          const s = eventData?.status || eventData?.scan_session?.status;
          if (s) {
            renderControlButtons(s);
            if (s === "completed" || s === "cancelled") {
              stopAllPolling();
              teardownWebSocket();
              appendTerminalSystem("Scan session ended.");
              loadFindings();
            }
          }
          break;
        }
        case "scan-completed":
        case "scan-finished":
        case "scan-done":
        case "job-completed":
        case "scancompleted":
        case "scanfinished":
          onScanComplete(eventData);
          break;
        default:
          if (eventData?.status === "completed") onScanComplete(eventData);
          break;
      }
    });
  }

  async function onScanComplete(data) {
    const status = data?.status || data?.scan_session?.status || "completed";
    scanSession = data?.scan_session || { ...(scanSession || {}), status };
    renderControlButtons(status);
    stopAllPolling();
    teardownWebSocket();
    appendTerminalSystem("Scan session ended.");
    publishScanEvent("scanCompleted", { scan: scanSession, status });
    await loadFindings();
    notify(
      status === "completed"
        ? `Scan completed — ${allFindings.length} finding(s) found.`
        : "Scan finished.",
      "success"
    );
  }

  function handleTerminalLog(event) {
    const line = typeof event === "string"
      ? event
      : (event?.logLine || event?.log_line || event?.message || "");
    if (line) appendTerminalLine(line);
  }

  function handleNewFinding(finding) {
    if (!finding || !finding.title) return;
    const id = finding.id || `${finding.title}::${finding.severity}`;
    if (seenFindingIds.has(id)) return;
    seenFindingIds.add(id);
    allFindings.push(finding);
    if (window.scannerAPI && typeof window.scannerAPI.rememberScanFindings === "function") {
      allFindings = window.scannerAPI.rememberScanFindings(scanJobId, allFindings, getCurrentScanContext());
    }
    renderFindingsTable(allFindings);
    rememberAndPublishFindings(allFindings);
    const countEl = document.getElementById("sp-findings-count");
    if (countEl) {
      countEl.textContent = `${allFindings.length} finding${allFindings.length !== 1 ? "s" : ""} discovered`;
    }
  }

  function teardownWebSocket() {
    if (window.echoInstance && scanJobId) {
      try { window.echoInstance.leaveChannel(`scan.${scanJobId}`); } catch (_) {}
    }
    echoChannel = null;
    wsConnected = false;
  }

  function showWsUnavailable() {
    const el = document.getElementById("sp-ws-indicator");
    if (el) {
      el.textContent = "Live updates unavailable — polling every 5s";
      el.classList.remove("hidden");
    }
    appendTerminalSystem("[!] WebSocket unavailable — using polling fallback.");
  }

  function hideWsUnavailable() {
    const el = document.getElementById("sp-ws-indicator");
    if (el) el.classList.add("hidden");
  }

  /* ═══════════════════════════════════════════════════════════════════════
     TERMINAL UI
  ═══════════════════════════════════════════════════════════════════════ */
  function appendTerminalLineRaw(text) {
    const terminal = document.getElementById("sp-terminal");
    if (!terminal) return;

    // Remove first line if too long (memory management)
    if (terminalLines > TERMINAL_MAX_LINES) {
      const firstLine = terminal.firstElementChild;
      if (firstLine) { firstLine.remove(); terminalLines--; }
    }

    const line = document.createElement("div");
    line.className = "sp-terminal-line " + getTerminalLineClass(text);
    line.textContent = text;
    terminal.appendChild(line);
    terminalLines++;
    terminal.scrollTop = terminal.scrollHeight;
  }

  function appendTerminalLine(text) {
    if (typeof scanJobId === "string" && scanJobId.startsWith("frontend_")) {
      if (window.scannerAPI && typeof window.scannerAPI.addFrontendLog === "function") {
        window.scannerAPI.addFrontendLog(scanJobId, text);
      }
    }
    appendTerminalLineRaw(text);
  }

  function appendTerminalSystem(msg) {
    appendTerminalLine(`[SYS] ${msg}`);
  }

  function getTerminalLineClass(line) {
    if (line.includes("[SYS]") || line.includes("[OK]"))   return "sp-tl-system";
    if (line.includes("[ERROR]") || line.includes("[ERR]")) return "sp-tl-error";
    if (line.includes("[WARN]"))                            return "sp-tl-warn";
    if (line.includes("[INFO]"))                            return "sp-tl-info";
    if (line.includes("[LIVE]"))                            return "sp-tl-live";
    if (line.includes("[!]"))                               return "sp-tl-warn";
    return "sp-tl-default";
  }

  /* ═══════════════════════════════════════════════════════════════════════
     METADATA PANEL
  ═══════════════════════════════════════════════════════════════════════ */
  function populateMetadata(session) {
    const s = session || {};
    _set("sp-meta-scan-id",    s.id || "—");
    _set("sp-meta-target-id",  s.target_id || "—");
    _set("sp-meta-project-id", s.project_id || "—");
    _set("sp-meta-started",    s.started_at ? fmtDateTime(s.started_at) : "—");
    _set("sp-meta-finished",   s.finished_at ? fmtDateTime(s.finished_at) : "—");

    const ids = Array.isArray(s.driver_id) ? s.driver_id : (s.driver_id ? [s.driver_id] : []);
    _set("sp-meta-drivers", ids.join(", ") || "—");
  }

  /* ═══════════════════════════════════════════════════════════════════════
     ERROR / SKELETON STATES
  ═══════════════════════════════════════════════════════════════════════ */
  function showSkeleton(visible) {
    const sk = document.getElementById("sp-skeleton");
    const mc = document.getElementById("sp-main-content");
    if (sk) sk.classList.toggle("hidden", !visible);
    if (mc) mc.classList.toggle("hidden", visible);
  }

  function hideSkeleton() {
    showSkeleton(false);
    // Populate metadata after data is loaded
    if (scanSession) populateMetadata(scanSession);
  }

  function showPageError(title, msg) {
    const sk = document.getElementById("sp-skeleton");
    const err = document.getElementById("sp-error-state");
    const mc  = document.getElementById("sp-main-content");
    if (sk) sk.classList.add("hidden");
    if (mc) mc.classList.add("hidden");
    if (err) {
      err.classList.remove("hidden");
      const t = document.getElementById("sp-error-title");
      const m = document.getElementById("sp-error-msg");
      if (t) t.textContent = title;
      if (m) m.textContent = msg;
    }
  }

  /* ═══════════════════════════════════════════════════════════════════════
     UTILITIES
  ═══════════════════════════════════════════════════════════════════════ */
  function _set(id, val) {
    const el = document.getElementById(id);
    if (el) el.textContent = val;
  }

  function escHtml(t) {
    const d = document.createElement("div");
    d.textContent = String(t ?? "");
    return d.innerHTML;
  }

  function fmtDateTime(iso) {
    if (!iso) return "—";
    try {
      return new Date(iso).toLocaleString("en-US", {
        year: "numeric", month: "short", day: "numeric",
        hour: "2-digit", minute: "2-digit",
      });
    } catch (_) { return iso; }
  }

  function btnLoading(btn, label) {
    if (!btn) return;
    btn._orig    = btn.innerHTML;
    btn.disabled = true;
    btn.innerHTML = `<span class="cyber-spinner-sm"></span>${escHtml(label)}`;
  }

  function notify(msg, type = "info") {
    if (window.CyberNotify) window.CyberNotify.alert(msg, { type });
    else console.log(`[ScanProgress][${type}]`, msg);
  }

  /* ─── Cleanup on page leave ───────────────────────────────────────────── */
  window.addEventListener("beforeunload", () => {
    stopAllPolling();
    teardownWebSocket();
  });

  window.addEventListener("beforeunload", () => {
    stopAllPolling();
    teardownWebSocket();
  });

  /* ═══════════════════════════════════════════════════════════════════════
     FINDINGS DETAILS MODAL & FORMATTERS
  ═══════════════════════════════════════════════════════════════════════ */
  const escapeHtml = escHtml;

  function getCVSSSeverity(score) {
    const s = parseFloat(score);
    if (isNaN(s)) return 'none';
    if (s === 0) return 'none';
    if (s < 4.0) return 'low';
    if (s < 7.0) return 'medium';
    if (s < 9.0) return 'high';
    return 'critical';
  }

  function getPortRisk(port) {
    const high = [21, 23, 445, 1433, 3389, 5900, 6379, 27017, 9200];
    const med = [22, 25, 80, 3306, 5432, 8080];
    if (high.includes(port)) return 'high';
    if (med.includes(port)) return 'medium';
    return 'low';
  }

  function formatIPGeolocationHtml(text) {
    if (!text) return '';
    const lines = text.split('\n');
    let html = '<div class="ip-geo-container mt-4 space-y-6">';
    let currentSection = null;
    let currentItems = [];
    const sections = [];
    lines.forEach(line => {
      const trimmed = line.trim();
      if (!trimmed) return;
      if (trimmed.includes('Location Details') || trimmed.includes('Network Information') || trimmed.includes('Regional Details') || trimmed.includes('Security Information')) {
        if (currentSection) {
          sections.push({ name: currentSection, items: currentItems });
        }
        currentSection = trimmed.replace(/[ðŸ“ðŸŒðŸ•ðŸ”’]/g, '').replace(/:$/, '').trim();
        currentItems = [];
      } else if (trimmed.includes(':') && currentSection) {
        const colonIdx = trimmed.indexOf(':');
        const key = trimmed.substring(0, colonIdx).trim();
        const val = trimmed.substring(colonIdx + 1).trim();
        currentItems.push({ key, val });
      }
    });
    if (currentSection) {
      sections.push({ name: currentSection, items: currentItems });
    }
    const iconMap = {
      'Location Details': `<svg class="w-5 h-5 text-indigo-400" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M15 10.5a3 3 0 1 1-6 0 3 3 0 0 1 6 0Z"/><path stroke-linecap="round" stroke-linejoin="round" d="M19.5 10.5c0 7.142-7.5 11.25-7.5 11.25S4.5 17.642 4.5 10.5a7.5 7.5 0 1 1 15 0Z"/></svg>`,
      'Network Information': `<svg class="w-5 h-5 text-emerald-400" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M12 21a9.004 9.004 0 0 0 8.716-6.747M12 21a9.004 9.004 0 0 1-8.716-6.747M12 21c2.485 0 4.5-4.03 4.5-9S14.485 3 12 3s-4.5 4.03-4.5 9 2.015 9 4.5 9Z"/><path stroke-linecap="round" stroke-linejoin="round" d="M2.25 12c0 5.385 4.365 9.75 9.75 9.75s9.75-4.365 9.75-9.75S17.385 2.25 12 2.25 2.25 6.615 2.25 12Z"/></svg>`,
      'Regional Details': `<svg class="w-5 h-5 text-amber-400" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M12 6v6h4.5m4.5 0a9 9 0 1 1-18 0 9 9 0 0 1 18 0Z"/></svg>`,
      'Security Information': `<svg class="w-5 h-5 text-rose-400" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 0 1 3.598 6 11.99 11.99 0 0 0 3 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285Z"/></svg>`
    };
    const cardColors = {
      'Location Details': 'border-indigo-500/20 bg-indigo-500/5',
      'Network Information': 'border-emerald-500/20 bg-emerald-500/5',
      'Regional Details': 'border-amber-500/20 bg-amber-500/5',
      'Security Information': 'border-rose-500/20 bg-rose-500/5'
    };
    html += '<div class="grid grid-cols-1 md:grid-cols-2 gap-4">';
    sections.forEach(section => {
      const icon = iconMap[section.name] || '';
      const colorCls = cardColors[section.name] || 'border-white/10 bg-white/5';
      html += `
        <div class="ip-geo-card p-4 rounded-xl border ${colorCls} transition-all duration-200 hover:border-white/20">
          <div class="flex items-center gap-2 mb-3 pb-2 border-b border-white/5">
            ${icon}
            <span class="text-xs font-bold uppercase tracking-wider text-slate-200">${escapeHtml(section.name)}</span>
          </div>
          <div class="space-y-2">
      `;
      section.items.forEach(item => {
        html += `
          <div class="flex justify-between items-center text-[11px] font-mono py-0.5">
            <span class="text-slate-400 select-none">${escapeHtml(item.key)}</span>
            <span class="text-slate-200 font-bold text-right">${escapeHtml(item.val)}</span>
          </div>
        `;
      });
      html += `
          </div>
        </div>
      `;
    });
    html += '</div></div>';
    return html;
  }

  function formatShodanScannerHtml(text) {
    if (!text) return '';
    const lines = text.split('\n').map(l => l.trim());
    
    let ip = '';
    let org = '';
    let isp = '';
    let location = '';
    let os = '';
    let hostnames = '';
    const ports = [];
    const stats = {};
    let vulnerabilities = 0;
    
    let currentSection = '';
    
    lines.forEach(line => {
      if (!line) return;
      
      if (line.includes('Host Information:')) {
        currentSection = 'host';
        return;
      }
      if (line.includes('Open Ports & Services:') || line.includes('Open Ports:')) {
        currentSection = 'ports';
        return;
      }
      if (line.includes('Scan Statistics:')) {
        currentSection = 'stats';
        return;
      }
      if (line.startsWith('Vulnerabilities:')) {
        const val = line.split('Vulnerabilities:')[1].trim();
        vulnerabilities = parseInt(val) || 0;
        return;
      }
      
      if (currentSection === 'host') {
        if (line.startsWith('- IP:')) ip = line.split('- IP:')[1].trim();
        else if (line.startsWith('- Organization:')) org = line.split('- Organization:')[1].trim();
        else if (line.startsWith('- ISP:')) isp = line.split('- ISP:')[1].trim();
        else if (line.startsWith('- Location:')) location = line.split('- Location:')[1].trim();
        else if (line.startsWith('- OS:')) os = line.split('- OS:')[1].trim();
        else if (line.startsWith('- Hostnames:')) hostnames = line.split('- Hostnames:')[1].trim();
      } else if (currentSection === 'ports') {
        if (line.startsWith('-')) {
          const cleanLine = line.substring(1).trim();
          const portMatch = cleanLine.match(/^(\d+)(?:\s*-\s*([^(]+))?(?:\s*\(([^)]+)\))?/);
          if (portMatch) {
            const portNum = portMatch[1];
            const srvName = (portMatch[2] || 'Unknown').trim();
            const details = (portMatch[3] || '').trim();
            ports.push({ port: portNum, service: srvName, details: details });
          }
        }
      } else if (currentSection === 'stats') {
        if (line.startsWith('-')) {
          const cleanLine = line.substring(1).trim();
          if (cleanLine.includes(':')) {
            const parts = cleanLine.split(':');
            const k = parts[0].trim();
            const v = parts.slice(1).join(':').trim();
            stats[k] = v;
          }
        }
      }
    });

    let html = '<div class="shodan-scan-container mt-4 space-y-6">';
    
    // Host Information Card (matching IP Geo style)
    html += `
      <div class="ip-geo-card p-4 rounded-xl border border-indigo-500/20 bg-indigo-500/5 transition-all duration-200 hover:border-white/20">
        <div class="flex items-center gap-2 mb-3 pb-2 border-b border-white/5">
          <svg class="w-5 h-5 text-indigo-400" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" d="M2.25 12c0 5.385 4.365 9.75 9.75 9.75s9.75-4.365 9.75-9.75S17.385 2.25 12 2.25 2.25 6.615 2.25 12Z"/>
            <path stroke-linecap="round" stroke-linejoin="round" d="M12 3v18M3 12h18"/>
          </svg>
          <span class="text-xs font-bold uppercase tracking-wider text-slate-200">Shodan Host Intelligence</span>
        </div>
        <div class="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-4 text-xs font-mono">
          <div class="flex flex-col gap-1.5 p-3 rounded-lg bg-white/[0.02] border border-white/5">
            <span class="text-[10px] text-slate-400 uppercase tracking-wider font-sans select-none">Target IP</span>
            <span class="text-slate-200 font-bold break-all">${escapeHtml(ip || '—')}</span>
          </div>
          <div class="flex flex-col gap-1.5 p-3 rounded-lg bg-white/[0.02] border border-white/5">
            <span class="text-[10px] text-slate-400 uppercase tracking-wider font-sans select-none">Location</span>
            <span class="text-slate-200 font-bold">${escapeHtml(location || '—')}</span>
          </div>
          <div class="flex flex-col gap-1.5 p-3 rounded-lg bg-white/[0.02] border border-white/5">
            <span class="text-[10px] text-slate-400 uppercase tracking-wider font-sans select-none">Operating System</span>
            <span class="text-slate-200 font-bold">${escapeHtml(os || '—')}</span>
          </div>
          <div class="flex flex-col gap-1.5 p-3 rounded-lg bg-white/[0.02] border border-white/5">
            <span class="text-[10px] text-slate-400 uppercase tracking-wider font-sans select-none">ISP</span>
            <span class="text-slate-200 font-bold">${escapeHtml(isp || '—')}</span>
          </div>
          <div class="flex flex-col gap-1.5 p-3 rounded-lg bg-white/[0.02] border border-white/5 sm:col-span-2 md:col-span-2">
            <span class="text-[10px] text-slate-400 uppercase tracking-wider font-sans select-none">Organization</span>
            <span class="text-slate-200 font-bold break-words">${escapeHtml(org || '—')}</span>
          </div>
          <div class="flex flex-col gap-1.5 p-3 rounded-lg bg-white/[0.02] border border-white/5 col-span-1 sm:col-span-2 md:col-span-3">
            <span class="text-[10px] text-slate-400 uppercase tracking-wider font-sans select-none">Hostnames</span>
            <span class="text-slate-200 font-bold break-all">${escapeHtml(hostnames || '—')}</span>
          </div>
        </div>
      </div>
    `;

    // Open Ports Detected Card / Grid
    if (ports.length > 0) {
      html += `
        <div>
          <div class="flex items-center justify-between mb-3">
            <h4 class="text-xs font-bold uppercase tracking-wider text-slate-400 select-none">Open Ports Detected</h4>
            <span class="bg-indigo-500/10 border border-indigo-500/20 px-2 py-0.5 rounded text-[10px] font-mono text-indigo-400 font-bold">${ports.length} Open</span>
          </div>
          <div class="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 gap-3">
      `;
      ports.forEach(p => {
        const portNum = parseInt(p.port);
        const risk = isNaN(portNum) ? 'low' : getPortRisk(portNum);
        const riskColorMap = {
          high: 'border-rose-500/20 bg-rose-500/5 text-rose-400 hover:border-rose-500/40',
          medium: 'border-amber-500/20 bg-amber-500/5 text-amber-400 hover:border-amber-500/40',
          low: 'border-emerald-500/20 bg-emerald-500/5 text-emerald-400 hover:border-emerald-500/40'
        };
        const borderBgClass = riskColorMap[risk] || 'border-slate-500/20 bg-slate-500/5 text-slate-400 hover:border-white/20';
        
        html += `
          <div class="p-3 rounded-xl border ${borderBgClass} flex flex-col justify-between gap-2 transition-all duration-200">
            <div class="flex items-center justify-between">
              <span class="text-xs font-mono font-bold text-slate-100">Port ${escapeHtml(p.port)}</span>
              <span class="w-1.5 h-1.5 rounded-full bg-current shrink-0"></span>
            </div>
            <div class="font-mono">
              <span class="text-[10px] text-slate-400 block truncate" title="${escapeHtml(p.service)}">${escapeHtml(p.service)}</span>
              ${p.details ? `<span class="text-[9px] text-rose-400 block truncate mt-0.5 font-semibold" title="${escapeHtml(p.details)}">${escapeHtml(p.details)}</span>` : ''}
            </div>
          </div>
        `;
      });
      html += '</div></div>';
    } else {
      html += `
        <div class="p-6 rounded-xl border border-slate-500/10 bg-slate-500/5 text-center text-xs text-slate-400">
          No open ports or services found in Shodan database.
        </div>
      `;
    }

    // Vulnerability Alert and Statistics Grid
    html += '<div class="grid grid-cols-1 md:grid-cols-2 gap-4">';
    
    // Vulnerability box
    if (vulnerabilities > 0) {
      html += `
        <div class="p-4 rounded-xl border border-rose-500/25 bg-rose-500/5 flex items-center gap-3">
          <div class="p-2 bg-rose-500/10 rounded-lg text-rose-400 shrink-0">
            <svg class="w-5 h-5" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126ZM12 15.75h.007v.008H12v-.008Z"/>
            </svg>
          </div>
          <div>
            <div class="text-xs font-bold uppercase tracking-wider text-rose-400 select-none">Vulnerabilities Detected</div>
            <div class="text-lg font-mono font-bold text-slate-100 mt-0.5">${vulnerabilities} Potential CVEs</div>
          </div>
        </div>
      `;
    } else {
      html += `
        <div class="p-4 rounded-xl border border-emerald-500/20 bg-emerald-500/5 flex items-center gap-3">
          <div class="p-2 bg-emerald-500/10 rounded-lg text-emerald-400 shrink-0">
            <svg class="w-5 h-5" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" d="M9 12.75L11.25 15 15 9.75M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
            </svg>
          </div>
          <div>
            <div class="text-xs font-bold uppercase tracking-wider text-emerald-400 select-none">Vulnerability Status</div>
            <div class="text-sm font-bold text-slate-200 mt-0.5">No vulnerabilities listed in host report.</div>
          </div>
        </div>
      `;
    }

    // Statistics box
    const totalPorts = stats['Total ports'] || stats['Services detected'] || ports.length;
    const duration = stats['Scan duration'] || '—';
    const freshness = stats['Data freshness'] || stats['Last update'] || '—';
    
    html += `
      <div class="p-4 rounded-xl border border-slate-500/20 bg-slate-500/5 flex flex-col justify-between">
        <div class="flex items-center gap-2 mb-3">
          <svg class="w-4 h-4 text-slate-400" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" d="M3 13.125C3 12.504 3.504 12 4.125 12h2.25c.621 0 1.125.504 1.125 1.125v5.25c0 .621-.504 1.125-1.125 1.125h-2.25A1.125 1.125 0 013 18.375v-5.25zM9.75 8.625c0-.621.504-1.125 1.125-1.125h2.25c.621 0 1.125.504 1.125 1.125v9.75c0 .621-.504 1.125-1.125 1.125h-2.25a1.125 1.125 0 01-1.125-1.125v-9.75zM16.5 4.125c0-.621.504-1.125 1.125-1.125h2.25C20.496 3 21 3.504 21 4.125v14.25c0 .621-.504 1.125-1.125 1.125h-2.25a1.125 1.125 0 01-1.125-1.125V4.125z"/>
          </svg>
          <span class="text-xs font-bold uppercase tracking-wider text-slate-200 select-none">Scan Statistics</span>
        </div>
        <div class="grid grid-cols-3 gap-2 text-center font-mono">
          <div class="bg-white/5 border border-white/5 p-2 rounded-lg">
            <div class="text-xs font-bold text-slate-100">${escapeHtml(String(totalPorts))}</div>
            <div class="text-[8px] text-slate-500 uppercase tracking-wider">Ports</div>
          </div>
          <div class="bg-white/5 border border-white/5 p-2 rounded-lg">
            <div class="text-xs font-bold text-slate-100">${escapeHtml(duration)}</div>
            <div class="text-[8px] text-slate-500 uppercase tracking-wider">Duration</div>
          </div>
          <div class="bg-white/5 border border-white/5 p-2 rounded-lg">
            <div class="text-xs font-bold text-slate-100 truncate" title="${escapeHtml(freshness)}">${escapeHtml(freshness.split('T')[0] || freshness)}</div>
            <div class="text-[8px] text-slate-500 uppercase tracking-wider">Freshness</div>
          </div>
        </div>
      </div>
    `;

    html += '</div></div>';
    return html;
  }

  function formatReverseDNSHtml(text) {
    if (!text) return '';
    const cleanText = text.replace(/[\u2700-\u27BF]|[\uE000-\uF8FF]|\uD83C[\uDC00-\uDFFF]|\uD83D[\uDC00-\uDFFF]|[\u2600-\u26FF]|\uD83E[\uDD10-\uDDFF]|[\uFE0F]/g, '').trim();
    const lines = cleanText.split('\n').map(l => l.trim()).filter(Boolean);
    let ip = '';
    let service = '';
    let provider = '';
    let type = '';
    let hostnames = [];
    let note = '';
    let isParsingHostnames = false;
    lines.forEach(line => {
      if (line.includes('IP:')) {
        ip = line.split('IP:')[1].trim();
        isParsingHostnames = false;
      } else if (line.startsWith('Service:')) {
        service = line.split('Service:')[1].trim();
        isParsingHostnames = false;
      } else if (line.startsWith('Provider:')) {
        provider = line.split('Provider:')[1].trim();
        isParsingHostnames = false;
      } else if (line.startsWith('Type:')) {
        type = line.split('Type:')[1].trim();
        isParsingHostnames = false;
      } else if (line.startsWith('Hostname(s):') || line.startsWith('Hostname:')) {
        isParsingHostnames = true;
      } else if (isParsingHostnames && line.startsWith('-')) {
        hostnames.push(line.replace(/^-/, '').trim());
      } else {
        note = note ? note + '\n' + line.trim() : line.trim();
        isParsingHostnames = false;
      }
    });
    const cardColorCls = 'border-emerald-500/20 bg-emerald-500/5';
    const icon = `<svg class="w-5 h-5 text-emerald-400" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M12 21a9.004 9.004 0 0 0 8.716-6.747M12 21a9.004 9.004 0 0 1-8.716-6.747M12 21c2.485 0 4.5-4.03 4.5-9S14.485 3 12 3s-4.5 4.03-4.5 9 2.015 9 4.5 9Z"/><path stroke-linecap="round" stroke-linejoin="round" d="M2.25 12c0 5.385 4.365 9.75 9.75 9.75s9.75-4.365 9.75-9.75S17.385 2.25 12 2.25 2.25 6.615 2.25 12Z"/></svg>`;
    let html = `
      <div class="rev-dns-container mt-4 space-y-4">
        <div class="rev-dns-card p-5 rounded-xl border ${cardColorCls} transition-all duration-200 hover:border-white/20">
          <div class="flex items-center gap-2 mb-4 pb-2 border-b border-white/5">
            ${icon}
            <span class="text-xs font-bold uppercase tracking-wider text-slate-200">Reverse DNS Analysis</span>
          </div>
          <div class="grid grid-cols-1 md:grid-cols-2 gap-x-6 gap-y-3">
    `;
    if (ip) {
      html += `<div class="flex justify-between items-center text-[11px] font-mono py-1 border-b border-white/5 md:border-none"><span class="text-slate-400 select-none">IP Address</span><span class="text-slate-200 font-bold text-right">${escapeHtml(ip)}</span></div>`;
    }
    if (service) {
      html += `<div class="flex justify-between items-center text-[11px] font-mono py-1 border-b border-white/5 md:border-none"><span class="text-slate-400 select-none">Service</span><span class="text-slate-200 font-bold text-right">${escapeHtml(service)}</span></div>`;
    }
    if (provider) {
      html += `<div class="flex justify-between items-center text-[11px] font-mono py-1 border-b border-white/5 md:border-none"><span class="text-slate-400 select-none">Provider</span><span class="text-slate-200 font-bold text-right">${escapeHtml(provider)}</span></div>`;
    }
    if (type) {
      html += `<div class="flex justify-between items-center text-[11px] font-mono py-1 border-b border-white/5 md:border-none"><span class="text-slate-400 select-none">Type</span><span class="text-slate-200 font-bold text-right">${escapeHtml(type)}</span></div>`;
    }
    if (hostnames.length > 0) {
      html += `
        <div class="flex justify-between items-start text-[11px] font-mono py-1 md:col-span-2 border-t border-white/5 mt-2 pt-2">
          <span class="text-slate-400 select-none">Hostname(s)</span>
          <div class="text-slate-200 font-bold text-right space-y-1">
            ${hostnames.map(h => `<div class="bg-white/5 px-2 py-0.5 rounded border border-white/10 text-[10px] text-slate-200 inline-block ml-1">${escapeHtml(h)}</div>`).join('')}
          </div>
        </div>
      `;
    }
    html += `</div>`;
    if (note) {
      html += `
        <div class="mt-4 p-3 rounded-lg bg-blue-500/10 border border-blue-500/20 flex items-start gap-2.5 text-xs text-blue-300">
          <svg class="w-4 h-4 text-blue-400 shrink-0 mt-0.5" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M11.25 11.25l.041-.02a.75.75 0 111.063.852l-.708 2.836a.75.75 0 001.063.852l.041-.021M21 12a9 9 0 11-18 0 9 9 0 0118 0zm-9-3.75h.008v.008H12V8.25z"/></svg>
          <div class="font-sans leading-relaxed whitespace-pre-wrap">${escapeHtml(note)}</div>
        </div>
      `;
    }
    html += `</div></div>`;
    return html;
  }

  function formatWhoisHtml(text) {
    if (!text) return '';
    const cleanText = text.replace(/[\u2700-\u27BF]|[\uE000-\uF8FF]|\uD83C[\uDC00-\uDFFF]|\uD83D[\uDC00-\uDFFF]|[\u2600-\u26FF]|\uD83E[\uDD10-\uDDFF]|[\uFE0F]/g, '').trim();
    const lines = cleanText.split('\n');
    const sections = [];
    let currentSection = null;
    let currentItems = [];
    let lastItem = null;
    let title = '';
    lines.forEach(line => {
      const trimmed = line.trim();
      if (!trimmed) return;
      if (/^[─=\-_\s]+$/.test(trimmed)) return;
      if (trimmed.includes('WHOIS DATA')) {
        title = trimmed;
        return;
      }
      const leadingSpaces = line.length - line.trimStart().length;
      if (trimmed.includes(':')) {
        const colonIdx = trimmed.indexOf(':');
        const key = trimmed.substring(0, colonIdx).trim();
        const val = trimmed.substring(colonIdx + 1).trim();
        lastItem = { key, val: [val] };
        currentItems.push(lastItem);
      } else {
        if (leadingSpaces > 8 && lastItem) {
          lastItem.val.push(trimmed);
        } else {
          if (currentSection) {
            sections.push({ name: currentSection, items: currentItems });
          }
          currentSection = trimmed;
          currentItems = [];
          lastItem = null;
        }
      }
    });
    if (currentSection) {
      sections.push({ name: currentSection, items: currentItems });
    }
    const iconMap = {
      'Location': `<svg class="w-5 h-5 text-indigo-400" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M15 10.5a3 3 0 1 1-6 0 3 3 0 0 1 6 0Z"/><path stroke-linecap="round" stroke-linejoin="round" d="M19.5 10.5c0 7.142-7.5 11.25-7.5 11.25S4.5 17.642 4.5 10.5a7.5 7.5 0 1 1 15 0Z"/></svg>`,
      'Network': `<svg class="w-5 h-5 text-emerald-400" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M12 21a9.004 9.004 0 0 0 8.716-6.747M12 21a9.004 9.004 0 0 1-8.716-6.747M12 21c2.485 0 4.5-4.03 4.5-9S14.485 3 12 3s-4.5 4.03-4.5 9 2.015 9 4.5 9Z"/><path stroke-linecap="round" stroke-linejoin="round" d="M2.25 12c0 5.385 4.365 9.75 9.75 9.75s9.75-4.365 9.75-9.75S17.385 2.25 12 2.25 2.25 6.615 2.25 12Z"/></svg>`,
      'Security': `<svg class="w-5 h-5 text-rose-400" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 0 1 3.598 6 11.99 11.99 0 0 0 3 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285Z"/></svg>`,
      'Registration': `<svg class="w-5 h-5 text-indigo-400" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M19.5 14.25v-2.625a3.375 3.375 0 0 0-3.375-3.375h-1.5A1.125 1.125 0 0 1 13.5 7.125v-1.5a3.375 3.375 0 0 0-3.375-3.375H8.25m0 12.75h7.5m-7.5 3H12M10.5 2.25H5.625c-.621 0-1.125.504-1.125 1.125v17.25c0 .621.504 1.125 1.125 1.125h12.75c.621 0 1.125-.504 1.125-1.125V11.25a9 9 0 0 0-9-9Z"/></svg>`,
      'Status': `<svg class="w-5 h-5 text-amber-400" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M9.568 3H5.25A2.25 2.25 0 0 0 3 5.25v4.318c0 .597.237 1.17.659 1.591l9.581 9.581a1.44 1.44 0 0 0 2.037 0l4.318-4.318a1.44 1.44 0 0 0 0-2.037L10.01 3.659A2.25 2.25 0 0 0 8.42 3H9.568Z"/><path stroke-linecap="round" stroke-linejoin="round" d="M6 7.5h.008v.008H6V7.5Z"/></svg>`,
      'DNS': `<svg class="w-5 h-5 text-purple-400" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M5.25 14.25h13.5m-13.5 0a3 3 0 0 1-3-3m3 3a3 3 0 0 0 3 3m13.5-3a3 3 0 0 1 3-3m-3 3a3 3 0 0 0-3 3m0-12h.008v.008H12V5.25Zm0 2.25h.008v.008H12V7.5Zm0 2.25h.008v.008H12V9.75ZM3 11.25a3 3 0 0 1 3-3h12a3 3 0 0 1 3 3m0 0v-6a3 3 0 0 0-3-3H6a3 3 0 0 0-3 3v6Zm3 3a3 3 0 0 0-3 3v2.25a3 3 0 0 0 3 3h12a3 3 0 0 0 3-3V17.25a3 3 0 0 0-3-3H6Z"/></svg>`
    };
    const cardColors = {
      'Location': 'border-indigo-500/20 bg-indigo-500/5',
      'Network': 'border-emerald-500/20 bg-emerald-500/5',
      'Security': 'border-rose-500/20 bg-rose-500/5',
      'Registration': 'border-indigo-500/20 bg-indigo-500/5',
      'Status': 'border-amber-500/20 bg-amber-500/5',
      'DNS': 'border-purple-500/20 bg-purple-500/5'
    };
    const defaultIcon = `<svg class="w-5 h-5 text-slate-400" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M11.25 11.25l.041-.02a.75.75 0 111.063.852l-.708 2.836a.75.75 0 001.063.852l.041-.021M21 12a9 9 0 11-18 0 9 9 0 0118 0zm-9-3.75h.008v.008H12V8.25z"/></svg>`;
    let html = '<div class="whois-container mt-4 space-y-6">';
    if (title) {
      html += `
        <div class="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-500/10 border border-slate-500/20 text-xs font-mono text-slate-300 w-fit select-none">
          <svg class="w-3.5 h-3.5 text-slate-400" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M21 21l-5.197-5.197m0 0A7.5 7.5 0 105.196 5.196a7.5 7.5 0 0010.637 10.637z"/></svg>
          <span>${escapeHtml(title)}</span>
        </div>
      `;
    }
    html += '<div class="grid grid-cols-1 md:grid-cols-2 gap-4">';
    sections.forEach(section => {
      const icon = iconMap[section.name] || defaultIcon;
      const colorCls = cardColors[section.name] || 'border-slate-500/20 bg-slate-500/5';
      html += `
        <div class="whois-card p-4 rounded-xl border ${colorCls} transition-all duration-200 hover:border-white/20">
          <div class="flex items-center gap-2 mb-3 pb-2 border-b border-white/5">
            ${icon}
            <span class="text-xs font-bold uppercase tracking-wider text-slate-200">${escapeHtml(section.name)}</span>
          </div>
          <div class="space-y-2">
      `;
      section.items.forEach(item => {
        if (item.val.length === 1) {
          html += `
            <div class="flex justify-between items-center text-[11px] font-mono py-0.5">
              <span class="text-slate-400 select-none">${escapeHtml(item.key)}</span>
              <span class="text-slate-200 font-bold text-right">${escapeHtml(item.val[0])}</span>
            </div>
          `;
        } else {
          html += `
            <div class="flex flex-col text-[11px] font-mono py-1 border-t border-white/5 first:border-none mt-1">
              <span class="text-slate-400 select-none mb-1">${escapeHtml(item.key)}</span>
              <div class="flex flex-wrap gap-1 justify-end">
                ${item.val.map(v => `<span class="bg-white/5 px-2 py-0.5 rounded border border-white/10 text-[10px] text-slate-200 ml-1">${escapeHtml(v)}</span>`).join('')}
              </div>
            </div>
          `;
        }
      });
      html += `</div></div>`;
    });
    html += '</div></div>';
    return html;
  }

  function formatUdpPortScanHtml(text) {
    if (!text) return '';
    const lines = text.split('\n').map(l => l.trimEnd());
    let hostname = '';
    let completedAt = '';
    let method = '';
    let workingServices = [];
    let failedServices = [];
    let limitations = [];
    let summary = {};
    let currentSection = '';
    lines.forEach(line => {
      const trimmed = line.trim();
      if (!trimmed) return;
      if (trimmed.includes('Results for')) {
        hostname = trimmed.split('Results for')[1].trim();
        return;
      }
      if (trimmed.startsWith('Test completed at')) {
        completedAt = trimmed.split('Test completed at')[1].trim();
        return;
      }
      if (trimmed.startsWith('Method:')) {
        method = trimmed.split('Method:')[1].trim();
        return;
      }
      if (trimmed.includes('WORKING UDP SERVICES:')) {
        currentSection = 'working';
        return;
      }
      if (trimmed.includes('FAILED/UNAVAILABLE UDP SERVICES:')) {
        currentSection = 'failed';
        return;
      }
      if (trimmed.includes('LIMITATIONS')) {
        currentSection = 'limitations';
        return;
      }
      if (trimmed.includes('SUMMARY:')) {
        currentSection = 'summary';
        return;
      }
      if (currentSection === 'working') {
        if (trimmed.startsWith('Port') || trimmed.startsWith('----')) return;
        if (line.startsWith('        ') || line.startsWith('\t') || trimmed.startsWith('Details:')) {
          if (workingServices.length > 0) {
            const details = trimmed.replace(/^Details:\s*/, '');
            workingServices[workingServices.length - 1].details = details;
          }
        } else {
          const parts = trimmed.split(/\s{2,}/);
          if (parts.length >= 2) {
            const port = parts[0];
            const service = parts[1];
            const protocol = parts[2] || 'UDP';
            const response = parts[3] || 'N/A';
            const status = parts[4] || 'Responding';
            workingServices.push({ port, service, protocol, response, status, details: '' });
          }
        }
      } else if (currentSection === 'failed') {
        const dashIndex = trimmed.indexOf('-');
        if (dashIndex !== -1) {
          const servicePart = trimmed.substring(0, dashIndex).trim();
          const error = trimmed.substring(dashIndex + 1).trim();
          const spaceIndex = servicePart.indexOf(' ');
          let portProto = servicePart;
          let serviceName = 'Unknown';
          if (spaceIndex !== -1) {
            portProto = servicePart.substring(0, spaceIndex).trim();
            serviceName = servicePart.substring(spaceIndex + 1).trim();
          }
          failedServices.push({ portProto, service: serviceName, error });
        } else {
          failedServices.push({ portProto: trimmed, service: 'Unknown', error: 'Service unavailable' });
        }
      } else if (currentSection === 'limitations') {
        limitations.push(trimmed.replace(/^-\s*/, ''));
      } else if (currentSection === 'summary') {
        if (trimmed.includes(':')) {
          const [k, v] = trimmed.split(':').map(s => s.trim());
          summary[k] = v;
        }
      }
    });
    let html = '<div class="udp-scan-container mt-4 space-y-6">';
    html += `
      <div class="p-4 rounded-xl border border-blue-500/20 bg-blue-500/5 flex flex-wrap items-center justify-between gap-4">
        <div>
          <div class="text-[10px] uppercase font-bold tracking-wider text-blue-400 select-none">Target Host</div>
          <div class="text-sm font-mono font-bold text-slate-100">${escapeHtml(hostname || 'Target Host')}</div>
        </div>
        ${completedAt ? `<div><div class="text-[10px] uppercase font-bold tracking-wider text-slate-400 select-none">Scan Time</div><div class="text-xs font-mono text-slate-300">${escapeHtml(completedAt)}</div></div>` : ''}
        ${method ? `<div><div class="text-[10px] uppercase font-bold tracking-wider text-slate-400 select-none">Scan Method</div><div class="text-xs text-slate-300">${escapeHtml(method)}</div></div>` : ''}
      </div>
    `;
    if (workingServices.length > 0) {
      html += `<div><h4 class="text-xs font-bold uppercase tracking-wider text-slate-400 mb-3 select-none">Working Services</h4><div class="grid grid-cols-1 md:grid-cols-2 gap-4">`;
      workingServices.forEach(srv => {
        html += `
          <div class="p-4 rounded-xl border border-emerald-500/20 bg-emerald-500/5 hover:border-emerald-500/30 transition-all">
            <div class="flex items-center justify-between gap-2 mb-2 pb-1.5 border-b border-white/5">
              <div class="flex items-center gap-2">
                <svg class="w-4 h-4 text-emerald-400 shrink-0" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12.75L11.25 15 15 9.75M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
                <span class="text-xs font-mono font-bold text-slate-200">${escapeHtml(srv.service)}</span>
              </div>
              <span class="bg-emerald-500/10 border border-emerald-500/20 px-2 py-0.5 rounded text-[10px] font-mono text-emerald-400 font-bold">${escapeHtml(srv.port)}/${escapeHtml(srv.protocol)}</span>
            </div>
            <div class="space-y-1.5 text-[11px] font-mono">
              <div class="flex justify-between"><span class="text-slate-400 select-none">Latency:</span><span class="text-slate-200 font-semibold">${escapeHtml(srv.response)}</span></div>
              <div class="flex justify-between"><span class="text-slate-400 select-none">Status:</span><span class="text-slate-200 font-semibold">${escapeHtml(srv.status)}</span></div>
              ${srv.details ? `<div class="text-slate-400 border-t border-white/5 pt-1 mt-1 text-[10px] italic">${escapeHtml(srv.details)}</div>` : ''}
            </div>
          </div>
        `;
      });
      html += `</div></div>`;
    } else {
      html += `<div class="p-4 rounded-xl border border-slate-500/10 bg-slate-500/5 text-center text-xs text-slate-400 py-6">No active UDP services detected responding on target.</div>`;
    }
    if (failedServices.length > 0) {
      html += `<div><h4 class="text-xs font-bold uppercase tracking-wider text-slate-400 mb-3 select-none">Unavailable / Filtered Ports</h4><div class="bg-slate-500/5 border border-white/5 rounded-xl divide-y divide-white/5 overflow-hidden">`;
      failedServices.forEach(srv => {
        html += `
          <div class="p-3 flex items-center justify-between gap-4 text-xs font-mono">
            <div class="flex items-center gap-2">
              <span class="bg-white/5 border border-white/10 px-2 py-0.5 rounded text-[10px] text-slate-400 font-bold">${escapeHtml(srv.portProto)}</span>
              <span class="font-bold text-slate-300">${escapeHtml(srv.service)}</span>
            </div>
            <span class="text-slate-500 text-[11px]">${escapeHtml(srv.error)}</span>
          </div>
        `;
      });
      html += `</div></div>`;
    }
    html += '<div class="grid grid-cols-1 md:grid-cols-2 gap-4">';
    if (limitations.length > 0) {
      html += `
        <div class="p-4 rounded-xl border border-amber-500/15 bg-amber-500/5">
          <div class="flex items-center gap-2 mb-2">
            <svg class="w-4 h-4 text-amber-400" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126ZM12 15.75h.007v.008H12v-.008Z"/></svg>
            <span class="text-xs font-bold uppercase tracking-wider text-slate-200 select-none">Browser Constraints</span>
          </div>
          <ul class="list-disc pl-4 text-[10px] text-slate-400 space-y-1 font-mono">${limitations.map(lim => `<li>${escapeHtml(lim)}</li>`).join('')}</ul>
        </div>
      `;
    }
    if (Object.keys(summary).length > 0) {
      html += `
        <div class="p-4 rounded-xl border border-slate-500/20 bg-slate-500/5 flex flex-col justify-between">
          <div class="flex items-center gap-2 mb-3">
            <svg class="w-4 h-4 text-slate-400" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M3 13.125C3 12.504 3.504 12 4.125 12h2.25c.621 0 1.125.504 1.125 1.125v5.25c0 .621-.504 1.125-1.125 1.125h-2.25A1.125 1.125 0 013 18.375v-5.25zM9.75 8.625c0-.621.504-1.125 1.125-1.125h2.25c.621 0 1.125.504 1.125 1.125v9.75c0 .621-.504 1.125-1.125 1.125h-2.25a1.125 1.125 0 01-1.125-1.125v-9.75zM16.5 4.125c0-.621.504-1.125 1.125-1.125h2.25C20.496 3 21 3.504 21 4.125v14.25c0 .621-.504 1.125-1.125 1.125h-2.25a1.125 1.125 0 01-1.125-1.125V4.125z"/></svg>
            <span class="text-xs font-bold uppercase tracking-wider text-slate-200 select-none">Test Summary</span>
          </div>
          <div class="grid grid-cols-3 gap-2 text-center">
            <div class="bg-white/5 border border-white/5 p-2 rounded-lg"><div class="text-xs font-mono font-bold text-slate-100">${escapeHtml(summary['Total services tested'] || '0')}</div><div class="text-[9px] text-slate-500 uppercase tracking-wider">Tested</div></div>
            <div class="bg-emerald-500/5 border border-emerald-500/10 p-2 rounded-lg"><div class="text-xs font-mono font-bold text-emerald-400">${escapeHtml(summary['Working services'] || '0')}</div><div class="text-[9px] text-slate-500 uppercase tracking-wider">Working</div></div>
            <div class="bg-rose-500/5 border border-rose-500/10 p-2 rounded-lg"><div class="text-xs font-mono font-bold text-rose-400">${escapeHtml(summary['Failed/Unavailable'] || '0')}</div><div class="text-[9px] text-slate-500 uppercase tracking-wider">Failed</div></div>
          </div>
        </div>
      `;
    }
    html += '</div></div>';
    return html;
  }

  function formatTcpPortScanHtml(text) {
    if (!text) return '';
    const trimmed = text.trim();
    if (trimmed.includes('\n')) {
      const lines = trimmed.split('\n').map(l => l.trim()).filter(Boolean);
      let ip = '';
      let org = '';
      let location = '';
      let os = '';
      let hostnames = '';
      let ports = [];
      let vulns = '';
      let duration = '';
      let isParsingPorts = false;
      lines.forEach(line => {
        if (line.includes('IP:')) ip = line.split('IP:')[1].trim();
        else if (line.includes('Organization:')) org = line.split('Organization:')[1].trim();
        else if (line.includes('Location:')) location = line.split('Location:')[1].trim();
        else if (line.includes('OS:')) os = line.split('OS:')[1].trim();
        else if (line.includes('Hostnames:')) hostnames = line.split('Hostnames:')[1].trim();
        else if (line.includes('Open Ports & Services:') || line.includes('Open Ports')) {
          isParsingPorts = true;
        } else if (line.includes('Vulnerabilities:')) {
          vulns = line.split('Vulnerabilities:')[1].trim();
          isParsingPorts = false;
        } else if (line.includes('Scan duration:') || line.includes('duration:')) {
          duration = line.split('duration:')[1].trim();
          isParsingPorts = false;
        } else if (isParsingPorts && line.startsWith('-')) {
          ports.push(line.replace(/^-/, '').trim());
        }
      });
      let html = '<div class="tcp-scan-container mt-4 space-y-4">';
      html += `
        <div class="p-4 rounded-xl border border-blue-500/20 bg-blue-500/5">
          <div class="text-[10px] uppercase font-bold tracking-wider text-blue-400 mb-3 select-none">Host Intelligence</div>
          <div class="grid grid-cols-1 md:grid-cols-2 gap-x-6 gap-y-2 text-xs font-mono">
            <div class="flex justify-between py-0.5 border-b border-white/5 md:border-none"><span class="text-slate-400">Target IP</span><span class="text-slate-200 font-bold">${escapeHtml(ip || '—')}</span></div>
            <div class="flex justify-between py-0.5 border-b border-white/5 md:border-none"><span class="text-slate-400">Organization</span><span class="text-slate-200 font-bold">${escapeHtml(org || '—')}</span></div>
            <div class="flex justify-between py-0.5 border-b border-white/5 md:border-none"><span class="text-slate-400">Location</span><span class="text-slate-200 font-bold">${escapeHtml(location || '—')}</span></div>
            <div class="flex justify-between py-0.5 border-b border-white/5 md:border-none"><span class="text-slate-400">Operating System</span><span class="text-slate-200 font-bold">${escapeHtml(os || '—')}</span></div>
            ${hostnames ? `<div class="flex justify-between py-0.5 md:col-span-2 border-t border-white/5 mt-1 pt-1"><span class="text-slate-400">Hostnames</span><span class="text-slate-200 font-bold text-right">${escapeHtml(hostnames)}</span></div>` : ''}
          </div>
        </div>
      `;
      if (ports.length > 0) {
        html += `<div><h4 class="text-xs font-bold uppercase tracking-wider text-slate-400 mb-2 select-none">Open Ports Detected</h4><div class="grid grid-cols-1 md:grid-cols-2 gap-3">`;
        ports.forEach(p => {
          let portNum = '—';
          let srvName = 'Unknown';
          let latency = '';
          const latencyMatch = p.match(/\(Latency:\s*([^)]+)\)/i);
          if (latencyMatch) latency = latencyMatch[1];
          const cleanP = p.replace(/\(Latency:[^)]+\)/gi, '').trim();
          const dashIndex = cleanP.indexOf('-');
          if (dashIndex !== -1) {
            portNum = cleanP.substring(0, dashIndex).trim();
            srvName = cleanP.substring(dashIndex + 1).trim();
          } else {
            portNum = cleanP;
          }
          const numericPort = parseInt(portNum);
          const risk = isNaN(numericPort) ? 'low' : getPortRisk(numericPort);
          const riskColorMap = {
            high: 'border-rose-500/20 bg-rose-500/5 text-rose-400',
            medium: 'border-amber-500/20 bg-amber-500/5 text-amber-400',
            low: 'border-emerald-500/20 bg-emerald-500/5 text-emerald-400'
          };
          const borderBgClass = riskColorMap[risk] || 'border-slate-500/20 bg-slate-500/5 text-slate-400';
          html += `
            <div class="p-3.5 rounded-xl border ${borderBgClass} flex items-center justify-between gap-4">
              <div class="flex items-center gap-2.5">
                <div class="w-1.5 h-1.5 rounded-full bg-current shrink-0"></div>
                <div class="font-mono">
                  <span class="text-xs font-bold text-slate-200">Port ${escapeHtml(portNum)}</span>
                  <span class="text-[10px] text-slate-400 block">${escapeHtml(srvName)}</span>
                </div>
              </div>
              <div class="text-right font-mono">
                <span class="text-[9px] uppercase tracking-wider font-bold block opacity-75">${risk} Risk</span>
                ${latency ? `<span class="text-[10px] text-slate-400">${escapeHtml(latency)}</span>` : ''}
              </div>
            </div>
          `;
        });
        html += '</div></div>';
      } else {
        html += `<div class="p-4 rounded-xl border border-slate-500/10 bg-slate-500/5 text-center text-xs text-slate-400 py-6">No open TCP ports detected.</div>`;
      }
      if (vulns || duration) {
        html += `
          <div class="grid grid-cols-2 gap-4 text-center text-xs font-mono pt-2">
            ${vulns ? `<div class="p-2 border border-rose-500/15 bg-rose-500/5 rounded-lg"><div class="font-bold text-rose-400">${escapeHtml(vulns)}</div><div class="text-[9px] text-slate-500 uppercase tracking-wider mt-0.5">Vulnerabilities</div></div>` : ''}
            ${duration ? `<div class="p-2 border border-slate-500/15 bg-slate-500/5 rounded-lg"><div class="font-bold text-slate-300">${escapeHtml(duration)}</div><div class="text-[9px] text-slate-500 uppercase tracking-wider mt-0.5">Duration</div></div>` : ''}
          </div>
        `;
      }
      html += '</div>';
      return html;
    }
    if (trimmed.toLowerCase().includes('open')) {
      const portMatch = trimmed.match(/Port\s+(\d+)/i);
      const serviceMatch = trimmed.match(/-\s*([^(]+)/);
      const latencyMatch = trimmed.match(/\(Latency:\s*([^)]+)\)/i);
      const portNum = portMatch ? portMatch[1] : '—';
      const service = serviceMatch ? serviceMatch[1].trim() : 'Unknown';
      const latency = latencyMatch ? latencyMatch[1] : '';
      const numericPort = parseInt(portNum);
      const risk = isNaN(numericPort) ? 'low' : getPortRisk(numericPort);
      const riskColorMap = {
        high: 'border-rose-500/20 bg-rose-500/5 text-rose-400',
        medium: 'border-amber-500/20 bg-amber-500/5 text-amber-400',
        low: 'border-emerald-500/20 bg-emerald-500/5 text-emerald-400'
      };
      const borderBgClass = riskColorMap[risk] || 'border-slate-500/20 bg-slate-500/5 text-slate-400';
      return `
        <div class="tcp-scan-container mt-4">
          <div class="p-5 rounded-xl border ${borderBgClass} flex items-center justify-between gap-4 transition-all hover:border-white/10">
            <div class="flex items-center gap-3">
              <div class="w-2.5 h-2.5 rounded-full bg-emerald-400 shrink-0 shadow-[0_0_8px_rgba(52,211,153,0.4)] animate-pulse"></div>
              <div>
                <div class="font-mono text-sm font-bold text-slate-200">Port ${escapeHtml(portNum)} is OPEN</div>
                <div class="text-xs text-slate-400 font-mono mt-0.5">Service: ${escapeHtml(service)}</div>
              </div>
            </div>
            <div class="text-right font-mono">
              <span class="bg-white/5 border border-white/10 px-2 py-0.5 rounded text-[10px] font-bold text-slate-300 uppercase tracking-wider select-none">${escapeHtml(risk)} Risk</span>
              ${latency ? `<span class="text-xs text-slate-400 block mt-1">${escapeHtml(latency)}</span>` : ''}
            </div>
          </div>
        </div>
      `;
    }
    const isFail = trimmed.toLowerCase().includes('fail') || trimmed.toLowerCase().includes('error');
    const borderBgClass = isFail ? 'border-rose-500/20 bg-rose-500/5 text-rose-300' : 'border-blue-500/20 bg-blue-500/5 text-blue-300';
    const icon = isFail ? `
      <svg class="w-4 h-4 text-rose-400 shrink-0" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M12 9v3.75m0-10.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.75c0 5.592 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.57-.598-3.75h-.152c-3.196 0-6.1-1.249-8.25-3.286zm0 13.036h.008v.008H12v-.008z"/></svg>` : `
      <svg class="w-4 h-4 text-blue-400 shrink-0" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M11.25 11.25l.041-.02a.75.75 0 111.063.852l-.708 2.836a.75.75 0 001.063.852l.041-.021M21 12a9 9 0 11-18 0 9 9 0 0118 0zm-9-3.75h.008v.008H12v-.008z"/></svg>`;
    return `
      <div class="tcp-scan-container mt-4">
        <div class="p-4 rounded-xl border ${borderBgClass} flex items-start gap-2.5 text-xs">
          ${icon}
          <div class="font-sans leading-relaxed whitespace-pre-wrap">${escapeHtml(trimmed)}</div>
        </div>
      </div>
    `;
  }

  function showFindingDetailModal(findingId) {
    const finding = allFindings.find(f => String(f.id || `${f.title}::${f.severity}`) === String(findingId));
    if (!finding) return;

    document.getElementById('finding-detail-modal-title').textContent = finding.title || 'Untitled Finding';
    
    const driverEl = document.getElementById('fd-driver');
    if (finding.driver_id) {
      driverEl.textContent = finding.driver_id;
      driverEl.classList.remove('hidden');
    } else {
      driverEl.classList.add('hidden');
    }

    const sev = (finding.severity || 'info').toLowerCase();
    const topBar = document.getElementById('fd-severity-top-bar');
    const sevColors = {
      critical: 'var(--cg-danger)',
      high: '#F97316',
      medium: 'var(--cg-warning)',
      low: 'var(--cg-info)',
      info: 'var(--cg-text-3)'
    };
    if (topBar) topBar.style.backgroundColor = sevColors[sev] || 'var(--cg-text-3)';

    const sevBadge = document.getElementById('fd-severity-badge');
    if (sevBadge) {
      sevBadge.textContent = sev.toUpperCase();
      sevBadge.className = `severity-badge sev-${sev}`;
    }

    const cvssBadge = document.getElementById('fd-cvss-badge');
    if (cvssBadge) {
      if (finding.cvss_score) {
        cvssBadge.textContent = `CVSS ${finding.cvss_score}`;
        cvssBadge.className = `cvss-badge cvss-${getCVSSSeverity(finding.cvss_score)}`;
        cvssBadge.classList.remove('hidden');
      } else {
        cvssBadge.classList.add('hidden');
      }
    }

    const statusBadge = document.getElementById('fd-status-badge');
    const status = (finding.status || 'open').toLowerCase();
    if (statusBadge) {
      statusBadge.textContent = status.toUpperCase();
      statusBadge.className = `finding-status status-${status}`;
    }

    const descSection = document.getElementById('fd-desc-section');
    const descText = document.getElementById('fd-description');
    if (descText && finding.description) {
      const isShodan = (finding.driver_id === 'SHODAN_SCANNER' || (finding.title && (finding.title.includes('Shodan') || finding.title.includes('Port Scanner'))));
      const isIPGeo = (finding.driver_id === 'IP_GEOLOCATION' || (finding.title && finding.title.includes('Geolocation')));
      const isReverseDNS = (finding.driver_id === 'REVERSE_DNS' || (finding.title && finding.title.includes('Reverse DNS')));
      const isWhois = (finding.driver_id === 'WHOIS_LOOKUP' || (finding.title && finding.title.includes('WHOIS')));
      const isUdpScan = (finding.driver_id === 'UDP_PORT_SCAN' || (finding.title && (finding.title.includes('UDP Services') || finding.title.includes('UDP Port') || finding.title.includes('UDP Service'))));
      const isTcpScan = (finding.driver_id === 'TCP_PORT_SCAN' || (finding.title && (finding.title.includes('TCP Connectivity') || finding.title.includes('TCP Port') || finding.title.includes('TCP Service'))));

      if (isShodan) {
        descText.className = "select-text text-sm w-full";
        descText.innerHTML = formatShodanScannerHtml(finding.description);
      } else if (isIPGeo) {
        descText.className = "select-text text-sm w-full";
        descText.innerHTML = formatIPGeolocationHtml(finding.description);
      } else if (isReverseDNS) {
        descText.className = "select-text text-sm w-full";
        descText.innerHTML = formatReverseDNSHtml(finding.description);
      } else if (isWhois) {
        descText.className = "select-text text-sm w-full";
        descText.innerHTML = formatWhoisHtml(finding.description);
      } else if (isUdpScan) {
        descText.className = "select-text text-sm w-full";
        descText.innerHTML = formatUdpPortScanHtml(finding.description);
      } else if (isTcpScan) {
        descText.className = "select-text text-sm w-full";
        descText.innerHTML = formatTcpPortScanHtml(finding.description);
      } else {
        descText.className = "text-slate-300 leading-relaxed break-words whitespace-pre-wrap select-text";
        descText.textContent = finding.description;
      }
      if (descSection) descSection.classList.remove('hidden');
    } else if (descSection) {
      descSection.classList.add('hidden');
    }

    const urlSection = document.getElementById('fd-url-section');
    const urlText = document.getElementById('fd-url-text');
    const urlLink = document.getElementById('fd-url-link');
    if (urlSection && urlText && urlLink) {
      if (finding.affected_url) {
        urlText.textContent = finding.affected_url;
        urlLink.href = finding.affected_url;
        urlSection.classList.remove('hidden');
      } else {
        urlSection.classList.add('hidden');
      }
    }

    const vectorSection = document.getElementById('fd-vector-section');
    const vectorText = document.getElementById('fd-vector-text');
    if (vectorSection && vectorText) {
      if (finding.cvss_vector) {
        vectorText.textContent = finding.cvss_vector;
        vectorSection.classList.remove('hidden');
      } else {
        vectorSection.classList.add('hidden');
      }
    }

    const proofSection = document.getElementById('fd-proof-section');
    const proofText = document.getElementById('fd-proof');
    if (proofSection && proofText) {
      if (finding.proof) {
        proofText.textContent = finding.proof;
        proofSection.classList.remove('hidden');
      } else {
        proofSection.classList.add('hidden');
      }
    }

    const remSection = document.getElementById('fd-remediation-section');
    const remText = document.getElementById('fd-remediation');
    if (remSection && remText) {
      if (finding.remediation) {
        remText.textContent = finding.remediation;
        remSection.classList.remove('hidden');
      } else {
        remSection.classList.add('hidden');
      }
    }

    const tagsSection = document.getElementById('fd-tags-section');
    const tagsContainer = document.getElementById('fd-tags');
    if (tagsSection && tagsContainer) {
      tagsContainer.innerHTML = '';
      if (finding.tags && finding.tags.length) {
        finding.tags.forEach(tag => {
          const span = document.createElement('span');
          span.className = 'finding-tag';
          span.textContent = tag;
          tagsContainer.appendChild(span);
        });
        tagsSection.classList.remove('hidden');
      } else {
        tagsSection.classList.add('hidden');
      }
    }

    const idEl = document.getElementById('fd-id');
    if (idEl) idEl.textContent = finding.id || '';

    const modal = document.getElementById('finding-detail-modal');
    const modalContent = document.getElementById('finding-detail-modal-content');
    if (modal && modalContent) {
      modal.classList.remove('hidden');
      setTimeout(() => {
        modalContent.classList.remove('scale-95', 'opacity-0');
        modalContent.classList.add('scale-100', 'opacity-100');
      }, 10);
    }
  }

  function hideFindingDetailModal() {
    const modal = document.getElementById('finding-detail-modal');
    const modalContent = document.getElementById('finding-detail-modal-content');
    if (!modal) return;
    if (modalContent) {
      modalContent.classList.remove('scale-100', 'opacity-100');
      modalContent.classList.add('scale-95', 'opacity-0');
    }
    setTimeout(() => {
      modal.classList.add('hidden');
    }, 150);
  }

  function copyToClipboard(textOrId, btn) {
    if (!textOrId) return;
    let text = textOrId;
    if (typeof textOrId === 'string' && (textOrId.startsWith('fd-') || textOrId.startsWith('ep-'))) {
      const el = document.getElementById(textOrId);
      if (el) {
        text = el.textContent || el.value || '';
      }
    }
    if (!text) return;
    navigator.clipboard.writeText(text).then(() => {
      if (btn) {
        const origHTML = btn.innerHTML;
        btn.innerHTML = `<svg class="w-3.5 h-3.5 text-emerald-400" fill="none" stroke="currentColor" stroke-width="2.5" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="m4.5 12.75 6 6 9-13.5"/></svg>`;
        btn.classList.add("text-emerald-400");
        btn.classList.add("bg-emerald-500/10");
        setTimeout(() => {
          btn.innerHTML = origHTML;
          btn.classList.remove("text-emerald-400");
          btn.classList.remove("bg-emerald-500/10");
        }, 2000);
      }
    });
  }

  // Expose finding modal handlers globally on window
  window.showFindingDetailModal = showFindingDetailModal;
  window.hideFindingDetailModal = hideFindingDetailModal;
  window.copyToClipboard = copyToClipboard;

  /* ─── Expose select functions to HTML onclick attributes ─────────────── */
  window._scanProgress = {
    handlePause,
    handleResume,
    handleCancel,
    doCancel,
    closeCancelDialog,
    loadFindings,
    toggleMetadata: function () {
      const panel = document.getElementById("sp-metadata-panel");
      if (panel) panel.classList.toggle("hidden");
    },
  };
})();
