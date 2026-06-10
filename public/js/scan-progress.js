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
  const FINDINGS_POLL_MS    = 15_000;  // poll findings every 15 s while running
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

      renderHeader(scanSession);
      renderControlButtons(currentStatus);
      hideSkeleton();

      // Load initial findings
      await loadFindings();

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
      try {
        const pendingRaw = sessionStorage.getItem("cg_pending_scan");
        if (pendingRaw) {
          const pending = JSON.parse(pendingRaw);
          if (pending.sessionId === scanJobId && pending.selectedFrontendTools?.length > 0) {
            const toolsToRun = pending.selectedFrontendTools;
            // Remove them from sessionStorage so they don't execute again on page refresh
            pending.selectedFrontendTools = [];
            sessionStorage.setItem("cg_pending_scan", JSON.stringify(pending));

            // Execute the tools asynchronously
            setTimeout(() => {
              runFrontendTools(toolsToRun, pending.targetValue);
            }, 1000);
          }
        }
      } catch (err) {
        console.error("[ScanProgress] Failed to run pending frontend tools:", err);
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
  async function runFrontendTools(selectedTools, targetValue) {
    appendTerminalSystem("Starting selected network analysis tools…");

    // Define custom hooks to route tools' outputs into the progress page UI
    window.onFrontendToolLog = function (msg, scanner) {
      appendTerminalLine(`[INFO] [${scanner}] ${msg}`);
    };

    window.onFrontendToolResult = function ({ timestamp, feature, message, status, details }) {
      let badge = "[INFO]";
      if (status === "danger" || status === "threat") badge = "[ERROR]";
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
    for (const toolId of selectedTools) {
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
    }

    appendTerminalSystem("All selected network analysis tools completed.");

    // Mark scan completed
    if (typeof scanJobId === "string" && scanJobId.startsWith("frontend_")) {
      if (window.scannerAPI && typeof window.scannerAPI.completeFrontendScan === "function") {
        window.scannerAPI.completeFrontendScan(scanJobId);
      }
      onScanComplete({ status: "completed" });
    }
  }

  /* ═══════════════════════════════════════════════════════════════════════
     HEADER RENDERING
  ═══════════════════════════════════════════════════════════════════════ */
  function renderHeader(session) {
    const s = session || {};
    const target = s.target || {};

    _set("sp-target-name", target.value || "Unknown Target");
    
    let displayId = s.id || "";
    if (displayId.startsWith("frontend_")) {
      displayId = displayId.replace("frontend_", "");
    }
    _set("sp-scan-id-short", displayId.substring(0, 8).toUpperCase());

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
      if (session.status !== currentStatus) {
        // Status changed
        renderControlButtons(session.status);
        if (session.status === "completed" || session.status === "cancelled") {
          stopAllPolling();
          teardownWebSocket();
          appendTerminalSystem(`Scan session ended (${session.status}).`);
          // Refresh findings one last time
          await loadFindings();
        }
      }
      scanSession = session;
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
      return `<tr class="sp-table-row">
        <td class="sp-td sp-td--title">${escHtml(f.title || "Untitled Finding")}</td>
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

  function onScanComplete(data) {
    const status = data?.status || data?.scan_session?.status || "completed";
    renderControlButtons(status);
    stopAllPolling();
    teardownWebSocket();
    appendTerminalSystem("Scan session ended.");
    loadFindings();
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
    renderFindingsTable(allFindings);
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
