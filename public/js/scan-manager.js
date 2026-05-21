(function () {
  "use strict";

  /* ─── Config ──────────────────────────────────────────────────────────── */
  const API_BASE = "https://peptonelike-lelia-interdepartmentally.ngrok-free.dev/api/";
  const JWT_KEY  = "cyberguard_jwt";

  /* ─── State ───────────────────────────────────────────────────────────── */
  const scanState = {
    sessionId       : null,
    targetId        : null,
    targetLabel     : null,
    targetValue     : null,
    targetType      : null,
    status          : "idle",
    findings        : [],
    pollingInterval : null,
    seenFindingIds  : new Set(),
    startedAt       : null,
    finishedAt      : null,
  };

  let _scanners = [];
  let _selected = new Set();

  // ── Echo state ────────────────────────────────────────────────────────────
  let activeScanChannel = null;
  let activeScanJobId   = null;
  let terminalLogs      = [];

  // ── Completion guards ─────────────────────────────────────────────────────
  let scanCompleted          = false;
  let scanTimeoutId          = null;
  let statusPollingInterval  = null;
  const MAX_SCAN_DURATION_MS = 5 * 60 * 1000; // 5 min

  /* ═══════════════════════════════════════════════════════════════════════
     API HELPER
  ═══════════════════════════════════════════════════════════════════════ */
  function apiFetch(endpoint, opts = {}) {
    const token   = localStorage.getItem(JWT_KEY);
    const headers = {
      "Accept"                  : "application/json",
      "Content-Type"            : "application/json",
      "ngrok-skip-browser-warning": "true",
    };
    if (token) headers["Authorization"] = `Bearer ${token}`;
    return fetch(API_BASE + endpoint.replace(/^\//, ""), { headers, ...opts });
  }

  /* ═══════════════════════════════════════════════════════════════════════
     SCANNER MODAL
  ═══════════════════════════════════════════════════════════════════════ */
  async function loadScanners() {
    try {
      const res = await apiFetch("/scanners");
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      _scanners = Array.isArray(data.scanners) ? data.scanners : [];
    } catch (err) {
      console.error("[ScanManager] loadScanners failed:", err);
      _scanners = [];
    }
  }

  async function openScanModal(buttonEl) {
    if (scanState.status === "running") {
      notify("A scan is already running.", "warning");
      return;
    }

    scanState.targetId    = buttonEl.dataset.tid || "";
    scanState.targetLabel = buttonEl.dataset.lbl || "";
    scanState.targetValue = buttonEl.dataset.val || "";
    scanState.targetType  = buttonEl.dataset.typ || "domain";
    _selected.clear();

    const modal   = document.getElementById("scan-scanner-modal");
    if (!modal) return;

    const titleEl  = document.getElementById("scan-modal-target-label");
    const detailEl = document.getElementById("scan-modal-target-detail");
    if (titleEl)  titleEl.textContent  = scanState.targetLabel || "Target";
    if (detailEl) detailEl.textContent = `${scanState.targetValue} (${scanState.targetType})`;

    const bodyEl = document.getElementById("scan-modal-scanner-body");
    if (bodyEl) bodyEl.innerHTML = `
      <div class="flex items-center justify-center py-10 text-slate-400 text-sm gap-3">
        <span class="cyber-spinner-sm"></span>Loading scanners…
      </div>`;

    modal.classList.remove("hidden");
    await loadScanners();
    renderScannerList();
  }

  function renderScannerList() {
    const bodyEl = document.getElementById("scan-modal-scanner-body");
    if (!bodyEl) return;

    if (_scanners.length === 0) {
      bodyEl.innerHTML = `<p class="text-sm text-slate-400 text-center py-8">No scanners available.</p>`;
      return;
    }

    const groups = {};
    _scanners.forEach((s) => {
      const cat = (s.category || "other").toLowerCase();
      if (!groups[cat]) groups[cat] = [];
      groups[cat].push(s);
    });

    let html = "";
    for (const [cat, list] of Object.entries(groups)) {
      html += `
        <div class="mb-5" data-scan-group="${escAttr(cat)}">
          <div class="flex items-center justify-between mb-3">
            <span class="text-xs font-bold uppercase tracking-widest text-[var(--cg-accent)]">
              ${escHtml(cat)}
            </span>
            <button type="button"
              class="text-xs text-[var(--cg-info)] hover:underline focus:outline-none"
              onclick="window.ScanManager._toggleGroup('${escAttr(cat)}')">
              Select All
            </button>
          </div>
          <div class="space-y-2">${list.map(renderScannerCard).join("")}</div>
        </div>`;
    }
    bodyEl.innerHTML = html;
  }

  function renderScannerCard(s) {
    const id   = escAttr(s.id || "");
    const name = escHtml(s.name || "");
    const catBadgeCls = ({
      recon: "text-[#38BDF8] bg-[rgba(56,189,248,0.1)] border-[rgba(56,189,248,0.25)]",
      vuln : "text-[#FB923C] bg-[rgba(251,146,60,0.1)] border-[rgba(251,146,60,0.25)]",
      audit: "text-[#A78BFA] bg-[rgba(167,139,250,0.1)] border-[rgba(167,139,250,0.25)]",
    })[s.category] || "text-slate-400 bg-slate-800/50 border-slate-700";

    return `
      <label class="scan-card flex items-center gap-3 p-3 rounded-xl border border-[var(--cg-border)]
                    hover:border-[var(--cg-accent)] cursor-pointer transition-all select-none"
             data-scanner-id="${id}">
        <input type="checkbox" class="scan-cb w-4 h-4 rounded" value="${id}"
               onchange="window.ScanManager._onCheckbox(this)" />
        <span class="flex-1 text-sm text-white">${name}</span>
        <span class="text-xs px-2 py-0.5 rounded-full border font-semibold ${catBadgeCls}">
          ${escHtml(s.category || "")}
        </span>
      </label>`;
  }

  function _toggleGroup(cat) {
    const group = document.querySelector(`[data-scan-group="${cat}"]`);
    if (!group) return;
    const cbs = [...group.querySelectorAll(".scan-cb")];
    const allOn = cbs.every((cb) => cb.checked);
    cbs.forEach((cb) => { cb.checked = !allOn; _syncSelection(cb); });
    _refreshCardStyles(group);
  }

  function _onCheckbox(cb) {
    _syncSelection(cb);
    const group = cb.closest("[data-scan-group]");
    if (group) _refreshCardStyles(group);
  }

  function _syncSelection(cb) {
    if (cb.checked) _selected.add(cb.value);
    else _selected.delete(cb.value);
  }

  function _refreshCardStyles(group) {
    group.querySelectorAll(".scan-card").forEach((card) => {
      const cb = card.querySelector(".scan-cb");
      card.classList.toggle("border-[var(--cg-accent)]",         !!cb?.checked);
      card.classList.toggle("bg-[rgba(167,139,250,0.07)]", !!cb?.checked);
    });
  }

  function closeScanModal() {
    document.getElementById("scan-scanner-modal")?.classList.add("hidden");
  }

  /* ═══════════════════════════════════════════════════════════════════════
     START SCAN — KEY FIX: driver_ids vs driver_id
  ═══════════════════════════════════════════════════════════════════════ */
  async function startScan() {
    if (_selected.size === 0) {
      notify("Please select at least one scanner.", "warning");
      return;
    }
    if (scanState.status === "running") {
      notify("A scan is already running.", "warning");
      return;
    }

    const btn = document.getElementById("scan-start-btn");
    _btnLoading(btn, "Starting…");

    try {
      // ── Build payload ────────────────────────────────────────────────────
      // The backend doc shows driver_id (singular string).
      // We support multiple by sending the first selected for single-driver
      // backends, and also include driver_ids array for multi-driver backends.
      const selectedArray = [..._selected];
      const payload = {
        target_id : scanState.targetId,
        driver_ids: selectedArray,        // multi-driver support
        driver_id : selectedArray[0],     // single-driver fallback
      };

      console.log("[ScanManager] POST /scan/start →", payload);

      const res = await apiFetch("/scan/start", {
        method: "POST",
        body  : JSON.stringify(payload),
      });

      let data = {};
      try { data = await res.json(); } catch (_) {}

      console.log("[ScanManager] /scan/start response:", res.status, data);

      if (!res.ok) {
        notify(data.message || `Failed to start scan (${res.status}).`, "error");
        return;
      }

      // ── Extract session ID (handle multiple response shapes) ─────────────
      const sessionId =
        data?.scan_job?.id          ||
        data?.scan_session_id       ||
        data?.session_id            ||
        data?.id;

      if (!sessionId) {
        console.error("[ScanManager] Unexpected response shape:", data);
        notify("Server did not return a scan job ID.", "error");
        return;
      }

      // ── Transition to running state ──────────────────────────────────────
      closeScanModal();
      scanState.sessionId      = sessionId;
      scanState.status         = "running";
      scanState.findings       = [];
      scanState.seenFindingIds = new Set();
      scanState.startedAt      = new Date().toISOString();
      scanState.finishedAt     = null;
      scanCompleted            = false;

      // ── Navigate to dedicated scan progress page ─────────────────────────
      // The scan-progress page will handle terminal, findings, controls.
      // Store session info so scan-progress.js can read it if needed.
      try {
        sessionStorage.setItem("cg_pending_scan", JSON.stringify({
          sessionId,
          targetValue : scanState.targetValue,
          targetId    : scanState.targetId,
          startedAt   : scanState.startedAt,
        }));
      } catch (_) {}

      notify("Scan started — opening progress view…", "success");

      // Small delay so the toast is visible before navigation
      setTimeout(() => {
        window.location.href = `/scan/${sessionId}`;
      }, 600);

    } catch (err) {
      console.error("[ScanManager] startScan error:", err);
      notify(err.message || "Failed to start scan.", "error");
    } finally {
      _btnRestore(btn);
    }
  }

  /**
   * Waits up to 5 s for the Pusher/Reverb WebSocket to reach "connected" state.
   * Resolves immediately if already connected or if Echo isn't available.
   */
  function waitForEchoConnection() {
    return new Promise((resolve) => {
      if (!window.echoInstance) { resolve(); return; }

      const pusher = window.echoInstance.connector?.pusher;
      if (!pusher) { resolve(); return; }

      // Already connected
      if (pusher.connection.state === "connected") { resolve(); return; }

      console.log("[Echo] Waiting for connection…");
      const timeout = setTimeout(resolve, 5000); // give up after 5 s

      pusher.connection.bind("connected", () => {
        clearTimeout(timeout);
        console.log("[Echo] Connection established — proceeding with subscription.");
        resolve();
      });
    });
  }

  /* ═══════════════════════════════════════════════════════════════════════
     SCAN PANEL
  ═══════════════════════════════════════════════════════════════════════ */
  function showScanPanel() {
    const panel = document.getElementById("scan-live-panel");
    if (!panel) return;
    terminalLogs = [];
    panel.classList.remove("hidden");
    panel.innerHTML = buildPanelHTML();
    panel.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }

  function buildPanelHTML() {
    return `
      <!-- Header -->
      <div class="flex items-center justify-between flex-wrap gap-3">
        <div class="flex items-center gap-3">
          <span class="flex items-center gap-1.5 text-xs font-bold uppercase tracking-wider"
                style="color:var(--cg-danger)">
            <span class="inline-block w-2 h-2 rounded-full animate-pulse"
                  style="background:var(--cg-danger)"></span>
            LIVE
          </span>
          <p class="text-sm font-semibold text-white">
            Scanning:
            <span class="font-mono" style="color:var(--cg-info)">
              ${escHtml(scanState.targetValue || "")}
            </span>
          </p>
        </div>
        <div class="flex items-center gap-3">
          <span class="text-xs text-slate-500 font-mono">
            Session: ${escHtml(scanState.sessionId || "")}
          </span>
          <button onclick="window.ScanManager.closeScanPanel()"
                  class="cyber-btn-ghost text-xs px-2 py-1 rounded" title="Close">✕</button>
        </div>
      </div>

      <!-- Status bar -->
      <div id="scan-status-bar"
           class="flex items-center gap-2 text-xs text-slate-400 py-1 border-b border-[var(--cg-border)]">
        <span class="cyber-spinner-sm"></span>
        <span id="scan-status-text">Initializing…</span>
      </div>

      <!-- Debug info (remove in production) -->
      <div id="scan-debug-bar"
           class="text-xs font-mono text-slate-500 py-1 px-2 rounded bg-black/20">
        Echo: <span id="dbg-echo">checking…</span> |
        Channel: <span id="dbg-channel">—</span> |
        Events received: <span id="dbg-events">0</span>
      </div>

      <!-- Terminal -->
      <div class="scan-terminal-wrapper">
        <div class="terminal-header">
          <div class="terminal-dots">
            <span class="dot dot-red"></span>
            <span class="dot dot-yellow"></span>
            <span class="dot dot-green"></span>
          </div>
          <span class="terminal-title">SCAN TERMINAL</span>
          <button class="terminal-clear-btn"
                  onclick="window.ScanManager.clearTerminal()">Clear</button>
        </div>
        <div id="scan-terminal" class="scan-terminal"><div class="terminal-line terminal-default">Waiting for scan to start…</div></div>
      </div>

      <!-- Findings stream -->
      <div id="scan-findings-stream"
           class="space-y-3 max-h-[520px] overflow-y-auto pr-1 scroll-smooth">
        <p id="scan-waiting-msg" class="text-xs text-slate-500 italic py-2">
          Waiting for findings…
        </p>
      </div>

      <!-- Completed state -->
      <div id="scan-complete-state" class="hidden mt-2 p-4 rounded-xl border"
           style="border-color:var(--cg-success);background:rgba(52,211,153,0.06)">
        <div class="flex items-center gap-2 mb-2">
          <svg class="w-5 h-5" style="color:var(--cg-success)" fill="none"
               viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round"
                  d="M9 12.75 11.25 15 15 9.75M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0Z"/>
          </svg>
          <span class="font-bold text-sm" style="color:var(--cg-success)">Scan Completed</span>
        </div>
        <div class="text-sm text-slate-300 space-y-1">
          <p>Total Findings: <strong id="scan-total-findings" class="text-white">0</strong></p>
          <p>Duration: <strong id="scan-duration" class="text-white">—</strong></p>
        </div>
      </div>

      <!-- Failed state -->
      <div id="scan-failed-state" class="hidden mt-2 p-4 rounded-xl border"
           style="border-color:var(--cg-danger);background:rgba(248,113,113,0.06)">
        <div class="flex items-center gap-2 mb-2">
          <svg class="w-5 h-5" style="color:var(--cg-danger)" fill="none"
               viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round"
                  d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71
                     c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5
                     -3.898 0L2.697 16.126ZM12 15.75h.007v.008H12v-.008Z"/>
          </svg>
          <span class="font-bold text-sm" style="color:var(--cg-danger)">Scan Failed</span>
        </div>
        <pre id="scan-error-log"
             class="text-xs text-slate-400 mt-1 font-mono whitespace-pre-wrap break-all"></pre>
      </div>`;
  }

  function closeScanPanel() {
    _clearPolling();
    stopStatusPolling();
    clearScanTimeout();
    scanCompleted = true;
    if (activeScanJobId) teardownScanChannel(activeScanJobId);
    scanState.status = "idle";
    document.getElementById("scan-live-panel")?.classList.add("hidden");
  }

  /* ═══════════════════════════════════════════════════════════════════════
     ECHO SUBSCRIPTION — THE CRITICAL SECTION
     ─────────────────────────────────────────────────────────────────────
     ARCHITECTURE DECISION:
     We use ONLY bind_global to route ALL events. We do NOT also call
     Echo's .listen() because Pusher.js internally uses bind() for both
     bind_global and .listen(), and when both are active on the same
     channel+event, Pusher fires the callback twice OR the global handler
     swallows the event before the named handler sees it (depending on
     library version). Using a single routing mechanism eliminates this
     entire class of bugs.
  ═══════════════════════════════════════════════════════════════════════ */
  /** Track whether we've received at least one real data event */
  let _hasReceivedDataEvent = false;
  let _lastEventTimestamp   = 0;
  let _inactivityCheckId    = null;
  const INACTIVITY_TIMEOUT_MS = 45_000; // 45 s of silence after first event → complete

  function subscribeToScanChannel(sessionId) {
    _updateDebugBar();
    _hasReceivedDataEvent = false;
    _lastEventTimestamp   = 0;

    if (!window.echoInstance) {
      console.warn("[ScanManager] Echo not initialised — using polling only.");
      _appendTerminalSystem("[!] WebSocket unavailable — using polling fallback");
      _setStatusText("WebSocket unavailable — polling every 5 s…");
      return;
    }

    const pusher  = window.echoInstance.connector?.pusher;
    const wsState = pusher?.connection?.state || "unknown";
    console.log("[Echo] WebSocket state before subscribe:", wsState);
    _appendTerminalSystem(`WebSocket state: ${wsState}`);

    if (wsState !== "connected") {
      _appendTerminalSystem(`[!] WebSocket not ready (${wsState}) — polling active`);
    }

    // ── Tear down any stale subscription ─────────────────────────────────
    if (activeScanJobId) teardownScanChannel(activeScanJobId);

    activeScanJobId   = sessionId;
    const channelName = `scan.${sessionId}`;

    console.log("[Echo] Subscribing to channel:", channelName);
    _appendTerminalSystem(`Subscribing to channel: ${channelName}`);

    const dbgChannel = document.getElementById("dbg-channel");
    if (dbgChannel) dbgChannel.textContent = channelName;

    // ── Subscribe via Echo (creates the Pusher subscription internally) ──
    activeScanChannel = window.echoInstance.channel(channelName);

    // ── Attach bind_global to the Pusher channel ─────────────────────────
    // The channel object may not be available synchronously because Pusher
    // creates it asynchronously. We poll until it appears (max 5 s).
    _attachGlobalHandler(pusher, channelName, 0);

    // ── Subscription lifecycle callbacks ─────────────────────────────────
    if (activeScanChannel.subscribed) {
      activeScanChannel.subscribed(() => {
        console.log("[Echo] Subscribed to:", channelName);
        _appendTerminalSystem("[OK] Live channel connected");
        _setStatusText("Connected — receiving live stream…");
        _updateDebugBar();
      });
    }

    if (activeScanChannel.error) {
      activeScanChannel.error((err) => {
        console.error("[Echo] Channel subscription error:", err);
        _appendTerminalSystem(`[ERR] Channel error: ${JSON.stringify(err)}`);
        _setStatusText("WebSocket error — polling active");
      });
    }

    _setStatusText("Connecting to live stream…");

    // ── Start inactivity watcher ─────────────────────────────────────────
    _startInactivityWatcher();
  }

  /**
   * Polls for the Pusher channel object and attaches bind_global once found.
   * Retries up to 10 times at 500 ms intervals (total 5 s).
   */
  function _attachGlobalHandler(pusher, channelName, attempt) {
    if (!pusher || attempt > 10) {
      if (attempt > 10) {
        console.warn("[Echo] Pusher channel never appeared after 5 s — relying on polling");
        _appendTerminalSystem("[!] WebSocket channel not found — polling is active");
      }
      return;
    }

    const pusherChannel = pusher.channel(channelName);
    if (!pusherChannel) {
      setTimeout(() => _attachGlobalHandler(pusher, channelName, attempt + 1), 500);
      return;
    }

    // ── Single global event router ─────────────────────────────────────
    pusherChannel.bind_global((eventName, eventData) => {
      // Ignore Pusher internal lifecycle events
      if (eventName.startsWith("pusher:") || eventName.startsWith("pusher_internal:")) return;

      console.log(`[Pusher RAW] Event: "${eventName}"`, eventData);
      _incrementDebugEventCount();
      _lastEventTimestamp = Date.now();

      // Normalize: Pusher strips the leading dot internally, but some
      // servers send it and some don't — handle both.
      const normalized = eventName.replace(/^\./, "").toLowerCase();

      switch (normalized) {
        case "terminal-log":
          _hasReceivedDataEvent = true;
          handleTerminalLog(eventData);
          break;

        case "scan-results":
        case "scan.finding":
          _hasReceivedDataEvent = true;
          handleScanResult(eventData);
          break;

        case "scan.status":
          _handleStatusData(eventData);
          break;

        case "scan-completed":
        case "scan-finished":
        case "scan-done":
        case "scancompleted":
        case "scanfinished":
        case "job-completed":
          onScanComplete(eventData || { status: "completed" });
          break;

        default:
          console.log(`[Pusher] Unhandled event: "${eventName}"`, eventData);
          // Try to detect completion from unknown event payloads
          if (eventData?.status === "completed" || eventData?.status === "failed") {
            onScanComplete(eventData);
          }
          break;
      }
    });

    console.log("[Echo] bind_global attached to Pusher channel:", channelName);
    _appendTerminalSystem("Event listener attached");
  }

  /**
   * Inactivity watcher: if we've received at least one data event but then
   * go silent for INACTIVITY_TIMEOUT_MS, assume the scan finished and the
   * completion signal was lost.
   */
  function _startInactivityWatcher() {
    _stopInactivityWatcher();
    _inactivityCheckId = setInterval(() => {
      if (scanCompleted) { _stopInactivityWatcher(); return; }
      if (!_hasReceivedDataEvent) return; // haven't started receiving yet

      const silentMs = Date.now() - _lastEventTimestamp;
      if (silentMs >= INACTIVITY_TIMEOUT_MS) {
        console.warn(`[Scan] No events for ${Math.round(silentMs / 1000)}s — assuming completed`);
        _appendTerminalSystem(`[!] No activity for ${Math.round(silentMs / 1000)}s — finalising`);
        onScanComplete({ status: "completed" });
        _stopInactivityWatcher();
      }
    }, 5000);
  }

  function _stopInactivityWatcher() {
    if (_inactivityCheckId) { clearInterval(_inactivityCheckId); _inactivityCheckId = null; }
  }

  function teardownScanChannel(sessionId) {
    _stopInactivityWatcher();
    if (window.echoInstance) {
      try { window.echoInstance.leaveChannel(`scan.${sessionId}`); } catch (_) {}
    }
    activeScanChannel = null;
    activeScanJobId   = null;
    console.log("[Echo] Left channel: scan." + sessionId);
  }

  /* ── Debug bar helpers ────────────────────────────────────────────────── */
  function _updateDebugBar() {
    const dbgEcho = document.getElementById("dbg-echo");
    if (!dbgEcho) return;
    if (!window.echoInstance) {
      dbgEcho.textContent = "[X] not initialised";
      return;
    }
    const state = window.echoInstance.connector?.pusher?.connection?.state || "unknown";
    const icons = { connected: "[OK]", connecting: "[~]", disconnected: "[X]", failed: "[X]" };
    dbgEcho.textContent = `${icons[state] || "[?]"} ${state}`;
  }

  let _debugEventCount = 0;
  function _incrementDebugEventCount() {
    _debugEventCount++;
    const el = document.getElementById("dbg-events");
    if (el) el.textContent = _debugEventCount;
  }

  function _appendTerminalSystem(msg) {
    appendTerminalLine(`[SYS] ${msg}`);
  }

  /* ═══════════════════════════════════════════════════════════════════════
     EVENT HANDLERS
  ═══════════════════════════════════════════════════════════════════════ */
  function handleTerminalLog(event) {
    // Handle multiple shapes:
    //   { logLine: "..." }
    //   { log_line: "..." }
    //   { message: "..." }
    //   "raw string"  (some backends send strings directly)
    const logLine =
      typeof event === "string"
        ? event
        : event?.logLine || event?.log_line || event?.message || "";

    if (logLine) {
      console.log("[Terminal]", logLine);
      terminalLogs.push(logLine);
      appendTerminalLine(logLine);

      if (typeof window.appendActivityEvent === "function") {
        window.appendActivityEvent({
          type   : detectLogType(logLine),
          scanner: "TERMINAL",
          message: cleanLogLine(logLine),
        });
      }
    }

    // Check for embedded status in the event payload
    if (typeof event === "object" && event !== null) {
      const embeddedStatus =
        event.status || event.scan_job?.status || event.scan_session?.status;

      if (embeddedStatus && scanState.status === "running" &&
          (embeddedStatus === "completed" || embeddedStatus === "failed")) {
        onScanComplete(event);
        return;
      }
    }

    // Detect completion from terminal content — expanded pattern matching
    if (scanState.status === "running" && logLine) {
      const lower = logLine.toLowerCase();
      const completionPatterns = [
        "[ok] scan complete",
        "[ok] finished at",
        "scan finished",
        "scan completed",
        "all scanners completed",
        "scan job completed",
        "scan session completed",
        "[done]",
        "scanning complete",
      ];

      if (completionPatterns.some((p) => lower.includes(p))) {
        // Wait briefly for any remaining events to arrive, then complete
        setTimeout(() => {
          if (scanState.status === "running") {
            onScanComplete({ status: "completed" });
          }
        }, 2000);
      }
    }
  }

  function handleScanResult(event) {
    // Handle both { finding: {...} } and the finding object directly
    const finding = event?.finding || event;
    if (!finding || !finding.title) {
      console.warn("[ScanManager] Received scan-results with no finding.title:", event);
      return;
    }
    console.log("[Finding] Received:", finding);
    appendFinding(finding);

    if (typeof window.appendActivityEvent === "function") {
      window.appendActivityEvent({
        type   : mapSeverityToActivityType(finding.severity),
        scanner: ((finding.type || finding.driver_id || "SCANNER") + "")
                   .toUpperCase().replace(/_/g, " "),
        message: finding.title,
        detail : (finding.severity || "").toUpperCase(),
      });
    }
  }

  function _handleStatusData(data) {
    if (!data) return;
    const status = data.status || data.scan_session?.status || data.scan_job?.status;
    if (status) {
      scanState.status = status;
      _setStatusText(`Status: ${status}`);
      if (status === "completed" || status === "failed") onScanComplete(data);
    }
    if (Array.isArray(data.findings)) data.findings.forEach(appendFinding);
  }

  /* ═══════════════════════════════════════════════════════════════════════
     TERMINAL UI
  ═══════════════════════════════════════════════════════════════════════ */
  function appendTerminalLine(logLine) {
    const terminal = document.getElementById("scan-terminal");
    if (!terminal) return;

    // Detect if this line is part of an ASCII art block.
    // ASCII art lines contain box-drawing characters or dense symbol sequences.
    const isAsciiArt = /[║╔╚╗╝═╠╣╦╩╬┌┐└┘├┤┬┴┼─│▀▄█▌▐]/.test(logLine);

    // Detect the subtitle line inside the banner (e.g. "Web Endpoint Fuzzer — CyberGuard v2.1")
    const isAsciiSubtitle = isAsciiArt && /Fuzzer|CyberGuard v/i.test(logLine);

    const line = document.createElement("div");
    line.className = "terminal-line " +
      (isAsciiArt
        ? (isAsciiSubtitle ? "terminal-ascii terminal-ascii-subtitle" : "terminal-ascii")
        : getTerminalLineClass(logLine));

    // CRITICAL: use textContent not innerHTML — preserves every space exactly
    line.textContent = logLine;

    terminal.appendChild(line);

    // Lock scroll to bottom after every line
    terminal.scrollTop = terminal.scrollHeight;
  }

  function getTerminalLineClass(line) {
    if (line.includes("[LIVE]"))  return "terminal-live";
    if (line.includes("[WAIT]"))  return "terminal-wait";
    if (line.includes("[ERROR]")) return "terminal-error";
    if (line.includes("[WARN]"))  return "terminal-warn";
    if (line.includes("[INFO]"))  return "terminal-info";
    if (line.includes("[SYS]"))   return "terminal-system";
    return "terminal-default";
  }

  function detectLogType(line) {
    if (line.includes("[LIVE]"))  return "success";
    if (line.includes("[WAIT]"))  return "info";
    if (line.includes("[ERROR]")) return "error";
    if (line.includes("[WARN]"))  return "warning";
    return "info";
  }

  function cleanLogLine(line) {
    return line.replace(/\x1B\[[0-9;]*m/g, "").trim();
  }

  function clearTerminal() {
    const terminal = document.getElementById("scan-terminal");
    if (terminal) {
      terminal.textContent = "";
      const placeholder = document.createElement("div");
      placeholder.className = "terminal-line terminal-default";
      placeholder.textContent = "Terminal cleared.";
      terminal.appendChild(placeholder);
    }
    terminalLogs = [];
  }

  /* ═══════════════════════════════════════════════════════════════════════
     FINDINGS RENDERING
  ═══════════════════════════════════════════════════════════════════════ */
  function appendFinding(data) {
    if (!data) return;

    const fid =
      data.id || data.finding_id ||
      (data.title ? `${data.title}::${data.severity}` : null) ||
      JSON.stringify(data).substring(0, 120);

    if (scanState.seenFindingIds.has(fid)) return;
    scanState.seenFindingIds.add(fid);
    scanState.findings.push(data);

    const stream = document.getElementById("scan-findings-stream");
    if (!stream) return;

    document.getElementById("scan-waiting-msg")?.remove();

    const div = document.createElement("div");
    div.innerHTML = renderFindingCard(data);

    // ── Add entry animation ───────────────────────────────────────────────
    const card = div.firstElementChild;
    if (card) {
      card.style.opacity   = "0";
      card.style.transform = "translateY(8px)";
      card.style.transition = "opacity 0.3s ease, transform 0.3s ease";
      stream.appendChild(card);
      requestAnimationFrame(() => {
        card.style.opacity   = "1";
        card.style.transform = "translateY(0)";
      });
    } else {
      stream.appendChild(div);
    }

    stream.scrollTop = stream.scrollHeight;

    const countEl = document.getElementById("scan-total-findings");
    if (countEl) countEl.textContent = scanState.findings.length;
  }

  const SEV = {
    critical: {
      badge: "bg-[rgba(248,113,113,0.18)] text-[var(--cg-danger)] border-[rgba(248,113,113,0.35)]",
      dot  : "background:var(--cg-danger)",
    },
    high: {
      badge: "bg-[rgba(249,115,22,0.18)] text-[#F97316] border-[rgba(249,115,22,0.35)]",
      dot  : "background:#F97316",
    },
    medium: {
      badge: "bg-[rgba(251,191,36,0.18)] text-[var(--cg-warning)] border-[rgba(251,191,36,0.35)]",
      dot  : "background:var(--cg-warning)",
    },
    low: {
      badge: "bg-[rgba(56,189,248,0.18)] text-[var(--cg-info)] border-[rgba(56,189,248,0.35)]",
      dot  : "background:var(--cg-info)",
    },
    info: {
      badge: "bg-[rgba(148,163,184,0.18)] text-[var(--cg-text-2)] border-[rgba(148,163,184,0.35)]",
      dot  : "background:var(--cg-text-2)",
    },
  };

  function renderFindingCard(f) {
    const sev = (f.severity || "info").toLowerCase();
    const s   = SEV[sev] || SEV.info;

    const cvssRow = f.cvss_score ? `
      <div class="flex flex-wrap gap-x-5 gap-y-1 text-xs text-slate-400">
        <span>CVSS: <strong class="text-white">${escHtml(String(f.cvss_score))}</strong></span>
        ${f.cvss_vector ? `<span class="font-mono break-all">Vector: ${escHtml(f.cvss_vector)}</span>` : ""}
      </div>` : "";

    const affectedRow = f.affected_url ? `
      <div class="text-xs">
        <span class="text-slate-400">Affected URL: </span>
        <a href="${escAttr(f.affected_url)}" target="_blank" rel="noopener noreferrer"
           class="font-mono break-all hover:underline" style="color:var(--cg-info)">
          ${escHtml(f.affected_url)}
        </a>
      </div>` : "";

    const proofRow = f.proof ? `
      <div class="rounded-lg p-2.5 text-xs font-mono break-all"
           style="background:rgba(0,0,0,0.3);color:var(--cg-text-2)">
        <span class="text-slate-500">Proof: </span>${escHtml(f.proof)}
      </div>` : "";

    const remediationRow = f.remediation ? `
      <details class="group">
        <summary class="cursor-pointer text-xs hover:underline list-none
                        flex items-center gap-1 select-none"
                 style="color:var(--cg-accent)">
          <svg class="w-3.5 h-3.5 transition-transform group-open:rotate-90 flex-shrink-0"
               fill="none" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" d="m8.25 4.5 7.5 7.5-7.5 7.5"/>
          </svg>
          Remediation
        </summary>
        <p class="mt-2 text-xs text-slate-300 leading-relaxed pl-5">
          ${escHtml(f.remediation)}
        </p>
      </details>` : "";

    return `
      <div class="rounded-xl border p-4 space-y-3"
           style="background:var(--cg-bg-surface);border-color:var(--cg-border)">
        <div class="flex items-start gap-3">
          <span class="w-2 h-2 mt-1.5 rounded-full flex-shrink-0" style="${s.dot}"></span>
          <div class="flex-1 min-w-0">
            <div class="flex flex-wrap items-center gap-2 mb-1">
              <span class="text-xs font-bold px-2 py-0.5 rounded-full border
                           uppercase tracking-wide ${s.badge}">
                ${escHtml(sev)}
              </span>
              <p class="text-sm font-semibold text-white leading-snug">
                ${escHtml(f.title || "Untitled Finding")}
              </p>
            </div>
            <p class="text-xs" style="color:var(--cg-text-2)">
              Driver: <span class="font-mono">${escHtml(f.driver_id || "—")}</span>
            </p>
          </div>
        </div>
        ${cvssRow}
        ${f.description ? `<p class="text-sm text-slate-300 leading-relaxed">${escHtml(f.description)}</p>` : ""}
        ${affectedRow}
        ${proofRow}
        ${remediationRow}
      </div>`;
  }

  /* ═══════════════════════════════════════════════════════════════════════
     SCAN COMPLETE / FAILED
  ═══════════════════════════════════════════════════════════════════════ */
  function onScanComplete(data) {
    if (scanCompleted) return;
    scanCompleted = true;

    const session = data?.scan_session || data?.scan_job || data || {};
    const status  = session.status || data?.status || "completed";

    scanState.status     = status;
    scanState.finishedAt = session.finished_at || new Date().toISOString();

    console.log("[Scan] Complete — status:", status,
                "findings:", scanState.findings.length);

    _clearPolling();
    stopStatusPolling();
    clearScanTimeout();
    if (activeScanJobId) teardownScanChannel(activeScanJobId);

    // Update status bar
    const bar = document.getElementById("scan-status-bar");
    if (bar) {
      const isTimeout = status === "timeout";
      const isFailed  = status === "failed";
      const color = isFailed || isTimeout ? "var(--cg-warning)" : "var(--cg-success)";
      const icon  = isFailed || isTimeout
        ? `<svg width="14" height="14" viewBox="0 0 24 24" fill="none"
                stroke="currentColor" stroke-width="2">
             <circle cx="12" cy="12" r="10"/>
             <polyline points="12 6 12 12 16 14"/>
           </svg>`
        : `<svg width="14" height="14" viewBox="0 0 24 24" fill="none"
                stroke="currentColor" stroke-width="2.5">
             <polyline points="20 6 9 17 4 12"/>
           </svg>`;
      const label = isTimeout
        ? "Scan timed out — partial results shown"
        : isFailed
          ? "Scan failed"
          : `Scan completed — ${scanState.findings.length} finding${
              scanState.findings.length !== 1 ? "s" : ""}`;

      bar.innerHTML = `
        <span style="color:${color};display:flex;align-items:center;gap:8px;font-size:13px">
          ${icon}<span>${escHtml(label)}</span>
        </span>`;
    }

    if (Array.isArray(data?.findings)) data.findings.forEach(appendFinding);

    if (status === "completed" || status === "timeout") {
      document.getElementById("scan-complete-state")?.classList.remove("hidden");

      const countEl = document.getElementById("scan-total-findings");
      if (countEl) countEl.textContent = scanState.findings.length;

      const durEl = document.getElementById("scan-duration");
      if (durEl && scanState.startedAt) {
        const s = Math.round(
          (new Date(scanState.finishedAt) - new Date(scanState.startedAt)) / 1000
        );
        durEl.textContent = s < 60 ? `${s}s` : `${Math.floor(s / 60)}m ${s % 60}s`;
      }
      notify(`Scan completed — ${scanState.findings.length} finding(s) found.`, "success");
    } else {
      document.getElementById("scan-failed-state")?.classList.remove("hidden");
      const logEl = document.getElementById("scan-error-log");
      if (logEl)
        logEl.textContent =
          session.error_log || data?.error_log || "An error occurred during scanning.";
      notify("Scan failed. See the panel for details.", "error");
    }
  }

  /* ═══════════════════════════════════════════════════════════════════════
     CONCURRENT STATUS POLLING
     ─────────────────────────────────────────────────────────────────────
     Tries multiple API endpoint patterns since the backend may use
     different URL structures. Only stops on 3 consecutive 404s
     (handles race conditions during scan startup).
  ═══════════════════════════════════════════════════════════════════════ */
  let _poll404Count = 0;
  const MAX_404_BEFORE_STOP = 3;

  /** Candidate status endpoint patterns — tried in order. */
  function _statusEndpoints(sessionId) {
    return [
      `/scan/${sessionId}/status`,
      `/scan/status/${sessionId}`,
      `/scan-jobs/${sessionId}`,
      `/scan-sessions/${sessionId}`,
    ];
  }

  function startStatusPolling(sessionId) {
    stopStatusPolling();
    _poll404Count = 0;
    console.log("[ScanManager] Polling started for:", sessionId);

    statusPollingInterval = setInterval(async () => {
      if (scanCompleted) { stopStatusPolling(); return; }

      const endpoints = _statusEndpoints(sessionId);
      let succeeded = false;

      for (const endpoint of endpoints) {
        if (scanCompleted) return;

        try {
          const res = await apiFetch(endpoint);

          if (res.status === 404) {
            // This endpoint doesn't exist — try the next one
            continue;
          }
          if (!res.ok) continue;

          // Got a valid response — reset 404 counter
          _poll404Count = 0;
          succeeded = true;

          const data    = await res.json();
          const session = data.scan_session || data.scan_job || data || {};
          const status  = session.status || data.status;

          console.log(`[Polling] ${endpoint} → status:`, status);

          if (Array.isArray(data.findings)) data.findings.forEach(appendFinding);

          if (status === "completed" || status === "failed") {
            onScanComplete(data);
            stopStatusPolling();
          }
          break; // Don't try other endpoints if this one worked
        } catch (err) {
          console.warn(`[Polling] ${endpoint} error:`, err.message);
        }
      }

      // If none of the endpoints returned a valid response
      if (!succeeded) {
        _poll404Count++;
        console.warn(`[Polling] All endpoints failed (${_poll404Count}/${MAX_404_BEFORE_STOP})`);
        if (_poll404Count >= MAX_404_BEFORE_STOP) {
          console.warn("[Polling] Giving up after", MAX_404_BEFORE_STOP, "consecutive failures");
          stopStatusPolling();
        }
      }
    }, 5000);
  }

  function stopStatusPolling() {
    if (statusPollingInterval) {
      clearInterval(statusPollingInterval);
      statusPollingInterval = null;
    }
  }

  /* ═══════════════════════════════════════════════════════════════════════
     SAFETY TIMEOUT
  ═══════════════════════════════════════════════════════════════════════ */
  function startScanTimeout(sessionId) {
    clearScanTimeout();
    scanTimeoutId = setTimeout(() => {
      if (!scanCompleted) {
        console.warn("[Scan] Max duration reached — forcing completion");
        onScanComplete({ status: "timeout" });
      }
    }, MAX_SCAN_DURATION_MS);
  }

  function clearScanTimeout() {
    if (scanTimeoutId) { clearTimeout(scanTimeoutId); scanTimeoutId = null; }
  }

  /* ═══════════════════════════════════════════════════════════════════════
     LEGACY POLLING (kept for closeScanPanel cleanup — unused otherwise)
  ═══════════════════════════════════════════════════════════════════════ */
  function _clearPolling() {
    if (scanState.pollingInterval) {
      clearInterval(scanState.pollingInterval);
      scanState.pollingInterval = null;
    }
  }

  /* ═══════════════════════════════════════════════════════════════════════
     UTILITIES
  ═══════════════════════════════════════════════════════════════════════ */
  function _setStatusText(msg) {
    const el = document.getElementById("scan-status-text");
    if (el) el.textContent = msg;
  }

  function mapSeverityToActivityType(severity) {
    return ({ critical:"error", high:"error", medium:"warning",
               low:"info", info:"info" })[(severity||"").toLowerCase()] || "info";
  }

  function escHtml(t) {
    const d = document.createElement("div");
    d.textContent = String(t ?? "");
    return d.innerHTML;
  }

  function escAttr(t) {
    return String(t ?? "").replace(
      /['"<>&]/g,
      (ch) => ({"'":"&#39;",'"':"&quot;","<":"&lt;",">":"&gt;","&":"&amp;"})[ch]
    );
  }

  function notify(msg, type = "info") {
    if (window.CyberNotify) window.CyberNotify.alert(msg, { type });
    else console.log(`[ScanManager][${type}]`, msg);
  }

  function _btnLoading(btn, label) {
    if (!btn) return;
    btn._orig    = btn.innerHTML;
    btn.disabled = true;
    btn.innerHTML = `<span class="cyber-spinner-sm mr-2"></span>${escHtml(label)}`;
  }

  function _btnRestore(btn) {
    if (!btn) return;
    btn.innerHTML = btn._orig || "▶ Start Scan";
    btn.disabled  = false;
  }

  function cleanupScan() {
    if (activeScanJobId) teardownScanChannel(activeScanJobId);
    _clearPolling();
    stopStatusPolling();
    clearScanTimeout();
  }

  window.addEventListener("beforeunload", cleanupScan);

  /* ═══════════════════════════════════════════════════════════════════════
     PAUSE / RESUME / CANCEL — called by scan-progress.js
  ═══════════════════════════════════════════════════════════════════════ */

  /**
   * Pause a running scan.
   * Returns the raw API response data.
   */
  async function pauseScan(scanJobId) {
    if (typeof window.scannerAPI !== "undefined") {
      return window.scannerAPI.pauseScan(scanJobId);
    }
    // Fallback — direct fetch
    const res = await apiFetch(`/scan/${scanJobId}/pause`, { method: "POST" });
    if (!res.ok) throw new Error(`Pause failed (HTTP ${res.status})`);
    return res.json();
  }

  /**
   * Continue (resume) a paused scan.
   * Returns scan_job data.
   */
  async function resumeScan(scanJobId) {
    if (typeof window.scannerAPI !== "undefined") {
      return window.scannerAPI.continueScan(scanJobId);
    }
    const res = await apiFetch(`/scan/${scanJobId}/continue`, { method: "POST" });
    if (!res.ok) throw new Error(`Resume failed (HTTP ${res.status})`);
    const data = await res.json();
    return data.scan_job || data;
  }

  /**
   * Cancel a scan permanently.
   * Returns scan_job data.
   */
  async function cancelScan(scanJobId) {
    if (typeof window.scannerAPI !== "undefined") {
      return window.scannerAPI.cancelScan(scanJobId);
    }
    const res = await apiFetch(`/scan/${scanJobId}/cancel`, { method: "POST" });
    if (!res.ok) throw new Error(`Cancel failed (HTTP ${res.status})`);
    const data = await res.json();
    return data.scan_job || data;
  }

  /* ═══════════════════════════════════════════════════════════════════════
     PUBLIC API
  ═══════════════════════════════════════════════════════════════════════ */
  window.ScanManager = {
    openScanModal,
    closeScanModal,
    closeScanPanel,
    startScan,
    pauseScan,
    resumeScan,
    cancelScan,
    clearTerminal,
    _toggleGroup,
    _onCheckbox,
    get state() { return scanState; },
  };
})();