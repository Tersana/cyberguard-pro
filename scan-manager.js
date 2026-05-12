/**
 * scan-manager.js — CyberGuard Pro
 *
 * Full scan lifecycle for the Projects > Targets flow.
 *
 * Responsibilities:
 *   1. Load available scanners  GET /api/scanners
 *   2. Render Scanner Selection Modal (grouped by category, Select-All toggle)
 *   3. Start scan               POST /api/scan/start
 *   4. Live WebSocket feed      wss://…/app/{key}?… → channel scan.{sessionId}
 *   5. Fallback polling         GET /api/scan/{sessionId}/status  (every 5 s)
 *   6. Render finding cards (severity badges, CVSS, remediation accordion)
 *   7. Scan-complete / failed states
 *
 * Exposed as window.ScanManager — called from project-detail.html.
 */
(function () {
  "use strict";

  /* ─── Config ────────────────────────────────────────────────────────────── */
  const API_BASE =
    "https://peptonelike-lelia-interdepartmentally.ngrok-free.dev/api/";
  const JWT_KEY = "cyberguard_jwt";
  const REVERB = {
    appKey: "p77kyuc5noyjaqc0t2te",
    host: "peptonelike-lelia-interdepartmentally.ngrok-free.dev",
  };

  /* ─── State ─────────────────────────────────────────────────────────────── */
  const scanState = {
    sessionId: null,
    targetId: null,
    targetLabel: null,
    targetValue: null,
    targetType: null,
    status: "idle", // idle | running | completed | failed
    findings: [],
    socket: null,
    pollingInterval: null,
    seenFindingIds: new Set(),
    startedAt: null,
    finishedAt: null,
  };

  let _scanners = []; // cached from GET /api/scanners
  let _selected = new Set(); // currently-checked scanner ids

  /* ─── API helper ─────────────────────────────────────────────────────────── */
  function apiFetch(endpoint, opts = {}) {
    const token = localStorage.getItem(JWT_KEY);
    const headers = {
      Accept: "application/json",
      "Content-Type": "application/json",
      "ngrok-skip-browser-warning": "true",
    };
    if (token) headers["Authorization"] = `Bearer ${token}`;
    return fetch(API_BASE + endpoint.replace(/^\//, ""), {
      headers,
      ...opts,
    });
  }

  /* ─── Load scanners ──────────────────────────────────────────────────────── */
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

  /* ─── Open scanner-selection modal ──────────────────────────────────────── */
  async function openScanModal(buttonEl) {
    if (scanState.status === "running") {
      notify("A scan is already running. Please wait for it to complete.", "warning");
      return;
    }

    // Read target info from data-* attributes on the clicked button
    scanState.targetId    = buttonEl.dataset.tid    || "";
    scanState.targetLabel = buttonEl.dataset.lbl    || "";
    scanState.targetValue = buttonEl.dataset.val    || "";
    scanState.targetType  = buttonEl.dataset.typ    || "domain";

    _selected.clear();

    const modal = document.getElementById("scan-scanner-modal");
    if (!modal) return;

    const titleEl  = document.getElementById("scan-modal-target-label");
    const detailEl = document.getElementById("scan-modal-target-detail");
    if (titleEl)  titleEl.textContent  = scanState.targetLabel || "Target";
    if (detailEl) detailEl.textContent =
      `${scanState.targetValue} (${scanState.targetType})`;

    // Show loading state in scanner body
    const bodyEl = document.getElementById("scan-modal-scanner-body");
    if (bodyEl)
      bodyEl.innerHTML = `
        <div class="flex items-center justify-center py-10 text-slate-400 text-sm gap-3">
          <span class="cyber-spinner-sm"></span>Loading scanners…
        </div>`;

    modal.classList.remove("hidden");

    await loadScanners();
    renderScannerList();
  }

  /* ─── Render grouped scanner list ────────────────────────────────────────── */
  function renderScannerList() {
    const bodyEl = document.getElementById("scan-modal-scanner-body");
    if (!bodyEl) return;

    if (_scanners.length === 0) {
      bodyEl.innerHTML = `
        <p class="text-sm text-slate-400 text-center py-8">No scanners available.</p>`;
      return;
    }

    // Group by category
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
            <span class="text-xs font-bold uppercase tracking-widest text-[var(--cg-accent)]">${escHtml(cat)}</span>
            <button
              type="button"
              class="text-xs text-[var(--cg-info)] hover:underline focus:outline-none"
              onclick="window.ScanManager._toggleGroup('${escAttr(cat)}')"
            >Select All</button>
          </div>
          <div class="space-y-2">
            ${list.map(renderScannerCard).join("")}
          </div>
        </div>`;
    }
    bodyEl.innerHTML = html;
  }

  function renderScannerCard(s) {
    const id   = escAttr(s.id   || "");
    const name = escHtml(s.name || "");
    const catBadgeCls =
      {
        recon: "text-[#38BDF8] bg-[rgba(56,189,248,0.1)] border-[rgba(56,189,248,0.25)]",
        vuln:  "text-[#FB923C] bg-[rgba(251,146,60,0.1)] border-[rgba(251,146,60,0.25)]",
        audit: "text-[#A78BFA] bg-[rgba(167,139,250,0.1)] border-[rgba(167,139,250,0.25)]",
      }[s.category] ||
      "text-slate-400 bg-slate-800/50 border-slate-700";

    return `
      <label
        class="scan-card flex items-center gap-3 p-3 rounded-xl border border-[var(--cg-border)]
               hover:border-[var(--cg-accent)] cursor-pointer transition-all select-none"
        data-scanner-id="${id}"
      >
        <input
          type="checkbox"
          class="scan-cb w-4 h-4 rounded"
          value="${id}"
          onchange="window.ScanManager._onCheckbox(this)"
        />
        <span class="flex-1 text-sm text-white">${name}</span>
        <span class="text-xs px-2 py-0.5 rounded-full border font-semibold ${catBadgeCls}">
          ${escHtml(s.category || "")}
        </span>
      </label>`;
  }

  /* ─── Select All toggle per category ─────────────────────────────────────── */
  function _toggleGroup(cat) {
    const group = document.querySelector(`[data-scan-group="${cat}"]`);
    if (!group) return;
    const cbs = [...group.querySelectorAll(".scan-cb")];
    const allOn = cbs.every((cb) => cb.checked);
    cbs.forEach((cb) => {
      cb.checked = !allOn;
      _syncSelection(cb);
    });
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
      card.classList.toggle("border-[var(--cg-accent)]",  !!cb?.checked);
      card.classList.toggle("bg-[rgba(167,139,250,0.07)]", !!cb?.checked);
    });
  }

  /* ─── Close modal ────────────────────────────────────────────────────────── */
  function closeScanModal() {
    document.getElementById("scan-scanner-modal")?.classList.add("hidden");
  }

  /* ─── Start scan ─────────────────────────────────────────────────────────── */
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
      const res = await apiFetch("/scan/start", {
        method: "POST",
        body: JSON.stringify({
          target_id:  scanState.targetId,
          driver_ids: [..._selected],
        }),
      });

      let data = {};
      try { data = await res.json(); } catch (_) {}

      if (!res.ok) {
        notify(data.message || `Failed to start scan (${res.status}).`, "error");
        return;
      }

      const sessionId = data.scan_session_id;
      if (!sessionId) {
        notify("Server did not return a scan session ID.", "error");
        return;
      }

      // Transition state
      closeScanModal();
      scanState.sessionId      = sessionId;
      scanState.status         = "running";
      scanState.findings       = [];
      scanState.seenFindingIds = new Set();
      scanState.startedAt      = new Date().toISOString();
      scanState.finishedAt     = null;
      scanState.socket         = null;
      scanState.pollingInterval = null;

      showScanPanel();
      connectWebSocket(sessionId);
      notify("Scan started — connecting to live feed…", "success");
    } catch (err) {
      console.error("[ScanManager] startScan:", err);
      notify(err.message || "Failed to start scan.", "error");
    } finally {
      _btnRestore(btn);
    }
  }

  /* ─── Scan live panel ────────────────────────────────────────────────────── */
  function showScanPanel() {
    const panel = document.getElementById("scan-live-panel");
    if (!panel) return;
    panel.classList.remove("hidden");
    panel.innerHTML = buildPanelHTML();
    panel.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }

  function buildPanelHTML() {
    const targetText = escHtml(scanState.targetValue || "");
    const sessionText = escHtml(scanState.sessionId || "");
    return `
      <!-- Panel header -->
      <div class="flex items-center justify-between flex-wrap gap-3">
        <div class="flex items-center gap-3">
          <span class="flex items-center gap-1.5 text-xs font-bold uppercase tracking-wider"
                style="color:var(--cg-danger)">
            <span class="inline-block w-2 h-2 rounded-full animate-pulse"
                  style="background:var(--cg-danger)"></span>
            LIVE
          </span>
          <p class="text-sm font-semibold text-white">
            Scanning: <span class="font-mono" style="color:var(--cg-info)">${targetText}</span>
          </p>
        </div>
        <div class="flex items-center gap-3">
          <span class="text-xs text-slate-500 font-mono">Session: ${sessionText}</span>
          <button
            onclick="window.ScanManager.closeScanPanel()"
            title="Close scan panel"
            class="cyber-btn-ghost text-xs px-2 py-1 rounded"
          >✕</button>
        </div>
      </div>

      <!-- Status bar -->
      <div id="scan-status-bar"
           class="flex items-center gap-2 text-xs text-slate-400 py-1 border-b border-[var(--cg-border)]">
        <span class="cyber-spinner-sm"></span>
        <span id="scan-status-text">Initializing…</span>
      </div>

      <!-- Findings stream -->
      <div id="scan-findings-stream"
           class="space-y-3 max-h-[520px] overflow-y-auto pr-1 scroll-smooth">
        <p id="scan-waiting-msg" class="text-xs text-slate-500 italic py-2">
          Waiting for findings…
        </p>
      </div>

      <!-- Completed state (hidden until done) -->
      <div id="scan-complete-state"
           class="hidden mt-2 p-4 rounded-xl border"
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

      <!-- Failed state (hidden until failed) -->
      <div id="scan-failed-state"
           class="hidden mt-2 p-4 rounded-xl border"
           style="border-color:var(--cg-danger);background:rgba(248,113,113,0.06)">
        <div class="flex items-center gap-2 mb-2">
          <svg class="w-5 h-5" style="color:var(--cg-danger)" fill="none"
               viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round"
                  d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0
                     2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898
                     0L2.697 16.126ZM12 15.75h.007v.008H12v-.008Z"/>
          </svg>
          <span class="font-bold text-sm" style="color:var(--cg-danger)">Scan Failed</span>
        </div>
        <pre id="scan-error-log"
             class="text-xs text-slate-400 mt-1 font-mono whitespace-pre-wrap break-all"></pre>
      </div>`;
  }

  function closeScanPanel() {
    _clearPolling();
    if (scanState.socket) {
      try { scanState.socket.close(); } catch (_) {}
      scanState.socket = null;
    }
    scanState.status = "idle";
    document.getElementById("scan-live-panel")?.classList.add("hidden");
  }

  /* ─── WebSocket connection ───────────────────────────────────────────────── */
  function connectWebSocket(sessionId) {
    const url =
      `wss://${REVERB.host}/app/${REVERB.appKey}` +
      `?protocol=7&client=js&version=8.0&flash=false`;

    let ws;
    try {
      ws = new WebSocket(url);
    } catch (err) {
      console.error("[WS] Cannot open WebSocket:", err);
      _setStatusText("WebSocket unavailable — falling back to polling…");
      startPolling(sessionId);
      return;
    }

    scanState.socket = ws;

    ws.onopen = () => {
      console.log("[WS] Open — subscribing to scan." + sessionId);
      ws.send(
        JSON.stringify({
          event: "pusher:subscribe",
          data:  { channel: `scan.${sessionId}` },
        })
      );
      _setStatusText("Connected — receiving live findings…");
    };

    ws.onmessage = (ev) => {
      let msg;
      try { msg = JSON.parse(ev.data); } catch (_) { return; }
      console.log("[WS] Message:", msg);

      // Ignore housekeeping frames
      if (
        msg.event === "pusher:connection_established" ||
        msg.event === "pusher_internal:subscription_succeeded"
      ) return;

      // Normalise data (Pusher wraps payload as JSON string)
      const raw  = msg.data;
      const data = typeof raw === "string"
        ? (() => { try { return JSON.parse(raw); } catch (_) { return {}; } })()
        : (raw || {});

      const evt = (msg.event || "").toLowerCase();

      if (evt.includes("finding")) {
        appendFinding(data);
      }

      if (evt.includes("status")) {
        _handleStatusData(data);
      }

      // Terminal check regardless of event name
      const status =
        data?.status ||
        data?.scan_session?.status ||
        data?.scan_job?.status;

      if (status === "completed" || status === "failed") {
        onScanComplete(data);
        ws.close();
      }
    };

    ws.onerror = (err) => {
      console.error("[WS] Error:", err);
      _setStatusText("WebSocket error — switching to polling…");
      startPolling(sessionId);
    };

    ws.onclose = (ev) => {
      console.log("[WS] Closed", ev.code, ev.reason);
      // Only auto-start polling if scan is still logically running
      if (scanState.status === "running") {
        startPolling(sessionId);
      }
    };
  }

  /* ─── Append a single finding ────────────────────────────────────────────── */
  function appendFinding(data) {
    if (!data) return;

    // Deduplicate — use id if present, else fingerprint
    const fid =
      data.id ||
      data.finding_id ||
      (data.title ? `${data.title}::${data.severity}` : null) ||
      JSON.stringify(data).substring(0, 120);

    if (scanState.seenFindingIds.has(fid)) return;
    scanState.seenFindingIds.add(fid);
    scanState.findings.push(data);

    const stream = document.getElementById("scan-findings-stream");
    if (!stream) return;

    // Remove placeholder message
    document.getElementById("scan-waiting-msg")?.remove();

    const div = document.createElement("div");
    div.innerHTML = renderFindingCard(data);
    stream.appendChild(div.firstElementChild || div);

    // Auto-scroll
    stream.scrollTop = stream.scrollHeight;

    // Keep running total in completed banner (updated live)
    const countEl = document.getElementById("scan-total-findings");
    if (countEl) countEl.textContent = scanState.findings.length;
  }

  /* ─── Finding card renderer ──────────────────────────────────────────────── */
  const SEV = {
    critical: {
      badge: "bg-[rgba(248,113,113,0.18)] text-[var(--cg-danger)] border-[rgba(248,113,113,0.35)]",
      dot:   "background:var(--cg-danger)",
    },
    high: {
      badge: "bg-[rgba(249,115,22,0.18)] text-[#F97316] border-[rgba(249,115,22,0.35)]",
      dot:   "background:#F97316",
    },
    medium: {
      badge: "bg-[rgba(251,191,36,0.18)] text-[var(--cg-warning)] border-[rgba(251,191,36,0.35)]",
      dot:   "background:var(--cg-warning)",
    },
    low: {
      badge: "bg-[rgba(56,189,248,0.18)] text-[var(--cg-info)] border-[rgba(56,189,248,0.35)]",
      dot:   "background:var(--cg-info)",
    },
    info: {
      badge: "bg-[rgba(148,163,184,0.18)] text-[var(--cg-text-2)] border-[rgba(148,163,184,0.35)]",
      dot:   "background:var(--cg-text-2)",
    },
  };

  function renderFindingCard(f) {
    const sev = (f.severity || "info").toLowerCase();
    const s   = SEV[sev] || SEV.info;

    const cvssRow =
      f.cvss_score
        ? `<div class="flex flex-wrap gap-x-5 gap-y-1 text-xs text-slate-400">
             <span>CVSS: <strong class="text-white">${escHtml(String(f.cvss_score))}</strong></span>
             ${
               f.cvss_vector
                 ? `<span class="font-mono break-all" title="${escAttr(f.cvss_vector)}">
                      Vector: ${escHtml(f.cvss_vector)}
                    </span>`
                 : ""
             }
           </div>`
        : "";

    const affectedRow =
      f.affected_url
        ? `<div class="text-xs">
             <span class="text-slate-400">Affected URL: </span>
             <a href="${escAttr(f.affected_url)}" target="_blank" rel="noopener noreferrer"
                class="font-mono break-all hover:underline" style="color:var(--cg-info)">
               ${escHtml(f.affected_url)}
             </a>
           </div>`
        : "";

    const proofRow =
      f.proof
        ? `<div class="rounded-lg p-2.5 text-xs font-mono break-all"
                style="background:rgba(0,0,0,0.3);color:var(--cg-text-2)">
             <span class="text-slate-500">Proof: </span>${escHtml(f.proof)}
           </div>`
        : "";

    const remediationRow =
      f.remediation
        ? `<details class="group">
             <summary class="cursor-pointer text-xs hover:underline list-none flex items-center gap-1 select-none"
                      style="color:var(--cg-accent)">
               <svg class="w-3.5 h-3.5 transition-transform group-open:rotate-90 flex-shrink-0"
                    fill="none" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor">
                 <path stroke-linecap="round" stroke-linejoin="round" d="m8.25 4.5 7.5 7.5-7.5 7.5"/>
               </svg>
               Remediation
             </summary>
             <p class="mt-2 text-xs text-slate-300 leading-relaxed pl-5">${escHtml(f.remediation)}</p>
           </details>`
        : "";

    return `
      <div class="rounded-xl border p-4 space-y-3"
           style="background:var(--cg-bg-surface);border-color:var(--cg-border)">
        <!-- Header row -->
        <div class="flex items-start gap-3">
          <span class="w-2 h-2 mt-1.5 rounded-full flex-shrink-0"
                style="${s.dot}"></span>
          <div class="flex-1 min-w-0">
            <div class="flex flex-wrap items-center gap-2 mb-1">
              <span class="text-xs font-bold px-2 py-0.5 rounded-full border uppercase tracking-wide ${s.badge}">
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

  /* ─── Status helpers ─────────────────────────────────────────────────────── */
  function _setStatusText(msg) {
    const el = document.getElementById("scan-status-text");
    if (el) el.textContent = msg;
  }

  function _handleStatusData(data) {
    if (!data) return;
    const status =
      data.status ||
      data.scan_session?.status ||
      data.scan_job?.status;
    if (status) {
      scanState.status = status;
      _setStatusText(`Status: ${status}`);
    }
    if (Array.isArray(data.findings)) {
      data.findings.forEach(appendFinding);
    }
  }

  /* ─── Scan complete / failed ─────────────────────────────────────────────── */
  function onScanComplete(data) {
    const session = data?.scan_session || data?.scan_job || data || {};
    const status  = session.status || data?.status || "completed";

    scanState.status     = status;
    scanState.finishedAt = session.finished_at || new Date().toISOString();

    _clearPolling();
    if (scanState.socket) {
      try { scanState.socket.close(); } catch (_) {}
      scanState.socket = null;
    }

    // Replace spinner status bar with plain text
    const bar = document.getElementById("scan-status-bar");
    if (bar)
      bar.innerHTML = `<span class="text-xs" style="color:var(--cg-text-2)">Scan ${escHtml(status)}</span>`;

    // Render any remaining findings from the final payload
    if (Array.isArray(data?.findings)) {
      data.findings.forEach(appendFinding);
    }

    if (status === "completed") {
      const el = document.getElementById("scan-complete-state");
      if (el) el.classList.remove("hidden");

      const countEl = document.getElementById("scan-total-findings");
      if (countEl) countEl.textContent = scanState.findings.length;

      const durEl = document.getElementById("scan-duration");
      if (durEl && scanState.startedAt) {
        const s = Math.round(
          (new Date(scanState.finishedAt) - new Date(scanState.startedAt)) / 1000
        );
        durEl.textContent =
          s < 60 ? `${s}s` : `${Math.floor(s / 60)}m ${s % 60}s`;
      }
      notify(`Scan completed — ${scanState.findings.length} finding(s) found.`, "success");
    } else {
      const el = document.getElementById("scan-failed-state");
      if (el) el.classList.remove("hidden");

      const logEl = document.getElementById("scan-error-log");
      if (logEl)
        logEl.textContent =
          session.error_log || data?.error_log || "An error occurred during scanning.";

      notify("Scan failed. See the panel for details.", "error");
    }
  }

  /* ─── Polling fallback ───────────────────────────────────────────────────── */
  function startPolling(sessionId) {
    if (scanState.pollingInterval) return; // already polling
    console.log("[ScanManager] Starting polling for", sessionId);
    _setStatusText("Polling for updates every 5 s…");

    scanState.pollingInterval = setInterval(async () => {
      if (scanState.status !== "running") {
        _clearPolling();
        return;
      }

      try {
        const res = await apiFetch(`/scan/${sessionId}/status`);

        if (res.status === 404) {
          _clearPolling();
          _setStatusText("Scan session not found on server.");
          notify("Scan session not found.", "error");
          return;
        }

        if (!res.ok) return; // transient — keep polling

        const data = await res.json();
        const session = data.scan_session || data.scan_job || {};

        // Render any new findings
        if (Array.isArray(data.findings)) {
          data.findings.forEach(appendFinding);
        }

        const status = session.status || data.status;
        if (status) {
          scanState.status = status;
          _setStatusText(`Status: ${status}`);
        }

        if (status === "completed" || status === "failed") {
          _clearPolling();
          onScanComplete(data);
        }
      } catch (err) {
        console.error("[ScanManager] Polling error:", err);
      }
    }, 5000);
  }

  function _clearPolling() {
    if (scanState.pollingInterval) {
      clearInterval(scanState.pollingInterval);
      scanState.pollingInterval = null;
    }
  }

  /* ─── Tiny utilities ─────────────────────────────────────────────────────── */
  function escHtml(t) {
    const d = document.createElement("div");
    d.textContent = String(t ?? "");
    return d.innerHTML;
  }

  function escAttr(t) {
    return String(t ?? "").replace(/['"<>&]/g, (ch) =>
      ({ "'": "&#39;", '"': "&quot;", "<": "&lt;", ">": "&gt;", "&": "&amp;" }[ch])
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

  /* ─── Public API ─────────────────────────────────────────────────────────── */
  window.ScanManager = {
    openScanModal,
    closeScanModal,
    closeScanPanel,
    startScan,
    // Used by inline onclick handlers in rendered HTML
    _toggleGroup,
    _onCheckbox,
    // Dev/debug access
    get state() { return scanState; },
  };
})();
