/**
 * live-scan-console.js — CyberGuard Pro Inline Live Scan Console
 *
 * Exposes window.LiveScanConsole to manage inline terminal log streaming,
 * real-time findings, progress bars, and parallel scan sessions on the project details page.
 */
(function () {
  "use strict";

  var LiveScanConsole = {
    sessions: {}, // [sessionId]: { targetValue, targetId, status, progress, findings: [], logs: [], channel: null }
    activeSessionId: null,
    minimized: false,

    init: function () {
      console.log("[LiveScanConsole] Initializing inline console...");
      
      var header = document.getElementById("live-scan-console-header");
      if (header) {
        // Prevent click events on buttons from toggling minimization
        header.addEventListener("click", function (e) {
          if (e.target.closest("button") || e.target.closest("select")) return;
          LiveScanConsole.toggleMinimize();
        });
      }

      var toggleBtn = document.getElementById("live-console-toggle-btn");
      if (toggleBtn) {
        toggleBtn.addEventListener("click", function (e) {
          e.stopPropagation();
          LiveScanConsole.toggleMinimize();
        });
      }

      var closeBtn = document.getElementById("live-console-close-btn");
      if (closeBtn) {
        closeBtn.addEventListener("click", function (e) {
          e.stopPropagation();
          LiveScanConsole.close();
        });
      }

      var select = document.getElementById("live-console-scan-select");
      if (select) {
        select.addEventListener("change", function () {
          LiveScanConsole.switchToSession(select.value);
        });
      }
    },

    startSession: function (sessionId, targetValue, targetId) {
      if (this.sessions[sessionId]) return;

      console.log("[LiveScanConsole] Starting session:", sessionId, "for target:", targetValue);

      // Create new session object
      this.sessions[sessionId] = {
        targetValue: targetValue,
        targetId: targetId,
        status: "running",
        progress: 0,
        findings: [],
        logs: [],
        channel: null
      };

      // Subscribe to websocket channel
      this.subscribeChannel(sessionId);

      // Slide up the console (ensure it is visible and expanded)
      var consoleEl = document.getElementById("live-scan-console");
      if (consoleEl) {
        consoleEl.classList.remove("translate-y-full");
        consoleEl.classList.remove("minimized");
        this.minimized = false;
        
        var icon = document.querySelector("#live-console-toggle-btn span");
        if (icon) icon.textContent = "keyboard_arrow_down";
      }

      // Update switcher dropdown
      this.updateSelectDropdown(sessionId);

      // Switch view context
      this.switchToSession(sessionId);
    },

    subscribeChannel: function (sessionId) {
      if (!window.echoInstance) {
        console.warn("[LiveScanConsole] Laravel Echo instance unavailable.");
        this.appendTerminalLine(sessionId, "[System] WebSocket unavailable — console listening offline.");
        return;
      }

      try {
        var channelName = "scan." + sessionId;
        var channel = window.echoInstance.channel(channelName);
        this.sessions[sessionId].channel = channel;

        var pusher = window.echoInstance.connector?.pusher;
        if (pusher) {
          this._attachGlobalHandler(pusher, channelName, sessionId, 0);
        }
      } catch (err) {
        console.error("[LiveScanConsole] Error subscribing to channel:", err);
      }
    },

    _attachGlobalHandler: function (pusher, channelName, sessionId, attempt) {
      if (attempt > 10) return;
      var ch = pusher.channel(channelName);
      if (!ch) {
        var self = this;
        setTimeout(function () {
          self._attachGlobalHandler(pusher, channelName, sessionId, attempt + 1);
        }, 500);
        return;
      }

      var self = this;
      ch.bind_global(function (eventName, eventData) {
        if (eventName.startsWith("pusher:") || eventName.startsWith("pusher_internal:")) return;

        var normalized = eventName.replace(/^\./, "").toLowerCase();
        
        // Router
        switch (normalized) {
          case "terminal-log":
            var rawLine = typeof eventData === "string" ? eventData : (eventData?.logLine || eventData?.log_line || eventData?.message || "");
            self.appendTerminalLine(sessionId, rawLine);
            break;

          case "scan-results":
          case "scan.finding":
            var finding = eventData?.finding || eventData;
            self.appendFinding(sessionId, finding);
            break;

          case "scan.status":
            var s = eventData?.status || eventData?.scan_session?.status || eventData?.scan_job?.status;
            var p = eventData?.progress || eventData?.scan_session?.progress || eventData?.scan_job?.progress;
            
            if (p !== undefined) {
              self.updateSessionProgress(sessionId, p);
            }
            if (s === "completed" || s === "failed" || s === "cancelled") {
              self.onScanComplete(sessionId, s);
            }
            break;

          case "scan-completed":
          case "scan-finished":
          case "scan-done":
          case "job-completed":
            self.onScanComplete(sessionId, "completed");
            break;
        }
      });
    },

    switchToSession: function (sessionId) {
      var session = this.sessions[sessionId];
      if (!session) return;

      this.activeSessionId = sessionId;

      // Update dropdown selection
      var select = document.getElementById("live-console-scan-select");
      if (select) {
        select.value = sessionId;
      }

      // Update Header details
      var targetEl = document.getElementById("live-console-target");
      if (targetEl) {
        targetEl.textContent = session.targetValue;
      }

      var idEl = document.getElementById("live-console-session-id");
      if (idEl) {
        idEl.textContent = sessionId.substring(0, 8) + "...";
      }

      var statusEl = document.getElementById("live-console-status");
      if (statusEl) {
        statusEl.textContent = session.status;
      }

      // Update progress bar
      this.updateProgressDOM(session.progress);

      // Re-populate terminal DOM
      var term = document.getElementById("live-console-terminal");
      if (term) {
        term.innerHTML = "";
        session.logs.forEach(function (logHtml) {
          term.appendChild(logHtml);
        });
        term.scrollTop = term.scrollHeight;
      }

      // Re-populate findings list DOM
      var emptyEl = document.getElementById("live-console-findings-empty");
      var listEl = document.getElementById("live-console-findings-list");

      if (session.findings.length === 0) {
        if (emptyEl) emptyEl.classList.remove("hidden");
        if (listEl) listEl.classList.add("hidden");
      } else {
        if (emptyEl) emptyEl.classList.add("hidden");
        if (listEl) {
          listEl.classList.remove("hidden");
          listEl.innerHTML = "";
          session.findings.forEach(function (finding) {
            listEl.appendChild(LiveScanConsole.createFindingRowHTML(finding));
          });
        }
      }
    },

    appendTerminalLine: function (sessionId, rawLine) {
      var session = this.sessions[sessionId];
      if (!session) return;

      // Escape HTML to prevent XSS
      var safeLine = rawLine
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;");

      var lineDiv = document.createElement("div");
      lineDiv.className = "terminal-line font-mono text-[11px] leading-relaxed break-all";
      lineDiv.innerHTML = this.colorizeTerminalLine(safeLine);

      // Append to cache (limit size to 800 lines to preserve memory)
      session.logs.push(lineDiv);
      if (session.logs.length > 800) {
        session.logs.shift();
      }

      // If active session, append to DOM and auto-scroll
      if (this.activeSessionId === sessionId) {
        var term = document.getElementById("live-console-terminal");
        if (term) {
          term.appendChild(lineDiv);
          // Limit DOM size
          while (term.children.length > 800) {
            term.removeChild(term.firstChild);
          }
          term.scrollTop = term.scrollHeight;
        }
      }
    },

    colorizeTerminalLine: function (line) {
      if (line.includes("[+]") || line.includes("SUCCESS")) {
        return '<span class="text-emerald-400">' + line + '</span>';
      }
      if (line.includes("[-]") || line.includes("ERROR") || line.includes("Failed")) {
        return '<span class="text-red-400">' + line + '</span>';
      }
      if (line.includes("[!]") || line.includes("WARNING")) {
        return '<span class="text-amber-400">' + line + '</span>';
      }
      if (line.includes("[i]") || line.includes("INFO")) {
        return '<span class="text-blue-400">' + line + '</span>';
      }
      return '<span class="text-slate-300">' + line + '</span>';
    },

    appendFinding: function (sessionId, finding) {
      var session = this.sessions[sessionId];
      if (!session || !finding || !finding.title) return;

      // De-duplicate findings
      var id = finding.id || (finding.title + "::" + (finding.severity || "info"));
      var exists = session.findings.some(function (f) {
        return (f.id || (f.title + "::" + (f.severity || "info"))) === id;
      });
      if (exists) return;

      session.findings.push(finding);

      // If active, render row
      if (this.activeSessionId === sessionId) {
        var emptyEl = document.getElementById("live-console-findings-empty");
        var listEl = document.getElementById("live-console-findings-list");
        if (emptyEl) emptyEl.classList.add("hidden");
        if (listEl) {
          listEl.classList.remove("hidden");
          listEl.appendChild(this.createFindingRowHTML(finding));
        }
      }
    },

    createFindingRowHTML: function (finding) {
      var sev = (finding.severity || "info").toLowerCase();
      var sevColor = "bg-blue-500/10 text-blue-400 border-blue-500/20";
      if (sev === "critical") sevColor = "bg-red-500/10 text-red-400 border-red-500/20";
      else if (sev === "high") sevColor = "bg-orange-500/10 text-orange-400 border-orange-500/20";
      else if (sev === "medium") sevColor = "bg-yellow-500/10 text-yellow-400 border-yellow-500/20";
      else if (sev === "low") sevColor = "bg-green-500/10 text-green-400 border-green-500/20";

      var row = document.createElement("div");
      row.className = "p-2 bg-white/[0.02] border border-white/5 rounded flex justify-between items-start gap-2";
      row.innerHTML = `
        <div class="flex-1 min-w-0">
          <div class="font-semibold text-slate-200 text-[11px] truncate" title="${finding.title}">${finding.title}</div>
          <div class="text-[9px] text-slate-500 truncate">${finding.description || "Vulnerability identified"}</div>
        </div>
        <span class="text-[9px] font-mono border px-1.5 py-0.5 rounded uppercase ${sevColor}">${sev}</span>
      `;
      return row;
    },

    updateSessionProgress: function (sessionId, progress) {
      var session = this.sessions[sessionId];
      if (!session) return;

      session.progress = progress;

      if (this.activeSessionId === sessionId) {
        this.updateProgressDOM(progress);
      }
    },

    updateProgressDOM: function (progress) {
      var fill = document.getElementById("live-console-progress-fill");
      var text = document.getElementById("live-console-progress-text");
      if (fill) fill.style.width = progress + "%";
      if (text) text.textContent = progress + "%";
    },

    onScanComplete: function (sessionId, finalStatus) {
      var session = this.sessions[sessionId];
      if (!session || session.status === "completed") return;

      session.status = "completed";
      session.progress = 100;

      if (this.activeSessionId === sessionId) {
        this.updateProgressDOM(100);
        var statusEl = document.getElementById("live-console-status");
        if (statusEl) statusEl.textContent = "completed";
      }

      // Unsubscribe channel
      if (session.channel && window.echoInstance) {
        try {
          window.echoInstance.leaveChannel("scan." + sessionId);
        } catch (_) {}
        session.channel = null;
      }

      // Update select option title to indicate complete state
      var select = document.getElementById("live-console-scan-select");
      if (select) {
        var option = select.querySelector("option[value='" + sessionId + "']");
        if (option) {
          option.textContent = "[Done] " + session.targetValue;
        }
      }

      // Trigger user notifications and project refresh
      if (window.CyberNotify) {
        window.CyberNotify.alert("Scan on " + session.targetValue + " has completed successfully!", { type: "success" });
      }

      // Refresh target listings on the parent project details page
      if (typeof window.loadProject === "function") {
        window.loadProject();
      }
      if (typeof window.loadProjectScans === "function") {
        window.loadProjectScans();
      }
    },

    updateSelectDropdown: function (newSessionId) {
      var select = document.getElementById("live-console-scan-select");
      if (!select) return;

      var option = document.createElement("option");
      option.value = newSessionId;
      option.textContent = "[Live] " + this.sessions[newSessionId].targetValue;
      select.appendChild(option);

      var sessionCount = Object.keys(this.sessions).length;
      if (sessionCount > 1) {
        select.classList.remove("hidden");
      } else {
        select.classList.add("hidden");
      }
    },

    toggleMinimize: function () {
      var consoleEl = document.getElementById("live-scan-console");
      if (!consoleEl) return;

      var icon = document.querySelector("#live-console-toggle-btn span");

      if (this.minimized) {
        consoleEl.classList.remove("minimized");
        this.minimized = false;
        if (icon) icon.textContent = "keyboard_arrow_down";
      } else {
        consoleEl.classList.add("minimized");
        this.minimized = true;
        if (icon) icon.textContent = "keyboard_arrow_up";
      }
    },

    close: function () {
      var consoleEl = document.getElementById("live-scan-console");
      if (consoleEl) {
        consoleEl.classList.add("translate-y-full");
      }
      
      // Clean up all running subscriptions
      Object.keys(this.sessions).forEach(function (sessionId) {
        var s = LiveScanConsole.sessions[sessionId];
        if (s.channel && window.echoInstance) {
          try {
            window.echoInstance.leaveChannel("scan." + sessionId);
          } catch (_) {}
        }
      });

      this.sessions = {};
      this.activeSessionId = null;

      var select = document.getElementById("live-console-scan-select");
      if (select) {
        select.innerHTML = "";
        select.classList.add("hidden");
      }
    }
  };

  // Expose globally
  window.LiveScanConsole = LiveScanConsole;

  // Initialize once DOM is ready
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", function () {
      LiveScanConsole.init();
    });
  } else {
    LiveScanConsole.init();
  }
})();
