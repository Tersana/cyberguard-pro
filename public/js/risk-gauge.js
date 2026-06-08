/**
 * risk-gauge.js
 * Dynamic Global Risk Score component — pure Vanilla JS
 *
 * Public API (attached to window.RiskGauge):
 *   RiskGauge.init()                  — reset to idle state
 *   RiskGauge.startScan()             — enter loading/scanning state
 *   RiskGauge.update(scanData)        — feed results and animate
 *   RiskGauge.refreshColors()         — invalidate color cache (call after theme changes)
 *
 * scanData shape:
 *   {
 *     vulnerabilities : number,   // raw vuln count
 *     latency         : number,   // ms
 *     openPorts       : number,   // optional, used in score calc
 *     warnings        : number,   // optional
 *     type            : 'critical'|'high'|'medium'|'low'  // optional severity hint
 *   }
 */

(function () {
  "use strict";

  // ─── SVG geometry ────────────────────────────────────────────────
  const RADIUS = 68;
  const CIRCUMFERENCE = 2 * Math.PI * RADIUS; // ≈ 427.26

  // ─── Token resolver (reads --cg-* from :root via getComputedStyle) ─
  /**
   * Resolves CSS custom property values from the document root.
   * Implements design token resolution with error handling and fallback support.
   * 
   * **Validates: Requirements 4.1, 4.2, 4.5, 4.6**
   * 
   * @param {string} name - CSS custom property name (e.g., '--cg-accent')
   * @param {string} fallback - Fallback value to use if token is not found
   * @returns {string} Resolved token value or fallback
   * 
   * @example
   * const accentColor = getCSSVar('--cg-accent', '#3b82f6');
   * // Returns: '#3b82f6' (from CSS) or fallback if not found
   */
  function getCSSVar(name, fallback) {
    try {
      const val = getComputedStyle(document.documentElement)
        .getPropertyValue(name)
        .trim();
      
      if (!val) {
        console.warn(`[RiskGauge] CSS token '${name}' not found, using fallback: ${fallback}`);
        return fallback;
      }
      
      return val;
    } catch (error) {
      console.warn(`[RiskGauge] Failed to resolve CSS token '${name}': ${error.message}, using fallback: ${fallback}`);
      return fallback;
    }
  }

  /** Lazily resolved colors — cached after first call */
  let _colors = null;
  function colors() {
    if (!_colors) {
      _colors = {
        success:  getCSSVar('--cg-success', '#34D399'),
        warning:  getCSSVar('--cg-warning', '#FBBF24'),
        danger:   getCSSVar('--cg-danger',  '#F87171'),
        accent:   getCSSVar('--cg-accent',  '#3b82f6'),
        info:     getCSSVar('--cg-info',    '#38BDF8'),
        muted:    getCSSVar('--cg-text-3',  '#64748B'),
      };
    }
    return _colors;
  }

  /**
   * Invalidates the color cache, forcing colors() to re-resolve tokens on next call.
   * Call this after theme changes or CSS custom property updates.
   * 
   * **Validates: Requirement 12.3**
   */
  function refreshColors() {
    _colors = null;
  }

  // ─── Threshold config (uses design tokens) ───────────────────────
  function getThresholds() {
    const c = colors();
    return [
      {
        max: 30,
        label: "LOW RISK",
        color: c.success,
        glow: `0 0 18px ${c.success}B3, 0 0 40px ${c.success}4D`,
        textColor: c.success,
        iconColor: c.success,
      },
      {
        max: 69,
        label: "MEDIUM RISK",
        color: c.warning,
        glow: `0 0 18px ${c.warning}B3, 0 0 40px ${c.warning}4D`,
        textColor: c.warning,
        iconColor: c.warning,
      },
      {
        max: 100,
        label: "HIGH RISK",
        color: c.danger,
        glow: `0 0 18px ${c.danger}B3, 0 0 40px ${c.danger}4D`,
        textColor: c.danger,
        iconColor: c.danger,
      },
    ];
  }

  function getIdleConfig() {
    const c = colors();
    return {
      label: "IDLE",
      color: c.muted,
      glow: "none",
      textColor: c.muted,
      iconColor: c.muted,
    };
  }

  function getScanConfig() {
    const c = colors();
    return {
      label: "SCANNING...",
      color: c.accent,
      glow: "none",
      textColor: c.accent,
      iconColor: c.accent,
    };
  }

  // ─── DOM refs (resolved lazily after DOMContentLoaded) ───────────
  let els = {};

  function resolveEls() {
    els = {
      card:    document.getElementById("riskScoreCard"),
      arc:     document.getElementById("riskGaugeArc"),
      score:   document.getElementById("riskScore"),
      label:   document.getElementById("riskLabel"),
      vuln:    document.getElementById("vulnCount"),
      latency: document.getElementById("latencyVal"),
      icon:    document.getElementById("riskCardIcon"),
      // quick-stat badges (optional — present in network tab)
      openPorts: document.getElementById("openPortsCount"),
      warnings:  document.getElementById("warningStatCount"),
    };
  }

  // ─── Animation state ─────────────────────────────────────────────
  let _scanSpinRaf = null;   // requestAnimationFrame id for spin loop
  let _countRaf    = null;   // requestAnimationFrame id for count-up
  let _arcRaf      = null;   // requestAnimationFrame id for arc fill

  // ─── Helpers ─────────────────────────────────────────────────────

  /** Map a 0-100 score to SVG stroke-dashoffset (full = 0, empty = CIRCUMFERENCE) */
  function scoreToOffset(score) {
    return CIRCUMFERENCE - (score / 100) * CIRCUMFERENCE;
  }

  /** Pick the threshold config for a given score */
  function getConfig(score) {
    const thresholds = getThresholds();
    return thresholds.find((t) => score <= t.max) || thresholds[2];
  }

  /**
   * Returns color and label information for a given risk score.
   * Maps scores to color thresholds according to requirements 6.1, 6.2, 6.3.
   * 
   * @param {number} score - Risk score between 0 and 100
   * @returns {Object} Object containing color and label properties
   * @returns {string} return.color - Resolved color from design tokens
   * @returns {string} return.label - Risk level label (LOW RISK, MEDIUM RISK, or HIGH RISK)
   */
  function getColorForScore(score) {
    const c = colors();
    // Validate input
    if (typeof score !== 'number' || isNaN(score)) {
      return { color: c.muted, label: 'INVALID' };
    }

    // Clamp score to valid range
    const clampedScore = Math.max(0, Math.min(100, score));

    // Determine color and label based on thresholds
    if (clampedScore <= 30) {
      return { color: c.success, label: 'LOW RISK' };
    } else if (clampedScore <= 69) {
      return { color: c.warning, label: 'MEDIUM RISK' };
    } else {
      return { color: c.danger, label: 'HIGH RISK' };
    }
  }

  /** Apply color/glow to the arc and label */
  function applyConfig(cfg) {
    if (!els.arc) return;
    els.arc.setAttribute("stroke", cfg.color);
    els.arc.style.filter = cfg.glow !== "none"
      ? `drop-shadow(0 0 6px ${cfg.color})`
      : "none";
    if (els.label) {
      els.label.textContent = cfg.label;
      els.label.style.color = cfg.textColor;
      els.label.style.textShadow = cfg.glow !== "none"
        ? `0 0 8px ${cfg.color}`
        : "none";
    }
    if (els.icon) {
      els.icon.style.color = cfg.iconColor;
    }
  }

  /** Cancel all running animation loops */
  function cancelAnimations() {
    if (_scanSpinRaf) { cancelAnimationFrame(_scanSpinRaf); _scanSpinRaf = null; }
    if (_countRaf)    { cancelAnimationFrame(_countRaf);    _countRaf    = null; }
    if (_arcRaf)      { cancelAnimationFrame(_arcRaf);      _arcRaf      = null; }
  }

  // ─── 1. Spinning indeterminate animation (scan state) ────────────
  function startSpinAnimation() {
    if (!els.arc) return;
    // Show a partial arc that rotates
    const spinLength = CIRCUMFERENCE * 0.25; // 25% arc visible
    els.arc.setAttribute("stroke-dasharray", `${spinLength} ${CIRCUMFERENCE - spinLength}`);
    els.arc.style.transition = "none";

    let angle = 0;
    const svg = document.getElementById("riskGaugeSvg");

    function spin() {
      angle = (angle + 4) % 360;
      if (svg) svg.style.transform = `rotate(${angle - 90}deg)`;
      _scanSpinRaf = requestAnimationFrame(spin);
    }
    spin();
  }

  function stopSpinAnimation() {
    cancelAnimationFrame(_scanSpinRaf);
    _scanSpinRaf = null;
    const svg = document.getElementById("riskGaugeSvg");
    if (svg) svg.style.transform = "rotate(-90deg)";
    // Restore full dasharray
    if (els.arc) {
      els.arc.setAttribute("stroke-dasharray", CIRCUMFERENCE.toFixed(2));
      els.arc.style.transition = "stroke-dashoffset 0.05s linear, stroke 0.4s ease, filter 0.4s ease";
    }
  }

  // ─── 2. Smooth arc fill animation ────────────────────────────────
  function animateArc(targetScore, duration = 1200) {
    if (!els.arc) return;
    const startOffset = parseFloat(els.arc.getAttribute("stroke-dashoffset")) || CIRCUMFERENCE;
    const endOffset   = scoreToOffset(targetScore);
    const startTime   = performance.now();

    function easeOutCubic(t) { return 1 - Math.pow(1 - t, 3); }

    function step(now) {
      const elapsed  = now - startTime;
      const progress = Math.min(elapsed / duration, 1);
      const eased    = easeOutCubic(progress);
      const current  = startOffset + (endOffset - startOffset) * eased;
      els.arc.setAttribute("stroke-dashoffset", current.toFixed(3));
      if (progress < 1) {
        _arcRaf = requestAnimationFrame(step);
      }
    }
    _arcRaf = requestAnimationFrame(step);
  }

  // ─── 3. Smooth count-up animation ────────────────────────────────
  function animateCount(el, from, to, duration = 1200, suffix = "") {
    if (!el) return;
    const startTime = performance.now();

    function easeOutCubic(t) { return 1 - Math.pow(1 - t, 3); }

    function step(now) {
      const elapsed  = now - startTime;
      const progress = Math.min(elapsed / duration, 1);
      const eased    = easeOutCubic(progress);
      const value    = Math.round(from + (to - from) * eased);
      el.textContent = value + suffix;
      if (progress < 1) {
        _countRaf = requestAnimationFrame(step);
      }
    }
    _countRaf = requestAnimationFrame(step);
  }

  // ─── 4. Score calculation ─────────────────────────────────────────
  /**
   * Calculates a 0-100 risk score from raw scan data.
   *
   * Weights:
   *   vulnerabilities : up to 50 pts  (each vuln = 5 pts, capped at 10 vulns)
   *   latency         : up to 20 pts  (>500ms = 20, >200ms = 10, >100ms = 5)
   *   openPorts       : up to 20 pts  (each port = 2 pts, capped at 10 ports)
   *   warnings        : up to 10 pts  (each warning = 2 pts, capped at 5 warnings)
   *   sslStatus       : up to 15 pts  (invalid SSL = 15 pts)
   *   type modifier   : critical +10, high +5, medium +0, low -5
   */
  function calculateScore(data) {
    // Handle null, undefined, or non-object inputs
    if (!data || typeof data !== 'object') {
      return 0;
    }

    let score = 0;

    // Vulnerability weight (0-50)
    const vulns = Math.min(data.vulnerabilities || 0, 10);
    score += vulns * 5;

    // Latency weight (0-20)
    const lat = data.latency || 0;
    if      (lat > 500) score += 20;
    else if (lat > 200) score += 10;
    else if (lat > 100) score += 5;

    // Open ports weight (0-20)
    const ports = Math.min(data.openPorts || 0, 10);
    score += ports * 2;

    // Warnings weight (0-10)
    const warns = Math.min(data.warnings || 0, 5);
    score += warns * 2;

    // SSL health weight (0-15)
    if (data.sslStatus && data.sslStatus !== 'valid') {
      score += 15;
    }

    // Severity type modifier (-5 to +10)
    const typeBonus = { critical: 10, high: 5, medium: 0, low: -5 };
    score += typeBonus[data.type] || 0;

    return Math.max(0, Math.min(100, score));
  }

  // ─── 5. Data Mapper ───────────────────────────────────────────────
  /**
   * Maps scan data to UI elements with formatting and validation.
   * Binds network, web, and issue data to dashboard elements.
   * 
   * @param {object} scanData - The scan results object
   * @param {object} scanData.network - Network scan results
   * @param {number} scanData.network.openPortsCount - Count of open ports
   * @param {number} scanData.network.responseTimeMs - Response time in milliseconds
   * @param {object} scanData.web - Web security scan results
   * @param {string} scanData.web.sslStatus - SSL status ('valid', 'expired', 'missing')
   * @param {object} scanData.issues - Security issues found
   * @param {number} scanData.issues.criticalCount - Count of critical vulnerabilities
   * @param {Array|number} scanData.issues.warnings - Array of warnings or warning count
   * @param {string} scanData.timestamp - ISO 8601 timestamp of scan
   * @returns {void}
   */
  function mapDataToUI(scanData) {
    // Validate input
    if (!scanData || typeof scanData !== 'object') {
      console.warn('Invalid scan data provided to mapper');
      return;
    }

    // Map open ports count
    const openPortsEl = document.getElementById('openPortsCount');
    if (openPortsEl) {
      const portCount = scanData.network?.openPortsCount ?? 0;
      openPortsEl.textContent = portCount === 0 ? 'None' : portCount;
    }

    // Map SSL health status with color coding
    const sslHealthEl = document.getElementById('sslHealthStatus');
    if (sslHealthEl && scanData.web?.sslStatus) {
      const c = colors();
      const status = scanData.web.sslStatus;
      if (status === 'valid') {
        sslHealthEl.textContent = 'Healthy';
        sslHealthEl.style.color = c.success;
      } else if (status === 'expired' || status === 'missing') {
        sslHealthEl.textContent = 'Critical';
        sslHealthEl.style.color = c.danger;
      }
    }

    // Map warnings count with color coding
    const warningsEl = document.getElementById('warningStatCount');
    if (warningsEl && scanData.issues?.warnings !== undefined) {
      const c = colors();
      const warnCount = Array.isArray(scanData.issues.warnings)
        ? scanData.issues.warnings.length
        : scanData.issues.warnings;
      warningsEl.textContent = warnCount;

      // Apply color based on severity
      if (warnCount === 0) {
        warningsEl.style.color = c.success;
      } else if (warnCount <= 5) {
        warningsEl.style.color = c.warning;
      } else {
        warningsEl.style.color = c.danger;
      }
    }

    // Map timestamp with formatting
    const lastScanEl = document.getElementById('lastScanTime');
    if (lastScanEl) {
      const timestamp = scanData.timestamp || new Date().toISOString();
      const date = new Date(timestamp);
      const formatted = `${date.getDate().toString().padStart(2, '0')}/${
        (date.getMonth() + 1).toString().padStart(2, '0')}/${
        date.getFullYear()} ${
        date.getHours().toString().padStart(2, '0')}:${
        date.getMinutes().toString().padStart(2, '0')}`;
      lastScanEl.textContent = formatted;
    }

    // Map vulnerabilities count
    const vulnEl = document.getElementById('vulnCount');
    if (vulnEl && scanData.issues?.criticalCount !== undefined) {
      vulnEl.textContent = scanData.issues.criticalCount;
    }

    // Map latency
    const latencyEl = document.getElementById('latencyVal');
    if (latencyEl && scanData.network?.responseTimeMs !== undefined) {
      latencyEl.textContent = `${scanData.network.responseTimeMs}ms`;
    }
  }

  // ─── Public API ───────────────────────────────────────────────────

  /** Reset to idle state */
  function init() {
    resolveEls();
    cancelAnimations();
    stopSpinAnimation();

    if (els.card) els.card.classList.remove("risk-scanning");

    // Reset arc
    if (els.arc) {
      els.arc.setAttribute("stroke-dasharray", CIRCUMFERENCE.toFixed(2));
      els.arc.setAttribute("stroke-dashoffset", CIRCUMFERENCE.toFixed(2));
      els.arc.style.transition = "none";
    }

    // Reset text
    if (els.score)   els.score.textContent   = "0";
    if (els.vuln)    els.vuln.textContent     = "0";
    if (els.latency) els.latency.textContent  = "0ms";

    applyConfig(getIdleConfig());
  }

  /** Enter scanning/loading state */
  function startScan() {
    resolveEls();
    cancelAnimations();

    if (els.card) els.card.classList.add("risk-scanning");
    if (els.score) els.score.textContent = "--";

    applyConfig(getScanConfig());
    startSpinAnimation();
  }

  /**
   * Feed scan results and animate the gauge.
   * @param {object} scanData  — { vulnerabilities, latency, openPorts, warnings, type }
   *                              OR full scanData with network, web, issues structure
   */
  function update(scanData) {
    resolveEls();
    cancelAnimations();
    stopSpinAnimation();

    if (els.card) els.card.classList.remove("risk-scanning");

    // Map data to UI elements if full scanData structure is provided
    if (scanData.network || scanData.web || scanData.issues) {
      mapDataToUI(scanData);
      
      // Transform to legacy format for gauge calculation
      scanData = {
        vulnerabilities: scanData.issues?.criticalCount || 0,
        latency: scanData.network?.responseTimeMs || 0,
        openPorts: scanData.network?.openPortsCount || 0,
        warnings: Array.isArray(scanData.issues?.warnings)
          ? scanData.issues.warnings.length
          : (scanData.issues?.warnings || 0),
        sslStatus: scanData.web?.sslStatus,
        type: scanData.type || 'medium'
      };
    }

    // Calculate risk score
    const score = calculateScore(scanData);
    
    // Get color and label using getColorForScore
    const colorInfo = getColorForScore(score);
    
    // Get full config for enhanced styling (glow, icon colors, etc.)
    const cfg = getConfig(score);

    // Apply color to gauge arc stroke
    if (els.arc) {
      els.arc.setAttribute("stroke", colorInfo.color);
      els.arc.style.filter = cfg.glow !== "none"
        ? `drop-shadow(0 0 6px ${colorInfo.color})`
        : "none";
    }
    
    // Update riskLabel text element with severity label
    if (els.label) {
      els.label.textContent = colorInfo.label;
      els.label.style.color = cfg.textColor;
      els.label.style.textShadow = cfg.glow !== "none"
        ? `0 0 8px ${colorInfo.color}`
        : "none";
    }
    
    // Apply icon color
    if (els.icon) {
      els.icon.style.color = cfg.iconColor;
    }

    // Animate gauge arc fill based on score percentage
    animateArc(score, 1200);

    // Update riskScore text element with animated counter
    const prevScore = parseInt(els.score?.textContent) || 0;
    animateCount(els.score, prevScore, score, 1200);

    // Animate vuln counter
    const prevVuln = parseInt(els.vuln?.textContent) || 0;
    animateCount(els.vuln, prevVuln, scanData.vulnerabilities || 0, 900);

    // Animate latency counter
    const prevLat = parseInt(els.latency?.textContent) || 0;
    animateCount(els.latency, prevLat, scanData.latency || 0, 900, "ms");

    // Update quick-stat badges if present
    if (els.openPorts && scanData.openPorts !== undefined) {
      animateCount(els.openPorts, parseInt(els.openPorts.textContent) || 0, scanData.openPorts, 900);
    }
    if (els.warnings && scanData.warnings !== undefined) {
      animateCount(els.warnings, parseInt(els.warnings.textContent) || 0, scanData.warnings, 900);
    }
  }

  // ─── CSS for scanning pulse (injected once) ───────────────────────
  function injectStyles() {
    if (document.getElementById("risk-gauge-styles")) return;
    const style = document.createElement("style");
    style.id = "risk-gauge-styles";
    style.textContent = `
      @keyframes riskCardPulse {
        0%, 100% { box-shadow: 0 0 0 0 rgba(255, 255, 255, 0); }
        50%       { box-shadow: 0 0 0 4px rgba(255, 255, 255, 0.1); }
      }
      .risk-scanning {
        animation: riskCardPulse 1.4s ease-in-out infinite;
      }
    `;
    document.head.appendChild(style);
  }

  // ─── Bootstrap ───────────────────────────────────────────────────
  function bootstrap() {
    // === AUTHENTICATION CHECK ===
    if (typeof window.runAuthGuard === 'function' && !window.runAuthGuard()) {
      return; // Stop initialization if not authenticated
    }

    injectStyles();
    init();

    // Hook into the existing scan flow via a custom event so main.js
    // can dispatch it without coupling to this module directly.
    document.addEventListener("cyberguard:scanStart", () => startScan());
    document.addEventListener("cyberguard:scanResult", (e) => update(e.detail));
    document.addEventListener("cyberguard:scanReset",  () => init());
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", bootstrap);
  } else {
    bootstrap();
  }

  // Expose public API
  window.RiskGauge = { init, startScan, update, calculateScore, mapDataToUI, getColorForScore, refreshColors };

})();
