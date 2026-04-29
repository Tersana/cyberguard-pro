/**
 * state-manager.js
 * State Manager for the Risk Dashboard
 * Manages transitions between empty, scanning, and result states
 */

(function () {
  "use strict";

  /**
   * State Manager for the Risk Dashboard
   * Manages visual states and transitions for the dashboard
   */
  const StateManager = {
    /**
     * Current state of the dashboard
     * @type {'empty'|'scanning'|'result'}
     */
    currentState: 'empty',

    /**
     * Resets dashboard to empty state
     * Sets all numeric elements to 0, labels to "N/A" or "Waiting",
     * resets gauge to 0% fill with neutral color, and removes scanning animations
     * 
     * @returns {void}
     */
    resetDashboard() {
      this.currentState = 'empty';

      // Reset all numeric displays to 0
      const numericElements = [
        'openPortsCount',
        'warningStatCount',
        'vulnCount'
      ];
      numericElements.forEach(id => {
        const el = document.getElementById(id);
        if (el) el.textContent = '0';
      });

      // Reset labels to waiting state
      const labelElements = [
        { id: 'sslHealthStatus', value: 'N/A' },
        { id: 'lastScanTime', value: 'Waiting' },
        { id: 'latencyVal', value: '0ms' }
      ];
      labelElements.forEach(({ id, value }) => {
        const el = document.getElementById(id);
        if (el) {
          el.textContent = value;
          // Reset colors to neutral
          el.style.color = '';
        }
      });

      // Reset gauge via RiskGauge module
      if (window.RiskGauge) {
        window.RiskGauge.init();
      }

      // Remove any scanning animations
      const card = document.getElementById('riskScoreCard');
      if (card) {
        card.classList.remove('risk-scanning');
      }
    },

    /**
     * Transitions to scanning state
     * Displays loading indicators and applies pulse animation
     * 
     * @returns {void}
     */
    enterScanningState() {
      this.currentState = 'scanning';

      // Show loading indicators
      const loadingElements = ['vulnCount', 'latencyVal'];
      loadingElements.forEach(id => {
        const el = document.getElementById(id);
        if (el) el.textContent = '--';
      });

      // Apply pulse animation to card
      const card = document.getElementById('riskScoreCard');
      if (card) {
        card.classList.add('risk-scanning');
      }

      // Trigger gauge scanning animation
      if (window.RiskGauge) {
        window.RiskGauge.startScan();
      }
    },

    /**
     * Transitions to result state with data
     * Removes scanning animations, maps data to UI, and updates gauge
     * 
     * @param {Object} scanData - The scan results object
     * @param {Object} scanData.network - Network scan results
     * @param {number} scanData.network.openPortsCount - Count of open ports
     * @param {number} scanData.network.responseTimeMs - Response time in milliseconds
     * @param {Object} scanData.web - Web security scan results
     * @param {string} scanData.web.sslStatus - SSL status ('valid', 'expired', 'missing')
     * @param {Object} scanData.issues - Security issues found
     * @param {number} scanData.issues.criticalCount - Count of critical vulnerabilities
     * @param {Array|number} scanData.issues.warnings - Array of warnings or warning count
     * @param {string} [scanData.timestamp] - ISO 8601 timestamp of scan
     * @param {string} [scanData.type] - Severity type ('critical', 'high', 'medium', 'low')
     * @returns {void}
     */
    enterResultState(scanData) {
      this.currentState = 'result';

      // Remove scanning state
      const card = document.getElementById('riskScoreCard');
      if (card) {
        card.classList.remove('risk-scanning');
      }

      // Map data to UI elements
      if (window.RiskGauge && window.RiskGauge.mapDataToUI) {
        window.RiskGauge.mapDataToUI(scanData);
      }

      // Transform scanData to RiskGauge format and update gauge
      if (window.RiskGauge) {
        const gaugeData = {
          vulnerabilities: scanData.issues?.criticalCount || 0,
          latency: scanData.network?.responseTimeMs || 0,
          openPorts: scanData.network?.openPortsCount || 0,
          warnings: Array.isArray(scanData.issues?.warnings) 
            ? scanData.issues.warnings.length 
            : (scanData.issues?.warnings || 0),
          sslStatus: scanData.web?.sslStatus,
          type: scanData.type || 'medium'
        };
        window.RiskGauge.update(gaugeData);
      }
    },

    /**
     * Handles scan failure
     * Displays connection error state with red gauge at 0%
     * 
     * @returns {void}
     */
    handleScanFailure() {
      this.currentState = 'empty';

      // Show error state
      const card = document.getElementById('riskScoreCard');
      if (card) {
        card.classList.remove('risk-scanning');
      }

      // Display connection error
      const scoreEl = document.getElementById('riskScore');
      const labelEl = document.getElementById('riskLabel');
      if (scoreEl) scoreEl.textContent = '0';
      if (labelEl) {
        labelEl.textContent = 'CONNECTION ERROR';
        labelEl.style.color = getComputedStyle(document.documentElement)
          .getPropertyValue('--cg-danger').trim() || '#F87171';
      }

      // Set gauge to red with 0 score
      const arc = document.getElementById('riskGaugeArc');
      if (arc) {
        arc.setAttribute('stroke', getComputedStyle(document.documentElement)
          .getPropertyValue('--cg-danger').trim() || '#F87171');
        arc.setAttribute('stroke-dashoffset', '427.26'); // 0% fill
      }
    }
  };

  // Expose StateManager to global scope
  window.StateManager = StateManager;

})();
