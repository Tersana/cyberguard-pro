/**
 * Unit tests for State Manager module
 * Tests state transitions and resetDashboard functionality
 */

import { describe, it, expect, beforeEach, vi } from "vitest";
import { JSDOM } from "jsdom";

describe("State Manager", () => {
  let dom;
  let document;
  let window;
  let StateManager;

  beforeEach(() => {
    // Create a fresh DOM for each test
    dom = new JSDOM(
      `
      <!DOCTYPE html>
      <html>
        <body>
          <div id="riskScoreCard"></div>
          <div id="openPortsCount">5</div>
          <div id="warningStatCount">3</div>
          <div id="vulnCount">2</div>
          <div id="sslHealthStatus">Healthy</div>
          <div id="lastScanTime">01/01/2024 12:00</div>
          <div id="latencyVal">150ms</div>
          <div id="riskScore">50</div>
          <div id="riskLabel">MEDIUM RISK</div>
          <svg>
            <path id="riskGaugeArc" stroke="#FBBF24" stroke-dashoffset="200"></path>
          </svg>
        </body>
      </html>
    `,
      { url: "http://localhost" },
    );

    document = dom.window.document;
    window = dom.window;
    global.document = document;
    global.window = window;

    // Mock RiskGauge
    window.RiskGauge = {
      init: vi.fn(),
      startScan: vi.fn(),
      update: vi.fn(),
    };

    // Load the state-manager module
    const stateManagerCode = require("fs").readFileSync(
      "./state-manager.js",
      "utf-8",
    );
    const script = new window.Function(stateManagerCode);
    script();

    StateManager = window.StateManager;
  });

  describe("resetDashboard", () => {
    it("should set currentState to empty", () => {
      StateManager.currentState = "result";
      StateManager.resetDashboard();
      expect(StateManager.currentState).toBe("empty");
    });

    it("should reset all numeric elements to 0", () => {
      StateManager.resetDashboard();

      expect(document.getElementById("openPortsCount").textContent).toBe("0");
      expect(document.getElementById("warningStatCount").textContent).toBe("0");
      expect(document.getElementById("vulnCount").textContent).toBe("0");
    });

    it("should reset label elements to N/A or Waiting", () => {
      StateManager.resetDashboard();

      expect(document.getElementById("sslHealthStatus").textContent).toBe(
        "N/A",
      );
      expect(document.getElementById("lastScanTime").textContent).toBe(
        "Waiting",
      );
      expect(document.getElementById("latencyVal").textContent).toBe("0ms");
    });

    it("should reset colors to neutral", () => {
      const sslEl = document.getElementById("sslHealthStatus");
      sslEl.style.color = "#F87171";

      StateManager.resetDashboard();

      expect(sslEl.style.color).toBe("");
    });

    it("should call RiskGauge.init if available", () => {
      StateManager.resetDashboard();

      expect(window.RiskGauge.init).toHaveBeenCalled();
    });

    it("should remove scanning animations from card", () => {
      const card = document.getElementById("riskScoreCard");
      card.classList.add("risk-scanning");

      StateManager.resetDashboard();

      expect(card.classList.contains("risk-scanning")).toBe(false);
    });

    it("should handle missing elements gracefully", () => {
      // Remove an element
      document.getElementById("openPortsCount").remove();

      // Should not throw
      expect(() => StateManager.resetDashboard()).not.toThrow();
    });

    it("should work when RiskGauge is not available", () => {
      window.RiskGauge = undefined;

      // Should not throw
      expect(() => StateManager.resetDashboard()).not.toThrow();
    });
  });

  describe("enterScanningState", () => {
    it("should set currentState to scanning", () => {
      StateManager.enterScanningState();
      expect(StateManager.currentState).toBe("scanning");
    });

    it("should display loading indicators in numeric elements", () => {
      StateManager.enterScanningState();

      expect(document.getElementById("vulnCount").textContent).toBe("--");
      expect(document.getElementById("latencyVal").textContent).toBe("--");
    });

    it("should apply pulse animation to card", () => {
      StateManager.enterScanningState();

      const card = document.getElementById("riskScoreCard");
      expect(card.classList.contains("risk-scanning")).toBe(true);
    });

    it("should call RiskGauge.startScan if available", () => {
      StateManager.enterScanningState();

      expect(window.RiskGauge.startScan).toHaveBeenCalled();
    });

    it("should handle missing elements gracefully", () => {
      document.getElementById("vulnCount").remove();

      // Should not throw
      expect(() => StateManager.enterScanningState()).not.toThrow();
    });
  });

  describe("enterResultState", () => {
    it("should set currentState to result", () => {
      const scanData = {
        network: { openPortsCount: 5, responseTimeMs: 150 },
        web: { sslStatus: "valid" },
        issues: { criticalCount: 2, warnings: 3 },
      };

      StateManager.enterResultState(scanData);
      expect(StateManager.currentState).toBe("result");
    });

    it("should remove scanning animations from card", () => {
      const card = document.getElementById("riskScoreCard");
      card.classList.add("risk-scanning");

      const scanData = {
        network: { openPortsCount: 5, responseTimeMs: 150 },
        web: { sslStatus: "valid" },
        issues: { criticalCount: 2, warnings: 3 },
      };

      StateManager.enterResultState(scanData);

      expect(card.classList.contains("risk-scanning")).toBe(false);
    });

    it("should call RiskGauge.update with transformed gaugeData", () => {
      const scanData = {
        network: { openPortsCount: 5, responseTimeMs: 150 },
        web: { sslStatus: "valid" },
        issues: { criticalCount: 2, warnings: 3 },
        type: "high",
      };

      StateManager.enterResultState(scanData);

      // Verify it was called with transformed data
      expect(window.RiskGauge.update).toHaveBeenCalledWith({
        vulnerabilities: 2,
        latency: 150,
        openPorts: 5,
        warnings: 3,
        sslStatus: "valid",
        type: "high",
      });
    });

    it("should call mapDataToUI with scanData", () => {
      window.RiskGauge.mapDataToUI = vi.fn();

      const scanData = {
        network: { openPortsCount: 5, responseTimeMs: 150 },
        web: { sslStatus: "valid" },
        issues: { criticalCount: 2, warnings: 3 },
      };

      StateManager.enterResultState(scanData);

      expect(window.RiskGauge.mapDataToUI).toHaveBeenCalledWith(scanData);
    });

    it("should transform warnings array to count", () => {
      const scanData = {
        network: { openPortsCount: 5, responseTimeMs: 150 },
        web: { sslStatus: "valid" },
        issues: {
          criticalCount: 2,
          warnings: ["Warning 1", "Warning 2", "Warning 3"],
        },
      };

      StateManager.enterResultState(scanData);

      expect(window.RiskGauge.update).toHaveBeenCalledWith({
        vulnerabilities: 2,
        latency: 150,
        openPorts: 5,
        warnings: 3,
        sslStatus: "valid",
        type: "medium",
      });
    });

    it("should use default values for missing fields", () => {
      const scanData = {
        network: {},
        web: {},
        issues: {},
      };

      StateManager.enterResultState(scanData);

      expect(window.RiskGauge.update).toHaveBeenCalledWith({
        vulnerabilities: 0,
        latency: 0,
        openPorts: 0,
        warnings: 0,
        sslStatus: undefined,
        type: "medium",
      });
    });

    it("should default type to medium when not provided", () => {
      const scanData = {
        network: { openPortsCount: 5, responseTimeMs: 150 },
        web: { sslStatus: "valid" },
        issues: { criticalCount: 2, warnings: 3 },
      };

      StateManager.enterResultState(scanData);

      const callArgs = window.RiskGauge.update.mock.calls[0][0];
      expect(callArgs.type).toBe("medium");
    });

    it("should work when RiskGauge is not available", () => {
      window.RiskGauge = undefined;

      const scanData = {
        network: { openPortsCount: 5, responseTimeMs: 150 },
        web: { sslStatus: "valid" },
        issues: { criticalCount: 2, warnings: 3 },
      };

      // Should not throw
      expect(() => StateManager.enterResultState(scanData)).not.toThrow();
    });
  });

  describe("handleScanFailure", () => {
    it("should set currentState to empty", () => {
      StateManager.currentState = "scanning";
      StateManager.handleScanFailure();
      expect(StateManager.currentState).toBe("empty");
    });

    it("should remove scanning animations from card", () => {
      const card = document.getElementById("riskScoreCard");
      card.classList.add("risk-scanning");

      StateManager.handleScanFailure();

      expect(card.classList.contains("risk-scanning")).toBe(false);
    });

    it("should display CONNECTION ERROR label in red", () => {
      StateManager.handleScanFailure();

      const labelEl = document.getElementById("riskLabel");
      expect(labelEl.textContent).toBe("CONNECTION ERROR");
      // JSDOM converts hex to rgb format
      expect(labelEl.style.color).toMatch(/rgb\(248,\s*113,\s*113\)|#F87171/);
    });

    it("should set risk score to 0", () => {
      StateManager.handleScanFailure();

      const scoreEl = document.getElementById("riskScore");
      expect(scoreEl.textContent).toBe("0");
    });

    it("should set gauge to red with 0% fill", () => {
      StateManager.handleScanFailure();

      const arc = document.getElementById("riskGaugeArc");
      expect(arc.getAttribute("stroke")).toBe("#F87171");
      expect(arc.getAttribute("stroke-dashoffset")).toBe("427.26");
    });

    it("should handle missing elements gracefully", () => {
      document.getElementById("riskLabel").remove();

      // Should not throw
      expect(() => StateManager.handleScanFailure()).not.toThrow();
    });
  });

  describe("State transitions", () => {
    it("should transition from empty to scanning", () => {
      StateManager.resetDashboard();
      expect(StateManager.currentState).toBe("empty");

      StateManager.enterScanningState();
      expect(StateManager.currentState).toBe("scanning");
    });

    it("should transition from scanning to result", () => {
      StateManager.enterScanningState();
      expect(StateManager.currentState).toBe("scanning");

      const scanData = {
        network: { openPortsCount: 5, responseTimeMs: 150 },
        web: { sslStatus: "valid" },
        issues: { criticalCount: 2, warnings: 3 },
      };

      StateManager.enterResultState(scanData);
      expect(StateManager.currentState).toBe("result");
    });

    it("should transition from scanning to empty on failure", () => {
      StateManager.enterScanningState();
      expect(StateManager.currentState).toBe("scanning");

      StateManager.handleScanFailure();
      expect(StateManager.currentState).toBe("empty");
    });

    it("should transition from result to scanning for new scan", () => {
      const scanData = {
        network: { openPortsCount: 5, responseTimeMs: 150 },
        web: { sslStatus: "valid" },
        issues: { criticalCount: 2, warnings: 3 },
      };

      StateManager.enterResultState(scanData);
      expect(StateManager.currentState).toBe("result");

      StateManager.enterScanningState();
      expect(StateManager.currentState).toBe("scanning");
    });

    it("should allow reset from any state", () => {
      StateManager.enterScanningState();
      StateManager.resetDashboard();
      expect(StateManager.currentState).toBe("empty");

      const scanData = {
        network: { openPortsCount: 5, responseTimeMs: 150 },
        web: { sslStatus: "valid" },
        issues: { criticalCount: 2, warnings: 3 },
      };

      StateManager.enterResultState(scanData);
      StateManager.resetDashboard();
      expect(StateManager.currentState).toBe("empty");
    });
  });

  describe("enterResultState - Task 5.3 Requirements", () => {
    it("should complete all required steps in correct order", () => {
      const callOrder = [];

      // Track call order
      window.RiskGauge.mapDataToUI = vi.fn(() => callOrder.push("mapDataToUI"));
      window.RiskGauge.update = vi.fn(() => callOrder.push("update"));

      const card = document.getElementById("riskScoreCard");
      card.classList.add("risk-scanning");

      const scanData = {
        network: { openPortsCount: 5, responseTimeMs: 150 },
        web: { sslStatus: "valid" },
        issues: { criticalCount: 2, warnings: ["Warning 1", "Warning 2"] },
        type: "high",
        timestamp: "2024-01-15T10:30:00Z",
      };

      StateManager.enterResultState(scanData);

      // Verify all requirements
      // 1. Set currentState to 'result'
      expect(StateManager.currentState).toBe("result");

      // 2. Remove scanning animations from riskScoreCard
      expect(card.classList.contains("risk-scanning")).toBe(false);

      // 3. Invoke mapDataToUI with scanData
      expect(window.RiskGauge.mapDataToUI).toHaveBeenCalledWith(scanData);

      // 4. Transform scanData to RiskGauge format
      // 5. Invoke RiskGauge.update with transformed data
      expect(window.RiskGauge.update).toHaveBeenCalledWith({
        vulnerabilities: 2,
        latency: 150,
        openPorts: 5,
        warnings: 2, // Array length
        sslStatus: "valid",
        type: "high",
      });

      // Verify call order: mapDataToUI should be called before update
      expect(callOrder).toEqual(["mapDataToUI", "update"]);
    });
  });
});
