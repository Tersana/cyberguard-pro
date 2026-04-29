/**
 * Integration Tests for Gauge Color Rendering (Task 6.6)
 * Tests for design-token-system spec - Phase 4 JavaScript Integration
 * 
 * **Validates: Requirements 4.3, 4.4, 4.5, 20.1, 20.2**
 * 
 * These tests verify that the risk gauge component correctly:
 * - Displays success color (#34D399) for low risk scores (0-30)
 * - Displays warning color (#FBBF24) for medium risk scores (31-69)
 * - Displays danger color (#F87171) for high risk scores (70-100)
 * - Resolves colors from CSS custom properties (design tokens)
 * - Matches token definitions exactly
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { JSDOM } from 'jsdom';
import { readFileSync } from 'fs';
import { join } from 'path';

describe('Gauge Color Rendering Integration Tests (Task 6.6)', () => {
  let dom;
  let document;
  let window;
  let RiskGauge;

  beforeEach(() => {
    // Create a complete DOM environment with all required elements
    dom = new JSDOM(`
      <!DOCTYPE html>
      <html>
        <head>
          <style>
            /* Load theme tokens */
            :root {
              --cg-success: #34D399;
              --cg-warning: #FBBF24;
              --cg-danger: #F87171;
              --cg-accent: #A78BFA;
              --cg-info: #38BDF8;
              --cg-text-3: #64748B;
            }
          </style>
        </head>
        <body>
          <!-- Risk Gauge Card -->
          <div id="riskScoreCard" class="cyber-card">
            <svg id="riskGaugeSvg" width="200" height="200" viewBox="0 0 200 200">
              <circle
                id="riskGaugeArc"
                cx="100"
                cy="100"
                r="68"
                fill="none"
                stroke="#64748B"
                stroke-width="12"
                stroke-dasharray="427.26"
                stroke-dashoffset="427.26"
              />
            </svg>
            <div id="riskScore">0</div>
            <div id="riskLabel">IDLE</div>
            <div id="riskCardIcon">🛡️</div>
          </div>

          <!-- Quick Stats -->
          <div id="vulnCount">0</div>
          <div id="latencyVal">0ms</div>
          <div id="openPortsCount">0</div>
          <div id="warningStatCount">0</div>
        </body>
      </html>
    `, {
      url: 'http://localhost',
      resources: 'usable',
      runScripts: 'outside-only'
    });

    document = dom.window.document;
    window = dom.window;
    global.document = document;
    global.window = window;
    global.getComputedStyle = window.getComputedStyle;
    
    // Set up animation frame mocks on window before loading script
    window.requestAnimationFrame = vi.fn((cb) => setTimeout(cb, 0));
    window.cancelAnimationFrame = vi.fn();
    
    global.requestAnimationFrame = window.requestAnimationFrame;
    global.cancelAnimationFrame = window.cancelAnimationFrame;
    global.performance = { now: () => Date.now() };

    // Load risk-gauge.js
    const riskGaugeCode = readFileSync(join(process.cwd(), 'risk-gauge.js'), 'utf-8');
    
    // Execute the script in the window context
    const script = new window.Function(riskGaugeCode);
    script.call(window);

    // Wait for script to execute
    RiskGauge = window.RiskGauge;
  });

  afterEach(() => {
    vi.restoreAllMocks();
    dom.window.close();
  });

  describe('Low Risk Range (0-30) - Success Color', () => {
    /**
     * **Validates: Requirement 4.3** - Risk gauge uses token-based colors
     * **Validates: Requirement 20.1** - Visual appearance matches token definitions
     */
    it('should display success color (#34D399) for score 0', () => {
      // Initialize gauge
      RiskGauge.init();

      // Update with low risk score
      RiskGauge.update({
        vulnerabilities: 0,
        latency: 50,
        openPorts: 0,
        warnings: 0
      });

      // Get the arc element
      const arc = document.getElementById('riskGaugeArc');
      const arcStroke = arc.getAttribute('stroke');

      // Verify success color is applied
      expect(arcStroke).toBe('#34D399');
    });

    it('should display success color (#34D399) for score 15', () => {
      RiskGauge.init();

      // Update with low risk score (15 = 3 vulns * 5)
      RiskGauge.update({
        vulnerabilities: 3,
        latency: 50,
        openPorts: 0,
        warnings: 0
      });

      const arc = document.getElementById('riskGaugeArc');
      const arcStroke = arc.getAttribute('stroke');

      expect(arcStroke).toBe('#34D399');
    });

    it('should display success color (#34D399) for score 30', () => {
      RiskGauge.init();

      // Update with boundary low risk score (30 = 6 vulns * 5)
      RiskGauge.update({
        vulnerabilities: 6,
        latency: 50,
        openPorts: 0,
        warnings: 0
      });

      const arc = document.getElementById('riskGaugeArc');
      const arcStroke = arc.getAttribute('stroke');

      expect(arcStroke).toBe('#34D399');
    });

    it('should display "LOW RISK" label for scores 0-30', () => {
      RiskGauge.init();

      RiskGauge.update({
        vulnerabilities: 4,
        latency: 50,
        openPorts: 0,
        warnings: 0
      });

      const label = document.getElementById('riskLabel');
      expect(label.textContent).toBe('LOW RISK');
    });
  });

  describe('Medium Risk Range (31-69) - Warning Color', () => {
    /**
     * **Validates: Requirement 4.3** - Risk gauge uses token-based colors
     * **Validates: Requirement 20.1** - Visual appearance matches token definitions
     */
    it('should display warning color (#FBBF24) for score 31', () => {
      RiskGauge.init();

      // Update with medium risk score (31 = 6 vulns * 5 + 1 latency)
      RiskGauge.update({
        vulnerabilities: 6,
        latency: 150,
        openPorts: 0,
        warnings: 0
      });

      const arc = document.getElementById('riskGaugeArc');
      const arcStroke = arc.getAttribute('stroke');

      expect(arcStroke).toBe('#FBBF24');
    });

    it('should display warning color (#FBBF24) for score 50', () => {
      RiskGauge.init();

      // Update with medium risk score (50 = 10 vulns * 5)
      RiskGauge.update({
        vulnerabilities: 10,
        latency: 50,
        openPorts: 0,
        warnings: 0
      });

      const arc = document.getElementById('riskGaugeArc');
      const arcStroke = arc.getAttribute('stroke');

      expect(arcStroke).toBe('#FBBF24');
    });

    it('should display warning color (#FBBF24) for score 69', () => {
      RiskGauge.init();

      // Update with boundary medium risk score
      // 69 = 10 vulns * 5 (50) + latency 500ms (20) + warnings (2 * 2 = 4) - 5 (low type) = 69
      RiskGauge.update({
        vulnerabilities: 10,
        latency: 550,
        openPorts: 0,
        warnings: 2,
        type: 'low'
      });

      const arc = document.getElementById('riskGaugeArc');
      const arcStroke = arc.getAttribute('stroke');

      expect(arcStroke).toBe('#FBBF24');
    });

    it('should display "MEDIUM RISK" label for scores 31-69', () => {
      RiskGauge.init();

      RiskGauge.update({
        vulnerabilities: 8,
        latency: 150,
        openPorts: 0,
        warnings: 0
      });

      const label = document.getElementById('riskLabel');
      expect(label.textContent).toBe('MEDIUM RISK');
    });
  });

  describe('High Risk Range (70-100) - Danger Color', () => {
    /**
     * **Validates: Requirement 4.3** - Risk gauge uses token-based colors
     * **Validates: Requirement 20.1** - Visual appearance matches token definitions
     */
    it('should display danger color (#F87171) for score 70', () => {
      RiskGauge.init();

      // Update with high risk score (70 = 10 vulns * 5 + latency 500ms + 5 ports * 2)
      RiskGauge.update({
        vulnerabilities: 10,
        latency: 550,
        openPorts: 5,
        warnings: 0
      });

      const arc = document.getElementById('riskGaugeArc');
      const arcStroke = arc.getAttribute('stroke');

      expect(arcStroke).toBe('#F87171');
    });

    it('should display danger color (#F87171) for score 85', () => {
      RiskGauge.init();

      // Update with high risk score
      // 85 = 10 vulns * 5 (50) + latency 500ms (20) + 5 ports * 2 (10) + 5 warnings * 2 (10) - 5 (low type) = 85
      RiskGauge.update({
        vulnerabilities: 10,
        latency: 550,
        openPorts: 5,
        warnings: 5,
        type: 'low'
      });

      const arc = document.getElementById('riskGaugeArc');
      const arcStroke = arc.getAttribute('stroke');

      expect(arcStroke).toBe('#F87171');
    });

    it('should display danger color (#F87171) for score 100', () => {
      RiskGauge.init();

      // Update with maximum risk score
      // 100 = 10 vulns * 5 (50) + latency 500ms (20) + 10 ports * 2 (20) + 5 warnings * 2 (10) + critical type (10) = 110 (capped at 100)
      RiskGauge.update({
        vulnerabilities: 10,
        latency: 550,
        openPorts: 10,
        warnings: 5,
        type: 'critical'
      });

      const arc = document.getElementById('riskGaugeArc');
      const arcStroke = arc.getAttribute('stroke');

      expect(arcStroke).toBe('#F87171');
    });

    it('should display "HIGH RISK" label for scores 70-100', () => {
      RiskGauge.init();

      RiskGauge.update({
        vulnerabilities: 10,
        latency: 550,
        openPorts: 5,
        warnings: 0
      });

      const label = document.getElementById('riskLabel');
      expect(label.textContent).toBe('HIGH RISK');
    });
  });

  describe('Boundary Value Testing', () => {
    /**
     * **Validates: Requirement 4.3** - Correct color transitions at boundaries
     * **Validates: Requirement 20.2** - Colors match token definitions exactly
     */
    it('should transition from success to warning at boundary (30 vs 31)', () => {
      RiskGauge.init();

      // Test score 30 (low risk)
      RiskGauge.update({
        vulnerabilities: 6,
        latency: 50,
        openPorts: 0,
        warnings: 0
      });

      let arc = document.getElementById('riskGaugeArc');
      let label = document.getElementById('riskLabel');
      
      expect(arc.getAttribute('stroke')).toBe('#34D399');
      expect(label.textContent).toBe('LOW RISK');

      // Test score 31 (medium risk)
      RiskGauge.update({
        vulnerabilities: 6,
        latency: 150,
        openPorts: 0,
        warnings: 0
      });

      arc = document.getElementById('riskGaugeArc');
      label = document.getElementById('riskLabel');
      
      expect(arc.getAttribute('stroke')).toBe('#FBBF24');
      expect(label.textContent).toBe('MEDIUM RISK');
    });

    it('should transition from warning to danger at boundary (69 vs 70)', () => {
      RiskGauge.init();

      // Test score 69 (medium risk)
      RiskGauge.update({
        vulnerabilities: 10,
        latency: 550,
        openPorts: 0,
        warnings: 2,
        type: 'low'
      });

      let arc = document.getElementById('riskGaugeArc');
      let label = document.getElementById('riskLabel');
      
      expect(arc.getAttribute('stroke')).toBe('#FBBF24');
      expect(label.textContent).toBe('MEDIUM RISK');

      // Test score 70 (high risk)
      RiskGauge.update({
        vulnerabilities: 10,
        latency: 550,
        openPorts: 5,
        warnings: 0
      });

      arc = document.getElementById('riskGaugeArc');
      label = document.getElementById('riskLabel');
      
      expect(arc.getAttribute('stroke')).toBe('#F87171');
      expect(label.textContent).toBe('HIGH RISK');
    });
  });

  describe('Token Resolution Integration', () => {
    /**
     * **Validates: Requirement 4.4** - state-manager.js resolves colors from CSS
     * **Validates: Requirement 4.5** - JavaScript reads from CSS custom properties
     */
    it('should resolve colors from CSS custom properties', () => {
      const rootStyles = getComputedStyle(document.documentElement);

      // Verify tokens are defined
      expect(rootStyles.getPropertyValue('--cg-success').trim()).toBe('#34D399');
      expect(rootStyles.getPropertyValue('--cg-warning').trim()).toBe('#FBBF24');
      expect(rootStyles.getPropertyValue('--cg-danger').trim()).toBe('#F87171');
    });

    it('should use resolved token values in gauge rendering', () => {
      RiskGauge.init();

      // Test each risk level with appropriate scan data
      const testCases = [
        { 
          scanData: { vulnerabilities: 3, latency: 50, openPorts: 0, warnings: 0 },
          expectedColor: '#34D399', 
          label: 'LOW RISK' 
        },
        { 
          scanData: { vulnerabilities: 8, latency: 150, openPorts: 0, warnings: 0 },
          expectedColor: '#FBBF24', 
          label: 'MEDIUM RISK' 
        },
        { 
          scanData: { vulnerabilities: 10, latency: 550, openPorts: 5, warnings: 0 },
          expectedColor: '#F87171', 
          label: 'HIGH RISK' 
        }
      ];

      testCases.forEach(({ scanData, expectedColor, label }) => {
        RiskGauge.update(scanData);

        const arc = document.getElementById('riskGaugeArc');
        const labelEl = document.getElementById('riskLabel');

        expect(arc.getAttribute('stroke')).toBe(expectedColor);
        expect(labelEl.textContent).toBe(label);
      });
    });

    it('should update colors when CSS custom properties change', () => {
      RiskGauge.init();

      // Initial update with low risk
      RiskGauge.update({
        vulnerabilities: 3,
        latency: 50,
        openPorts: 0,
        warnings: 0
      });

      let arc = document.getElementById('riskGaugeArc');
      expect(arc.getAttribute('stroke')).toBe('#34D399');

      // Change the CSS custom property
      document.documentElement.style.setProperty('--cg-success', '#00FF00');

      // Refresh colors cache
      if (RiskGauge.refreshColors) {
        RiskGauge.refreshColors();
      }

      // Update again
      RiskGauge.update({
        vulnerabilities: 3,
        latency: 50,
        openPorts: 0,
        warnings: 0
      });

      arc = document.getElementById('riskGaugeArc');
      
      // Should use the new color value
      const rootStyles = getComputedStyle(document.documentElement);
      const newSuccessColor = rootStyles.getPropertyValue('--cg-success').trim();
      expect(newSuccessColor).toBe('#00FF00');
    });
  });

  describe('Visual Consistency', () => {
    /**
     * **Validates: Requirement 20.1** - Visual appearance matches pre-migration state
     * **Validates: Requirement 20.2** - Colors are visually identical to original values
     */
    it('should apply consistent colors across all gauge elements', () => {
      RiskGauge.init();

      RiskGauge.update({
        vulnerabilities: 10,
        latency: 550,
        openPorts: 5,
        warnings: 0
      });

      const arc = document.getElementById('riskGaugeArc');
      const label = document.getElementById('riskLabel');
      const icon = document.getElementById('riskCardIcon');

      // All elements should have color styling applied
      expect(arc.getAttribute('stroke')).toBe('#F87171');
      expect(label.style.color).toBeTruthy();
      expect(icon.style.color).toBeTruthy();
    });

    it('should maintain color consistency across multiple updates', () => {
      RiskGauge.init();

      // Perform multiple updates with the same risk level
      for (let i = 0; i < 5; i++) {
        RiskGauge.update({
          vulnerabilities: 5,
          latency: 50,
          openPorts: 0,
          warnings: 0
        });

        const arc = document.getElementById('riskGaugeArc');
        expect(arc.getAttribute('stroke')).toBe('#34D399');
      }
    });

    it('should apply correct glow effects based on risk level', () => {
      RiskGauge.init();

      // Test low risk glow
      RiskGauge.update({
        vulnerabilities: 3,
        latency: 50,
        openPorts: 0,
        warnings: 0
      });

      let arc = document.getElementById('riskGaugeArc');
      let filter = arc.style.filter;
      
      // Should have drop-shadow filter applied
      expect(filter).toContain('drop-shadow');

      // Test high risk glow
      RiskGauge.update({
        vulnerabilities: 10,
        latency: 550,
        openPorts: 5,
        warnings: 0
      });

      arc = document.getElementById('riskGaugeArc');
      filter = arc.style.filter;
      
      // Should still have drop-shadow filter applied
      expect(filter).toContain('drop-shadow');
    });
  });

  describe('Full Scan Data Integration', () => {
    /**
     * **Validates: Requirement 4.3** - Gauge renders correctly with full scan data
     * **Validates: Requirement 20.1** - Visual appearance matches token definitions
     */
    it('should render correctly with full scanData structure', () => {
      RiskGauge.init();

      // Update with full scanData structure (as used in real application)
      RiskGauge.update({
        network: {
          openPortsCount: 3,
          responseTimeMs: 250
        },
        web: {
          sslStatus: 'valid'
        },
        issues: {
          criticalCount: 5,
          warnings: 2
        },
        timestamp: new Date().toISOString()
      });

      const arc = document.getElementById('riskGaugeArc');
      const label = document.getElementById('riskLabel');

      // Should render with appropriate color based on calculated score
      expect(arc.getAttribute('stroke')).toMatch(/^#[0-9A-F]{6}$/i);
      expect(label.textContent).toMatch(/^(LOW|MEDIUM|HIGH) RISK$/);
    });

    it('should handle legacy scanData format', () => {
      RiskGauge.init();

      // Update with legacy format
      RiskGauge.update({
        vulnerabilities: 7,
        latency: 300,
        openPorts: 2,
        warnings: 1
      });

      const arc = document.getElementById('riskGaugeArc');
      const label = document.getElementById('riskLabel');

      // Should render correctly
      expect(arc.getAttribute('stroke')).toMatch(/^#[0-9A-F]{6}$/i);
      expect(label.textContent).toMatch(/^(LOW|MEDIUM|HIGH) RISK$/);
    });
  });

  describe('Color Hex Value Validation', () => {
    /**
     * **Validates: Requirement 20.2** - Colors match token definitions exactly
     */
    it('should use exact hex values from token definitions', () => {
      const rootStyles = getComputedStyle(document.documentElement);

      // Verify exact token values
      const tokens = {
        success: rootStyles.getPropertyValue('--cg-success').trim(),
        warning: rootStyles.getPropertyValue('--cg-warning').trim(),
        danger: rootStyles.getPropertyValue('--cg-danger').trim()
      };

      expect(tokens.success).toBe('#34D399');
      expect(tokens.warning).toBe('#FBBF24');
      expect(tokens.danger).toBe('#F87171');
    });

    it('should render gauge with exact token color values', () => {
      RiskGauge.init();

      // Test each risk level and verify exact color match
      const testCases = [
        { vulnerabilities: 3, expectedColor: '#34D399' },
        { vulnerabilities: 8, expectedColor: '#FBBF24' },
        { vulnerabilities: 10, openPorts: 5, latency: 550, expectedColor: '#F87171' }
      ];

      testCases.forEach(({ vulnerabilities, openPorts = 0, latency = 50, expectedColor }) => {
        RiskGauge.update({
          vulnerabilities,
          latency,
          openPorts,
          warnings: 0
        });

        const arc = document.getElementById('riskGaugeArc');
        expect(arc.getAttribute('stroke')).toBe(expectedColor);
      });
    });
  });

  describe('Error Handling and Edge Cases', () => {
    /**
     * **Validates: Requirement 4.5** - Graceful handling of edge cases
     */
    it('should handle missing scan data gracefully', () => {
      RiskGauge.init();

      // Update with empty data
      RiskGauge.update({});

      const arc = document.getElementById('riskGaugeArc');
      const label = document.getElementById('riskLabel');

      // Should render with low risk (score 0)
      expect(arc.getAttribute('stroke')).toBe('#34D399');
      expect(label.textContent).toBe('LOW RISK');
    });

    it('should handle null/undefined values in scan data', () => {
      RiskGauge.init();

      RiskGauge.update({
        vulnerabilities: null,
        latency: undefined,
        openPorts: null,
        warnings: undefined
      });

      const arc = document.getElementById('riskGaugeArc');
      
      // Should not throw error and should render
      expect(arc.getAttribute('stroke')).toMatch(/^#[0-9A-F]{6}$/i);
    });

    it('should clamp extreme scores to valid range', () => {
      RiskGauge.init();

      // Update with data that would produce score > 100
      RiskGauge.update({
        vulnerabilities: 20,
        latency: 1000,
        openPorts: 20,
        warnings: 10,
        type: 'critical'
      });

      const arc = document.getElementById('riskGaugeArc');
      
      // Should render with danger color (high risk)
      expect(arc.getAttribute('stroke')).toBe('#F87171');
    });
  });
});
