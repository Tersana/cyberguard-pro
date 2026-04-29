/**
 * Unit tests for RiskGauge.startScan method
 * Validates Task 7.2 requirements
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { JSDOM } from 'jsdom';

describe('RiskGauge.startScan', () => {
  let dom;
  let document;
  let window;

  beforeEach(() => {
    // Create a minimal DOM environment
    dom = new JSDOM(`
      <!DOCTYPE html>
      <html>
        <body>
          <div id="riskScoreCard"></div>
          <svg id="riskGaugeSvg">
            <path id="riskGaugeArc" stroke-dasharray="427.26"></path>
          </svg>
          <div id="riskScore">0</div>
          <div id="riskLabel">IDLE</div>
          <div id="vulnCount">0</div>
          <div id="latencyVal">0ms</div>
          <div id="riskCardIcon"></div>
        </body>
      </html>
    `, { 
      url: 'http://localhost',
      pretendToBeVisual: true,
      resources: 'usable'
    });

    document = dom.window.document;
    window = dom.window;
    global.document = document;
    global.window = window;
    global.requestAnimationFrame = vi.fn((cb) => {
      setTimeout(cb, 16);
      return 1;
    });
    global.cancelAnimationFrame = vi.fn();
    global.performance = { now: () => Date.now() };

    // Load the risk-gauge.js module
    const script = require('fs').readFileSync('./risk-gauge.js', 'utf8');
    const scriptEl = document.createElement('script');
    scriptEl.textContent = script;
    document.body.appendChild(scriptEl);
    
    // Execute the script in the JSDOM context
    eval(script);
  });

  it('should apply spinning animation to gauge arc', () => {
    // Arrange
    const arc = document.getElementById('riskGaugeArc');
    const initialDashArray = arc.getAttribute('stroke-dasharray');

    // Act
    window.RiskGauge.startScan();

    // Assert - spinning animation modifies stroke-dasharray to show partial arc
    const newDashArray = arc.getAttribute('stroke-dasharray');
    expect(newDashArray).not.toBe(initialDashArray);
    expect(newDashArray).toContain('106.814'); // 25% of 427.26 (approximately)
  });

  it('should set riskLabel to "SCANNING..."', () => {
    // Arrange
    const label = document.getElementById('riskLabel');

    // Act
    window.RiskGauge.startScan();

    // Assert
    expect(label.textContent).toBe('SCANNING...');
  });

  it('should apply scanning state styling', () => {
    // Arrange
    const card = document.getElementById('riskScoreCard');

    // Act
    window.RiskGauge.startScan();

    // Assert
    expect(card.classList.contains('risk-scanning')).toBe(true);
  });

  it('should set score display to loading indicator', () => {
    // Arrange
    const score = document.getElementById('riskScore');

    // Act
    window.RiskGauge.startScan();

    // Assert
    expect(score.textContent).toBe('--');
  });

  it('should apply violet accent color theme for scanning state', () => {
    // Arrange
    const arc = document.getElementById('riskGaugeArc');
    const label = document.getElementById('riskLabel');

    // Act
    window.RiskGauge.startScan();

    // Assert
    expect(arc.getAttribute('stroke')).toBe('#A78BFA'); // violet accent
    // JSDOM converts hex colors to rgb format
    expect(label.style.color).toBe('rgb(167, 139, 250)'); // violet accent (#A78BFA)
  });
});
