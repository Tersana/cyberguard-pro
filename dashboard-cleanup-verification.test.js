/**
 * Dashboard Cleanup Verification Tests
 * Task 8.1: Verify inline styles removed and CSS classes applied correctly
 * 
 * Tests verify:
 * - No inline style attributes remain in dashboard.html
 * - CSS classes exist in cyber-theme.css
 * - Visual parity maintained (classes provide equivalent styling)
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { join } from 'path';

describe('Task 8.1: Dashboard Inline Style Cleanup', () => {
  const dashboardHtml = readFileSync(join(process.cwd(), 'dashboard.html'), 'utf-8');
  const cyberThemeCss = readFileSync(join(process.cwd(), 'cyber-theme.css'), 'utf-8');

  describe('Requirement 5.1: Remove inline styles from dashboard.html', () => {
    it('should have no inline style attributes with color values', () => {
      // Check for style= attributes
      const styleMatches = dashboardHtml.match(/style\s*=\s*["'][^"']*["']/gi);
      
      if (styleMatches) {
        // If any style attributes exist, they should not contain color-related properties
        const colorRelatedStyles = styleMatches.filter(style => {
          const content = style.toLowerCase();
          return content.includes('color') || 
                 content.includes('background') || 
                 content.includes('border') ||
                 content.includes('#') ||
                 content.includes('rgb');
        });
        
        expect(colorRelatedStyles).toEqual([]);
      }
      
      // Verify no style attributes exist at all
      expect(styleMatches).toBeNull();
    });

    it('should not have inline styles on risk gauge wrapper', () => {
      const gaugeWrapperMatch = dashboardHtml.match(/<div[^>]*class="[^"]*cyber-gauge-wrapper[^"]*"[^>]*>/);
      expect(gaugeWrapperMatch).toBeTruthy();
      
      if (gaugeWrapperMatch) {
        expect(gaugeWrapperMatch[0]).not.toMatch(/style\s*=/);
      }
    });

    it('should not have inline styles on risk gauge SVG', () => {
      const svgMatch = dashboardHtml.match(/<svg[^>]*id="riskGaugeSvg"[^>]*>/);
      expect(svgMatch).toBeTruthy();
      
      if (svgMatch) {
        expect(svgMatch[0]).not.toMatch(/style\s*=/);
      }
    });

    it('should not have inline styles on risk gauge arc', () => {
      const arcMatch = dashboardHtml.match(/<circle[^>]*id="riskGaugeArc"[^>]*>/);
      expect(arcMatch).toBeTruthy();
      
      if (arcMatch) {
        expect(arcMatch[0]).not.toMatch(/style\s*=/);
      }
    });

    it('should not have inline styles on risk gauge content div', () => {
      const contentMatch = dashboardHtml.match(/<div[^>]*class="[^"]*cyber-gauge-content[^"]*"[^>]*>/);
      expect(contentMatch).toBeTruthy();
      
      if (contentMatch) {
        expect(contentMatch[0]).not.toMatch(/style\s*=/);
      }
    });

    it('should not have inline styles on risk score span', () => {
      const scoreMatch = dashboardHtml.match(/<span[^>]*id="riskScore"[^>]*>/);
      expect(scoreMatch).toBeTruthy();
      
      if (scoreMatch) {
        expect(scoreMatch[0]).not.toMatch(/style\s*=/);
      }
    });

    it('should not have inline styles on risk label span', () => {
      const labelMatch = dashboardHtml.match(/<span[^>]*id="riskLabel"[^>]*>/);
      expect(labelMatch).toBeTruthy();
      
      if (labelMatch) {
        expect(labelMatch[0]).not.toMatch(/style\s*=/);
      }
    });

    it('should not have inline styles on threat intel search input', () => {
      const inputMatch = dashboardHtml.match(/<input[^>]*id="threat-intel-search-input"[^>]*>/);
      expect(inputMatch).toBeTruthy();
      
      if (inputMatch) {
        expect(inputMatch[0]).not.toMatch(/style\s*=/);
      }
    });
  });

  describe('Requirement 5.5: Create equivalent CSS classes', () => {
    it('should have .cyber-gauge-wrapper class in cyber-theme.css', () => {
      expect(cyberThemeCss).toMatch(/\.cyber-gauge-wrapper\s*\{/);
      expect(cyberThemeCss).toMatch(/position:\s*relative/);
      expect(cyberThemeCss).toMatch(/display:\s*inline-flex/);
      expect(cyberThemeCss).toMatch(/align-items:\s*center/);
      expect(cyberThemeCss).toMatch(/justify-content:\s*center/);
    });

    it('should have .cyber-gauge-svg class in cyber-theme.css', () => {
      expect(cyberThemeCss).toMatch(/\.cyber-gauge-svg\s*\{/);
      expect(cyberThemeCss).toMatch(/transform:\s*rotate\(-90deg\)/);
    });

    it('should have .cyber-gauge-arc class in cyber-theme.css', () => {
      expect(cyberThemeCss).toMatch(/\.cyber-gauge-arc\s*\{/);
      expect(cyberThemeCss).toMatch(/transition:.*stroke-dashoffset/);
      expect(cyberThemeCss).toMatch(/transition:.*stroke/);
    });

    it('should have .cyber-gauge-content class in cyber-theme.css', () => {
      expect(cyberThemeCss).toMatch(/\.cyber-gauge-content\s*\{/);
      expect(cyberThemeCss).toMatch(/position:\s*absolute/);
      expect(cyberThemeCss).toMatch(/text-align:\s*center/);
      expect(cyberThemeCss).toMatch(/display:\s*flex/);
      expect(cyberThemeCss).toMatch(/flex-direction:\s*column/);
    });

    it('should have .cyber-gauge-score class in cyber-theme.css', () => {
      expect(cyberThemeCss).toMatch(/\.cyber-gauge-score\s*\{/);
      expect(cyberThemeCss).toMatch(/font-size:\s*2\.5rem/);
      expect(cyberThemeCss).toMatch(/font-weight:\s*800/);
      expect(cyberThemeCss).toMatch(/color:\s*#fff/);
      expect(cyberThemeCss).toMatch(/line-height:\s*1/);
    });

    it('should have .cyber-gauge-status class in cyber-theme.css', () => {
      expect(cyberThemeCss).toMatch(/\.cyber-gauge-status\s*\{/);
      expect(cyberThemeCss).toMatch(/font-size:\s*0\.6rem/);
      expect(cyberThemeCss).toMatch(/font-weight:\s*700/);
      expect(cyberThemeCss).toMatch(/letter-spacing:\s*0\.12em/);
      expect(cyberThemeCss).toMatch(/margin-top:\s*2px/);
    });

    it('should have .cyber-search-constrained class in cyber-theme.css', () => {
      expect(cyberThemeCss).toMatch(/\.cyber-search-constrained\s*\{/);
      expect(cyberThemeCss).toMatch(/max-width:\s*600px/);
    });
  });

  describe('Requirement 20.1 & 20.2: Visual parity maintained', () => {
    it('should use cyber-gauge-wrapper class on gauge container', () => {
      expect(dashboardHtml).toMatch(/class="cyber-gauge-wrapper"/);
    });

    it('should use cyber-gauge-svg class on SVG element', () => {
      expect(dashboardHtml).toMatch(/class="cyber-gauge-svg"/);
    });

    it('should use cyber-gauge-arc class on arc circle', () => {
      expect(dashboardHtml).toMatch(/class="cyber-gauge-arc"/);
    });

    it('should use cyber-gauge-content class on inner content div', () => {
      expect(dashboardHtml).toMatch(/class="cyber-gauge-content"/);
    });

    it('should use cyber-gauge-score class on risk score span', () => {
      expect(dashboardHtml).toMatch(/class="cyber-gauge-score"/);
    });

    it('should use cyber-gauge-status class on risk label span', () => {
      expect(dashboardHtml).toMatch(/class="cyber-gauge-status"/);
    });

    it('should use cyber-search-constrained class on threat intel search input', () => {
      expect(dashboardHtml).toMatch(/class="[^"]*cyber-search-constrained[^"]*"/);
    });
  });

  describe('Integration: HTML structure integrity', () => {
    it('should maintain risk gauge SVG structure', () => {
      expect(dashboardHtml).toMatch(/<svg[^>]*id="riskGaugeSvg"[^>]*>/);
      expect(dashboardHtml).toMatch(/<circle[^>]*id="riskGaugeArc"[^>]*>/);
    });

    it('should maintain risk gauge content structure', () => {
      expect(dashboardHtml).toMatch(/<span[^>]*id="riskScore"[^>]*>/);
      expect(dashboardHtml).toMatch(/<span[^>]*id="riskLabel"[^>]*>/);
    });

    it('should maintain threat intel search input structure', () => {
      expect(dashboardHtml).toMatch(/<input[^>]*id="threat-intel-search-input"[^>]*>/);
    });

    it('should have proper nesting: gauge wrapper > svg + content', () => {
      const gaugeSection = dashboardHtml.match(
        /<div class="cyber-gauge-wrapper">[\s\S]*?<svg[\s\S]*?<\/svg>[\s\S]*?<div class="cyber-gauge-content">[\s\S]*?<\/div>[\s\S]*?<\/div>/
      );
      expect(gaugeSection).toBeTruthy();
    });
  });

  describe('CSS Token Integration', () => {
    it('should use design tokens in gauge classes', () => {
      // Verify that gauge classes use CSS custom properties where appropriate
      const gaugeScoreSection = cyberThemeCss.match(/\.cyber-gauge-score\s*\{[^}]+\}/);
      if (gaugeScoreSection) {
        // Font family should use token
        expect(gaugeScoreSection[0]).toMatch(/font-family:\s*var\(--cg-font-mono\)/);
      }
    });

    it('should maintain consistency with existing cyber-theme classes', () => {
      // All new classes should follow the cyber- prefix convention
      const newClasses = [
        'cyber-gauge-svg',
        'cyber-gauge-arc',
        'cyber-gauge-content',
        'cyber-gauge-score',
        'cyber-gauge-status',
        'cyber-search-constrained'
      ];

      newClasses.forEach(className => {
        expect(cyberThemeCss).toMatch(new RegExp(`\\.${className}\\s*\\{`));
      });
    });
  });
});
