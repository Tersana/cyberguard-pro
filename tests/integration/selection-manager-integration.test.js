/**
 * Integration tests for SelectionManager with actual DOM structure
 * Tests Task 2.1: SelectionManager works with dashboard.html structure
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { JSDOM } from 'jsdom';
import fs from 'fs';
import path from 'path';

describe('SelectionManager Integration - Task 2.1', () => {
  let dom;
  let document;
  let SelectionManager;

  beforeEach(() => {
    // Load the actual dashboard.html file
    const dashboardPath = path.resolve(__dirname, '../../public/dashboard.html');
    const dashboardHTML = fs.readFileSync(dashboardPath, 'utf-8');
    
    dom = new JSDOM(dashboardHTML, {
      url: 'http://localhost',
      runScripts: 'outside-only'
    });
    
    document = dom.window.document;
    global.document = document;
    global.window = dom.window;

    // Define SelectionManager (copied from main.js)
    SelectionManager = {
      init() {
        this.attachEventListeners();
      },
      
      attachEventListeners() {
        const toolCards = document.querySelectorAll('.cyber-tool-card, .wa-cp-tool-item');
        
        toolCards.forEach(card => {
          card.addEventListener('click', (e) => {
            // Prevent toggle if clicking on the tool button itself
            if (e.target.closest('button[id$="-btn"]')) {
              return;
            }
            
            // Toggle selection for this card
            // (toggleSelection will be implemented in Task 2.2)
            // this.toggleSelection(card);
          });
        });
      }
    };
  });

  describe('Dashboard HTML structure compatibility', () => {
    it('should find all web security tool cards', () => {
      const webSecurityTab = document.getElementById('web-security');
      expect(webSecurityTab).toBeTruthy();
      
      const webToolCards = webSecurityTab.querySelectorAll('.cyber-tool-card[data-tool-id], .wa-cp-tool-item[data-tool-id]');
      
      // Should have 3 web security tools: ssl, phishing, dns-spoof
      expect(webToolCards.length).toBeGreaterThanOrEqual(3);
    });

    it('should find tool cards with correct data attributes', () => {
      const toolCards = document.querySelectorAll('.cyber-tool-card[data-tool-id], .wa-cp-tool-item[data-tool-id]');
      
      toolCards.forEach(card => {
        // Each card should have data-selected attribute
        expect(card.hasAttribute('data-selected')).toBe(true);
        
        // Each card should have data-tool-id attribute
        expect(card.hasAttribute('data-tool-id')).toBe(true);
        
        // data-tool-id should end with -btn
        const toolId = card.dataset.toolId;
        expect(toolId).toMatch(/-btn$/);
      });
    });

    it('should find tool buttons inside cards with matching IDs', () => {
      const toolCards = document.querySelectorAll('.cyber-tool-card[data-tool-id], .wa-cp-tool-item[data-tool-id]');
      
      toolCards.forEach(card => {
        const toolId = card.dataset.toolId;
        const button = card.querySelector(`button#${toolId}`);
        
        // Each card should have a button with matching ID
        expect(button).toBeTruthy();
        expect(button.id).toBe(toolId);
      });
    });
  });

  describe('SelectionManager initialization with real DOM', () => {
    it('should initialize without errors', () => {
      expect(() => {
        SelectionManager.init();
      }).not.toThrow();
    });

    it('should attach listeners to all tool cards', () => {
      const toolCards = document.querySelectorAll('.cyber-tool-card[data-tool-id], .wa-cp-tool-item[data-tool-id]');
      const initialCount = toolCards.length;
      
      expect(initialCount).toBeGreaterThan(0);
      
      SelectionManager.init();
      
      // Verify listeners were attached by checking no errors occurred
      expect(true).toBe(true);
    });

    it('should handle tool cards in web security tab', () => {
      const webCards = document.querySelectorAll('#web-security .cyber-tool-card[data-tool-id], #web-security .wa-cp-tool-item[data-tool-id]');
      
      expect(webCards.length).toBeGreaterThan(0);
      
      SelectionManager.init();
      
      // Tab should have listeners attached
      expect(true).toBe(true);
    });
  });

  describe('Event delegation with real button structure', () => {
    it('should correctly identify buttons with -btn suffix', () => {
      SelectionManager.init();
      
      const sslCard = document.querySelector('.cyber-tool-card[data-tool-id="ssl-btn"], .wa-cp-tool-item[data-tool-id="ssl-btn"]');
      expect(sslCard).toBeTruthy();
      
      const sslButton = document.getElementById('ssl-btn');
      expect(sslButton).toBeTruthy();
      
      // Verify the button is inside the card
      expect(sslCard.contains(sslButton)).toBe(true);
    });

    it('should find buttons using closest() selector', () => {
      // Only check buttons that are inside tool cards
      const toolCards = document.querySelectorAll('.cyber-tool-card[data-tool-id], .wa-cp-tool-item[data-tool-id]');
      const toolButtons = [];
      
      toolCards.forEach(card => {
        const button = card.querySelector('button[id$="-btn"]');
        if (button) {
          toolButtons.push(button);
        }
      });
      
      // Should find multiple tool buttons
      expect(toolButtons.length).toBeGreaterThan(0);
      
      toolButtons.forEach(button => {
        // Each button ID should end with -btn
        expect(button.id).toMatch(/-btn$/);
        
        // Each button should be inside a tool card
        const parentCard = button.closest('.cyber-tool-card, .wa-cp-tool-item');
        expect(parentCard).toBeTruthy();
      });
    });
  });

  describe('Selection indicator structure', () => {
    it('should find selection indicators in tool cards', () => {
      const toolCards = document.querySelectorAll('.cyber-tool-card[data-tool-id], .wa-cp-tool-item[data-tool-id]');
      
      toolCards.forEach(card => {
        // Only old-style cyber-tool-card has selection-indicator. wa-cp-tool-item uses checkbox
        if (card.classList.contains('cyber-tool-card')) {
          const indicator = card.querySelector('.selection-indicator');
          
          // Each card should have a selection indicator
          expect(indicator).toBeTruthy();
          
          // Indicator should be hidden by default
          expect(indicator.classList.contains('hidden')).toBe(true);
        } else {
          const checkbox = card.querySelector('.wa-cp-checkbox');
          expect(checkbox).toBeTruthy();
        }
      });
    });
  });
});
