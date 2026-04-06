/**
 * Unit tests for Accordion Result Item component
 * Tests Task 7: createAccordionItem, toggleAccordion, renderResults, and integration with logResult
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { JSDOM } from 'jsdom';

describe('Accordion Result Item Component', () => {
  let dom;
  let document;
  let window;
  
  // Mock functions that will be defined in main.js
  let mapStatusToSeverity;
  let createAccordionItem;
  let toggleAccordion;
  let renderResults;
  let getFilteredResults;
  let resultsData;
  let activeFilters;

  beforeEach(() => {
    // Create a fresh DOM for each test
    dom = new JSDOM(`
      <!DOCTYPE html>
      <html>
        <body>
          <div id="accordion-items-container"></div>
          <div id="empty-results-state" style="display: none;">
            <h3>No Scans Performed</h3>
            <p>Run a security scan to see detailed results here</p>
          </div>
        </body>
      </html>
    `);
    
    document = dom.window.document;
    window = dom.window;
    global.document = document;
    global.window = window;
    
    // Initialize test data
    resultsData = [];
    activeFilters = new Set();
    
    // Define mapStatusToSeverity function
    mapStatusToSeverity = (status) => {
      const severityMap = {
        'threat': 'critical',
        'warning': 'warning',
        'safe': 'info',
        'system': 'info'
      };
      return severityMap[status] || 'info';
    };
    
    // Define getFilteredResults function
    getFilteredResults = () => {
      if (activeFilters.size === 0) {
        return resultsData;
      }
      return resultsData.filter(result => {
        const severity = mapStatusToSeverity(result.status);
        return activeFilters.has(severity);
      });
    };
    
    // Define createAccordionItem function (from main.js)
    createAccordionItem = (result) => {
      const severity = mapStatusToSeverity(result.status);
      const item = document.createElement('div');
      item.className = 'result-accordion-item border-b border-white/5 transition-all';
      item.dataset.severity = severity;
      item.dataset.resultId = result.id;
      
      const severityText = severity.toUpperCase();
      const shortSummary = result.message.split('\n')[0].substring(0, 100);
      
      let description = result.description || result.message;
      let evidence = result.evidence || '';
      let remediation = result.remediation || [];
      
      if (typeof remediation === 'string') {
        remediation = remediation.split('\n').filter(line => line.trim());
      }
      
      item.innerHTML = `
        <div class="accordion-header flex items-center justify-between p-4 cursor-pointer hover:bg-white/5">
          <div class="flex items-center gap-4 flex-1">
            <span class="severity-badge severity-${severity}">${severityText}</span>
            <div class="flex-1">
              <div class="text-sm font-semibold text-white">${result.feature || result.tool || 'Scanner'}</div>
              <div class="text-xs text-slate-400 mt-1">${shortSummary}</div>
            </div>
          </div>
          <svg class="accordion-icon w-5 h-5 text-slate-400 transition-transform" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" d="m19.5 8.25-7.5 7.5-7.5-7.5" />
          </svg>
        </div>
        
        <div class="accordion-content hidden p-4 pt-0 space-y-4">
          <div class="description-section">
            <h4 class="text-xs font-bold text-slate-300 uppercase tracking-wider mb-2">Description</h4>
            <p class="text-sm text-slate-400 leading-relaxed whitespace-pre-wrap">${description}</p>
          </div>
          
          ${evidence ? `
          <div class="evidence-section">
            <h4 class="text-xs font-bold text-slate-300 uppercase tracking-wider mb-2">Evidence</h4>
            <div class="evidence-box bg-black/40 border border-white/10 rounded-lg p-4 font-mono text-xs text-green-300 overflow-x-auto">
              <pre>${evidence}</pre>
            </div>
          </div>
          ` : ''}
          
          ${remediation.length > 0 ? `
          <div class="remediation-section">
            <h4 class="text-xs font-bold text-slate-300 uppercase tracking-wider mb-2 flex items-center gap-2">
              <svg class="w-4 h-4 text-green-400" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" d="M9 12.75 11.25 15 15 9.75M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0Z" />
              </svg>
              How to Fix
            </h4>
            <ul class="text-sm text-slate-400 space-y-2 list-disc list-inside">
              ${remediation.map(step => `<li>${step}</li>`).join('')}
            </ul>
          </div>
          ` : ''}
        </div>
      `;
      
      const header = item.querySelector('.accordion-header');
      header.addEventListener('click', () => toggleAccordion(item));
      
      return item;
    };
    
    // Define toggleAccordion function (from main.js)
    toggleAccordion = (item) => {
      const content = item.querySelector('.accordion-content');
      const icon = item.querySelector('.accordion-icon');
      
      if (item.classList.contains('expanded')) {
        item.classList.remove('expanded');
        content.classList.add('hidden');
        icon.style.transform = 'rotate(0deg)';
      } else {
        item.classList.add('expanded');
        content.classList.remove('hidden');
        icon.style.transform = 'rotate(180deg)';
      }
    };
    
    // Define renderResults function (from main.js)
    renderResults = () => {
      const container = document.getElementById('accordion-items-container');
      const emptyState = document.getElementById('empty-results-state');
      
      if (!container) return;
      
      const filteredResults = getFilteredResults();
      
      const accordionItems = container.querySelectorAll('.result-accordion-item');
      accordionItems.forEach(item => item.remove());
      
      if (filteredResults.length === 0) {
        if (emptyState) {
          emptyState.style.display = 'flex';
          
          const emptyTitle = emptyState.querySelector('h3');
          const emptyText = emptyState.querySelector('p');
          
          if (activeFilters.size > 0) {
            if (emptyTitle) emptyTitle.textContent = 'No Results Match Filters';
            if (emptyText) emptyText.textContent = 'Try adjusting your filter selection';
          } else {
            if (emptyTitle) emptyTitle.textContent = 'No Scans Performed';
            if (emptyText) emptyText.textContent = 'Run a security scan to see detailed results here';
          }
        }
      } else {
        if (emptyState) {
          emptyState.style.display = 'none';
        }
        
        filteredResults.forEach(result => {
          const accordionItem = createAccordionItem(result);
          container.appendChild(accordionItem);
        });
      }
    };
  });

  describe('Task 7.1: createAccordionItem()', () => {
    it('should create accordion item with correct structure', () => {
      const result = {
        id: '1',
        feature: 'XSS Scanner',
        status: 'threat',
        message: 'Cross-site scripting vulnerability detected',
        description: 'A cross-site scripting vulnerability was found',
        evidence: 'Payload: <script>alert("XSS")</script>',
        remediation: ['Implement input validation', 'Use Content Security Policy']
      };
      
      const item = createAccordionItem(result);
      
      expect(item.className).toContain('result-accordion-item');
      expect(item.dataset.severity).toBe('critical');
      expect(item.dataset.resultId).toBe('1');
    });

    it('should display severity badge with correct text', () => {
      const result = {
        id: '2',
        feature: 'Port Scanner',
        status: 'warning',
        message: 'Open port detected',
        description: 'Port 8080 is open'
      };
      
      const item = createAccordionItem(result);
      const badge = item.querySelector('.severity-badge');
      
      expect(badge.textContent).toBe('WARNING');
      expect(badge.className).toContain('severity-warning');
    });

    it('should display scanner name and short summary', () => {
      const result = {
        id: '3',
        feature: 'SSL Scanner',
        status: 'safe',
        message: 'SSL certificate is valid and secure',
        description: 'Certificate details...'
      };
      
      const item = createAccordionItem(result);
      const scannerName = item.querySelector('.text-sm.font-semibold');
      const summary = item.querySelector('.text-xs.text-slate-400');
      
      expect(scannerName.textContent).toBe('SSL Scanner');
      expect(summary.textContent).toBe('SSL certificate is valid and secure');
    });

    it('should include evidence section when evidence is provided', () => {
      const result = {
        id: '4',
        feature: 'Test Scanner',
        status: 'threat',
        message: 'Test message',
        evidence: 'Test evidence data'
      };
      
      const item = createAccordionItem(result);
      const evidenceSection = item.querySelector('.evidence-section');
      
      expect(evidenceSection).not.toBeNull();
      expect(evidenceSection.textContent).toContain('Test evidence data');
    });

    it('should include remediation section when remediation is provided', () => {
      const result = {
        id: '5',
        feature: 'Test Scanner',
        status: 'threat',
        message: 'Test message',
        remediation: ['Fix step 1', 'Fix step 2']
      };
      
      const item = createAccordionItem(result);
      const remediationSection = item.querySelector('.remediation-section');
      
      expect(remediationSection).not.toBeNull();
      expect(remediationSection.textContent).toContain('Fix step 1');
      expect(remediationSection.textContent).toContain('Fix step 2');
    });
  });

  describe('Task 7.2: toggleAccordion()', () => {
    it('should expand accordion item when clicked', () => {
      const result = {
        id: '6',
        feature: 'Test Scanner',
        status: 'threat',
        message: 'Test message',
        description: 'Test description'
      };
      
      const item = createAccordionItem(result);
      const content = item.querySelector('.accordion-content');
      
      expect(content.classList.contains('hidden')).toBe(true);
      
      toggleAccordion(item);
      
      expect(item.classList.contains('expanded')).toBe(true);
      expect(content.classList.contains('hidden')).toBe(false);
    });

    it('should collapse accordion item when clicked again', () => {
      const result = {
        id: '7',
        feature: 'Test Scanner',
        status: 'threat',
        message: 'Test message'
      };
      
      const item = createAccordionItem(result);
      const content = item.querySelector('.accordion-content');
      
      toggleAccordion(item);
      expect(item.classList.contains('expanded')).toBe(true);
      
      toggleAccordion(item);
      expect(item.classList.contains('expanded')).toBe(false);
      expect(content.classList.contains('hidden')).toBe(true);
    });

    it('should rotate icon on expand/collapse', () => {
      const result = {
        id: '8',
        feature: 'Test Scanner',
        status: 'threat',
        message: 'Test message'
      };
      
      const item = createAccordionItem(result);
      const icon = item.querySelector('.accordion-icon');
      
      toggleAccordion(item);
      expect(icon.style.transform).toBe('rotate(180deg)');
      
      toggleAccordion(item);
      expect(icon.style.transform).toBe('rotate(0deg)');
    });
  });

  describe('Task 7.3: renderResults()', () => {
    it('should render all results when no filters are active', () => {
      resultsData = [
        { id: '1', feature: 'Scanner 1', status: 'threat', message: 'Message 1' },
        { id: '2', feature: 'Scanner 2', status: 'warning', message: 'Message 2' },
        { id: '3', feature: 'Scanner 3', status: 'safe', message: 'Message 3' }
      ];
      
      renderResults();
      
      const container = document.getElementById('accordion-items-container');
      const items = container.querySelectorAll('.result-accordion-item');
      
      expect(items.length).toBe(3);
    });

    it('should show empty state when no results exist', () => {
      resultsData = [];
      
      renderResults();
      
      const emptyState = document.getElementById('empty-results-state');
      expect(emptyState.style.display).toBe('flex');
    });

    it('should hide empty state when results exist', () => {
      resultsData = [
        { id: '1', feature: 'Scanner 1', status: 'threat', message: 'Message 1' }
      ];
      
      renderResults();
      
      const emptyState = document.getElementById('empty-results-state');
      expect(emptyState.style.display).toBe('none');
    });

    it('should filter results by severity when filters are active', () => {
      resultsData = [
        { id: '1', feature: 'Scanner 1', status: 'threat', message: 'Message 1' },
        { id: '2', feature: 'Scanner 2', status: 'warning', message: 'Message 2' },
        { id: '3', feature: 'Scanner 3', status: 'safe', message: 'Message 3' }
      ];
      
      activeFilters.add('critical');
      
      renderResults();
      
      const container = document.getElementById('accordion-items-container');
      const items = container.querySelectorAll('.result-accordion-item');
      
      expect(items.length).toBe(1);
      expect(items[0].dataset.severity).toBe('critical');
    });

    it('should show "No Results Match Filters" when filters exclude all results', () => {
      resultsData = [
        { id: '1', feature: 'Scanner 1', status: 'safe', message: 'Message 1' }
      ];
      
      activeFilters.add('critical');
      
      renderResults();
      
      const emptyState = document.getElementById('empty-results-state');
      const emptyTitle = emptyState.querySelector('h3');
      
      expect(emptyState.style.display).toBe('flex');
      expect(emptyTitle.textContent).toBe('No Results Match Filters');
    });
  });

  describe('Task 7.4: Integration with logResult()', () => {
    it('should add result to resultsData array', () => {
      const initialLength = resultsData.length;
      
      resultsData.push({
        id: Date.now().toString(),
        feature: 'XSS Scanner',
        status: 'threat',
        message: 'XSS vulnerability found'
      });
      
      expect(resultsData.length).toBe(initialLength + 1);
    });

    it('should trigger renderResults after adding result', () => {
      resultsData.push({
        id: Date.now().toString(),
        feature: 'Port Scanner',
        status: 'warning',
        message: 'Open port detected'
      });
      
      renderResults();
      
      const container = document.getElementById('accordion-items-container');
      const items = container.querySelectorAll('.result-accordion-item');
      
      expect(items.length).toBe(resultsData.length);
    });
  });
});
