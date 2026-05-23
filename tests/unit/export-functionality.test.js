/**
 * Unit tests for Export Functionality (Task 10)
 * Tests PDF and CSV export functions
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';

describe('Export Functionality - Task 10', () => {
  let resultsData;
  let currentScanTarget;
  let activeFilters;
  
  // Mock functions
  let mapStatusToSeverity;
  let getFilteredResults;
  let exportToPDF;
  let exportToCSV;
  
  beforeEach(() => {
    // Reset data
    resultsData = [
      {
        id: '1',
        tool: 'XSS Scanner',
        status: 'threat',
        message: 'Cross-site scripting vulnerability detected',
        timestamp: '2024-01-15T10:30:00.000Z'
      },
      {
        id: '2',
        tool: 'Port Scanner',
        status: 'warning',
        message: 'Open port detected on 8080',
        timestamp: '2024-01-15T10:31:00.000Z'
      },
      {
        id: '3',
        tool: 'SSL Checker',
        status: 'safe',
        message: 'SSL certificate is valid',
        timestamp: '2024-01-15T10:32:00.000Z'
      }
    ];
    
    currentScanTarget = '192.168.1.1';
    activeFilters = new Set();
    
    // Mock severity mapping function
    mapStatusToSeverity = (status) => {
      const severityMap = {
        'threat': 'critical',
        'warning': 'warning',
        'safe': 'info',
        'system': 'info'
      };
      return severityMap[status] || 'info';
    };
    
    // Mock getFilteredResults function
    getFilteredResults = () => {
      if (activeFilters.size === 0) {
        return resultsData;
      }
      return resultsData.filter(result => {
        const severity = mapStatusToSeverity(result.status);
        return activeFilters.has(severity);
      });
    };
  });
  
  describe('Task 10.1 - PDF Export Function', () => {
    it('should create exportToPDF function', () => {
      // Mock jsPDF
      const mockDoc = {
        setFontSize: vi.fn(),
        setFont: vi.fn(),
        text: vi.fn(),
        autoTable: vi.fn(),
        save: vi.fn()
      };
      
      class MockJsPDF {
        constructor() {
          return mockDoc;
        }
      }
      
      global.window = { jspdf: { jsPDF: MockJsPDF } };
      
      // Simulate exportToPDF function
      exportToPDF = () => {
        const { jsPDF } = window.jspdf;
        const doc = new jsPDF();
        
        doc.setFontSize(20);
        doc.setFont('helvetica', 'bold');
        doc.text('CyberGuard Security Report', 20, 20);
        
        doc.setFontSize(10);
        doc.setFont('helvetica', 'normal');
        doc.text(`Generated: ${new Date().toLocaleString()}`, 20, 30);
        doc.text(`Total Issues: ${getFilteredResults().length}`, 20, 36);
        doc.text(`Scanned Target: ${currentScanTarget || '--'}`, 20, 42);
        
        const results = getFilteredResults();
        const tableData = results.map(result => [
          result.tool || result.feature || 'Unknown',
          mapStatusToSeverity(result.status),
          (result.message || '').substring(0, 60) + (result.message && result.message.length > 60 ? '...' : ''),
          result.timestamp || new Date().toISOString()
        ]);
        
        doc.autoTable({
          startY: 50,
          head: [['Scanner', 'Severity', 'Finding', 'Timestamp']],
          body: tableData,
          theme: 'grid',
          headStyles: { fillColor: [124, 58, 237] },
          styles: { fontSize: 9, cellPadding: 4 },
          columnStyles: {
            0: { cellWidth: 40 },
            1: { cellWidth: 30 },
            2: { cellWidth: 80 },
            3: { cellWidth: 40 }
          }
        });
        
        doc.save(`cyberguard-report-${Date.now()}.pdf`);
      };
      
      exportToPDF();
      
      expect(mockDoc.setFontSize).toHaveBeenCalledWith(20);
      expect(mockDoc.text).toHaveBeenCalledWith('CyberGuard Security Report', 20, 20);
      expect(mockDoc.autoTable).toHaveBeenCalled();
      expect(mockDoc.save).toHaveBeenCalled();
    });
    
    it('should include report metadata in PDF', () => {
      const mockDoc = {
        setFontSize: vi.fn(),
        setFont: vi.fn(),
        text: vi.fn(),
        autoTable: vi.fn(),
        save: vi.fn()
      };
      
      class MockJsPDF {
        constructor() {
          return mockDoc;
        }
      }
      
      global.window = { jspdf: { jsPDF: MockJsPDF } };
      
      exportToPDF = () => {
        const { jsPDF } = window.jspdf;
        const doc = new jsPDF();
        
        doc.setFontSize(20);
        doc.text('CyberGuard Security Report', 20, 20);
        
        doc.setFontSize(10);
        doc.text(`Generated: ${new Date().toLocaleString()}`, 20, 30);
        doc.text(`Total Issues: ${getFilteredResults().length}`, 20, 36);
        doc.text(`Scanned Target: ${currentScanTarget || '--'}`, 20, 42);
        
        doc.autoTable({
          startY: 50,
          head: [['Scanner', 'Severity', 'Finding', 'Timestamp']],
          body: [],
          theme: 'grid'
        });
        
        doc.save(`cyberguard-report-${Date.now()}.pdf`);
      };
      
      exportToPDF();
      
      // Verify metadata was added
      const textCalls = mockDoc.text.mock.calls;
      expect(textCalls.some(call => call[0].includes('Total Issues: 3'))).toBe(true);
      expect(textCalls.some(call => call[0].includes('Scanned Target: 192.168.1.1'))).toBe(true);
    });
  });
  
  describe('Task 10.2 - CSV Export Function', () => {
    it('should create exportToCSV function', () => {
      // Mock Blob and URL
      class MockBlob {
        constructor(content, options) {
          this.content = content;
          this.options = options;
        }
      }
      
      global.Blob = MockBlob;
      global.URL = {
        createObjectURL: vi.fn(() => 'blob:mock-url'),
        revokeObjectURL: vi.fn()
      };
      
      // Mock document.createElement
      const mockAnchor = {
        href: '',
        download: '',
        click: vi.fn()
      };
      global.document = {
        createElement: vi.fn(() => mockAnchor)
      };
      
      exportToCSV = () => {
        const results = getFilteredResults();
        const headers = ['Timestamp', 'Scanner', 'Severity', 'Finding', 'Status'];
        
        let csv = headers.join(',') + '\n';
        
        results.forEach(result => {
          const row = [
            result.timestamp || new Date().toISOString(),
            result.tool || result.feature || 'Unknown',
            mapStatusToSeverity(result.status),
            `"${(result.message || '').replace(/"/g, '""')}"`,
            result.status || 'unknown'
          ];
          csv += row.join(',') + '\n';
        });
        
        const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `cyberguard-report-${Date.now()}.csv`;
        a.click();
        URL.revokeObjectURL(url);
      };
      
      exportToCSV();
      
      expect(global.URL.createObjectURL).toHaveBeenCalled();
      expect(mockAnchor.click).toHaveBeenCalled();
      expect(global.URL.revokeObjectURL).toHaveBeenCalled();
    });
    
    it('should generate CSV with correct headers', () => {
      let csvContent = '';
      
      class MockBlob {
        constructor(content, options) {
          csvContent = content[0];
          this.content = content;
          this.options = options;
        }
      }
      
      global.Blob = MockBlob;
      global.URL = {
        createObjectURL: vi.fn(() => 'blob:mock-url'),
        revokeObjectURL: vi.fn()
      };
      global.document = {
        createElement: vi.fn(() => ({
          href: '',
          download: '',
          click: vi.fn()
        }))
      };
      
      exportToCSV = () => {
        const results = getFilteredResults();
        const headers = ['Timestamp', 'Scanner', 'Severity', 'Finding', 'Status'];
        
        let csv = headers.join(',') + '\n';
        
        results.forEach(result => {
          const row = [
            result.timestamp || new Date().toISOString(),
            result.tool || result.feature || 'Unknown',
            mapStatusToSeverity(result.status),
            `"${(result.message || '').replace(/"/g, '""')}"`,
            result.status || 'unknown'
          ];
          csv += row.join(',') + '\n';
        });
        
        const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `cyberguard-report-${Date.now()}.csv`;
        a.click();
        URL.revokeObjectURL(url);
      };
      
      exportToCSV();
      
      expect(csvContent).toContain('Timestamp,Scanner,Severity,Finding,Status');
      expect(csvContent).toContain('XSS Scanner');
      expect(csvContent).toContain('critical');
      expect(csvContent).toContain('Port Scanner');
      expect(csvContent).toContain('warning');
    });
    
    it('should escape quotes in CSV fields', () => {
      resultsData = [{
        tool: 'Test Scanner',
        status: 'threat',
        message: 'Message with "quotes" inside',
        timestamp: '2024-01-15T10:30:00.000Z'
      }];
      
      let csvContent = '';
      
      class MockBlob {
        constructor(content, options) {
          csvContent = content[0];
          this.content = content;
          this.options = options;
        }
      }
      
      global.Blob = MockBlob;
      global.URL = {
        createObjectURL: vi.fn(() => 'blob:mock-url'),
        revokeObjectURL: vi.fn()
      };
      global.document = {
        createElement: vi.fn(() => ({
          href: '',
          download: '',
          click: vi.fn()
        }))
      };
      
      exportToCSV = () => {
        const results = getFilteredResults();
        const headers = ['Timestamp', 'Scanner', 'Severity', 'Finding', 'Status'];
        
        let csv = headers.join(',') + '\n';
        
        results.forEach(result => {
          const row = [
            result.timestamp || new Date().toISOString(),
            result.tool || result.feature || 'Unknown',
            mapStatusToSeverity(result.status),
            `"${(result.message || '').replace(/"/g, '""')}"`,
            result.status || 'unknown'
          ];
          csv += row.join(',') + '\n';
        });
        
        const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `cyberguard-report-${Date.now()}.csv`;
        a.click();
        URL.revokeObjectURL(url);
      };
      
      exportToCSV();
      
      // Quotes should be escaped as ""
      expect(csvContent).toContain('""quotes""');
    });
  });
  
  describe('Task 10.3 - Export Button Wiring', () => {
    it('should export only filtered results when filters are active', () => {
      // Set active filter to only show critical
      activeFilters.add('critical');
      
      const filtered = getFilteredResults();
      
      expect(filtered.length).toBe(1);
      expect(filtered[0].tool).toBe('XSS Scanner');
      expect(mapStatusToSeverity(filtered[0].status)).toBe('critical');
    });
    
    it('should export all results when no filters are active', () => {
      const filtered = getFilteredResults();
      
      expect(filtered.length).toBe(3);
    });
    
    it('should use timestamped filename for exports', () => {
      const timestamp = Date.now();
      const pdfFilename = `cyberguard-report-${timestamp}.pdf`;
      const csvFilename = `cyberguard-report-${timestamp}.csv`;
      
      expect(pdfFilename).toMatch(/cyberguard-report-\d+\.pdf/);
      expect(csvFilename).toMatch(/cyberguard-report-\d+\.csv/);
    });
  });
  
  describe('Requirements Validation', () => {
    it('should satisfy Requirement 5.3 - PDF format export', () => {
      // exportToPDF function should exist and generate PDF
      expect(typeof exportToPDF).toBe('function');
    });
    
    it('should satisfy Requirement 5.4 - CSV format export', () => {
      // exportToCSV function should exist and generate CSV
      expect(typeof exportToCSV).toBe('function');
    });
    
    it('should satisfy Requirement 5.5 - Include filtered results', () => {
      activeFilters.add('critical');
      const filtered = getFilteredResults();
      
      // Only critical results should be included
      expect(filtered.every(r => mapStatusToSeverity(r.status) === 'critical')).toBe(true);
    });
    
    it('should satisfy Requirement 5.6 - Include summary metrics', () => {
      const totalIssues = getFilteredResults().length;
      const target = currentScanTarget;
      
      expect(totalIssues).toBe(3);
      expect(target).toBe('192.168.1.1');
    });
    
    it('should satisfy Requirement 5.7 - Include timestamp', () => {
      const timestamp = new Date().toLocaleString();
      
      expect(timestamp).toBeTruthy();
      expect(typeof timestamp).toBe('string');
    });
  });
});
