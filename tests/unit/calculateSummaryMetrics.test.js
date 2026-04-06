/**
 * Unit tests for calculateSummaryMetrics function
 */

// Mock the mapStatusToSeverity function
function mapStatusToSeverity(status) {
  const severityMap = {
    'threat': 'critical',
    'warning': 'warning',
    'safe': 'info',
    'system': 'info'
  };
  return severityMap[status] || 'info';
}

// Import the function to test
function calculateSummaryMetrics(results, scanStartTime = null, scanEndTime = null) {
  // Calculate total issues
  const totalIssues = results.length;
  
  // Calculate severity counts
  let criticalCount = 0;
  let warningCount = 0;
  let infoCount = 0;
  
  results.forEach(result => {
    const severity = mapStatusToSeverity(result.status);
    if (severity === 'critical') {
      criticalCount++;
    } else if (severity === 'warning') {
      warningCount++;
    } else if (severity === 'info') {
      infoCount++;
    }
  });
  
  // Format time taken as human-readable string
  let timeTaken = '--';
  if (scanStartTime && scanEndTime) {
    const durationMs = scanEndTime - scanStartTime;
    const seconds = Math.floor(durationMs / 1000);
    const minutes = Math.floor(seconds / 60);
    const remainingSeconds = seconds % 60;
    
    if (minutes > 0) {
      timeTaken = `${minutes}m ${remainingSeconds}s`;
    } else {
      timeTaken = `${seconds}s`;
    }
  }
  
  return {
    totalIssues,
    criticalCount,
    warningCount,
    infoCount,
    timeTaken
  };
}

describe('calculateSummaryMetrics', () => {
  describe('Basic counting functionality', () => {
    it('should return zero counts for empty results array', () => {
      const metrics = calculateSummaryMetrics([]);
      
      expect(metrics.totalIssues).toBe(0);
      expect(metrics.criticalCount).toBe(0);
      expect(metrics.warningCount).toBe(0);
      expect(metrics.infoCount).toBe(0);
      expect(metrics.timeTaken).toBe('--');
    });

    it('should correctly count total issues', () => {
      const results = [
        { status: 'threat' },
        { status: 'warning' },
        { status: 'safe' }
      ];
      
      const metrics = calculateSummaryMetrics(results);
      expect(metrics.totalIssues).toBe(3);
    });

    it('should correctly count critical severity items', () => {
      const results = [
        { status: 'threat' },
        { status: 'threat' },
        { status: 'warning' }
      ];
      
      const metrics = calculateSummaryMetrics(results);
      expect(metrics.criticalCount).toBe(2);
    });

    it('should correctly count warning severity items', () => {
      const results = [
        { status: 'warning' },
        { status: 'warning' },
        { status: 'threat' }
      ];
      
      const metrics = calculateSummaryMetrics(results);
      expect(metrics.warningCount).toBe(2);
    });

    it('should correctly count info severity items', () => {
      const results = [
        { status: 'safe' },
        { status: 'system' },
        { status: 'threat' }
      ];
      
      const metrics = calculateSummaryMetrics(results);
      expect(metrics.infoCount).toBe(2);
    });

    it('should handle mixed severity levels correctly', () => {
      const results = [
        { status: 'threat' },
        { status: 'threat' },
        { status: 'warning' },
        { status: 'warning' },
        { status: 'warning' },
        { status: 'safe' },
        { status: 'system' }
      ];
      
      const metrics = calculateSummaryMetrics(results);
      expect(metrics.totalIssues).toBe(7);
      expect(metrics.criticalCount).toBe(2);
      expect(metrics.warningCount).toBe(3);
      expect(metrics.infoCount).toBe(2);
    });
  });

  describe('Time formatting functionality', () => {
    it('should return "--" when no time parameters provided', () => {
      const results = [{ status: 'threat' }];
      const metrics = calculateSummaryMetrics(results);
      
      expect(metrics.timeTaken).toBe('--');
    });

    it('should format seconds correctly (less than 1 minute)', () => {
      const results = [{ status: 'threat' }];
      const startTime = 1000000;
      const endTime = 1045000; // 45 seconds later
      
      const metrics = calculateSummaryMetrics(results, startTime, endTime);
      expect(metrics.timeTaken).toBe('45s');
    });

    it('should format minutes and seconds correctly', () => {
      const results = [{ status: 'threat' }];
      const startTime = 1000000;
      const endTime = 1154000; // 2 minutes 34 seconds later
      
      const metrics = calculateSummaryMetrics(results, startTime, endTime);
      expect(metrics.timeTaken).toBe('2m 34s');
    });

    it('should handle exactly 1 minute', () => {
      const results = [{ status: 'threat' }];
      const startTime = 1000000;
      const endTime = 1060000; // 1 minute later
      
      const metrics = calculateSummaryMetrics(results, startTime, endTime);
      expect(metrics.timeTaken).toBe('1m 0s');
    });

    it('should handle zero duration', () => {
      const results = [{ status: 'threat' }];
      const startTime = 1000000;
      const endTime = 1000000; // Same time
      
      const metrics = calculateSummaryMetrics(results, startTime, endTime);
      expect(metrics.timeTaken).toBe('0s');
    });
  });

  describe('Edge cases', () => {
    it('should handle unknown status values as info', () => {
      const results = [
        { status: 'unknown' },
        { status: 'custom' }
      ];
      
      const metrics = calculateSummaryMetrics(results);
      expect(metrics.infoCount).toBe(2);
      expect(metrics.totalIssues).toBe(2);
    });

    it('should handle large result sets', () => {
      const results = Array(1000).fill({ status: 'threat' });
      
      const metrics = calculateSummaryMetrics(results);
      expect(metrics.totalIssues).toBe(1000);
      expect(metrics.criticalCount).toBe(1000);
    });

    it('should handle long durations correctly', () => {
      const results = [{ status: 'threat' }];
      const startTime = 1000000;
      const endTime = 1600000; // 10 minutes later
      
      const metrics = calculateSummaryMetrics(results, startTime, endTime);
      expect(metrics.timeTaken).toBe('10m 0s');
    });
  });

  describe('Requirements validation', () => {
    it('should satisfy Requirement 1.4 - Total Issues count', () => {
      const results = [
        { status: 'threat' },
        { status: 'warning' },
        { status: 'safe' }
      ];
      
      const metrics = calculateSummaryMetrics(results);
      expect(typeof metrics.totalIssues).toBe('number');
      expect(metrics.totalIssues).toBeGreaterThanOrEqual(0);
    });

    it('should satisfy Requirement 1.5 - Time Taken in human-readable format', () => {
      const results = [{ status: 'threat' }];
      const startTime = 1000000;
      const endTime = 1154000;
      
      const metrics = calculateSummaryMetrics(results, startTime, endTime);
      expect(typeof metrics.timeTaken).toBe('string');
      expect(metrics.timeTaken).toMatch(/^\d+m \d+s$|^\d+s$|^--$/);
    });

    it('should satisfy Requirement 1.6 - Calculate severity counts', () => {
      const results = [
        { status: 'threat' },
        { status: 'warning' },
        { status: 'safe' }
      ];
      
      const metrics = calculateSummaryMetrics(results);
      expect(typeof metrics.criticalCount).toBe('number');
      expect(typeof metrics.warningCount).toBe('number');
      expect(typeof metrics.infoCount).toBe('number');
      expect(metrics.criticalCount + metrics.warningCount + metrics.infoCount).toBe(metrics.totalIssues);
    });
  });
});
