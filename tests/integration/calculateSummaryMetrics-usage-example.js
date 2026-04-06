/**
 * Usage example for calculateSummaryMetrics function
 * This demonstrates how the function integrates with the existing results system
 */

// Example usage in the context of the CyberGuard application

// Sample results data (as would be stored in resultsData array)
const sampleResults = [
  {
    id: '1234567890',
    timestamp: '14:23:45',
    feature: 'XSS Scanner',
    message: 'Cross-site scripting vulnerability detected',
    status: 'threat', // Maps to 'critical' severity
    details: null,
    date: new Date()
  },
  {
    id: '1234567891',
    timestamp: '14:23:46',
    feature: 'Port Scanner',
    message: 'Open port detected on 8080',
    status: 'warning', // Maps to 'warning' severity
    details: null,
    date: new Date()
  },
  {
    id: '1234567892',
    timestamp: '14:23:47',
    feature: 'SSL Scanner',
    message: 'SSL certificate is valid',
    status: 'safe', // Maps to 'info' severity
    details: null,
    date: new Date()
  },
  {
    id: '1234567893',
    timestamp: '14:23:48',
    feature: 'System',
    message: 'Scan completed successfully',
    status: 'system', // Maps to 'info' severity
    details: null,
    date: new Date()
  }
];

// Simulate scan timing
const scanStartTime = Date.now();
const scanEndTime = scanStartTime + 154000; // 2 minutes 34 seconds later

// Calculate summary metrics
const metrics = calculateSummaryMetrics(sampleResults, scanStartTime, scanEndTime);

console.log('Summary Metrics:');
console.log('================');
console.log(`Total Issues: ${metrics.totalIssues}`);
console.log(`Critical: ${metrics.criticalCount}`);
console.log(`Warning: ${metrics.warningCount}`);
console.log(`Info: ${metrics.infoCount}`);
console.log(`Time Taken: ${metrics.timeTaken}`);

// Expected output:
// Summary Metrics:
// ================
// Total Issues: 4
// Critical: 1
// Warning: 1
// Info: 2
// Time Taken: 2m 34s

// Example integration with updateSummaryBar function (from design.md)
function updateSummaryBar(metrics, target) {
  const totalIssuesElement = document.getElementById('total-issues-count');
  const scanTimeElement = document.getElementById('scan-time-display');
  const scannedTargetElement = document.getElementById('scanned-target-display');
  
  if (totalIssuesElement) {
    totalIssuesElement.textContent = metrics.totalIssues;
  }
  
  if (scanTimeElement) {
    scanTimeElement.textContent = metrics.timeTaken;
  }
  
  if (scannedTargetElement) {
    scannedTargetElement.textContent = target || '--';
  }
}

// Usage in scan completion handler
function onScanComplete(resultsData, scanStartTime, scanEndTime, target) {
  const metrics = calculateSummaryMetrics(resultsData, scanStartTime, scanEndTime);
  updateSummaryBar(metrics, target);
  
  // Also update filter counts if needed
  console.log(`Found ${metrics.criticalCount} critical issues`);
  console.log(`Found ${metrics.warningCount} warnings`);
  console.log(`Found ${metrics.infoCount} informational items`);
}
