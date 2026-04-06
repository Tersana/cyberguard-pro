# calculateSummaryMetrics API Documentation

## Overview

The `calculateSummaryMetrics()` function aggregates security scan results data and provides summary statistics for display in the Summary Bar component of the Professional Security Reports View.

## Function Signature

```javascript
function calculateSummaryMetrics(results, scanStartTime = null, scanEndTime = null)
```

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `results` | Array | Yes | Array of result objects with `status` property |
| `scanStartTime` | Number | No | Timestamp (milliseconds) when scan started |
| `scanEndTime` | Number | No | Timestamp (milliseconds) when scan ended |

## Return Value

Returns an object with the following properties:

```javascript
{
  totalIssues: number,      // Total count of all results
  criticalCount: number,    // Count of critical severity items (status: 'threat')
  warningCount: number,     // Count of warning severity items (status: 'warning')
  infoCount: number,        // Count of info severity items (status: 'safe' or 'system')
  timeTaken: string         // Human-readable time format (e.g., "2m 34s", "45s", or "--")
}
```

## Time Formatting

The `timeTaken` field is formatted as follows:

- **No time data**: Returns `"--"` when `scanStartTime` or `scanEndTime` is not provided
- **Less than 1 minute**: Returns `"Xs"` (e.g., `"45s"`)
- **1 minute or more**: Returns `"Xm Ys"` (e.g., `"2m 34s"`)

## Severity Mapping

The function uses `mapStatusToSeverity()` to convert status values to severity levels:

| Status | Severity |
|--------|----------|
| `'threat'` | `'critical'` |
| `'warning'` | `'warning'` |
| `'safe'` | `'info'` |
| `'system'` | `'info'` |
| Unknown | `'info'` (default) |

## Usage Examples

### Basic Usage (No Timing)

```javascript
const results = [
  { status: 'threat', message: 'XSS vulnerability detected' },
  { status: 'warning', message: 'Open port found' },
  { status: 'safe', message: 'SSL certificate valid' }
];

const metrics = calculateSummaryMetrics(results);

console.log(metrics);
// Output:
// {
//   totalIssues: 3,
//   criticalCount: 1,
//   warningCount: 1,
//   infoCount: 1,
//   timeTaken: '--'
// }
```

### With Scan Timing

```javascript
const results = [
  { status: 'threat', message: 'XSS vulnerability detected' },
  { status: 'warning', message: 'Open port found' }
];

const scanStartTime = Date.now();
// ... perform scan ...
const scanEndTime = Date.now() + 154000; // 2 minutes 34 seconds later

const metrics = calculateSummaryMetrics(results, scanStartTime, scanEndTime);

console.log(metrics);
// Output:
// {
//   totalIssues: 2,
//   criticalCount: 1,
//   warningCount: 1,
//   infoCount: 0,
//   timeTaken: '2m 34s'
// }
```

### Integration with Summary Bar

```javascript
function updateSummaryBar(resultsData, scanStartTime, scanEndTime, target) {
  // Calculate metrics
  const metrics = calculateSummaryMetrics(resultsData, scanStartTime, scanEndTime);
  
  // Update UI elements
  document.getElementById('total-issues-count').textContent = metrics.totalIssues;
  document.getElementById('scan-time-display').textContent = metrics.timeTaken;
  document.getElementById('scanned-target-display').textContent = target || '--';
  
  // Optionally update filter counts
  console.log(`Critical: ${metrics.criticalCount}`);
  console.log(`Warning: ${metrics.warningCount}`);
  console.log(`Info: ${metrics.infoCount}`);
}
```

### Empty Results

```javascript
const metrics = calculateSummaryMetrics([]);

console.log(metrics);
// Output:
// {
//   totalIssues: 0,
//   criticalCount: 0,
//   warningCount: 0,
//   infoCount: 0,
//   timeTaken: '--'
// }
```

## Requirements Satisfied

This function satisfies the following requirements from the Professional Security Reports View specification:

- **Requirement 1.4**: Calculate and display "Total Issues Found" as a numeric count
- **Requirement 1.5**: Display "Time Taken" in a human-readable time format
- **Requirement 1.6**: Calculate severity-based counts (Critical, Warning, Info)

## Related Functions

- `mapStatusToSeverity(status)` - Converts status values to severity levels
- `updateSummaryBar(metrics, target)` - Updates the Summary Bar UI with metrics
- `logResult(timestamp, feature, message, status, details)` - Adds results to the results array

## Testing

The function is thoroughly tested with 17 unit tests covering:

- Basic counting functionality
- Time formatting (seconds, minutes, edge cases)
- Edge cases (empty arrays, unknown statuses, large datasets)
- Requirements validation

Run tests with:

```bash
npm test -- calculateSummaryMetrics.test.js
```

## Location

- **Implementation**: `main.js` (lines 52-115)
- **Tests**: `tests/unit/calculateSummaryMetrics.test.js`
- **Usage Example**: `tests/integration/calculateSummaryMetrics-usage-example.js`
