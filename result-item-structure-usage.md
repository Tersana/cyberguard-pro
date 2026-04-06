# Result Item Data Structure - Usage Guide

## Overview

This document provides guidance on using the Result Item data structure for the Professional Security Reports View in CyberGuard Pro. The data structure extends the existing results array with additional fields needed for enhanced reporting capabilities.

## Data Structure Schema

### ResultItem Object

```javascript
{
  id: string,              // Unique identifier (timestamp-based)
  tool: string,            // Scanner name (e.g., "XSS Scanner", "Port Scanner")
  status: string,          // "safe", "warning", "threat", "system"
  message: string,         // Short summary message
  description: string,     // Detailed explanation of the finding
  evidence: string,        // Code snippet, terminal output, or technical details
  remediation: string[],   // Array of remediation steps
  target: string,          // IP address or URL that was scanned
  timestamp: string,       // Human-readable timestamp (e.g., "2:34:56 PM")
  confidence: number       // Confidence score (0-100)
}
```

## Field Descriptions

### Required Fields

- **id**: Unique identifier generated from `Date.now().toString()`. Used for tracking and referencing specific results.
- **tool**: Name of the scanner that generated this result (e.g., "XSS Scanner", "Port Scanner", "WHOIS Lookup")
- **status**: Status indicator with four possible values:
  - `"safe"` - No issues found
  - `"warning"` - Potential issue that needs attention
  - `"threat"` - Critical security vulnerability
  - `"system"` - System message or informational log
- **message**: Short summary displayed in the collapsed accordion view
- **timestamp**: Human-readable time string (e.g., "2:34:56 PM")

### Optional Fields

- **description**: Detailed explanation shown in the expanded accordion view. Can include technical details about the vulnerability or finding.
- **evidence**: Technical evidence displayed in the Evidence Box. Can include:
  - Code snippets
  - Terminal output
  - HTTP requests/responses
  - Configuration details
- **remediation**: Array of strings describing how to fix the issue. Each string is displayed as a bullet point in the "How to Fix" section.
- **target**: The IP address or URL that was scanned
- **confidence**: Numeric score from 0-100 indicating confidence in the finding

## Usage Examples

### Creating a New Result Item

```javascript
// Using the createResultItem helper function
const result = createResultItem({
  tool: 'XSS Scanner',
  status: 'threat',
  message: 'Cross-site scripting vulnerability detected',
  description: 'A cross-site scripting (XSS) vulnerability was detected in the target application. This allows attackers to inject malicious scripts into web pages viewed by other users.',
  evidence: 'Payload: <script>alert(\'XSS\')</script>\nLocation: /search?q=test\nResponse: 200 OK',
  remediation: [
    'Implement input validation and sanitization',
    'Use Content Security Policy (CSP) headers',
    'Encode output data before rendering'
  ],
  target: '192.168.1.100',
  confidence: 95
});
```

### Creating a Minimal Result Item

```javascript
// Only required fields
const result = createResultItem({
  tool: 'System',
  status: 'system',
  message: 'Scan started'
});
// Optional fields will be set to defaults:
// description: ""
// evidence: ""
// remediation: []
// target: ""
// confidence: 100
```

### Converting Legacy Results

```javascript
// Existing result format from logResult()
const legacyResult = {
  id: '1234567890',
  timestamp: '2:34:56 PM',
  feature: 'XSS Scanner',  // Old field name
  message: 'Vulnerability detected',
  status: 'threat',
  details: 'Some details',  // Old field name
  date: new Date()
};

// Convert to new format
const newResult = convertLegacyResult(legacyResult);
// newResult.tool === 'XSS Scanner' (converted from feature)
// newResult.description === 'Some details' (converted from details)
```

### Validating Result Items

```javascript
const result = createResultItem({
  tool: 'Port Scanner',
  status: 'warning',
  message: 'Open port detected'
});

if (isValidResultItem(result)) {
  // Result is valid, safe to use
  resultsData.push(result);
} else {
  console.error('Invalid result item');
}
```

## Integration with Existing Code

### Modifying logResult() Function

The existing `logResult()` function can be extended to support the new fields:

```javascript
function logResult(
  timestamp,
  feature,
  message,
  status = "info",
  details = null,
  options = {}
) {
  // Map old status to new status system
  let newStatus = status;
  if (status === "success") newStatus = "safe";
  else if (status === "warning") newStatus = "warning";
  else if (status === "danger") newStatus = "threat";
  else if (status === "info") newStatus = "system";

  const result = {
    id: Date.now().toString(),
    timestamp: timestamp.toLocaleTimeString(),
    tool: feature,  // Use 'tool' instead of 'feature'
    message: message,
    status: newStatus,
    description: options.description || details || "",
    evidence: options.evidence || "",
    remediation: options.remediation || [],
    target: options.target || "",
    confidence: options.confidence || 100,
    date: timestamp,
  };

  resultsData.push(result);
  updateResultsStats();
  renderResults();
}
```

### Using Enhanced logResult()

```javascript
// Simple usage (backward compatible)
logResult(
  new Date(),
  'XSS Scanner',
  'Vulnerability detected',
  'danger'
);

// Enhanced usage with new fields
logResult(
  new Date(),
  'XSS Scanner',
  'Cross-site scripting vulnerability detected',
  'danger',
  null,
  {
    description: 'A cross-site scripting vulnerability was detected...',
    evidence: 'Payload: <script>alert("XSS")</script>\nLocation: /search',
    remediation: [
      'Implement input validation',
      'Use CSP headers',
      'Encode output data'
    ],
    target: '192.168.1.100',
    confidence: 95
  }
);
```

## Severity Mapping

The status field maps to severity levels for visual display:

```javascript
function mapStatusToSeverity(status) {
  const severityMap = {
    'threat': 'critical',   // Red badge with neon glow
    'warning': 'warning',   // Amber badge with neon glow
    'safe': 'info',         // Blue badge with neon glow
    'system': 'info'        // Blue badge with neon glow
  };
  return severityMap[status] || 'info';
}
```

## Example Results for Different Severity Levels

### Critical (Threat)

```javascript
{
  id: "1704123456789",
  tool: "XSS Scanner",
  status: "threat",
  message: "Cross-site scripting vulnerability detected",
  description: "A cross-site scripting (XSS) vulnerability was detected...",
  evidence: "Payload: <script>alert('XSS')</script>\nLocation: /search?q=test",
  remediation: [
    "Implement input validation and sanitization",
    "Use Content Security Policy (CSP) headers"
  ],
  target: "192.168.1.100",
  timestamp: "2:34:56 PM",
  confidence: 95
}
```

### Warning

```javascript
{
  id: "1704123456790",
  tool: "Port Scanner",
  status: "warning",
  message: "Open port detected: 8080",
  description: "Port 8080 is open and responding...",
  evidence: "Port: 8080\nState: OPEN\nService: http-proxy",
  remediation: [
    "Review if this port needs to be publicly accessible",
    "Implement firewall rules to restrict access"
  ],
  target: "192.168.1.100",
  timestamp: "2:35:12 PM",
  confidence: 100
}
```

### Info (Safe)

```javascript
{
  id: "1704123456791",
  tool: "SSL Certificate Check",
  status: "safe",
  message: "Valid SSL certificate found",
  description: "The target has a valid SSL/TLS certificate...",
  evidence: "Issuer: Let's Encrypt\nValid From: 2024-01-01\nValid Until: 2024-04-01",
  remediation: [],
  target: "example.com",
  timestamp: "2:35:45 PM",
  confidence: 100
}
```

### System

```javascript
{
  id: "1704123456792",
  tool: "System",
  status: "system",
  message: "Scan completed successfully",
  description: "All security scans have been completed.",
  evidence: "Total scans: 5\nDuration: 2m 34s",
  remediation: [],
  target: "192.168.1.100",
  timestamp: "2:36:00 PM",
  confidence: 100
}
```

## Best Practices

1. **Always use createResultItem()** for creating new results to ensure proper field initialization
2. **Validate results** with `isValidResultItem()` before adding to the results array
3. **Use convertLegacyResult()** when working with existing result objects
4. **Provide meaningful descriptions** - the description field should explain the finding in detail
5. **Include actionable remediation** - each remediation step should be specific and actionable
6. **Format evidence clearly** - use newlines (`\n`) to separate different pieces of evidence
7. **Set appropriate confidence levels** - use lower confidence for heuristic detections
8. **Always include the target** - helps users understand which system was scanned

## Backward Compatibility

The data structure is designed to be backward compatible with the existing results array:

- The `tool` field replaces `feature` but `convertLegacyResult()` handles the conversion
- The `description` field replaces `details` with automatic conversion
- All new fields are optional and have sensible defaults
- Existing scanner functions continue to work without modification
- The validation function accepts both old and new formats

## Testing

Unit tests are provided in `tests/unit/result-item-structure.test.js` covering:

- Result item creation with all fields
- Result item creation with minimal fields
- Field validation
- Legacy result conversion
- Edge cases and error handling

Run tests with:
```bash
npm test -- tests/unit/result-item-structure.test.js
```

## Requirements Traceability

This data structure satisfies the following requirements:

- **Requirement 7.4**: Populate Result_Items dynamically via JavaScript
- **Requirement 7.6**: Receive and display scan results when Scanner completes
- **Requirement 7.7**: Maintain compatibility with existing scan result data structures
