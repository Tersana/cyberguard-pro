/**
 * Result Item Data Structure for Professional Security Reports View
 * 
 * This module defines the schema for result objects used in the CyberGuard
 * professional security reports view. It extends the existing results array structure
 * with additional fields for enhanced reporting capabilities.
 * 
 * Requirements: 7.4, 7.6, 7.7
 */

/**
 * Result Item Schema
 * 
 * @typedef {Object} ResultItem
 * @property {string} id - Unique identifier (timestamp-based, e.g., "1234567890123")
 * @property {string} tool - Scanner name (e.g., "XSS Scanner", "Port Scanner", "WHOIS Lookup")
 * @property {string} status - Status indicator: "safe", "warning", "threat", "system"
 * @property {string} message - Short summary message displayed in collapsed view
 * @property {string} description - Detailed explanation of the finding (for expanded view)
 * @property {string} evidence - Code snippet, terminal output, or technical details (displayed in Evidence Box)
 * @property {string[]} remediation - Array of remediation steps for "How to Fix" section
 * @property {string} target - IP address or URL that was scanned
 * @property {string} timestamp - Human-readable timestamp (e.g., "12:34:56 PM")
 * @property {number} confidence - Confidence score (0-100) indicating certainty of the finding
 * 
 * @example
 * {
 *   id: "1704123456789",
 *   tool: "XSS Scanner",
 *   status: "threat",
 *   message: "Cross-site scripting vulnerability detected",
 *   description: "A cross-site scripting (XSS) vulnerability was detected in the target application. This allows attackers to inject malicious scripts into web pages viewed by other users.",
 *   evidence: "Payload: <script>alert('XSS')</script>\nLocation: /search?q=test\nResponse: 200 OK\nReflected in: <div class=\"results\">",
 *   remediation: [
 *     "Implement input validation and sanitization",
 *     "Use Content Security Policy (CSP) headers",
 *     "Encode output data before rendering",
 *     "Use modern frameworks with built-in XSS protection"
 *   ],
 *   target: "192.168.1.100",
 *   timestamp: "2:34:56 PM",
 *   confidence: 95
 * }
 */

/**
 * Creates a new result item with all required fields
 * 
 * @param {Object} params - Parameters for creating the result item
 * @param {string} params.tool - Scanner name
 * @param {string} params.status - Status: "safe", "warning", "threat", or "system"
 * @param {string} params.message - Short summary message
 * @param {string} [params.description=""] - Detailed explanation (optional)
 * @param {string} [params.evidence=""] - Technical evidence (optional)
 * @param {string[]} [params.remediation=[]] - Remediation steps (optional)
 * @param {string} [params.target=""] - Scanned target (optional)
 * @param {number} [params.confidence=100] - Confidence score 0-100 (optional)
 * @returns {ResultItem} Complete result item object
 */
function createResultItem({
  tool,
  status,
  message,
  description = "",
  evidence = "",
  remediation = [],
  target = "",
  confidence = 100
}) {
  const now = new Date();
  
  return {
    id: Date.now().toString(),
    tool: tool,
    status: status,
    message: message,
    description: description,
    evidence: evidence,
    remediation: Array.isArray(remediation) ? remediation : [],
    target: target,
    timestamp: now.toLocaleTimeString(),
    confidence: Math.max(0, Math.min(100, confidence)) // Clamp between 0-100
  };
}

/**
 * Validates a result item object
 * 
 * @param {Object} result - Result item to validate
 * @returns {boolean} True if valid, false otherwise
 */
function isValidResultItem(result) {
  if (!result || typeof result !== 'object') return false;
  
  // Required fields
  if (typeof result.id !== 'string' || result.id.trim() === '') return false;
  if (typeof result.tool !== 'string' || result.tool.trim() === '') return false;
  if (!['safe', 'warning', 'threat', 'system'].includes(result.status)) return false;
  if (typeof result.message !== 'string' || result.message.trim() === '') return false;
  if (typeof result.timestamp !== 'string' || result.timestamp.trim() === '') return false;
  
  // Optional fields with type checking
  if (result.description !== undefined && typeof result.description !== 'string') return false;
  if (result.evidence !== undefined && typeof result.evidence !== 'string') return false;
  if (result.remediation !== undefined && !Array.isArray(result.remediation)) return false;
  if (result.target !== undefined && typeof result.target !== 'string') return false;
  if (result.confidence !== undefined && (typeof result.confidence !== 'number' || result.confidence < 0 || result.confidence > 100)) return false;
  
  return true;
}

/**
 * Converts legacy result format to new format
 * 
 * @param {Object} legacyResult - Result in old format (with feature instead of tool)
 * @returns {ResultItem} Result in new format
 */
function convertLegacyResult(legacyResult) {
  return {
    id: legacyResult.id || Date.now().toString(),
    tool: legacyResult.feature || legacyResult.tool || "Unknown",
    status: legacyResult.status || "system",
    message: legacyResult.message || "",
    description: legacyResult.details || legacyResult.description || "",
    evidence: legacyResult.evidence || "",
    remediation: legacyResult.remediation || [],
    target: legacyResult.target || "",
    timestamp: legacyResult.timestamp || new Date().toLocaleTimeString(),
    confidence: legacyResult.confidence || 100
  };
}

/**
 * Example result items for different severity levels
 */
const EXAMPLE_RESULTS = {
  critical: {
    id: "1704123456789",
    tool: "XSS Scanner",
    status: "threat",
    message: "Cross-site scripting vulnerability detected",
    description: "A cross-site scripting (XSS) vulnerability was detected in the target application. This allows attackers to inject malicious scripts into web pages viewed by other users, potentially stealing session cookies, credentials, or performing actions on behalf of the victim.",
    evidence: "Payload: <script>alert('XSS')</script>\nLocation: /search?q=test\nResponse: 200 OK\nReflected in: <div class=\"results\">",
    remediation: [
      "Implement input validation and sanitization",
      "Use Content Security Policy (CSP) headers",
      "Encode output data before rendering",
      "Use modern frameworks with built-in XSS protection"
    ],
    target: "192.168.1.100",
    timestamp: "2:34:56 PM",
    confidence: 95
  },
  
  warning: {
    id: "1704123456790",
    tool: "Port Scanner",
    status: "warning",
    message: "Open port detected: 8080",
    description: "Port 8080 is open and responding. This port is commonly used for web servers and development environments. While not necessarily a vulnerability, exposed ports increase the attack surface.",
    evidence: "Port: 8080\nState: OPEN\nService: http-proxy\nBanner: Apache Tomcat/9.0.50",
    remediation: [
      "Review if this port needs to be publicly accessible",
      "Implement firewall rules to restrict access",
      "Ensure the service is up-to-date with security patches",
      "Use strong authentication if the service must be exposed"
    ],
    target: "192.168.1.100",
    timestamp: "2:35:12 PM",
    confidence: 100
  },
  
  info: {
    id: "1704123456791",
    tool: "SSL Certificate Check",
    status: "safe",
    message: "Valid SSL certificate found",
    description: "The target has a valid SSL/TLS certificate that is properly configured. The certificate is issued by a trusted Certificate Authority and has not expired.",
    evidence: "Issuer: Let's Encrypt\nValid From: 2024-01-01\nValid Until: 2024-04-01\nSubject: example.com\nSignature Algorithm: SHA256-RSA",
    remediation: [],
    target: "example.com",
    timestamp: "2:35:45 PM",
    confidence: 100
  },
  
  system: {
    id: "1704123456792",
    tool: "System",
    status: "system",
    message: "Scan completed successfully",
    description: "All security scans have been completed. Review the findings above to identify and remediate any security issues.",
    evidence: "Total scans: 5\nDuration: 2m 34s\nTarget: 192.168.1.100",
    remediation: [],
    target: "192.168.1.100",
    timestamp: "2:36:00 PM",
    confidence: 100
  }
};

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    createResultItem,
    isValidResultItem,
    convertLegacyResult,
    EXAMPLE_RESULTS
  };
}
