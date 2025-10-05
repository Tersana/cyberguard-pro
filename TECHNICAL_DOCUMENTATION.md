# 🔧 CyberGuard Pro - Technical Documentation

## 📋 Table of Contents

- [Architecture Overview](#architecture-overview)
- [Core Functions](#core-functions)
- [API Integrations](#api-integrations)
- [Security Implementations](#security-implementations)
- [Performance Optimizations](#performance-optimizations)
- [Error Handling](#error-handling)
- [Code Structure](#code-structure)

## 🏗️ Architecture Overview

### System Components

```
┌─────────────────────────────────────────────────────────────┐
│                    CyberGuard Pro Platform                   │
├─────────────────────────────────────────────────────────────┤
│  Frontend Layer (Browser-based)                             │
│  ├── User Interface (HTML/CSS/JavaScript)                   │
│  ├── Security Tools Engine                                  │
│  ├── API Integration Layer                                  │
│  └── Real-time Monitoring System                           │
├─────────────────────────────────────────────────────────────┤
│  Backend Services                                           │
│  ├── Proxy Server (Node.js/Express)                        │
│  ├── OWASP ZAP (Docker Container)                          │
│  └── External API Integrations                             │
├─────────────────────────────────────────────────────────────┤
│  External Services                                          │
│  ├── VirusTotal API                                        │
│  ├── WHOIS APIs                                            │
│  ├── Geolocation Services                                  │
│  └── Hash Databases                                         │
└─────────────────────────────────────────────────────────────┘
```

## 🔧 Core Functions

### 1. Port Scanner Engine

#### Implementation

```javascript
class PortScanner {
  constructor(target) {
    this.target = target;
    this.results = [];
    this.serviceDatabase = this.getServiceDatabase();
  }

  async scanPorts(ports) {
    // Multi-threaded port scanning
    const promises = ports.map((port) => this.scanPort(port));
    return Promise.all(promises);
  }

  async scanPort(port) {
    // Multiple detection methods
    const methods = await this.runDetectionMethods(port);
    return this.analyzeResults(port, methods);
  }
}
```

#### Detection Methods

1. **HTTP/HTTPS Detection**: Browser-based HTTP requests
2. **WebSocket Detection**: WebSocket connection attempts
3. **Resource Loading**: Image and resource loading tests
4. **Service-Specific Detection**: Protocol-specific tests
5. **Advanced HTTP Headers**: Header analysis and fingerprinting

#### Service Database

- **Web Services**: HTTP, HTTPS, alternative ports
- **Remote Access**: SSH, RDP, VNC, Telnet
- **Email Services**: SMTP, POP3, IMAP
- **Database Services**: MySQL, PostgreSQL, MongoDB
- **Network Services**: DNS, FTP, SNMP, LDAP

### 2. XSS Vulnerability Scanner

#### OWASP ZAP Integration

```javascript
async function testXss(url) {
  // ZAP API configuration
  const ZAP_API_BASE = "http://localhost:3001/zap";

  // Check ZAP status
  const zapStatus = await checkZapStatus();

  // Start active scan
  const scanId = await startZapScan(url);

  // Monitor progress with timeout
  const progress = await monitorScanProgress(scanId);

  // Get and display results
  const results = await getZapScanResults();
  await displayXssResults(results);
}
```

#### Scan Process

1. **URL Validation**: Input sanitization and validation
2. **ZAP Connection**: Proxy server communication
3. **Scan Initiation**: Active scan with progress monitoring
4. **Progress Tracking**: Real-time progress updates (2.5 min timeout)
5. **Result Analysis**: Vulnerability detection and reporting
6. **Security Recommendations**: Automated remediation suggestions

#### Timeout Handling

```javascript
async function monitorScanProgress(scanId) {
  let progress = 0;
  let attempts = 0;
  const maxAttempts = 30; // 2.5 minutes

  while (progress < 100 && attempts < maxAttempts) {
    // Progress monitoring with stuck detection
    // Error handling and connection validation
    // Automatic timeout and fallback
  }
}
```

### 3. Hash Analysis Engine

#### Hash Generation

```javascript
async function generateHash(text, algorithm) {
  const encoder = new TextEncoder();
  const data = encoder.encode(text);
  const hashBuffer = await crypto.subtle.digest(algorithm, data);
  return Array.from(new Uint8Array(hashBuffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}
```

#### Supported Algorithms

- **MD5**: Fast, legacy compatibility
- **SHA-1**: Widely supported, being phased out
- **SHA-256**: Current standard, secure
- **SHA-512**: High security, longer output

#### Hash Verification

```javascript
async function verifyHash(text, hash, algorithm) {
  const generatedHash = await generateHash(text, algorithm);
  return generatedHash.toLowerCase() === hash.toLowerCase();
}
```

### 4. Network Security Analysis

#### TCP Connectivity Testing

```javascript
async function realTcpPortScan(target) {
  const testablePorts = [
    { port: 80, service: "HTTP", protocol: "http" },
    { port: 443, service: "HTTPS", protocol: "https" },
    { port: 8080, service: "HTTP-Alt", protocol: "http" },
  ];

  // Real connectivity tests using browser APIs
  for (const portInfo of testablePorts) {
    await testPortConnectivity(target, portInfo);
  }
}
```

#### WebSocket Testing

```javascript
async function testWebSocketConnection(host, port) {
  try {
    const ws = new WebSocket(`ws://${host}:${port}`);
    return new Promise((resolve) => {
      ws.onopen = () => resolve({ connected: true });
      ws.onerror = () => resolve({ connected: false });
    });
  } catch (error) {
    return { connected: false, error: error.message };
  }
}
```

### 5. SSL/TLS Certificate Analysis

#### Certificate Validation

```javascript
async function checkSsl(url) {
  try {
    if (!url.startsWith("https://")) {
      throw new Error("Site does not use HTTPS");
    }

    // Certificate validation
    const response = await fetch(url);
    const certificate = response.headers.get("x-certificate");

    // Analyze certificate details
    return analyzeCertificate(certificate);
  } catch (error) {
    return { valid: false, error: error.message };
  }
}
```

## 🔌 API Integrations

### OWASP ZAP API Integration

#### Configuration

```javascript
const ZAP_CONFIG = {
  baseUrl: "http://localhost:3001/zap",
  apiKey: "", // Disabled for testing
  timeout: 150000, // 2.5 minutes
  retryAttempts: 3,
};
```

#### API Endpoints

- **Core API**: `/JSON/core/view/version/`
- **Scan API**: `/JSON/ascan/action/scan/`
- **Status API**: `/JSON/ascan/view/status/`
- **Alerts API**: `/JSON/core/view/alerts/`

#### CORS Proxy Implementation

```javascript
// Express.js proxy server
app.use(
  "/zap",
  createProxyMiddleware({
    target: "http://localhost:8080",
    changeOrigin: true,
    pathRewrite: { "^/zap": "/JSON" },
    onError: (err, req, res) => {
      res.status(500).json({ error: "ZAP API not accessible" });
    },
  })
);
```

### VirusTotal API Integration

#### File Scanning

```javascript
async function scanWithVirusTotal(fileHash) {
  const response = await fetch(
    `https://www.virustotal.com/vtapi/v2/file/report`,
    {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: `apikey=${VIRUSTOTAL_API_KEY}&resource=${fileHash}`,
    }
  );

  return await response.json();
}
```

#### URL Analysis

```javascript
async function analyzeUrlWithVirusTotal(url) {
  const response = await fetch(
    `https://www.virustotal.com/vtapi/v2/url/report`,
    {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: `apikey=${VIRUSTOTAL_API_KEY}&resource=${url}`,
    }
  );

  return await response.json();
}
```

### WHOIS API Integration

#### Domain Lookup

```javascript
async function whoisLookup(domain) {
  const response = await fetch(
    `https://www.whoisxmlapi.com/whoisserver/WhoisService`,
    {
      method: "GET",
      params: {
        apiKey: WHOIS_API_KEY,
        domainName: domain,
        outputFormat: "JSON",
      },
    }
  );

  return await response.json();
}
```

## 🛡️ Security Implementations

### Input Validation

```javascript
function validateInput(input, type) {
  switch (type) {
    case "url":
      return /^https?:\/\/.+/.test(input);
    case "ip":
      return /^(\d{1,3}\.){3}\d{1,3}$/.test(input);
    case "domain":
      return /^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(input);
    default:
      return false;
  }
}
```

### XSS Prevention

```javascript
function sanitizeInput(input) {
  return input
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#x27;")
    .replace(/\//g, "&#x2F;");
}
```

### CSRF Protection

```javascript
function generateCSRFToken() {
  return crypto
    .getRandomValues(new Uint8Array(32))
    .reduce((str, byte) => str + byte.toString(16).padStart(2, "0"), "");
}
```

## ⚡ Performance Optimizations

### Asynchronous Operations

```javascript
// Parallel processing for multiple operations
async function performMultipleScans(targets) {
  const promises = targets.map((target) => scanTarget(target));
  return Promise.all(promises);
}
```

### Memory Management

```javascript
// Cleanup resources after operations
function cleanupResources() {
  // Clear large objects
  this.results = [];
  this.cache = new Map();

  // Force garbage collection if available
  if (window.gc) {
    window.gc();
  }
}
```

### Caching Strategy

```javascript
class CacheManager {
  constructor(maxSize = 100) {
    this.cache = new Map();
    this.maxSize = maxSize;
  }

  set(key, value) {
    if (this.cache.size >= this.maxSize) {
      const firstKey = this.cache.keys().next().value;
      this.cache.delete(firstKey);
    }
    this.cache.set(key, value);
  }
}
```

## 🚨 Error Handling

### Global Error Handler

```javascript
window.addEventListener("error", (event) => {
  console.error("Global error:", event.error);
  logResult(new Date(), "System", `❌ Error: ${event.error.message}`, "danger");
});
```

### API Error Handling

```javascript
async function safeApiCall(apiFunction, fallbackFunction) {
  try {
    return await apiFunction();
  } catch (error) {
    console.error("API call failed:", error);
    if (fallbackFunction) {
      return await fallbackFunction();
    }
    throw error;
  }
}
```

### Timeout Management

```javascript
function withTimeout(promise, timeoutMs) {
  return Promise.race([
    promise,
    new Promise((_, reject) =>
      setTimeout(() => reject(new Error("Operation timeout")), timeoutMs)
    ),
  ]);
}
```

## 📁 Code Structure

### File Organization

```
CyberGuardWeb/
├── index.html                 # Main application file
├── package.json              # Node.js dependencies
├── zap-proxy.js              # CORS proxy server
├── start-zap-xss.bat         # Windows startup script
├── stop-zap-xss.bat         # Windows shutdown script
├── README.md                # User documentation
├── TECHNICAL_DOCUMENTATION.md # Technical documentation
└── icons/                   # Application icons
    ├── DNS spoofing.png
    ├── hash.png
    ├── IP Geolocation.png
    ├── phishing.png
    ├── port scanner.png
    ├── ssl-tls.png
    ├── threat intelligence.png
    ├── web.png
    ├── WHOIS Lookup.png
    └── XSS.png
```

### JavaScript Architecture

```javascript
// Main application structure
document.addEventListener("DOMContentLoaded", () => {
  // Global variables
  let isRunning = false;
  let history = [];
  let virusTotalApiKey = "";
  let whoisApiKey = "";

  // Tool runner
  async function runTool(
    feature,
    toolFunction,
    inputProvider,
    validationMessage,
    buttonId
  ) {
    // Tool execution logic
  }

  // Individual tool implementations
  // - Port Scanner
  // - XSS Scanner
  // - Hash Tools
  // - Network Analysis
  // - Security Testing
});
```

### CSS Architecture

```css
/* Tailwind CSS framework */
@tailwind base;
@tailwind components;
@tailwind utilities;

/* Custom components */
.security-tool-card {
  @apply bg-white rounded-lg shadow-md p-6 border border-gray-200;
}

.progress-bar {
  @apply w-full bg-gray-200 rounded-full h-2.5;
}

.status-indicator {
  @apply inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium;
}
```

## 🔄 Development Workflow

### Local Development

1. **Setup**: Install dependencies with `npm install`
2. **Services**: Start ZAP and proxy server
3. **Testing**: Use browser developer tools
4. **Debugging**: Check console logs and network requests

### Production Deployment

1. **Build**: Optimize JavaScript and CSS
2. **Deploy**: Upload to web server
3. **Configure**: Set up API keys and services
4. **Monitor**: Check logs and performance

### Testing Strategy

- **Unit Tests**: Individual function testing
- **Integration Tests**: API integration testing
- **Security Tests**: Vulnerability scanning
- **Performance Tests**: Load and stress testing

---

This technical documentation provides comprehensive information about the CyberGuard Pro platform's architecture, implementation, and development practices. For user-facing documentation, refer to the main README.md file.

