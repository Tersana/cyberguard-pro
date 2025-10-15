# CyberGuard Pro - Functions & Technologies Documentation

## Overview

CyberGuard Pro is a comprehensive cybersecurity toolkit built with modern web technologies. This document provides detailed explanations of each function, the technologies used, and how they work together to provide advanced security analysis capabilities.

---

## 🛡️ Core Technologies Used

### Frontend Technologies

- **HTML5**: Modern semantic markup with accessibility features
- **CSS3**: Advanced styling with Tailwind CSS framework
- **JavaScript (ES6+)**: Modern JavaScript with async/await, classes, and modules
- **Tailwind CSS**: Utility-first CSS framework for responsive design
- **Framer Motion**: Animation library for smooth UI transitions

### Security & Cryptography Libraries

- **Crypto-JS**: Client-side encryption for API key storage
- **jsPDF**: PDF generation for report export
- **jsPDF-AutoTable**: Table generation in PDF reports

### External APIs & Services

- **Shodan API**: Network intelligence and port scanning
- **VirusTotal API**: Malware detection and threat intelligence
- **AbuseIPDB API**: IP reputation checking
- **WhoisXML API**: Domain and IP geolocation data
- **ipapi.co**: IP geolocation service
- **OWASP ZAP**: Web application security testing

---

## 🔧 Input Validation Functions

### `isValidIP(ip)`

**Purpose**: Validates IPv4 address format
**Technology**: Regular expressions
**Implementation**: Uses regex pattern to match valid IPv4 addresses (0.0.0.0 to 255.255.255.255)
**Usage**: Prevents invalid IP inputs and potential injection attacks

### `isValidDomain(domain)`

**Purpose**: Validates domain name format
**Technology**: Regular expressions
**Implementation**: Validates domain structure according to RFC standards
**Usage**: Ensures proper domain format for DNS lookups and WHOIS queries

### `isValidTarget(target)`

**Purpose**: Comprehensive target validation
**Technology**: XSS prevention and input sanitization
**Implementation**: Removes potentially dangerous characters and validates format
**Usage**: Primary validation function for all security tools

### `validateTargetInput(target, toolName)`

**Purpose**: User-friendly input validation with error messages
**Technology**: Input sanitization and user feedback
**Implementation**: Combines validation with helpful error messages
**Usage**: Provides real-time feedback to users during input

---

## 🔐 Security & Encryption Functions

### `encryptApiKey(key)`

**Purpose**: Encrypts API keys for secure storage
**Technology**: XOR encryption with Base64 encoding
**Implementation**: Simple but effective encryption for client-side storage
**Usage**: Protects sensitive API credentials from plain text storage

### `decryptApiKey(encryptedKey)`

**Purpose**: Decrypts stored API keys
**Technology**: XOR decryption with Base64 decoding
**Implementation**: Reverses the encryption process
**Usage**: Retrieves API keys for authenticated requests

### `maskApiKey(key)`

**Purpose**: Masks API keys for display purposes
**Technology**: String manipulation
**Implementation**: Shows only first 4 and last 4 characters
**Usage**: Secure display of API keys in UI

---

## 🌐 Network Analysis Functions

### `portScan(target)`

**Purpose**: Comprehensive port scanning using Shodan API
**Technology**: Shodan API, CORS proxy
**Implementation**:

- Uses Shodan's database of internet-connected devices
- Provides detailed service information, vulnerabilities, and banners
- Includes rate limiting and error handling
  **API Used**: Shodan API (`https://api.shodan.io`)
  **Features**:
- Open port detection
- Service identification
- Version detection
- Vulnerability assessment
- Banner grabbing
- Geographic location data

### `realTcpPortScan(target)`

**Purpose**: Real-time TCP connectivity testing
**Technology**: Fetch API, WebSocket connections
**Implementation**:

- Tests actual connectivity to common ports
- Uses HTTP/HTTPS requests for port 80/443
- WebSocket connections for real-time testing
- Includes timeout handling and error management
  **Features**:
- Real connectivity verification
- Response time measurement
- Service detection
- Timeout handling

### `realUdpConnectivityTest(target)`

**Purpose**: UDP connectivity testing
**Technology**: Custom UDP simulation
**Implementation**: Simulates UDP connections for common services
**Features**:

- UDP port testing
- Service identification
- Response time measurement

---

## 🗺️ Geolocation & DNS Functions

### `ipGeolocation(target)`

**Purpose**: IP address geolocation analysis
**Technology**: ipapi.co API
**Implementation**:

- Fetches comprehensive location data
- Includes ISP, organization, and threat intelligence
- Provides geographic coordinates and timezone
  **API Used**: ipapi.co (`https://ipapi.co/{ip}/json/`)
  **Features**:
- Country, region, city detection
- ISP and organization information
- Timezone and currency data
- Threat intelligence indicators

### `reverseDns(target)`

**Purpose**: Reverse DNS lookup
**Technology**: Browser DNS resolution
**Implementation**: Uses browser's built-in DNS resolution
**Features**:

- IP to hostname resolution
- Multiple hostname detection
- DNS record validation

### `whoisLookup(target)`

**Purpose**: WHOIS domain/IP information
**Technology**: WhoisXML API
**Implementation**:

- Comprehensive domain/IP registration data
- Includes registrar, creation date, expiration
- Geographic and contact information
  **API Used**: WhoisXML API (`https://ip-geolocation.whoisxmlapi.com/api/v1`)
  **Features**:
- Domain registration details
- IP geolocation data
- Registrar information
- Contact details (when available)

---

## 🚨 Threat Intelligence Functions

### `threatIntelCheck(target)`

**Purpose**: Multi-source threat intelligence analysis
**Technology**: VirusTotal API, AbuseIPDB API
**Implementation**:

- Checks URLs against VirusTotal database
- Analyzes IP reputation with AbuseIPDB
- Provides comprehensive threat assessment
  **APIs Used**:
- VirusTotal API (`https://www.virustotal.com/api/v3`)
- AbuseIPDB API (`https://api.abuseipdb.com/api/v2`)
  **Features**:
- Malware detection
- Reputation scoring
- Historical abuse data
- Multi-engine analysis

---

## 🦠 VirusTotal Integration Functions

### `scanHashVirusTotal(hash)`

**Purpose**: File hash analysis using VirusTotal
**Technology**: VirusTotal API
**Implementation**: Checks file hashes against VirusTotal's malware database
**Features**:

- SHA256/MD5 hash analysis
- Multi-engine malware detection
- Detailed scan results
- Historical analysis data

### `scanUrlVirusTotal(url)`

**Purpose**: URL analysis using VirusTotal
**Technology**: VirusTotal API
**Implementation**: Submits URLs for analysis and retrieves results
**Features**:

- URL reputation checking
- Phishing detection
- Malware URL identification
- Community feedback integration

### `scanFileVirusTotal(file)`

**Purpose**: File upload and analysis
**Technology**: VirusTotal API, File API
**Implementation**: Uploads files for comprehensive malware analysis
**Features**:

- File upload and scanning
- Real-time analysis results
- Detailed threat reports
- File type identification

---

## 🎣 Phishing Detection Functions

### `loadPhishingModel()`

**Purpose**: Loads machine learning model for phishing detection
**Technology**: Custom ML model, TensorFlow.js
**Implementation**: Loads pre-trained model for URL analysis
**Features**:

- Machine learning-based detection
- Feature extraction from URLs
- Probability scoring
- Pattern recognition

### `extractURLFeatures(url)`

**Purpose**: Extracts features from URLs for ML analysis
**Technology**: URL parsing, pattern recognition
**Implementation**: Analyzes URL structure and content for suspicious patterns
**Features**:

- Domain analysis
- Path examination
- Parameter inspection
- Character substitution detection

### `detectPhishing(url)`

**Purpose**: Main phishing detection function
**Technology**: Machine learning, pattern analysis
**Implementation**:

- Uses ML model to analyze URL features
- Provides risk assessment and recommendations
- Generates detailed security reports
  **Features**:
- Risk level assessment
- Suspicious pattern detection
- Security recommendations
- Detailed analysis reports

---

## 🔒 Web Security Testing Functions

### `testXss(url)`

**Purpose**: Cross-Site Scripting (XSS) vulnerability testing
**Technology**: OWASP ZAP API, custom XSS simulation
**Implementation**:

- Uses OWASP ZAP for comprehensive XSS testing
- Includes custom payload testing
- Monitors scan progress and results
  **API Used**: OWASP ZAP API (`http://localhost:8080/JSON`)
  **Features**:
- Automated XSS scanning
- Custom payload testing
- Real-time progress monitoring
- Detailed vulnerability reports

### `checkSsl(url)`

**Purpose**: SSL/TLS certificate analysis
**Technology**: Browser security APIs
**Implementation**: Analyzes SSL certificates and security configurations
**Features**:

- Certificate validation
- Encryption strength analysis
- Expiration date checking
- Security configuration review

### `checkDnsSpoof(url)`

**Purpose**: DNS spoofing detection
**Technology**: DNS analysis, machine learning
**Implementation**:

- Analyzes DNS records for inconsistencies
- Detects potential DNS hijacking
- Uses ML model for pattern recognition
  **Features**:
- DNS record validation
- Spoofing detection
- Historical DNS analysis
- Threat assessment

---

## 🔐 Hash & Cryptography Functions

### `analyzePassword(pwd)`

**Purpose**: Password strength analysis
**Technology**: Password complexity algorithms
**Implementation**:

- Analyzes password complexity
- Checks against common patterns
- Provides security recommendations
  **Features**:
- Strength scoring
- Pattern analysis
- Security recommendations
- Entropy calculation

---

## 📊 Data Management Functions

### `saveSession(sessionName)`

**Purpose**: Saves analysis session data
**Technology**: Local storage, JSON serialization
**Implementation**: Stores session data for later retrieval
**Features**:

- Session persistence
- Data encryption
- Export capabilities
- Session management

### `loadSession()`

**Purpose**: Loads saved session data
**Technology**: Local storage, JSON parsing
**Implementation**: Retrieves and restores session data
**Features**:

- Session restoration
- Data validation
- Error handling
- User interface updates

### `exportResults()`

**Purpose**: Exports analysis results
**Technology**: jsPDF, CSV generation
**Implementation**: Creates downloadable reports in multiple formats
**Features**:

- PDF report generation
- CSV data export
- Formatted output
- Professional reporting

---

## 🎨 User Interface Functions

### `applyTheme(theme)`

**Purpose**: Applies dark/light theme
**Technology**: CSS classes, localStorage
**Implementation**: Manages theme switching and persistence
**Features**:

- Theme persistence
- Smooth transitions
- User preference storage
- Accessibility support

### `showProgressBar()` / `hideProgressBar()`

**Purpose**: Progress indication during operations
**Technology**: CSS animations, DOM manipulation
**Implementation**: Shows/hides loading indicators
**Features**:

- Visual feedback
- Progress indication
- User experience enhancement

### `logResult(timestamp, feature, message, status)`

**Purpose**: Logs analysis results
**Technology**: DOM manipulation, CSS styling
**Implementation**: Creates formatted log entries with status indicators
**Features**:

- Timestamped logging
- Status categorization
- Formatted output
- Real-time updates

---

## 🔧 Utility Functions

### `runTool(toolName, toolFunction, getTarget, errorMessage, buttonId)`

**Purpose**: Generic tool execution wrapper
**Technology**: Async/await, error handling
**Implementation**: Provides consistent tool execution with error handling
**Features**:

- Input validation
- Error handling
- Progress indication
- Result logging

### `updateStatus(message)`

**Purpose**: Updates status bar with current operation
**Technology**: DOM manipulation
**Implementation**: Provides real-time status updates
**Features**:

- Real-time updates
- User feedback
- Operation tracking

---

## 🚀 Advanced Features

### Machine Learning Integration

- **Phishing Detection**: Custom ML model for URL analysis
- **Pattern Recognition**: Advanced algorithms for threat detection
- **Feature Extraction**: Automated analysis of security indicators

### Real-time Analysis

- **Live Scanning**: Real-time port and service detection
- **Progress Monitoring**: Live updates during long operations
- **Interactive Results**: Dynamic result presentation

### Security Best Practices

- **Input Validation**: Comprehensive input sanitization
- **XSS Prevention**: Protection against cross-site scripting
- **API Key Encryption**: Secure storage of sensitive credentials
- **Rate Limiting**: Respect for API rate limits

---

## 📈 Performance Optimizations

### Caching

- **Model Caching**: ML models cached for faster subsequent use
- **Result Caching**: Analysis results cached to avoid redundant requests
- **Session Persistence**: User sessions saved for continuity

### Error Handling

- **Graceful Degradation**: Fallback options when APIs fail
- **User Feedback**: Clear error messages and recovery options
- **Retry Logic**: Automatic retry for transient failures

### Security Considerations

- **CORS Handling**: Proper cross-origin request management
- **API Key Security**: Encrypted storage and secure transmission
- **Input Sanitization**: Protection against injection attacks

---

## 🔗 API Integrations Summary

| Service        | Purpose              | Key Features                                               |
| -------------- | -------------------- | ---------------------------------------------------------- |
| **Shodan**     | Network Intelligence | Port scanning, service detection, vulnerability assessment |
| **VirusTotal** | Threat Intelligence  | Malware detection, URL analysis, file scanning             |
| **AbuseIPDB**  | IP Reputation        | Abuse scoring, historical data, community reports          |
| **WhoisXML**   | Domain Intelligence  | Registration data, geolocation, contact information        |
| **ipapi.co**   | IP Geolocation       | Location data, ISP information, timezone details           |
| **OWASP ZAP**  | Web Security         | XSS testing, vulnerability scanning, security assessment   |

---

## 🛠️ Development Notes

### Code Architecture

- **Modular Design**: Functions organized by purpose and functionality
- **Async/Await**: Modern JavaScript patterns for API calls
- **Error Handling**: Comprehensive error management throughout
- **User Experience**: Intuitive interface with real-time feedback

### Security Implementation

- **Client-Side Security**: Encryption and validation on the client
- **API Security**: Secure API key management and transmission
- **Input Validation**: Multi-layer input sanitization and validation
- **XSS Prevention**: Protection against cross-site scripting attacks

### Performance Features

- **Rate Limiting**: Respect for external API rate limits
- **Caching**: Intelligent caching for improved performance
- **Progress Indication**: Real-time feedback for long operations
- **Session Management**: Persistent user sessions and data

---

This documentation provides a comprehensive overview of all functions and technologies used in CyberGuard Pro, making it easy to understand the codebase and its capabilities.
