# 🛡️ CyberGuard Pro - Comprehensive Cybersecurity Analysis Platform

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Technologies Used](#technologies-used)
- [Installation & Setup](#installation--setup)
- [Usage Guide](#usage-guide)
- [API Integrations](#api-integrations)
- [Security Tools](#security-tools)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)

## 🎯 Overview

CyberGuard Pro is a comprehensive web-based cybersecurity analysis platform that provides real-time security scanning, vulnerability assessment, and threat intelligence. The application combines multiple security tools and APIs to deliver professional-grade security analysis in a user-friendly interface.

### Key Capabilities

- **Real-time vulnerability scanning** using OWASP ZAP
- **Network security analysis** with port scanning and service detection
- **Web application security testing** including XSS detection
- **Threat intelligence** with VirusTotal and WHOIS integration
- **Hash analysis** and cryptographic operations
- **DNS security** and geolocation analysis
- **SSL/TLS certificate validation**

## 🚀 Features

### 🔍 Network Security Tools

- **Port Scanner**: Comprehensive port scanning with service detection
- **TCP Connectivity Testing**: Real TCP connection validation
- **Service Detection**: Advanced service and version identification
- **Network Mapping**: Visual network topology analysis

### 🌐 Web Security Tools

- **XSS Vulnerability Scanner**: Real OWASP ZAP integration
- **SSL/TLS Certificate Analysis**: Certificate validation and security assessment
- **URL Phishing Detection**: AI-powered phishing URL analysis
- **Web Application Security Testing**: Comprehensive web app vulnerability scanning

### 🔐 Cryptographic Tools

- **Hash Analysis**: MD5, SHA-1, SHA-256, SHA-512 hash generation and verification
- **Hash Cracking**: Integration with online hash databases
- **Password Security**: Password strength analysis and recommendations

### 🌍 Intelligence & Analysis

- **WHOIS Lookup**: Domain registration and ownership information
- **IP Geolocation**: Geographic location and ISP information
- **DNS Analysis**: DNS record analysis and security assessment
- **Threat Intelligence**: VirusTotal integration for malware detection

## 🛠️ Technologies Used

### Frontend Technologies

- **HTML5**: Semantic markup and modern web standards
- **CSS3**: Advanced styling with Tailwind CSS framework
- **JavaScript (ES6+)**: Modern JavaScript with async/await patterns
- **Web APIs**: Fetch API, WebSocket API, Geolocation API
- **Responsive Design**: Mobile-first responsive design approach

### Backend & Integration Technologies

- **Node.js**: JavaScript runtime for proxy server
- **Express.js**: Web framework for API proxy
- **Docker**: Containerization for OWASP ZAP
- **REST APIs**: RESTful API integration and consumption

### Security Technologies

- **OWASP ZAP**: Industry-standard web application security scanner
- **VirusTotal API**: Malware detection and threat intelligence
- **WHOIS API**: Domain registration information
- **SSL/TLS**: Cryptographic protocol analysis
- **Hash Algorithms**: MD5, SHA-1, SHA-256, SHA-512

### Development Tools

- **Git**: Version control
- **npm**: Package management
- **Docker**: Container orchestration
- **PowerShell**: Windows automation scripts

## 📦 Installation & Setup

### Prerequisites

- **Node.js** (v14 or higher)
- **Docker** (for OWASP ZAP)
- **Modern web browser** (Chrome, Firefox, Edge, Safari)
- **Internet connection** (for API integrations)

### Quick Start

1. **Clone the repository**

   ```bash
   git clone <repository-url>
   cd CyberGuardWeb
   ```

2. **Install dependencies**

   ```bash
   npm install
   ```

3. **Start the services**

   ```bash
   # Option 1: Use the automated startup script
   start-zap-xss.bat

   # Option 2: Manual setup
   # Start ZAP
   docker run -d -p 8080:8080 -i zaproxy/zap-stable zap.sh -daemon -host 0.0.0.0 -port 8080 -config api.disablekey=true -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true

   # Start proxy server
   npm start
   ```

4. **Open the application**
   - Navigate to `index.html` in your web browser
   - The application will automatically detect and connect to services

### Configuration

#### API Keys (Optional)

For enhanced functionality, configure API keys in the application:

- **VirusTotal API**: Get free API key from [VirusTotal](https://www.virustotal.com/)
- **WHOIS API**: Get API key from [WhoisXML](https://whoisxmlapi.com/)

## 📖 Usage Guide

### Network Security Analysis

#### Port Scanning

1. Navigate to the **Network Tools** tab
2. Enter target IP address or hostname
3. Click **"Port Scanner"** button
4. Review scan results and open ports

#### TCP Connectivity Testing

1. Enter target IP address
2. Click **"TCP Port Scan"** button
3. View real connectivity test results

### Web Security Testing

#### XSS Vulnerability Scanning

1. Navigate to **Web Security** tab
2. Enter target URL (e.g., `https://example.com`)
3. Click **"XSS Test"** button
4. Monitor real-time scan progress
5. Review vulnerability report

#### SSL/TLS Analysis

1. Enter target URL
2. Click **"SSL/TLS Check"** button
3. Review certificate information and security recommendations

### Cryptographic Operations

#### Hash Analysis

1. Navigate to **Hash Tools** tab
2. Enter text or file for hashing
3. Select hash algorithm (MD5, SHA-1, SHA-256, SHA-512)
4. Click **"Generate Hash"** button
5. Use **"Hash Cracker"** for hash verification

### Intelligence Gathering

#### WHOIS Lookup

1. Enter domain name
2. Click **"WHOIS Lookup"** button
3. Review domain registration information

#### IP Geolocation

1. Enter IP address
2. Click **"IP Geolocation"** button
3. View geographic and ISP information

## 🔌 API Integrations

### OWASP ZAP Integration

- **Purpose**: Real vulnerability scanning
- **API Endpoints**: `/JSON/ascan/`, `/JSON/core/`, `/JSON/alert/`
- **Features**: Active scanning, vulnerability detection, report generation
- **Configuration**: CORS proxy on port 3001

### VirusTotal Integration

- **Purpose**: Malware detection and threat intelligence
- **API**: VirusTotal Public API v2.1
- **Features**: File scanning, URL analysis, domain reputation
- **Rate Limits**: 4 requests/minute (free tier)

### WHOIS Integration

- **Purpose**: Domain registration information
- **API**: WhoisXML API
- **Features**: Domain lookup, ownership details, registration history
- **Rate Limits**: Varies by subscription

### Browser APIs

- **Fetch API**: HTTP requests and API communication
- **WebSocket API**: Real-time communication
- **Geolocation API**: IP-based location services
- **Crypto API**: Cryptographic operations

## 🛡️ Security Tools

### Port Scanner Engine

```javascript
// Advanced port scanning with multiple detection methods
class PortScanner {
  async scanPorts(ports) {
    // HTTP/HTTPS detection
    // WebSocket detection
    // Service-specific detection
    // Resource loading detection
  }
}
```

### XSS Scanner (OWASP ZAP Integration)

```javascript
// Real vulnerability scanning with OWASP ZAP
async function testXss(url) {
  // ZAP API integration
  // Progress monitoring
  // Vulnerability reporting
  // Security recommendations
}
```

### Hash Analysis Engine

```javascript
// Cryptographic hash operations
async function generateHash(text, algorithm) {
  // MD5, SHA-1, SHA-256, SHA-512
  // Hash verification
  // Online hash database lookup
}
```

### Network Security Analysis

```javascript
// Comprehensive network scanning
class NetworkAnalyzer {
  // Port scanning
  // Service detection
  // Vulnerability assessment
  // Security recommendations
}
```

## 🔧 Troubleshooting

### Common Issues

#### ZAP Connection Issues

**Problem**: "OWASP ZAP not detected"
**Solution**:

1. Ensure Docker is running
2. Start ZAP with correct configuration
3. Check proxy server status

#### CORS Errors

**Problem**: "NetworkError when attempting to fetch resource"
**Solution**:

1. Use the provided proxy server
2. Ensure proxy is running on port 3001
3. Check ZAP configuration

#### API Key Issues

**Problem**: API requests failing
**Solution**:

1. Verify API keys are correctly configured
2. Check rate limits
3. Ensure internet connectivity

### Performance Optimization

#### Scan Timeout Issues

- **Default timeout**: 2.5 minutes
- **Stuck scan detection**: Automatic timeout
- **Progress monitoring**: Real-time updates
- **Fallback mechanisms**: Simulation mode

#### Resource Management

- **Memory usage**: Optimized for browser limits
- **Network requests**: Rate-limited API calls
- **Error handling**: Graceful degradation

## 📊 System Architecture

### Frontend Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   User Interface │    │  Security Tools │    │  API Integration │
│   (HTML/CSS/JS)  │◄──►│   (JavaScript)   │◄──►│   (REST APIs)   │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

### Backend Services

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  Proxy Server   │    │   OWASP ZAP     │    │  External APIs  │
│   (Node.js)     │◄──►│   (Docker)      │◄──►│ (VirusTotal, etc)│
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## 🚀 Advanced Features

### Real-time Monitoring

- **Progress tracking**: Live scan progress updates
- **Status indicators**: Visual progress bars and status messages
- **Error reporting**: Detailed error messages and solutions

### Security Recommendations

- **Automated suggestions**: Security best practices
- **Vulnerability remediation**: Step-by-step fix instructions
- **Compliance guidance**: Industry standard recommendations

### Report Generation

- **Comprehensive reports**: Detailed security analysis
- **Export functionality**: Save results for documentation
- **Historical tracking**: Session history and saved results

## 🤝 Contributing

### Development Setup

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

### Code Standards

- **JavaScript**: ES6+ syntax
- **CSS**: Tailwind CSS framework
- **HTML**: Semantic markup
- **Documentation**: Comprehensive comments

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

For support and questions:

- **Documentation**: Check this README
- **Issues**: Create GitHub issues
- **Community**: Join our discussion forums

## 🔄 Updates & Maintenance

### Regular Updates

- **Security patches**: Regular security updates
- **Feature additions**: New security tools and capabilities
- **API updates**: Integration with latest security APIs
- **Performance improvements**: Optimization and bug fixes

### Version History

- **v1.0.0**: Initial release with basic security tools
- **v1.1.0**: Added OWASP ZAP integration
- **v1.2.0**: Enhanced XSS scanning capabilities
- **v1.3.0**: Improved timeout handling and error management

---

**CyberGuard Pro** - Your comprehensive cybersecurity analysis platform 🛡️

