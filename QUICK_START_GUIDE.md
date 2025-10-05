# 🚀 CyberGuard Pro - Quick Start Guide

## ⚡ 5-Minute Setup

### Step 1: Start Services

```bash
# Double-click this file:
start-zap-xss.bat
```

### Step 2: Open Application

- Open `index.html` in your web browser
- Wait for "CyberGuard Pro initialized successfully!" message

### Step 3: Test XSS Scanner

1. Go to **Web Security** tab
2. Enter URL: `https://httpbin.org`
3. Click **"XSS Test"** button
4. Watch real vulnerability scanning!

## 🛠️ Available Tools

### 🔍 Network Security

| Tool             | Purpose           | Input       | Output               |
| ---------------- | ----------------- | ----------- | -------------------- |
| **Port Scanner** | Scan open ports   | IP address  | Open ports, services |
| **TCP Scan**     | Test connectivity | IP address  | Connection status    |
| **DNS Analysis** | DNS record lookup | Domain name | DNS records          |

### 🌐 Web Security

| Tool               | Purpose                  | Input | Output               |
| ------------------ | ------------------------ | ----- | -------------------- |
| **XSS Test**       | Find XSS vulnerabilities | URL   | Vulnerability report |
| **SSL Check**      | Certificate validation   | URL   | SSL/TLS analysis     |
| **Phishing Check** | URL safety analysis      | URL   | Risk assessment      |

### 🔐 Hash Tools

| Tool               | Purpose       | Input      | Output                       |
| ------------------ | ------------- | ---------- | ---------------------------- |
| **Hash Generator** | Create hashes | Text       | MD5, SHA-1, SHA-256, SHA-512 |
| **Hash Cracker**   | Verify hashes | Hash value | Verification result          |

### 🌍 Intelligence

| Tool               | Purpose            | Input       | Output               |
| ------------------ | ------------------ | ----------- | -------------------- |
| **WHOIS Lookup**   | Domain information | Domain name | Registration details |
| **IP Geolocation** | Location tracking  | IP address  | Geographic data      |

## 🎯 Common Use Cases

### 1. Website Security Testing

```
1. Enter website URL
2. Click "XSS Test"
3. Review vulnerability report
4. Check SSL certificate
```

### 2. Network Scanning

```
1. Enter target IP
2. Click "Port Scanner"
3. Review open ports
4. Analyze services
```

### 3. Hash Verification

```
1. Enter text to hash
2. Select algorithm (SHA-256)
3. Click "Generate Hash"
4. Use "Hash Cracker" to verify
```

## ⚠️ Troubleshooting

### Problem: "OWASP ZAP not detected"

**Solution**:

1. Check if Docker is running
2. Run `start-zap-xss.bat` again
3. Wait 30-60 seconds for ZAP to start

### Problem: "NetworkError" or CORS issues

**Solution**:

1. Ensure proxy server is running (`npm start`)
2. Check if port 3001 is accessible
3. Restart both ZAP and proxy

### Problem: Scan stuck at "Monitoring progress"

**Solution**:

- Wait for 2.5 minute timeout
- Try smaller websites
- Use basic simulation mode

## 🔧 Configuration

### API Keys (Optional)

For enhanced features, add API keys:

1. **VirusTotal**: Get free key from [virustotal.com](https://www.virustotal.com/)
2. **WHOIS**: Get key from [whoisxmlapi.com](https://whoisxmlapi.com/)

### Browser Requirements

- **Chrome**: Recommended for best performance
- **Firefox**: Full compatibility
- **Edge**: Supported
- **Safari**: Basic functionality

## 📊 Understanding Results

### XSS Scanner Results

- ✅ **SECURE**: No vulnerabilities found
- ⚠️ **WARNING**: Potential issues detected
- ❌ **VULNERABILITY**: XSS vulnerabilities found
- 💡 **Recommendations**: Security improvements

### Port Scanner Results

- **Open Ports**: Services running on target
- **Service Detection**: Identified services and versions
- **Security Analysis**: Potential security issues

### Hash Analysis

- **Hash Generation**: Cryptographic hash values
- **Verification**: Hash comparison results
- **Security**: Hash strength analysis

## 🚀 Advanced Features

### Real-time Monitoring

- Live progress updates
- Status indicators
- Error reporting

### Security Recommendations

- Automated suggestions
- Best practices
- Compliance guidance

### Report Generation

- Detailed analysis
- Export functionality
- Historical tracking

## 🆘 Getting Help

### Quick Fixes

1. **Refresh page** if tools don't work
2. **Restart services** using batch files
3. **Check console** for error messages

### Common Commands

```bash
# Start everything
start-zap-xss.bat

# Stop everything
stop-zap-xss.bat

# Check Docker status
docker ps

# Check proxy status
curl http://localhost:3001/health
```

### Support Resources

- **Documentation**: README.md
- **Technical Docs**: TECHNICAL_DOCUMENTATION.md
- **Issues**: Create GitHub issue

## 🎉 Success Indicators

### ✅ Everything Working

- "CyberGuard Pro initialized successfully!"
- "OWASP ZAP detected via proxy"
- Real vulnerability scanning (not simulation)
- Progress updates during scans

### ⚠️ Partial Functionality

- "Running basic XSS simulation"
- Some tools work, others don't
- API connection issues

### ❌ Nothing Working

- "Please start the proxy server"
- No service connections
- Check Docker and Node.js installation

---

**Need more help?** Check the full documentation in README.md and TECHNICAL_DOCUMENTATION.md files! 🛡️
