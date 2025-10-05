# 🧪 CyberGuard Pro - Security Functions Testing Guide

## 📋 Overview

This guide provides real-world testing examples for every security function in your CyberGuard Pro application. Test all the cybersecurity tools to ensure they work correctly.

## 🚀 Quick Start Testing

### 1. Start Your Application

```bash
# Start Frontend Server
cd D:\Code\CyberGuardWeb
http-server -p 3000
```

### 2. Access Your Application

- **CyberGuard Pro:** http://localhost:3000
- **Test all security functions** using the examples below

---

## 🔍 Network Security Testing

### Test 1: Port Scanner

#### Scenario: Scan Common Ports

**Test Target:** `8.8.8.8` (Google DNS)
**Steps:**

1. Go to **Network** tab
2. Enter target: `8.8.8.8`
3. Select "Common ports" mode
4. Click **Port Scanner**

**Expected Results:**

- ✅ Port 53 (DNS) should be open
- ✅ Port 80 (HTTP) might be open
- ✅ Port 443 (HTTPS) might be open
- ✅ Service detection shows correct services
- ✅ Response times are reasonable

#### Scenario: Custom Port Range

**Test Target:** `127.0.0.1` (Localhost)
**Steps:**

1. Enter target: `127.0.0.1`
2. Select "Specific ports/range" mode
3. Enter ports: `22,80,443,3000,8080`
4. Click **Port Scanner**

**Expected Results:**

- ✅ Local ports show as open/closed
- ✅ Web server ports (80, 443) detected
- ✅ Development ports (3000, 8080) detected

### Test 2: TCP Port Scan

#### Scenario: Deep TCP Analysis

**Test Target:** `google.com`
**Steps:**

1. Enter target: `google.com`
2. Click **TCP Port Scan**
3. Wait for completion

**Expected Results:**

- ✅ HTTP ports (80, 443) detected
- ✅ Service banners captured
- ✅ Response times measured
- ✅ Protocol detection working

### Test 3: UDP Port Scan

#### Scenario: UDP Service Detection

**Test Target:** `8.8.8.8`
**Steps:**

1. Enter target: `8.8.8.8`
2. Click **UDP Port Scan**
3. Monitor results

**Expected Results:**

- ✅ DNS port 53 detected
- ✅ NTP port 123 might be detected
- ✅ UDP-specific services identified

### Test 4: Reverse DNS Lookup

#### Scenario: IP to Hostname Resolution

**Test Data:**

- `8.8.8.8` → Should resolve to `dns.google`
- `1.1.1.1` → Should resolve to `one.one.one.one`
- `208.67.222.222` → Should resolve to `resolver2.opendns.com`

**Steps:**

1. Enter IP address
2. Click **Reverse DNS**

**Expected Results:**

- ✅ Correct hostname resolution
- ✅ Multiple hostnames if available
- ✅ PTR record information

### Test 5: IP Geolocation

#### Scenario: Location Analysis

**Test Data:**

- `8.8.8.8` → Should show US location
- `1.1.1.1` → Should show US location
- `114.114.114.114` → Should show China location

**Steps:**

1. Enter IP address
2. Click **IP Geolocation**

**Expected Results:**

- ✅ Country, region, city information
- ✅ ISP details
- ✅ Timezone information
- ✅ Coordinates (latitude/longitude)

### Test 6: WHOIS Lookup

#### Scenario: Domain Information

**Test Data:**

- `google.com`
- `github.com`
- `stackoverflow.com`

**Steps:**

1. Enter domain name
2. Click **WHOIS Lookup**

**Expected Results:**

- ✅ Registrar information
- ✅ Creation/expiration dates
- ✅ Name servers
- ✅ Contact information (if available)

### Test 7: Threat Intelligence

#### Scenario: Security Analysis

**Test Data:**

- `malware.com` (known malicious)
- `google.com` (legitimate)
- `suspicious-site.com` (test domain)

**Steps:**

1. Enter IP/domain
2. Click **Threat Intelligence**

**Expected Results:**

- ✅ Reputation score
- ✅ Threat indicators
- ✅ Security recommendations
- ✅ Historical data

---

## 🌐 Web Security Testing

### Test 8: URL Phishing Analyzer

#### Scenario: Phishing Detection

**Test Data:**

- `https://google.com` (legitimate)
- `https://g00gle.com` (suspicious)
- `https://paypal-security.com` (likely phishing)

**Steps:**

1. Go to **Web** tab
2. Enter URL
3. Click **URL Phishing Analyzer**

**Expected Results:**

- ✅ Legitimate sites marked as safe
- ✅ Suspicious domains flagged
- ✅ Phishing indicators identified
- ✅ Risk score provided

### Test 9: XSS Test

#### Scenario: Cross-Site Scripting Detection

**Test Data:**

- `https://httpbin.org/get` (test site)
- `https://example.com` (basic site)
- `https://xss-game.appspot.com` (XSS test site)

**Steps:**

1. Enter target URL
2. Click **XSS Test**
3. Wait for scan completion

**Expected Results:**

- ✅ XSS vulnerabilities detected
- ✅ Security recommendations provided
- ✅ Risk assessment completed
- ✅ Detailed vulnerability report

### Test 10: SSL/TLS Check

#### Scenario: Certificate Analysis

**Test Data:**

- `https://google.com` (valid SSL)
- `https://badssl.com` (test certificates)
- `http://example.com` (no SSL)

**Steps:**

1. Enter URL
2. Click **SSL/TLS Check**

**Expected Results:**

- ✅ Valid certificates marked as secure
- ✅ Expired certificates flagged
- ✅ Certificate chain analysis
- ✅ Security grade provided

### Test 11: DNS Spoofing Detection

#### Scenario: DNS Security Analysis

**Test Data:**

- `google.com` (legitimate)
- `facebook.com` (legitimate)
- `suspicious-domain.com` (test)

**Steps:**

1. Enter domain
2. Click **DNS Spoofing**

**Expected Results:**

- ✅ DNSSEC status checked
- ✅ DNS consistency verified
- ✅ Spoofing indicators identified
- ✅ Security recommendations

---

## 🦠 VirusTotal Integration Testing

### Test 12: URL Scanning

#### Scenario: Malicious URL Detection

**Test Data:**

- `https://google.com` (clean)
- `https://malware.com` (if available)
- `https://suspicious-site.com` (test)

**Steps:**

1. Go to **Web** tab
2. Enter URL in VirusTotal section
3. Click **Scan URL**

**Expected Results:**

- ✅ Clean URLs marked as safe
- ✅ Malicious URLs flagged
- ✅ Scan results from multiple engines
- ✅ Detection ratio provided

### Test 13: Hash Analysis

#### Scenario: File Hash Checking

**Test Data:**

- Known good file hash
- Known malicious file hash
- Random hash for testing

**Steps:**

1. Enter file hash (SHA256/MD5)
2. Click **Check Hash**

**Expected Results:**

- ✅ Clean hashes marked as safe
- ✅ Malicious hashes flagged
- ✅ Detection engines results
- ✅ File reputation score

### Test 14: File Scanning

#### Scenario: File Upload Analysis

**Test Data:**

- Clean text file
- Suspicious executable (if available)
- Image file

**Steps:**

1. Select file to upload
2. Click **Scan File**

**Expected Results:**

- ✅ Clean files marked as safe
- ✅ Suspicious files flagged
- ✅ File type analysis
- ✅ Threat detection results

---

## 🔐 Hash & Cryptography Testing

### Test 15: Text Hashing

#### Scenario: Hash Generation

**Test Data:**

- `"Hello World"`
- `"Password123"`
- `"CyberGuard Pro"`

**Steps:**

1. Go to **Hash** tab
2. Enter text
3. Click **Generate Hashes**

**Expected Results:**

- ✅ MD5 hash generated
- ✅ SHA1 hash generated
- ✅ SHA256 hash generated
- ✅ SHA512 hash generated
- ✅ All hashes are consistent

### Test 16: File Hashing

#### Scenario: File Hash Generation

**Test Data:**

- Small text file
- Image file
- Document file

**Steps:**

1. Select file
2. Wait for hash generation

**Expected Results:**

- ✅ File hashes generated
- ✅ Hash values are consistent
- ✅ Different files produce different hashes
- ✅ Same file produces same hash

### Test 17: Password Strength Analysis

#### Scenario: Password Security Testing

**Test Data:**

- `"password"` (weak)
- `"Password123!"` (medium)
- `"MyStr0ng!P@ssw0rd2024"` (strong)

**Steps:**

1. Enter password
2. Click **Analyze Password**

**Expected Results:**

- ✅ Weak passwords flagged
- ✅ Strong passwords praised
- ✅ Security recommendations
- ✅ Strength score provided

---

## 📊 Advanced Testing Scenarios

### Test 18: Comprehensive Security Audit

#### Scenario: Full Website Analysis

**Test Target:** `https://httpbin.org`
**Steps:**

1. **Port Scan:** Check for open ports
2. **SSL Check:** Verify certificate
3. **XSS Test:** Scan for vulnerabilities
4. **DNS Check:** Verify DNS security
5. **Threat Intel:** Check reputation

**Expected Results:**

- ✅ All tests complete successfully
- ✅ Security report generated
- ✅ Vulnerabilities identified
- ✅ Recommendations provided

### Test 19: Performance Testing

#### Scenario: Large Scale Scanning

**Test Data:**

- Multiple IP addresses
- Large port ranges
- Multiple URLs

**Steps:**

1. Test with 100+ ports
2. Test with multiple targets
3. Monitor performance

**Expected Results:**

- ✅ Scans complete in reasonable time
- ✅ No crashes or errors
- ✅ Results are accurate
- ✅ UI remains responsive

### Test 20: Error Handling

#### Scenario: Invalid Input Testing

**Test Data:**

- Invalid IP addresses
- Malformed URLs
- Non-existent domains
- Empty inputs

**Steps:**

1. Enter invalid data
2. Test error handling

**Expected Results:**

- ✅ Graceful error messages
- ✅ No application crashes
- ✅ User-friendly feedback
- ✅ Proper validation

---

## 🎯 Real-World Test Cases

### Test Case 1: Corporate Network Assessment

**Scenario:** Test a corporate network
**Target:** `company.com`
**Tests:**

- Port scan for open services
- SSL certificate validation
- DNS security check
- Threat intelligence lookup

### Test Case 2: Personal Website Security

**Scenario:** Test personal website
**Target:** `your-website.com`
**Tests:**

- XSS vulnerability scan
- SSL/TLS configuration
- DNS spoofing protection
- Overall security posture

### Test Case 3: Suspicious Activity Investigation

**Scenario:** Investigate suspicious domain
**Target:** `suspicious-domain.com`
**Tests:**

- Threat intelligence analysis
- DNS reputation check
- Port scanning for services
- SSL certificate analysis

---

## 📝 Testing Checklist

### ✅ Network Security Tests

- [ ] Port scanning works correctly
- [ ] TCP/UDP scans function
- [ ] Reverse DNS lookup accurate
- [ ] IP geolocation correct
- [ ] WHOIS data complete
- [ ] Threat intelligence functional

### ✅ Web Security Tests

- [ ] Phishing detection accurate
- [ ] XSS testing comprehensive
- [ ] SSL/TLS analysis detailed
- [ ] DNS spoofing detection works
- [ ] VirusTotal integration functional

### ✅ Hash & Crypto Tests

- [ ] Text hashing generates correct values
- [ ] File hashing works properly
- [ ] Password analysis accurate
- [ ] Hash algorithms consistent

### ✅ Performance Tests

- [ ] Large scans complete successfully
- [ ] Multiple targets handled
- [ ] UI remains responsive
- [ ] No memory leaks

### ✅ Error Handling Tests

- [ ] Invalid inputs handled gracefully
- [ ] Error messages clear
- [ ] No application crashes
- [ ] Proper validation

---

## 🚀 Quick Test Commands

### Test Port Scanner

```javascript
// Open browser console and run:
document.getElementById("target-ip").value = "8.8.8.8";
document.getElementById("port-scan-btn").click();
```

### Test XSS Scanner

```javascript
// Open browser console and run:
document.getElementById("target-url").value = "https://httpbin.org/get";
document.getElementById("xss-btn").click();
```

### Test SSL Check

```javascript
// Open browser console and run:
document.getElementById("target-url").value = "https://google.com";
document.getElementById("ssl-btn").click();
```

---

## 🎯 Success Criteria

### ✅ All Functions Working

- **Port Scanner:** Detects open ports accurately
- **XSS Test:** Identifies vulnerabilities correctly
- **SSL Check:** Validates certificates properly
- **DNS Analysis:** Detects spoofing attempts
- **Hash Tools:** Generate consistent hashes
- **Threat Intel:** Provides accurate reputation data

### ✅ Performance Standards

- **Scan Speed:** Port scans complete in <30 seconds
- **Accuracy:** Results match expected outcomes
- **Reliability:** No crashes or errors
- **Usability:** Clear, intuitive interface

---

## 📞 Troubleshooting

### Common Issues:

1. **Port scans timeout:** Check network connectivity
2. **XSS tests fail:** Verify target URL is accessible
3. **SSL checks fail:** Ensure HTTPS URLs are used
4. **Hash generation slow:** Large files may take time
5. **API errors:** Check API keys are configured

### Solutions:

1. **Test with localhost first**
2. **Use known good URLs**
3. **Verify API key configuration**
4. **Check browser console for errors**
5. **Restart the application if needed**

**Happy Testing! 🎉**

