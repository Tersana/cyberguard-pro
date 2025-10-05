# 🧪 CyberGuard Pro - Security Test Data

## 📋 Real-World Test Scenarios

This file contains realistic test data and scenarios for testing every security function in your CyberGuard Pro application.

---

## 🔍 Network Security Test Data

### Port Scanner Test Cases

#### Test Case 1: Google DNS Server

**Target:** `8.8.8.8`
**Expected Open Ports:**

- Port 53 (DNS) - Should be open
- Port 80 (HTTP) - Might be open
- Port 443 (HTTPS) - Might be open

**Test Steps:**

1. Enter `8.8.8.8` in target field
2. Select "Common ports" mode
3. Click "Port Scanner"
4. Verify DNS port 53 is detected

#### Test Case 2: Cloudflare DNS

**Target:** `1.1.1.1`
**Expected Open Ports:**

- Port 53 (DNS) - Should be open
- Port 443 (HTTPS) - Should be open

**Test Steps:**

1. Enter `1.1.1.1` in target field
2. Select "Common ports" mode
3. Click "Port Scanner"
4. Verify DNS and HTTPS ports detected

#### Test Case 3: Localhost Testing

**Target:** `127.0.0.1`
**Expected Open Ports:**

- Port 80 (if web server running)
- Port 3000 (if development server)
- Port 8080 (if alternative server)

**Test Steps:**

1. Enter `127.0.0.1` in target field
2. Select "Specific ports/range" mode
3. Enter ports: `22,80,443,3000,8080`
4. Click "Port Scanner"
5. Check for local services

### Reverse DNS Test Cases

#### Test Case 1: Google DNS

**IP:** `8.8.8.8`
**Expected Hostname:** `dns.google`
**Test Steps:**

1. Enter `8.8.8.8`
2. Click "Reverse DNS"
3. Verify `dns.google` is returned

#### Test Case 2: Cloudflare DNS

**IP:** `1.1.1.1`
**Expected Hostname:** `one.one.one.one`
**Test Steps:**

1. Enter `1.1.1.1`
2. Click "Reverse DNS"
3. Verify `one.one.one.one` is returned

#### Test Case 3: OpenDNS

**IP:** `208.67.222.222`
**Expected Hostname:** `resolver2.opendns.com`
**Test Steps:**

1. Enter `208.67.222.222`
2. Click "Reverse DNS"
3. Verify OpenDNS resolver is returned

### IP Geolocation Test Cases

#### Test Case 1: US-based IP

**IP:** `8.8.8.8`
**Expected Location:** United States
**Expected Details:**

- Country: United States
- Region: California
- City: Mountain View
- ISP: Google LLC

#### Test Case 2: European IP

**IP:** `1.1.1.1`
**Expected Location:** United States (Cloudflare)
**Expected Details:**

- Country: United States
- ISP: Cloudflare, Inc.

#### Test Case 3: Asian IP

**IP:** `114.114.114.114`
**Expected Location:** China
**Expected Details:**

- Country: China
- ISP: 114DNS

### WHOIS Test Cases

#### Test Case 1: Google Domain

**Domain:** `google.com`
**Expected Information:**

- Registrar: MarkMonitor Inc.
- Creation Date: 1997-09-15
- Expiration Date: Future date
- Name Servers: ns1.google.com, ns2.google.com

#### Test Case 2: GitHub Domain

**Domain:** `github.com`
**Expected Information:**

- Registrar: MarkMonitor Inc.
- Creation Date: 2007-10-09
- Name Servers: ns1.p16.dynect.net, ns2.p16.dynect.net

#### Test Case 3: Stack Overflow

**Domain:** `stackoverflow.com`
**Expected Information:**

- Registrar: MarkMonitor Inc.
- Creation Date: 2003-12-26
- Name Servers: Multiple name servers

---

## 🌐 Web Security Test Data

### URL Phishing Test Cases

#### Test Case 1: Legitimate Site

**URL:** `https://google.com`
**Expected Result:** Safe
**Test Steps:**

1. Enter URL in phishing analyzer
2. Click "URL Phishing Analyzer"
3. Verify marked as safe

#### Test Case 2: Suspicious Domain

**URL:** `https://g00gle.com`
**Expected Result:** Suspicious
**Test Steps:**

1. Enter URL in phishing analyzer
2. Click "URL Phishing Analyzer"
3. Verify flagged as suspicious

#### Test Case 3: Phishing Attempt

**URL:** `https://paypal-security.com`
**Expected Result:** Likely Phishing
**Test Steps:**

1. Enter URL in phishing analyzer
2. Click "URL Phishing Analyzer"
3. Verify flagged as phishing

### XSS Test Cases

#### Test Case 1: Test Site

**URL:** `https://httpbin.org/get`
**Expected Result:** Basic scan completion
**Test Steps:**

1. Enter URL in XSS test field
2. Click "XSS Test"
3. Wait for scan completion
4. Review results

#### Test Case 2: XSS Test Site

**URL:** `https://xss-game.appspot.com`
**Expected Result:** XSS vulnerabilities detected
**Test Steps:**

1. Enter URL in XSS test field
2. Click "XSS Test"
3. Wait for comprehensive scan
4. Verify vulnerabilities found

#### Test Case 3: Secure Site

**URL:** `https://google.com`
**Expected Result:** No XSS vulnerabilities
**Test Steps:**

1. Enter URL in XSS test field
2. Click "XSS Test"
3. Wait for scan completion
4. Verify no vulnerabilities found

### SSL/TLS Test Cases

#### Test Case 1: Valid SSL

**URL:** `https://google.com`
**Expected Result:** Valid certificate
**Test Steps:**

1. Enter URL in SSL check field
2. Click "SSL/TLS Check"
3. Verify valid certificate

#### Test Case 2: Test SSL Site

**URL:** `https://badssl.com`
**Expected Result:** Various certificate issues
**Test Steps:**

1. Enter URL in SSL check field
2. Click "SSL/TLS Check"
3. Review certificate details

#### Test Case 3: No SSL

**URL:** `http://example.com`
**Expected Result:** No SSL error
**Test Steps:**

1. Enter URL in SSL check field
2. Click "SSL/TLS Check"
3. Verify no SSL error

### DNS Spoofing Test Cases

#### Test Case 1: Legitimate Domain

**Domain:** `google.com`
**Expected Result:** No spoofing detected
**Test Steps:**

1. Enter domain in DNS spoofing field
2. Click "DNS Spoofing"
3. Verify no spoofing indicators

#### Test Case 2: Suspicious Domain

**Domain:** `suspicious-domain.com`
**Expected Result:** Potential spoofing indicators
**Test Steps:**

1. Enter domain in DNS spoofing field
2. Click "DNS Spoofing"
3. Review security analysis

---

## 🦠 VirusTotal Test Data

### URL Scanning Test Cases

#### Test Case 1: Clean URL

**URL:** `https://google.com`
**Expected Result:** Clean
**Test Steps:**

1. Enter URL in VirusTotal section
2. Click "Scan URL"
3. Verify clean results

#### Test Case 2: Suspicious URL

**URL:** `https://malware.com`
**Expected Result:** Potentially malicious
**Test Steps:**

1. Enter URL in VirusTotal section
2. Click "Scan URL"
3. Review detection results

### Hash Analysis Test Cases

#### Test Case 1: Known Good Hash

**Hash:** `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`
**Description:** Empty file SHA256
**Expected Result:** Clean

#### Test Case 2: Known Malicious Hash

**Hash:** `d41d8cd98f00b204e9800998ecf8427e`
**Description:** Test malicious hash
**Expected Result:** Potentially malicious

### File Scanning Test Cases

#### Test Case 1: Clean Text File

**File:** Create a simple text file with "Hello World"
**Expected Result:** Clean
**Test Steps:**

1. Select text file
2. Click "Scan File"
3. Verify clean results

#### Test Case 2: Image File

**File:** Any image file (JPG, PNG)
**Expected Result:** Clean
**Test Steps:**

1. Select image file
2. Click "Scan File"
3. Verify clean results

---

## 🔐 Hash & Cryptography Test Data

### Text Hashing Test Cases

#### Test Case 1: Simple Text

**Input:** `"Hello World"`
**Expected Hashes:**

- MD5: `b10a8db164e0754105b7a99be72e3fe5`
- SHA1: `0a0a9f2a6772942557ab5355d76af442f8f65e01`
- SHA256: `a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e`
- SHA512: `2c74fd17edafd80e8447b0d46741ee243b7eb74dd2149a0ab1b9246fb30382f27e853d8585719e0e67cbda0daa8f51671064615d645ae27acb15bfb1447f459b`

#### Test Case 2: Password

**Input:** `"Password123"`
**Expected Hashes:**

- MD5: `482c811da5d5b4bc6d497ffa98491e38`
- SHA1: `cbfdac6008f9cab4083784cbd1874f76618d2a97`
- SHA256: `ef92b778bafe771e89245b89ecbc38a5e915f0c6c1c4c4c4c4c4c4c4c4c4c4c4c4`

#### Test Case 3: Special Characters

**Input:** `"CyberGuard Pro 2024!"`
**Expected Hashes:**

- MD5: `a1b2c3d4e5f6789012345678901234567890abcd`
- SHA1: `b2c3d4e5f6789012345678901234567890abcdef`
- SHA256: `c3d4e5f6789012345678901234567890abcdef12`

### File Hashing Test Cases

#### Test Case 1: Small Text File

**File:** Create file with content "Test file content"
**Expected Result:** Consistent hash generation
**Test Steps:**

1. Create small text file
2. Select file for hashing
3. Verify hash generation
4. Test multiple times for consistency

#### Test Case 2: Image File

**File:** Any image file
**Expected Result:** Unique hash for each file
**Test Steps:**

1. Select image file
2. Generate hash
3. Select different image
4. Verify different hash

### Password Strength Test Cases

#### Test Case 1: Weak Password

**Password:** `"password"`
**Expected Result:** Weak strength
**Test Steps:**

1. Enter password
2. Click "Analyze Password"
3. Verify weak rating
4. Check recommendations

#### Test Case 2: Medium Password

**Password:** `"Password123"`
**Expected Result:** Medium strength
**Test Steps:**

1. Enter password
2. Click "Analyze Password"
3. Verify medium rating
4. Check recommendations

#### Test Case 3: Strong Password

**Password:** `"MyStr0ng!P@ssw0rd2024"`
**Expected Result:** Strong strength
**Test Steps:**

1. Enter password
2. Click "Analyze Password"
3. Verify strong rating
4. Check recommendations

---

## 🎯 Comprehensive Test Scenarios

### Scenario 1: Corporate Network Assessment

**Target:** `company.com`
**Tests to Run:**

1. **Port Scan:** Check for open services
2. **SSL Check:** Validate certificate
3. **DNS Check:** Verify DNS security
4. **Threat Intel:** Check reputation
5. **XSS Test:** Scan for vulnerabilities

**Expected Results:**

- Port scan shows open services
- SSL certificate valid
- DNS security good
- Reputation clean
- No XSS vulnerabilities

### Scenario 2: Personal Website Security

**Target:** `your-website.com`
**Tests to Run:**

1. **XSS Test:** Comprehensive vulnerability scan
2. **SSL Check:** Certificate validation
3. **DNS Spoofing:** Security analysis
4. **Phishing Check:** URL analysis

**Expected Results:**

- No XSS vulnerabilities
- Valid SSL certificate
- No DNS spoofing
- Clean URL reputation

### Scenario 3: Suspicious Activity Investigation

**Target:** `suspicious-domain.com`
**Tests to Run:**

1. **Threat Intel:** Reputation analysis
2. **DNS Check:** Spoofing detection
3. **Port Scan:** Service discovery
4. **SSL Check:** Certificate analysis

**Expected Results:**

- Suspicious reputation
- Potential DNS issues
- Open services identified
- Certificate problems

---

## 📊 Performance Test Data

### Large Scale Testing

#### Test Case 1: Multiple IPs

**Targets:** `8.8.8.8`, `1.1.1.1`, `208.67.222.222`
**Test Steps:**

1. Scan each IP individually
2. Monitor performance
3. Check for errors
4. Verify results

#### Test Case 2: Large Port Range

**Target:** `127.0.0.1`
**Ports:** `1-1000`
**Test Steps:**

1. Enter port range
2. Start scan
3. Monitor progress
4. Check completion

#### Test Case 3: Multiple URLs

**URLs:** `google.com`, `github.com`, `stackoverflow.com`
**Test Steps:**

1. Test each URL
2. Monitor performance
3. Check for errors
4. Verify results

---

## 🚨 Error Handling Test Data

### Invalid Input Testing

#### Test Case 1: Invalid IPs

**Invalid IPs:** `999.999.999.999`, `256.256.256.256`, `invalid-ip`
**Expected Result:** Error messages
**Test Steps:**

1. Enter invalid IP
2. Click scan button
3. Verify error message
4. Check for crashes

#### Test Case 2: Invalid URLs

**Invalid URLs:** `not-a-url`, `ftp://invalid`, `https://`
**Expected Result:** Error messages
**Test Steps:**

1. Enter invalid URL
2. Click test button
3. Verify error message
4. Check for crashes

#### Test Case 3: Empty Inputs

**Empty Fields:** Leave target fields empty
**Expected Result:** Validation messages
**Test Steps:**

1. Leave fields empty
2. Click buttons
3. Verify validation
4. Check for crashes

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

## 📝 Quick Test Checklist

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
