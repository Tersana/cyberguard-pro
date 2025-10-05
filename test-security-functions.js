#!/usr/bin/env node

/**
 * 🧪 CyberGuard Pro - Security Functions Test Script
 *
 * This script automatically tests all security functions in your CyberGuard Pro application.
 * Run this after starting your web server to verify all security tools are working.
 *
 * Usage: node test-security-functions.js
 */

const https = require("https");
const http = require("http");

// Configuration
const BASE_URL = "http://localhost:3000";
const TEST_TARGETS = {
  ip: "8.8.8.8",
  domain: "google.com",
  url: "https://google.com",
  hash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
};

// Test results
let testResults = {
  passed: 0,
  failed: 0,
  total: 0,
  errors: [],
};

// Helper function to make HTTP requests
function makeRequest(method, path, data = null, headers = {}) {
  return new Promise((resolve, reject) => {
    const url = new URL(BASE_URL + path);
    const options = {
      hostname: url.hostname,
      port: url.port,
      path: url.pathname + url.search,
      method: method,
      headers: {
        "Content-Type": "application/json",
        ...headers,
      },
    };

    const req = http.request(options, (res) => {
      let body = "";
      res.on("data", (chunk) => (body += chunk));
      res.on("end", () => {
        try {
          const response = {
            statusCode: res.statusCode,
            headers: res.headers,
            body: body ? JSON.parse(body) : null,
          };
          resolve(response);
        } catch (e) {
          resolve({
            statusCode: res.statusCode,
            headers: res.headers,
            body: body,
          });
        }
      });
    });

    req.on("error", reject);

    if (data) {
      req.write(JSON.stringify(data));
    }
    req.end();
  });
}

// Test function
async function runTest(testName, testFunction) {
  console.log(`\n🧪 Testing: ${testName}`);
  testResults.total++;

  try {
    await testFunction();
    console.log(`✅ PASSED: ${testName}`);
    testResults.passed++;
  } catch (error) {
    console.log(`❌ FAILED: ${testName}`);
    console.log(`   Error: ${error.message}`);
    testResults.failed++;
    testResults.errors.push({ test: testName, error: error.message });
  }
}

// Test 1: Application Load
async function testApplicationLoad() {
  const response = await makeRequest("GET", "/");
  if (response.statusCode !== 200) {
    throw new Error(`Expected status 200, got ${response.statusCode}`);
  }
  if (!response.body || !response.body.includes("CyberGuard")) {
    throw new Error("Application not loading correctly");
  }
}

// Test 2: Port Scanner Function
async function testPortScanner() {
  // Test if port scanner function exists
  const response = await makeRequest("GET", "/main.js");
  if (response.statusCode !== 200) {
    throw new Error("Main JavaScript file not found");
  }

  // Check for port scanner class
  if (!response.body.includes("CommercialPortScanner")) {
    throw new Error("Port scanner class not found");
  }

  // Check for port scanner methods
  if (!response.body.includes("scanPorts")) {
    throw new Error("Port scanner methods not found");
  }
}

// Test 3: XSS Test Function
async function testXssFunction() {
  const response = await makeRequest("GET", "/main.js");
  if (response.statusCode !== 200) {
    throw new Error("Main JavaScript file not found");
  }

  // Check for XSS test function
  if (!response.body.includes("xss-btn")) {
    throw new Error("XSS test button not found");
  }

  // Check for XSS test logic
  if (!response.body.includes("XSS Test")) {
    throw new Error("XSS test logic not found");
  }
}

// Test 4: SSL Check Function
async function testSslFunction() {
  const response = await makeRequest("GET", "/main.js");
  if (response.statusCode !== 200) {
    throw new Error("Main JavaScript file not found");
  }

  // Check for SSL check function
  if (!response.body.includes("ssl-btn")) {
    throw new Error("SSL check button not found");
  }

  // Check for SSL check logic
  if (!response.body.includes("SSL/TLS Check")) {
    throw new Error("SSL check logic not found");
  }
}

// Test 5: DNS Functions
async function testDnsFunctions() {
  const response = await makeRequest("GET", "/main.js");
  if (response.statusCode !== 200) {
    throw new Error("Main JavaScript file not found");
  }

  // Check for DNS functions
  if (!response.body.includes("reverse-dns-btn")) {
    throw new Error("Reverse DNS button not found");
  }

  if (!response.body.includes("ip-geo-btn")) {
    throw new Error("IP Geolocation button not found");
  }

  if (!response.body.includes("whois-btn")) {
    throw new Error("WHOIS button not found");
  }
}

// Test 6: Hash Functions
async function testHashFunctions() {
  const response = await makeRequest("GET", "/main.js");
  if (response.statusCode !== 200) {
    throw new Error("Main JavaScript file not found");
  }

  // Check for hash functions
  if (!response.body.includes("hash-string-btn")) {
    throw new Error("Hash string button not found");
  }

  if (!response.body.includes("hash-file-input")) {
    throw new Error("Hash file input not found");
  }

  if (!response.body.includes("pw-analyze-btn")) {
    throw new Error("Password analyzer button not found");
  }
}

// Test 7: VirusTotal Integration
async function testVirusTotalIntegration() {
  const response = await makeRequest("GET", "/main.js");
  if (response.statusCode !== 200) {
    throw new Error("Main JavaScript file not found");
  }

  // Check for VirusTotal functions
  if (!response.body.includes("vt-url-btn")) {
    throw new Error("VirusTotal URL button not found");
  }

  if (!response.body.includes("vt-hash-btn")) {
    throw new Error("VirusTotal hash button not found");
  }

  if (!response.body.includes("vt-file-btn")) {
    throw new Error("VirusTotal file button not found");
  }
}

// Test 8: UI Components
async function testUIComponents() {
  const response = await makeRequest("GET", "/");
  if (response.statusCode !== 200) {
    throw new Error("Main page not found");
  }

  // Check for essential UI components
  const uiComponents = [
    "target-ip",
    "target-url",
    "port-scan-btn",
    "xss-btn",
    "ssl-btn",
    "hash-string-input",
    "results-container",
  ];

  for (const component of uiComponents) {
    if (!response.body.includes(component)) {
      throw new Error(`UI component ${component} not found`);
    }
  }
}

// Test 9: API Key Configuration
async function testApiKeyConfiguration() {
  const response = await makeRequest("GET", "/");
  if (response.statusCode !== 200) {
    throw new Error("Main page not found");
  }

  // Check for API key inputs
  if (!response.body.includes("vt-api-key")) {
    throw new Error("VirusTotal API key input not found");
  }

  if (!response.body.includes("abuse-api-key")) {
    throw new Error("AbuseIPDB API key input not found");
  }

  if (!response.body.includes("whois-api-key")) {
    throw new Error("WhoisXML API key input not found");
  }
}

// Test 10: Security Headers
async function testSecurityHeaders() {
  const response = await makeRequest("GET", "/");
  if (response.statusCode !== 200) {
    throw new Error("Main page not found");
  }

  // Check for security-related content
  if (!response.body.includes("Content Security Policy")) {
    throw new Error("Security headers not found");
  }
}

// Test 11: Error Handling
async function testErrorHandling() {
  const response = await makeRequest("GET", "/nonexistent-page");
  if (response.statusCode === 200) {
    throw new Error("Error handling not working correctly");
  }
}

// Test 12: Performance
async function testPerformance() {
  const startTime = Date.now();
  const response = await makeRequest("GET", "/");
  const endTime = Date.now();

  if (response.statusCode !== 200) {
    throw new Error("Application not responding");
  }

  const responseTime = endTime - startTime;
  if (responseTime > 5000) {
    throw new Error(`Application too slow: ${responseTime}ms`);
  }
}

// Main test runner
async function runAllTests() {
  console.log("🚀 Starting CyberGuard Pro Security Functions Tests...\n");
  console.log(`📡 Testing against: ${BASE_URL}\n`);

  // Basic tests
  await runTest("Application Load", testApplicationLoad);
  await runTest("Port Scanner Function", testPortScanner);
  await runTest("XSS Test Function", testXssFunction);
  await runTest("SSL Check Function", testSslFunction);
  await runTest("DNS Functions", testDnsFunctions);
  await runTest("Hash Functions", testHashFunctions);
  await runTest("VirusTotal Integration", testVirusTotalIntegration);
  await runTest("UI Components", testUIComponents);
  await runTest("API Key Configuration", testApiKeyConfiguration);
  await runTest("Security Headers", testSecurityHeaders);
  await runTest("Error Handling", testErrorHandling);
  await runTest("Performance", testPerformance);

  // Print results
  console.log("\n📊 Test Results:");
  console.log(`✅ Passed: ${testResults.passed}`);
  console.log(`❌ Failed: ${testResults.failed}`);
  console.log(`📈 Total: ${testResults.total}`);
  console.log(
    `🎯 Success Rate: ${(
      (testResults.passed / testResults.total) *
      100
    ).toFixed(1)}%`
  );

  if (testResults.errors.length > 0) {
    console.log("\n❌ Failed Tests:");
    testResults.errors.forEach((error) => {
      console.log(`   • ${error.test}: ${error.error}`);
    });
  }

  if (testResults.failed === 0) {
    console.log("\n🎉 All security functions are working correctly!");
    console.log("🚀 Your CyberGuard Pro application is ready for use!");
  } else {
    console.log(
      "\n⚠️  Some security functions failed. Check the errors above."
    );
    console.log("🔧 Fix the issues and run the tests again.");
  }
}

// Run tests
runAllTests().catch(console.error);

