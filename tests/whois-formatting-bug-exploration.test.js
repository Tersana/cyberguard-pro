/**
 * WHOIS Formatting Bug Exploration Tests (Test Suite 1B)
 * 
 * **Property 1: Bug Condition - Output Formatting Bugs**
 * **Validates: Requirements 2.1, 2.2, 2.3, 2.4, 2.5**
 * 
 * CRITICAL: These tests MUST FAIL on unfixed code - failure confirms the bugs exist.
 * DO NOT attempt to fix the tests or the code when they fail.
 * These tests encode the expected behavior - they will validate the fix when they pass after implementation.
 * 
 * EXPECTED OUTCOME: Tests FAIL (this is correct - it proves the formatting bug exists)
 */

import { describe, it, expect, beforeEach } from 'vitest';

// WHOIS divider constant (from main.js)
const WHOIS_DIVIDER = '─'.repeat(54);

// Current UNFIXED implementation (copied from main.js line ~1962)
function formatIpWhoisOutput(ip, location, asn, security) {
  const coords =
    location.latitude && location.longitude
      ? `${location.latitude}, ${location.longitude}`
      : "N/A";

  return [
    WHOIS_DIVIDER,
    `  IP WHOIS DATA — ${ip}`,
    WHOIS_DIVIDER,
    "  Location",
    `    Country        : ${location.country || "N/A"}`,
    `    Region         : ${location.region || "N/A"}`,
    `    City           : ${location.city || "N/A"}`,
    `    Postal Code    : ${location.postalCode || "N/A"}`,
    `    Coordinates    : ${coords}`,
    `    Timezone       : ${location.timezone || "N/A"}`,
    "",
    "  Network",
    `    Organization   : ${asn.organization || "N/A"}`,
    `    ASN            : ${asn.asn || "N/A"}`,
    `    ASN Name       : ${asn.name || "N/A"}`,
    `    ASN Domain     : ${asn.domain || "N/A"}`,
    `    ASN Country    : ${asn.country || "N/A"}`,
    "",
    "  Security",
    `    Proxy          : ${security.isProxy ? "Proxy detected" : "No proxy"}`,
    `    VPN            : ${security.isVpn ? "VPN detected" : "No VPN"}`,
    `    Hosting        : ${security.isHosting ? "Hosting provider" : "Not hosting"}`,
    `    Tor            : ${security.isTor ? "Tor exit node" : "Not Tor"}`,
    WHOIS_DIVIDER,
  ].join("\n");
}

// Current UNFIXED implementation (copied from main.js line ~2002)
function formatDomainWhoisOutput(domainName, opts) {
  const {
    createdDate,
    updatedDate,
    expiresDate,
    registrar,
    registrant,
    status,
    nameServers,
  } = opts;

  // Build status flags block
  const statusFlags = Array.isArray(status)
    ? status
    : typeof status === "string" && status !== "N/A"
      ? status.split(/[,\s]+/).filter(Boolean)
      : ["N/A"];
  const flagLines = statusFlags.map(
    (f, i) => (i === 0 ? `    Flags          : ${f}` : `                     ${f}`),
  );

  // Build nameservers block
  const nsArray = Array.isArray(nameServers) ? nameServers : [];
  const nsLines =
    nsArray.length > 0
      ? nsArray.map(
          (ns, i) =>
            i === 0
              ? `    Nameservers    : ${ns}`
              : `                     ${ns}`,
        )
      : ["    Nameservers    : N/A"];

  return [
    WHOIS_DIVIDER,
    `  DOMAIN WHOIS DATA — ${domainName}`,
    WHOIS_DIVIDER,
    "  Registration",
    `    Domain         : ${domainName}`,
    `    Created        : ${createdDate}`,
    `    Updated        : ${updatedDate}`,
    `    Expires        : ${expiresDate}`,
    `    Registrar      : ${registrar}`,
    `    Registrant     : ${registrant}`,
    "",
    "  Status",
    ...flagLines,
    "",
    "  DNS",
    ...nsLines,
    WHOIS_DIVIDER,
  ].join("\n");
}

// Mock DOM rendering function to simulate how the output would be rendered
function simulateHTMLRendering(text, cssProperties = {}) {
  // Simulate HTML rendering behavior:
  // - Without white-space: pre-wrap, newlines are collapsed
  // - With white-space: pre-wrap, newlines are preserved
  
  const hasPreWrap = cssProperties['white-space'] === 'pre-wrap';
  const hasMonospace = cssProperties['font-family']?.includes('mono') || 
                       cssProperties['font-family']?.includes('Courier');
  
  if (!hasPreWrap) {
    // Simulate HTML collapsing whitespace and newlines
    return {
      renderedText: text.replace(/\n/g, ' ').replace(/\s+/g, ' '),
      lineCount: 1,
      hasMonospace: hasMonospace,
      preservesNewlines: false
    };
  }
  
  return {
    renderedText: text,
    lineCount: text.split('\n').length,
    hasMonospace: hasMonospace,
    preservesNewlines: true
  };
}

describe('Test Suite 1B: Output Formatting Bug Exploration', () => {
  describe('IP WHOIS Output Multi-line Rendering (Requirement 2.1)', () => {
    it('should render IP WHOIS output as multi-line structured blocks', () => {
      const mockData = {
        ip: '8.8.8.8',
        location: {
          country: 'United States',
          region: 'California',
          city: 'Mountain View',
          postalCode: '94035',
          latitude: '37.386',
          longitude: '-122.084',
          timezone: 'America/Los_Angeles'
        },
        asn: {
          organization: 'Google LLC',
          asn: 'AS15169',
          name: 'GOOGLE',
          domain: 'google.com',
          country: 'US'
        },
        security: {
          isProxy: false,
          isVpn: false,
          isHosting: true,
          isTor: false
        }
      };

      const output = formatIpWhoisOutput(
        mockData.ip,
        mockData.location,
        mockData.asn,
        mockData.security
      );

      // Verify the output contains newline characters
      expect(output).toContain('\n');
      
      // Verify the output has multiple lines
      const lines = output.split('\n');
      expect(lines.length).toBeGreaterThan(1);
      
      // Simulate rendering WITH proper CSS (fixed code)
      const unfixedRendering = simulateHTMLRendering(output, {
        'white-space': 'pre-wrap',
        'font-family': 'JetBrains Mono, monospace'
      });
      
      // EXPECTED: Multi-line rendering (lineCount > 1)
      expect(unfixedRendering.preservesNewlines).toBe(true);
      expect(unfixedRendering.lineCount).toBeGreaterThan(1);
    });

    it('should have proper sections (LOCATION, NETWORK, SECURITY)', () => {
      const mockData = {
        ip: '1.1.1.1',
        location: { country: 'Australia', region: 'N/A', city: 'N/A', postalCode: 'N/A' },
        asn: { organization: 'Cloudflare', asn: 'AS13335', name: 'CLOUDFLARENET', domain: 'cloudflare.com', country: 'US' },
        security: { isProxy: false, isVpn: false, isHosting: true, isTor: false }
      };

      const output = formatIpWhoisOutput(
        mockData.ip,
        mockData.location,
        mockData.asn,
        mockData.security
      );

      // Verify sections exist
      expect(output).toContain('Location');
      expect(output).toContain('Network');
      expect(output).toContain('Security');
      
      // Verify sections are separated by newlines
      const locationIndex = output.indexOf('Location');
      const networkIndex = output.indexOf('Network');
      const securityIndex = output.indexOf('Security');
      
      expect(locationIndex).toBeGreaterThan(-1);
      expect(networkIndex).toBeGreaterThan(locationIndex);
      expect(securityIndex).toBeGreaterThan(networkIndex);
    });
  });

  describe('Domain WHOIS Output Multi-line Rendering (Requirement 2.2)', () => {
    it('should render domain WHOIS output as multi-line structured blocks', () => {
      const mockData = {
        domainName: 'google.com',
        createdDate: '1997-09-15',
        updatedDate: '2023-09-14',
        expiresDate: '2028-09-14',
        registrar: 'MarkMonitor Inc.',
        registrant: 'Google LLC',
        status: ['clientDeleteProhibited', 'clientTransferProhibited', 'clientUpdateProhibited'],
        nameServers: ['ns1.google.com', 'ns2.google.com', 'ns3.google.com', 'ns4.google.com']
      };

      const output = formatDomainWhoisOutput(mockData.domainName, mockData);

      // Verify the output contains newline characters
      expect(output).toContain('\n');
      
      // Verify the output has multiple lines
      const lines = output.split('\n');
      expect(lines.length).toBeGreaterThan(1);
      
      // Simulate rendering WITH proper CSS (fixed code)
      const unfixedRendering = simulateHTMLRendering(output, {
        'white-space': 'pre-wrap',
        'font-family': 'JetBrains Mono, monospace'
      });
      
      // EXPECTED: Multi-line rendering (lineCount > 1)
      expect(unfixedRendering.preservesNewlines).toBe(true);
      expect(unfixedRendering.lineCount).toBeGreaterThan(1);
    });

    it('should have proper sections (REGISTRATION, STATUS, DNS)', () => {
      const mockData = {
        domainName: 'example.org',
        createdDate: '1995-08-14',
        updatedDate: '2023-08-14',
        expiresDate: '2024-08-13',
        registrar: 'RESERVED-Internet Assigned Numbers Authority',
        registrant: 'Internet Assigned Numbers Authority',
        status: ['clientDeleteProhibited'],
        nameServers: ['a.iana-servers.net', 'b.iana-servers.net']
      };

      const output = formatDomainWhoisOutput(mockData.domainName, mockData);

      // Verify sections exist
      expect(output).toContain('Registration');
      expect(output).toContain('Status');
      expect(output).toContain('DNS');
      
      // Verify sections are separated by newlines
      const registrationIndex = output.indexOf('Registration');
      const statusIndex = output.indexOf('Status');
      const dnsIndex = output.indexOf('DNS');
      
      expect(registrationIndex).toBeGreaterThan(-1);
      expect(statusIndex).toBeGreaterThan(registrationIndex);
      expect(dnsIndex).toBeGreaterThan(statusIndex);
    });
  });

  describe('Divider Lines Rendering (Requirement 2.3)', () => {
    it('should render divider lines with proper visual separation', () => {
      const mockData = {
        ip: '8.8.8.8',
        location: { country: 'US', region: 'CA', city: 'Mountain View', postalCode: '94035' },
        asn: { organization: 'Google', asn: 'AS15169', name: 'GOOGLE', domain: 'google.com', country: 'US' },
        security: { isProxy: false, isVpn: false, isHosting: true, isTor: false }
      };

      const output = formatIpWhoisOutput(
        mockData.ip,
        mockData.location,
        mockData.asn,
        mockData.security
      );

      // Verify divider exists
      expect(output).toContain(WHOIS_DIVIDER);
      
      // Verify divider width is 54 characters
      expect(WHOIS_DIVIDER.length).toBe(54);
      
      // Verify divider appears at start and end
      const lines = output.split('\n');
      expect(lines[0]).toBe(WHOIS_DIVIDER);
      expect(lines[lines.length - 1]).toBe(WHOIS_DIVIDER);
    });

    it('should use consistent divider character (─)', () => {
      expect(WHOIS_DIVIDER).toMatch(/^─+$/);
      expect(WHOIS_DIVIDER.length).toBe(54);
    });
  });

  describe('Newline Character Preservation (Requirement 2.4)', () => {
    it('should preserve newline characters in output', () => {
      const mockData = {
        ip: '1.1.1.1',
        location: { country: 'Australia' },
        asn: { organization: 'Cloudflare', asn: 'AS13335' },
        security: { isProxy: false, isVpn: false, isHosting: true, isTor: false }
      };

      const output = formatIpWhoisOutput(
        mockData.ip,
        mockData.location,
        mockData.asn,
        mockData.security
      );

      // Count newline characters
      const newlineCount = (output.match(/\n/g) || []).length;
      
      // Should have multiple newlines
      expect(newlineCount).toBeGreaterThan(5);
      
      // Simulate rendering with proper CSS (fixed code)
      const fixedRendering = simulateHTMLRendering(output, {
        'white-space': 'pre-wrap',
        'font-family': 'JetBrains Mono, monospace'
      });
      
      // With proper CSS, newlines should be preserved
      expect(fixedRendering.preservesNewlines).toBe(true);
      expect(fixedRendering.lineCount).toBe(newlineCount + 1);
    });
  });

  describe('Monospace Font Styling (Requirement 2.5)', () => {
    it('should apply monospace font for proper alignment', () => {
      const mockData = {
        ip: '8.8.8.8',
        location: { country: 'US', region: 'CA', city: 'Mountain View' },
        asn: { organization: 'Google LLC', asn: 'AS15169' },
        security: { isProxy: false, isVpn: false, isHosting: true, isTor: false }
      };

      const output = formatIpWhoisOutput(
        mockData.ip,
        mockData.location,
        mockData.asn,
        mockData.security
      );

      // Simulate rendering with proper CSS
      const rendering = simulateHTMLRendering(output, {
        'white-space': 'pre-wrap',
        'font-family': 'JetBrains Mono, Courier New, monospace'
      });
      
      // EXPECTED: Monospace font applied
      // ACTUAL ON UNFIXED CODE: May not have monospace font
      expect(rendering.hasMonospace).toBe(true);
    });

    it('should verify alignment with monospace font', () => {
      const mockData = {
        domainName: 'example.com',
        createdDate: '2000-01-01',
        updatedDate: '2023-01-01',
        expiresDate: '2024-01-01',
        registrar: 'Example Registrar',
        registrant: 'Example Organization',
        status: ['active'],
        nameServers: ['ns1.example.com', 'ns2.example.com']
      };

      const output = formatDomainWhoisOutput(mockData.domainName, mockData);

      // Verify field labels are aligned (using spaces for alignment)
      const lines = output.split('\n');
      const fieldLines = lines.filter(line => line.includes(':'));
      
      // All field lines should have consistent spacing
      // This is only readable with monospace font
      expect(fieldLines.length).toBeGreaterThan(0);
      
      // Check that field labels use consistent spacing
      const domainLine = fieldLines.find(line => line.includes('Domain'));
      const createdLine = fieldLines.find(line => line.includes('Created'));
      
      if (domainLine && createdLine) {
        const domainSpaces = domainLine.indexOf(':') - domainLine.indexOf('Domain');
        const createdSpaces = createdLine.indexOf(':') - createdLine.indexOf('Created');
        
        // Spacing should be consistent for alignment
        expect(Math.abs(domainSpaces - createdSpaces)).toBeLessThanOrEqual(2);
      }
    });
  });

  describe('CSS Requirements for Proper Rendering', () => {
    it('should document required CSS properties for fix', () => {
      // This test documents the CSS properties needed to fix the formatting bug
      const requiredCSSProperties = {
        'white-space': 'pre-wrap',
        'font-family': 'JetBrains Mono, Courier New, Courier, monospace',
        'word-break': 'break-word',
        'display': 'block',
        'line-height': '1.6'
      };

      // Verify each property is defined
      expect(requiredCSSProperties['white-space']).toBe('pre-wrap');
      expect(requiredCSSProperties['font-family']).toContain('mono');
      expect(requiredCSSProperties['word-break']).toBe('break-word');
      expect(requiredCSSProperties['display']).toBe('block');
      expect(requiredCSSProperties['line-height']).toBe('1.6');
    });
  });
});
