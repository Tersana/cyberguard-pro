import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { JSDOM } from 'jsdom';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const apiClientCode = fs.readFileSync(path.resolve(__dirname, '../../public/js/api-client.js'), 'utf8');

describe('scannerAPI discovery-finding helpers', () => {
  let dom;
  let window;

  beforeEach(() => {
    dom = new JSDOM('<!doctype html><html><body></body></html>', {
      url: 'http://localhost',
      runScripts: 'dangerously'
    });
    window = dom.window;
    global.window = window;
    global.document = window.document;
    global.localStorage = window.localStorage;
    global.sessionStorage = window.sessionStorage;
    global.fetch = vi.fn(() => Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve({}) }));
    window.fetch = global.fetch;

    const apiScript = window.document.createElement('script');
    apiScript.textContent = apiClientCode;
    window.document.body.appendChild(apiScript);
  });

  afterEach(() => {
    vi.restoreAllMocks();
    delete global.window;
    delete global.document;
    delete global.localStorage;
    delete global.sessionStorage;
    delete global.fetch;
  });

  describe('isDiscoveryFinding', () => {
    it('flags web-endpoint-fuzzer findings by driver_id', () => {
      expect(window.scannerAPI.isDiscoveryFinding({ driver_id: 'web-endpoint-fuzzer', severity: 'high' })).toBe(true);
    });

    it('flags findings by tool alias and title heuristics', () => {
      expect(window.scannerAPI.isDiscoveryFinding({ tool: 'web_endpoint_fuzzer' })).toBe(true);
      expect(window.scannerAPI.isDiscoveryFinding({ title: 'High Risk Endpoint: /a/acme.com/ServiceLogin' })).toBe(true);
      expect(window.scannerAPI.isDiscoveryFinding({ driver_id: 'url-fuzz' })).toBe(true);
      expect(window.scannerAPI.isDiscoveryFinding({ driver_id: 'classifier' })).toBe(true);
    });

    it('does NOT flag a normal high vulnerability from another scanner', () => {
      expect(window.scannerAPI.isDiscoveryFinding({ driver_id: 'XSS_SCANNER', severity: 'high', title: 'Reflected XSS' })).toBe(false);
      expect(window.scannerAPI.isDiscoveryFinding({ driver_id: 'PORT_SCANNER', severity: 'medium' })).toBe(false);
    });

    it('honors explicit backend flags over the heuristic', () => {
      // Promoted / explicitly-not-discovery wins even if the driver_id looks like a fuzzer.
      expect(window.scannerAPI.isDiscoveryFinding({ driver_id: 'web-endpoint-fuzzer', promoted: true })).toBe(false);
      expect(window.scannerAPI.isDiscoveryFinding({ driver_id: 'web-endpoint-fuzzer', is_discovery: false })).toBe(false);
      // Explicit discovery flag wins even without a matching driver_id.
      expect(window.scannerAPI.isDiscoveryFinding({ driver_id: 'CUSTOM', is_discovery: true })).toBe(true);
      expect(window.scannerAPI.isDiscoveryFinding({ driver_id: 'CUSTOM', category: 'discovery' })).toBe(true);
    });

    it('returns false for nullish / non-object input', () => {
      expect(window.scannerAPI.isDiscoveryFinding(null)).toBe(false);
      expect(window.scannerAPI.isDiscoveryFinding(undefined)).toBe(false);
    });
  });

  describe('normalizeEndpointUrl', () => {
    it('treats scheme, host case, and trailing slash as equivalent', () => {
      const a = window.scannerAPI.normalizeEndpointUrl('https://Example.com/a/Path/');
      const b = window.scannerAPI.normalizeEndpointUrl('http://example.com/a/Path');
      expect(a).toBe(b);
    });

    it('keeps the query string as part of the identity', () => {
      const a = window.scannerAPI.normalizeEndpointUrl('https://x.com/login?service=jotspot');
      const b = window.scannerAPI.normalizeEndpointUrl('https://x.com/login?service=other');
      expect(a).not.toBe(b);
    });

    it('falls back gracefully for bare paths', () => {
      expect(window.scannerAPI.normalizeEndpointUrl('/A/Path/')).toBe('/a/path');
      expect(window.scannerAPI.normalizeEndpointUrl('')).toBe('');
    });
  });

  describe('partitionFindings', () => {
    it('splits vulnerabilities from discovery findings', () => {
      const findings = [
        { id: 1, driver_id: 'web-endpoint-fuzzer', severity: 'high' },
        { id: 2, driver_id: 'XSS_SCANNER', severity: 'high' },
        { id: 3, driver_id: 'web-endpoint-fuzzer', severity: 'high', promoted: true },
      ];
      const { vulnerabilities, discovery } = window.scannerAPI.partitionFindings(findings);
      expect(discovery.map(f => f.id)).toEqual([1]);
      expect(vulnerabilities.map(f => f.id).sort()).toEqual([2, 3]);
    });

    it('handles non-array input', () => {
      expect(window.scannerAPI.partitionFindings(null)).toEqual({ vulnerabilities: [], discovery: [] });
    });
  });

  describe('include-discovery preference', () => {
    it('defaults to false and round-trips through localStorage', () => {
      expect(window.scannerAPI.getIncludeDiscovery()).toBe(false);
      window.scannerAPI.setIncludeDiscovery(true);
      expect(window.scannerAPI.getIncludeDiscovery()).toBe(true);
      expect(window.localStorage.getItem('cyberguard_include_discovery')).toBe('true');
      window.scannerAPI.setIncludeDiscovery(false);
      expect(window.scannerAPI.getIncludeDiscovery()).toBe(false);
    });
  });

  describe('promote feature flag', () => {
    it('is disabled by default', () => {
      expect(window.scannerAPI.isPromoteEnabled()).toBe(false);
    });
  });
});
