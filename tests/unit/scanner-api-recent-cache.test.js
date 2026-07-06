import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { JSDOM } from 'jsdom';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const apiClientCode = fs.readFileSync(path.resolve(__dirname, '../../public/js/api-client.js'), 'utf8');

function jsonResponse(data) {
  return Promise.resolve({
    ok: true,
    status: 200,
    json: () => Promise.resolve(data)
  });
}

describe('scannerAPI recent scan and finding cache', () => {
  let dom;
  let window;
  let document;
  let fetchMock;

  beforeEach(() => {
    dom = new JSDOM('<!doctype html><html><body></body></html>', {
      url: 'http://localhost',
      runScripts: 'dangerously'
    });

    window = dom.window;
    document = window.document;
    global.window = window;
    global.document = document;
    global.localStorage = window.localStorage;
    global.sessionStorage = window.sessionStorage;

    window.localStorage.setItem('cyberguard_jwt', 'test-token');

    fetchMock = vi.fn((url) => {
      const pathName = String(url).replace(/^https?:\/\/[^/]+\/api\//, '');

      if (pathName === 'scan/FUZZ123/status') {
        return jsonResponse({
          status: 'success',
          scan_session: {
            id: 'FUZZ123',
            status: 'running',
            project_id: 42,
            target_id: 7,
            driver_id: ['WEB_ENDPOINT_FUZZER', 'classifier'],
            target: { id: 7, value: 'google.com' },
            project: { id: 42 },
            started_at: '2026-07-06T05:37:00Z'
          }
        });
      }

      if (pathName === 'scan/FUZZ123/findings') {
        return jsonResponse({
          status: 'success',
          findings: [
            {
              id: 'finding-1',
              scan_job_id: 'FUZZ123',
              title: '/admin',
              affected_url: 'https://google.com/admin',
              severity: 'medium',
              status: 'open',
              created_at: '2026-07-06T05:38:00Z'
            }
          ]
        });
      }

      if (pathName === 'projects/42/scans' || pathName === 'targets/7/scans') {
        return jsonResponse({ status: 'success', scans: [] });
      }

      throw new Error(`Unexpected URL: ${url}`);
    });
    window.fetch = fetchMock;
    global.fetch = fetchMock;

    const apiScript = document.createElement('script');
    apiScript.textContent = apiClientCode;
    document.body.appendChild(apiScript);
  });

  afterEach(() => {
    vi.restoreAllMocks();
    delete global.window;
    delete global.document;
    delete global.localStorage;
    delete global.sessionStorage;
    delete global.fetch;
  });

  it('remembers backend fuzzer scans from status calls when project and target history endpoints are empty', async () => {
    const status = await window.scannerAPI.getScanStatus('FUZZ123');
    expect(status.id).toBe('FUZZ123');

    const projectScans = await window.scannerAPI.getProjectScans('42');
    const targetScans = await window.scannerAPI.getTargetScans('7');

    expect(projectScans).toHaveLength(1);
    expect(targetScans).toHaveLength(1);
    expect(projectScans[0].id).toBe('FUZZ123');
    expect(targetScans[0].id).toBe('FUZZ123');
    expect(window.scannerAPI.formatScanShortId(projectScans[0])).toMatch(/^FUZZ-/);
  });

  it('caches loaded backend fuzzer findings with project and target IDs normalized as strings', async () => {
    await window.scannerAPI.getScanStatus('FUZZ123');

    const findings = await window.scannerAPI.getScanFindings('FUZZ123');
    const projectFindings = window.scannerAPI.getRecentFindingsForProject('42');
    const targetFindings = window.scannerAPI.getRecentFindingsForTarget('7');

    expect(findings).toHaveLength(1);
    expect(projectFindings).toHaveLength(1);
    expect(targetFindings).toHaveLength(1);
    expect(projectFindings[0]).toMatchObject({
      id: 'finding-1',
      scan_job_id: 'FUZZ123',
      project_id: '42',
      target_id: '7',
      severity: 'medium',
      status: 'open'
    });
  });

  it('dedupes cached scans once backend project history later returns the same scan', async () => {
    await window.scannerAPI.getScanStatus('FUZZ123');

    fetchMock.mockImplementation((url) => {
      const pathName = String(url).replace(/^https?:\/\/[^/]+\/api\//, '');
      if (pathName === 'projects/42/scans') {
        return jsonResponse({
          status: 'success',
          scans: [
            {
              id: 'FUZZ123',
              status: 'completed',
              project_id: '42',
              target_id: '7',
              driver_id: ['waybackurls'],
              started_at: '2026-07-06T05:37:00Z',
              finished_at: '2026-07-06T05:39:00Z'
            }
          ]
        });
      }
      return jsonResponse({ status: 'success', scans: [] });
    });

    const projectScans = await window.scannerAPI.getProjectScans(42);

    expect(projectScans).toHaveLength(1);
    expect(projectScans[0]).toMatchObject({
      id: 'FUZZ123',
      status: 'completed',
      project_id: '42',
      target_id: '7'
    });
  });
});
