import { describe, it, expect, beforeEach, vi } from 'vitest';
import { JSDOM } from 'jsdom';

// Simple mock for APIClient and ProjectManager
describe('ProjectManager - lazyLoadProjectMetrics', () => {
  let dom;
  let document;
  let window;

  beforeEach(() => {
    dom = new JSDOM(`
      <!DOCTYPE html>
      <html>
        <body>
          <div class="project-targets-count-val" data-project-id="123">0 targets</div>
          <div class="project-findings-count-val" data-project-id="123">0 findings</div>
          <div class="project-scans-count-val" data-project-id="123">0 scans</div>
          <div class="project-risk-score-value" data-project-id="123">0.0 / 100</div>
          <div class="project-card-item" data-project-id="123"><span class="project-risk-level">Stale</span></div>
          <div class="project-progress-fill" data-progress-project-id="123" style="width: 0%;"></div>
        </body>
      </html>
    `, { url: 'http://localhost' });
    document = dom.window.document;
    window = dom.window;
    global.document = document;
    global.window = window;
  });

  it('should calculate and render risk score correctly', async () => {
    // Mock apiClient
    const mockApiClient = {
      get: vi.fn().mockImplementation((url) => {
        if (url === '/projects/123/targets') {
          return Promise.resolve({
            status: 'success',
            targets: [{ id: 'target_1' }, { id: 'target_2' }]
          });
        }
        if (url === '/projects/123/scans') {
          return Promise.resolve({
            status: 'success',
            scans: [{ id: 'scan_1', status: 'completed' }]
          });
        }
        if (url === '/projects/123/findings?page=1') {
          return Promise.resolve({
            status: 'success',
            findings: {
              current_page: 1,
              last_page: 1,
              data: [
                { id: 'f1', severity: 'critical', status: 'open' },
                { id: 'f2', severity: 'high', status: 'open' },
                { id: 'f3', severity: 'medium', status: 'open' },
                { id: 'f4', severity: 'low', status: 'open' }
              ]
            }
          });
        }
        return Promise.reject(new Error('Unknown url: ' + url));
      })
    };

    // Load ProjectManager
    const { ProjectManager } = await import('../../public/js/project-manager.js');
    const pm = new ProjectManager(mockApiClient);

    // Call lazyLoadProjectMetrics
    await pm.lazyLoadProjectMetrics('123');

    // Verify updates in DOM
    const targetsEl = document.querySelector('.project-targets-count-val[data-project-id="123"]');
    const findingsEl = document.querySelector('.project-findings-count-val[data-project-id="123"]');
    const scansEl = document.querySelector('.project-scans-count-val[data-project-id="123"]');
    const scoreEl = document.querySelector('.project-risk-score-value[data-project-id="123"]');
    const fillEl = document.querySelector('.project-progress-fill[data-progress-project-id="123"]');
    const riskLevelEl = document.querySelector('.project-card-item[data-project-id="123"] .project-risk-level');

    expect(targetsEl.textContent).toBe('2 targets');
    expect(scansEl.textContent).toBe('1 scan');
    expect(findingsEl.textContent).toBe('4 findings');
    
    // Critical: 1, High: 1, Medium: 1, Low: 1
    // Score calculation: (1 * 10 + 1 * 7 + 1 * 4 + 1 * 1) / 10 = 22 / 10 = 2.2
    expect(scoreEl.textContent).toBe('2.2 / 100');
    expect(fillEl.style.width).toBe('2%');
    expect(riskLevelEl.textContent).toBe('Controlled');
  });
  it('should use normalized scannerAPI scans and merge cached recent findings', async () => {
    window.scannerAPI = {
      getProjectScans: vi.fn().mockResolvedValue([
        { id: 'FUZZ123', project_id: '123', driver_id: ['WEB_ENDPOINT_FUZZER'] }
      ]),
      getRecentFindingsForProject: vi.fn().mockReturnValue([
        { id: 'cached-fuzzer-finding', scan_job_id: 'FUZZ123', severity: 'medium', status: 'open' }
      ])
    };

    const mockApiClient = {
      get: vi.fn().mockImplementation((url) => {
        if (url === '/projects/123/targets') {
          return Promise.resolve({ status: 'success', targets: [{ id: 'target_1' }] });
        }
        if (url === '/projects/123/findings?page=1') {
          return Promise.resolve({
            status: 'success',
            findings: { current_page: 1, last_page: 1, data: [] }
          });
        }
        if (url === '/projects/123/scans') {
          return Promise.reject(new Error('direct scan endpoint should not be used'));
        }
        return Promise.reject(new Error('Unknown url: ' + url));
      })
    };

    const { ProjectManager } = await import('../../public/js/project-manager.js');
    const pm = new ProjectManager(mockApiClient);

    await pm.lazyLoadProjectMetrics('123');

    expect(window.scannerAPI.getProjectScans).toHaveBeenCalledWith('123');
    expect(window.scannerAPI.getRecentFindingsForProject).toHaveBeenCalledWith('123');
    expect(mockApiClient.get).not.toHaveBeenCalledWith('/projects/123/scans');
    expect(document.querySelector('.project-scans-count-val[data-project-id="123"]').textContent).toBe('1 scan');
    expect(document.querySelector('.project-findings-count-val[data-project-id="123"]').textContent).toBe('1 finding');
    expect(document.querySelector('.project-risk-score-value[data-project-id="123"]').textContent).toBe('0.4 / 100');
    expect(document.querySelector('.project-card-item[data-project-id="123"] .project-risk-level').textContent).toBe('Controlled');
  });
});
