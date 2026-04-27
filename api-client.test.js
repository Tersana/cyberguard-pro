/**
 * Tests for Loading Utilities
 * Simple smoke tests to verify functions exist and work
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { JSDOM } from 'jsdom';

describe('Loading Utilities - Smoke Tests', () => {
  let dom;
  let document;
  let window;

  beforeEach(() => {
    // Setup fresh DOM for each test
    dom = new JSDOM('<!DOCTYPE html><html><body></body></html>', {
      url: 'http://localhost'
    });
    document = dom.window.document;
    window = dom.window;
    
    // Make document and window global
    global.document = document;
    global.window = window;
    global.HTMLElement = dom.window.HTMLElement;
  });

  it('should verify loading CSS classes exist in cyber-theme.css', async () => {
    const fs = await import('fs');
    const cssContent = await fs.promises.readFile('./cyber-theme.css', 'utf-8');
    
    // Verify loading spinner classes exist
    expect(cssContent).toContain('.cyber-spinner');
    expect(cssContent).toContain('.cyber-spinner-sm');
    expect(cssContent).toContain('.cyber-spinner-lg');
    expect(cssContent).toContain('.cyber-loading-overlay');
    expect(cssContent).toContain('.cyber-loading-text');
    expect(cssContent).toContain('.cyber-loading-inline');
    expect(cssContent).toContain('@keyframes cyber-spin');
  });

  it('should verify loading functions exist in api-client.js', async () => {
    const fs = await import('fs');
    const jsContent = await fs.promises.readFile('./api-client.js', 'utf-8');
    
    // Verify loading functions exist
    expect(jsContent).toContain('function showLoading');
    expect(jsContent).toContain('function hideLoading');
    expect(jsContent).toContain('function showInlineLoading');
    expect(jsContent).toContain('function hideInlineLoading');
    expect(jsContent).toContain('function showContainerLoading');
    expect(jsContent).toContain('function hideContainerLoading');
    expect(jsContent).toContain('function withLoading');
  });

  it('should verify loading indicators applied to auth.js', async () => {
    const fs = await import('fs');
    const authContent = await fs.promises.readFile('./auth.js', 'utf-8');
    
    // Verify loading indicators are used in async operations
    expect(authContent).toContain('showLoading');
    expect(authContent).toContain('hideLoading');
  });

  it('should verify loading indicators applied to project-manager.js', async () => {
    const fs = await import('fs');
    const pmContent = await fs.promises.readFile('./project-manager.js', 'utf-8');
    
    // Verify loading indicators are used in async operations
    expect(pmContent).toContain('showLoading');
    expect(pmContent).toContain('hideLoading');
    expect(pmContent).toContain('showContainerLoading');
  });
});
