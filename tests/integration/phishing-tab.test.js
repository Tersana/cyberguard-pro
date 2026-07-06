/**
 * Integration Test — Phishing tab wiring
 *
 * 1. Asserts the real public/dashboard.html carries the Phishing nav item, the
 *    six sub-view panes, the CSS <link>, and the phishing.js <script> in the
 *    correct place.
 * 2. Injects the real #phishing pane markup into a JSDOM, boots PhishingManager
 *    with a mocked apiClient, and verifies the sub-nav switches panes without
 *    leaking console errors.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { JSDOM } from "jsdom";
import fs from "fs";
import path from "path";

const DASHBOARD = fs.readFileSync(
  path.resolve(__dirname, "../../public/dashboard.html"),
  "utf-8"
);
const PHISHING_SRC = fs.readFileSync(
  path.resolve(__dirname, "../../public/js/phishing.js"),
  "utf8"
);

function extractPhishingPane(html) {
  const start = html.indexOf("<!-- PHISHING SIMULATION TAB -->");
  const end = html.indexOf("<!-- END PHISHING SIMULATION TAB -->");
  if (start === -1 || end === -1) return null;
  return html.slice(start, end);
}

describe("dashboard.html phishing wiring", () => {
  it("registers the Phishing nav item", () => {
    expect(DASHBOARD).toContain("switchToTab('phishing')");
    expect(DASHBOARD).toContain(">Phishing<");
  });

  it("includes the six sub-view panes and modal host", () => {
    [
      'id="phishing"',
      'id="phishing-view-campaigns"',
      'id="phishing-view-templates"',
      'id="phishing-view-employees"',
      'id="phishing-view-domains"',
      'id="phishing-view-reports"',
      'id="phishing-view-permissions"',
      'id="phishing-modal-host"',
      'id="phishing-subnav-permissions"',
    ].forEach((needle) => expect(DASHBOARD).toContain(needle));
  });

  it("loads the phishing stylesheet and script", () => {
    expect(DASHBOARD).toContain('href="css/phishing.css"');
    expect(DASHBOARD).toContain('src="js/phishing.js"');
  });

  it("loads phishing.js before the dashboard tab manager", () => {
    const phishingIdx = DASHBOARD.indexOf('src="js/phishing.js"');
    const tabMgrIdx = DASHBOARD.indexOf('src="js/dashboard-tab-manager.js');
    expect(phishingIdx).toBeGreaterThan(-1);
    expect(tabMgrIdx).toBeGreaterThan(-1);
    expect(phishingIdx).toBeLessThan(tabMgrIdx);
  });
});

describe("phishing sub-nav switching", () => {
  let dom;
  let window;
  let document;
  let api;
  let pm;
  let consoleErrors;
  let originalConsoleError;

  beforeEach(() => {
    const pane = extractPhishingPane(DASHBOARD);
    expect(pane).not.toBeNull();

    dom = new JSDOM(`<!DOCTYPE html><html><body>${pane}</body></html>`, {
      url: "http://localhost",
      runScripts: "dangerously",
      resources: "usable",
    });
    window = dom.window;
    document = window.document;

    global.window = window;
    global.document = document;
    global.localStorage = window.localStorage;

    window.runAuthGuard = () => false; // neutralize bootstrap
    window.CyberNotify = { alert: vi.fn(), confirm: vi.fn((_m, cb) => cb(true)) };
    window.organizationManager = { getActiveOrg: () => ({ role: "owner" }), getActiveOrgId: () => "o1" };

    api = {
      get: vi.fn().mockResolvedValue({ campaigns: [], templates: [], employees: { data: [] }, domains: [], permissions: [] }),
      post: vi.fn().mockResolvedValue({}),
      put: vi.fn().mockResolvedValue({}),
      delete: vi.fn().mockResolvedValue({}),
      _request: vi.fn().mockResolvedValue({}),
    };
    window.apiClient = api;

    consoleErrors = [];
    originalConsoleError = console.error;
    console.error = (...args) => {
      consoleErrors.push(args.join(" "));
    };

    window.eval(PHISHING_SRC);
    pm = new window.PhishingManager(api);
  });

  afterEach(() => {
    console.error = originalConsoleError;
    delete global.window;
    delete global.document;
    delete global.localStorage;
    vi.clearAllMocks();
  });

  const flush = () => new Promise((r) => setTimeout(r, 0));

  it("defaults to the Campaigns sub-view on init", async () => {
    pm.init();
    await flush();
    expect(document.getElementById("phishing-view-campaigns").classList.contains("hidden")).toBe(false);
    expect(document.getElementById("phishing-view-templates").classList.contains("hidden")).toBe(true);
    expect(consoleErrors).toEqual([]);
  });

  it("clicking a sub-nav button switches the visible pane", async () => {
    pm.init();
    await flush();

    const templatesBtn = document.querySelector('.phishing-subnav-btn[data-subview="templates"]');
    templatesBtn.click();
    await flush();

    expect(document.getElementById("phishing-view-templates").classList.contains("hidden")).toBe(false);
    expect(document.getElementById("phishing-view-campaigns").classList.contains("hidden")).toBe(true);
    expect(templatesBtn.classList.contains("active")).toBe(true);
    expect(consoleErrors).toEqual([]);
  });

  it("reveals the Owner-only Permissions sub-nav for an owner", async () => {
    pm.init();
    await flush();
    expect(document.getElementById("phishing-subnav-permissions").style.display).toBe("");
  });
});
