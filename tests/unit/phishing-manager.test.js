/**
 * Unit Tests — PhishingManager
 *
 * Validates the phishing-simulation frontend module against the API contract in
 * docs/PHISHING_WORKFLOW_v2.md:
 *   - API wrapper methods hit the correct endpoint + method + payload
 *   - Risk-level banding and rate math (spec §5.1, §6.7)
 *   - CSV import sends multipart FormData + enforces the 5 MB limit
 *   - Owner-only Permissions sub-nav gating
 *   - Error extraction + surfacing
 *   - List rendering (happy / empty / error states)
 *
 * Recipe mirrors tests/unit/organization-manager.test.js: build a JSDOM, mock
 * window.apiClient, eval the source, then drive the class directly.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { JSDOM } from "jsdom";
import fs from "fs";
import path from "path";

describe("PhishingManager", () => {
  let dom;
  let window;
  let document;
  let api;
  let pm;

  beforeEach(() => {
    dom = new JSDOM(`<!DOCTYPE html><html><body></body></html>`, {
      url: "http://localhost",
      runScripts: "dangerously",
      resources: "usable",
    });
    window = dom.window;
    document = window.document;

    global.window = window;
    global.document = document;
    global.localStorage = window.localStorage;

    // Prevent the auto-bootstrap IIFE from doing anything.
    window.runAuthGuard = () => false;

    // Mock CyberNotify (toast/confirm)
    window.CyberNotify = {
      alert: vi.fn(),
      confirm: vi.fn((_msg, cb) => cb(true)),
    };

    // Mock apiClient — all methods resolve to {} by default.
    api = {
      get: vi.fn().mockResolvedValue({}),
      post: vi.fn().mockResolvedValue({}),
      put: vi.fn().mockResolvedValue({}),
      delete: vi.fn().mockResolvedValue({}),
      _request: vi.fn().mockResolvedValue({}),
    };
    window.apiClient = api;

    // Load source
    const src = fs.readFileSync(
      path.resolve(__dirname, "../../public/js/phishing.js"),
      "utf8"
    );
    window.eval(src);

    pm = new window.PhishingManager(api);
  });

  afterEach(() => {
    delete global.window;
    delete global.document;
    delete global.localStorage;
    vi.clearAllMocks();
    vi.restoreAllMocks();
  });

  // ─── API wrappers ──────────────────────────────────────────────────────────

  describe("campaign endpoints", () => {
    it("listCampaigns → GET /phishing/campaigns", () => {
      pm.listCampaigns();
      expect(api.get).toHaveBeenCalledWith("/phishing/campaigns");
    });
    it("getCampaign → GET /phishing/campaigns/{id}", () => {
      pm.getCampaign("c1");
      expect(api.get).toHaveBeenCalledWith("/phishing/campaigns/c1");
    });
    it("createCampaign → POST with payload", () => {
      const payload = { name: "Q3", template_id: "t1", target_type: "all" };
      pm.createCampaign(payload);
      expect(api.post).toHaveBeenCalledWith("/phishing/campaigns", payload);
    });
    it("updateCampaign → PUT /phishing/campaigns/{id}", () => {
      pm.updateCampaign("c1", { name: "x" });
      expect(api.put).toHaveBeenCalledWith("/phishing/campaigns/c1", { name: "x" });
    });
    it("launchCampaign → POST .../launch", () => {
      pm.launchCampaign("c1");
      expect(api.post).toHaveBeenCalledWith("/phishing/campaigns/c1/launch", {});
    });
    it("cancelCampaign → POST .../cancel", () => {
      pm.cancelCampaign("c1");
      expect(api.post).toHaveBeenCalledWith("/phishing/campaigns/c1/cancel", {});
    });
    it("getCampaignReport → GET .../report", () => {
      pm.getCampaignReport("c1");
      expect(api.get).toHaveBeenCalledWith("/phishing/campaigns/c1/report");
    });
  });

  describe("template endpoints", () => {
    it("listTemplates() → GET /phishing/templates (no query)", () => {
      pm.listTemplates();
      expect(api.get).toHaveBeenCalledWith("/phishing/templates");
    });
    it("listTemplates('email') → GET with type query", () => {
      pm.listTemplates("email");
      expect(api.get).toHaveBeenCalledWith("/phishing/templates?type=email");
    });
    it("createTemplate → POST", () => {
      pm.createTemplate({ name: "t" });
      expect(api.post).toHaveBeenCalledWith("/phishing/templates", { name: "t" });
    });
    it("deleteTemplate → DELETE /phishing/templates/{id}", () => {
      pm.deleteTemplate("t1");
      expect(api.delete).toHaveBeenCalledWith("/phishing/templates/t1");
    });
  });

  describe("employee endpoints", () => {
    it("listEmployees builds a filtered query string", () => {
      pm.listEmployees({ department: "IT", search: "ali", per_page: 25, page: 2 });
      expect(api.get).toHaveBeenCalledWith(
        "/phishing/employees?department=IT&search=ali&per_page=25&page=2"
      );
    });
    it("listEmployees with no filters → bare endpoint", () => {
      pm.listEmployees({});
      expect(api.get).toHaveBeenCalledWith("/phishing/employees");
    });
    it("createEmployee → POST", () => {
      pm.createEmployee({ name: "A", email: "a@x.com" });
      expect(api.post).toHaveBeenCalledWith("/phishing/employees", {
        name: "A",
        email: "a@x.com",
      });
    });
    it("deleteEmployee → DELETE", () => {
      pm.deleteEmployee("e1");
      expect(api.delete).toHaveBeenCalledWith("/phishing/employees/e1");
    });
    it("importEmployees posts multipart FormData with the file field", () => {
      const blob = new window.Blob(["name,email\nA,a@x.com"], { type: "text/csv" });
      pm.importEmployees(blob);
      expect(api.post).toHaveBeenCalledTimes(1);
      const [endpoint, body] = api.post.mock.calls[0];
      expect(endpoint).toBe("/phishing/employees/import");
      expect(body instanceof window.FormData).toBe(true);
      expect(body.get("file")).toBeTruthy();
    });
  });

  describe("domain endpoints", () => {
    it("addDomain → POST with { domain }", () => {
      pm.addDomain("acme.com");
      expect(api.post).toHaveBeenCalledWith("/phishing/domains", { domain: "acme.com" });
    });
    it("getDomainDns → GET .../dns-records", () => {
      pm.getDomainDns("d1");
      expect(api.get).toHaveBeenCalledWith("/phishing/domains/d1/dns-records");
    });
    it("verifyDomain → POST .../verify", () => {
      pm.verifyDomain("d1");
      expect(api.post).toHaveBeenCalledWith("/phishing/domains/d1/verify", {});
    });
    it("deleteDomain → DELETE", () => {
      pm.deleteDomain("d1");
      expect(api.delete).toHaveBeenCalledWith("/phishing/domains/d1");
    });
  });

  describe("permission endpoints", () => {
    it("grantPermissions → PUT with permissions array", () => {
      pm.grantPermissions("u1", ["phishing.templates.manage"]);
      expect(api.put).toHaveBeenCalledWith("/phishing/permissions/u1", {
        permissions: ["phishing.templates.manage"],
      });
    });
    it("revokePermission uses _request DELETE with a body (delete() sends none)", () => {
      pm.revokePermission("u1", "phishing.reports.view");
      expect(api._request).toHaveBeenCalledWith(
        "DELETE",
        "/phishing/permissions/u1",
        { permission: "phishing.reports.view" }
      );
      expect(api.delete).not.toHaveBeenCalled();
    });
  });

  describe("report endpoints", () => {
    it("reportOverview → GET /phishing/reports/overview", () => {
      pm.reportOverview();
      expect(api.get).toHaveBeenCalledWith("/phishing/reports/overview");
    });
    it("reportEmployeesRisk → GET /phishing/reports/employees/risk", () => {
      pm.reportEmployeesRisk();
      expect(api.get).toHaveBeenCalledWith("/phishing/reports/employees/risk");
    });
    it("reportDepartments → GET /phishing/reports/departments", () => {
      pm.reportDepartments();
      expect(api.get).toHaveBeenCalledWith("/phishing/reports/departments");
    });
  });

  // ─── Risk banding & rate math ──────────────────────────────────────────────

  describe("riskLevelFromScore (spec §5.1 boundaries)", () => {
    it("0 → safe", () => expect(pm.riskLevelFromScore(0)).toBe("safe"));
    it("1 → low", () => expect(pm.riskLevelFromScore(1)).toBe("low"));
    it("5 → low", () => expect(pm.riskLevelFromScore(5)).toBe("low"));
    it("6 → medium", () => expect(pm.riskLevelFromScore(6)).toBe("medium"));
    it("15 → medium", () => expect(pm.riskLevelFromScore(15)).toBe("medium"));
    it("16 → high", () => expect(pm.riskLevelFromScore(16)).toBe("high"));
    it("negative / null defaults to safe", () => {
      expect(pm.riskLevelFromScore(-3)).toBe("safe");
      expect(pm.riskLevelFromScore(null)).toBe("safe");
    });
  });

  describe("formatRate", () => {
    it("3 of 10 → 30", () => expect(pm.formatRate(3, 10)).toBe(30));
    it("1 of 3 → 33.3 (one decimal)", () => expect(pm.formatRate(1, 3)).toBe(33.3));
    it("divide-by-zero → 0", () => expect(pm.formatRate(5, 0)).toBe(0));
  });

  // ─── Error handling ─────────────────────────────────────────────────────────

  describe("_errorMessage extraction", () => {
    it("prefers error.data.message", () => {
      expect(pm._errorMessage({ data: { message: "A" } })).toBe("A");
    });
    it("falls back to errors[0].message", () => {
      expect(pm._errorMessage({ errors: [{ message: "B" }] })).toBe("B");
    });
    it("falls back to error.message", () => {
      expect(pm._errorMessage({ message: "C" })).toBe("C");
    });
    it("uses the fallback when nothing matches", () => {
      expect(pm._errorMessage(null, "fb")).toBe("fb");
    });
  });

  it("_handleError surfaces a toast via CyberNotify", () => {
    pm._handleError({ message: "boom" }, "fallback");
    expect(window.CyberNotify.alert).toHaveBeenCalledWith("boom", { type: "error" });
  });

  // ─── Owner-only Permissions gating ──────────────────────────────────────────

  describe("_applyRoleVisibility", () => {
    beforeEach(() => {
      document.body.innerHTML = `<button id="phishing-subnav-permissions"></button>`;
    });
    it("hides Permissions for a non-owner admin", () => {
      window.organizationManager = { getActiveOrg: () => ({ role: "admin" }), getActiveOrgId: () => "o1" };
      pm._applyRoleVisibility();
      expect(document.getElementById("phishing-subnav-permissions").style.display).toBe("none");
    });
    it("shows Permissions for the Owner", () => {
      window.organizationManager = { getActiveOrg: () => ({ role: "owner" }), getActiveOrgId: () => "o1" };
      pm._applyRoleVisibility();
      expect(document.getElementById("phishing-subnav-permissions").style.display).toBe("");
    });
    it("shows Permissions when role is unknown (fall back to backend 403)", () => {
      window.organizationManager = undefined;
      pm._applyRoleVisibility();
      expect(document.getElementById("phishing-subnav-permissions").style.display).toBe("");
    });
  });

  // ─── CSV import guard ──────────────────────────────────────────────────────

  describe("_doImportEmployees size guard", () => {
    it("rejects a file over 5 MB without calling the API", async () => {
      await pm._doImportEmployees({ size: 6 * 1024 * 1024 });
      expect(api.post).not.toHaveBeenCalled();
      expect(window.CyberNotify.alert).toHaveBeenCalledWith(
        expect.stringContaining("5 MB"),
        { type: "warning" }
      );
    });
  });

  // ─── Rendering ──────────────────────────────────────────────────────────────

  describe("renderCampaigns", () => {
    beforeEach(() => {
      document.body.innerHTML = `<div id="phishing-view-campaigns"></div>`;
    });

    it("renders a card with a Launch button for a draft campaign", async () => {
      api.get.mockResolvedValueOnce({
        campaigns: [
          { id: "c1", name: "Q3 Test", status: "draft", target_type: "all", template: { name: "IT Reset" }, targets_count: 0, clicks_count: 0 },
        ],
      });
      await pm.renderCampaigns();
      const html = document.getElementById("phishing-view-campaigns").innerHTML;
      expect(html).toContain("Q3 Test");
      expect(html).toContain('data-phishing-action="campaign-launch"');
    });

    it("renders an empty state when there are no campaigns", async () => {
      api.get.mockResolvedValueOnce({ campaigns: [] });
      await pm.renderCampaigns();
      expect(document.getElementById("phishing-view-campaigns").innerHTML).toContain("No campaigns yet");
    });

    it("renders an inline error + retry on failure", async () => {
      api.get.mockRejectedValueOnce({ message: "Server error" });
      await pm.renderCampaigns();
      const html = document.getElementById("phishing-view-campaigns").innerHTML;
      expect(html).toContain("Server error");
      expect(html).toContain('data-phishing-action="campaign-refresh"');
    });

    it("running campaigns expose Report + Cancel but not Launch", async () => {
      api.get.mockResolvedValueOnce({
        campaigns: [{ id: "c2", name: "Live", status: "running", target_type: "all", template: {} }],
      });
      await pm.renderCampaigns();
      const html = document.getElementById("phishing-view-campaigns").innerHTML;
      expect(html).toContain('data-phishing-action="campaign-report"');
      expect(html).toContain('data-phishing-action="campaign-cancel"');
      expect(html).not.toContain('data-phishing-action="campaign-launch"');
    });
  });

  describe("renderEmployees risk badge", () => {
    beforeEach(() => {
      document.body.innerHTML = `<div id="phishing-view-employees"></div>`;
    });
    it("derives risk_level from score when the backend omits it", async () => {
      api.get.mockResolvedValueOnce({
        employees: { data: [{ id: "e1", name: "Risky", email: "r@x.com", risk_score: 20 }], current_page: 1, last_page: 1, total: 1, per_page: 50 },
      });
      await pm.renderEmployees();
      const html = document.getElementById("phishing-view-employees").innerHTML;
      expect(html).toContain("Risky");
      expect(html).toContain("high");
    });
  });

  describe("template read-only guard", () => {
    beforeEach(() => {
      document.body.innerHTML = `<div id="phishing-view-templates"></div>`;
    });
    it("global templates render read-only (no edit/delete actions)", async () => {
      api.get.mockResolvedValueOnce({
        templates: [{ id: "g1", name: "Global One", organization_id: null }],
      });
      await pm.renderTemplates();
      const html = document.getElementById("phishing-view-templates").innerHTML;
      expect(html).toContain("Read-only");
      expect(html).not.toContain('data-phishing-action="template-delete"');
    });
    it("org-owned templates expose edit + delete", async () => {
      api.get.mockResolvedValueOnce({
        templates: [{ id: "o1", name: "Mine", organization_id: "org1" }],
      });
      await pm.renderTemplates();
      const html = document.getElementById("phishing-view-templates").innerHTML;
      expect(html).toContain('data-phishing-action="template-edit"');
      expect(html).toContain('data-phishing-action="template-delete"');
    });
  });
});
