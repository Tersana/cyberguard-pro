/**
 * Sidebar Widget Controller
 * 
 * Dynamically queries active subscription details, projects, targets, and scans usage
 * to display actual values in the sidebar widget under the "System & Scans" section.
 * 
 * Hooks into auth, project, and scan result events to support real-time reactive updates.
 */

const SidebarSystemHealth = {
  _initialized: false,
  _loading: false,

  /**
   * Initialize module listeners
   */
  init() {
    if (this._initialized) return;
    this._initialized = true;

    console.log("[SidebarSystemHealth] Initializing sidebar controller...");

    // Event listeners for real-time reactivity
    document.addEventListener("cyberguard:projectsUpdated", () => {
      console.log("[SidebarSystemHealth] Event: projects updated");
      this.loadData();
    });

    document.addEventListener("cyberguard:subscriptionUpdated", () => {
      console.log("[SidebarSystemHealth] Event: subscription updated");
      this.loadData();
    });

    document.addEventListener("cyberguard:scanResult", () => {
      console.log("[SidebarSystemHealth] Event: scan completed");
      this.loadData();
    });

    window.addEventListener("userLoggedIn", () => {
      console.log("[SidebarSystemHealth] Event: user logged in");
      this.loadData();
    });

    // Run initial data load
    this.loadData();
  },

  /**
   * Retrieve limits and counts, then refresh UI
   */
  async loadData() {
    const token = localStorage.getItem("cyberguard_jwt");
    if (!token) {
      console.log("[SidebarSystemHealth] No authenticated user session, skipping update.");
      this.resetUI();
      return;
    }

    if (this._loading) return;
    this._loading = true;

    try {
      // 1. Fetch current subscription limits (cached or fetched)
      let subscription = window.currentSubscription;
      if (!subscription && typeof BillingAPI !== "undefined") {
        try {
          subscription = await BillingAPI.getCurrentSubscription();
          window.currentSubscription = subscription;
        } catch (err) {
          console.warn("[SidebarSystemHealth] Failed to load subscription details:", err);
        }
      }

      // Extract plan limits
      const limits = {
        maxProjects: subscription?.limits?.max_projects ?? 0,
        maxTargets: subscription?.limits?.max_targets ?? 0,
        maxScansPerMonth: subscription?.limits?.max_scans_per_month ?? 0
      };

      // If limits are missing but we know it's a specific plan, we can fall back to standard limits
      if (!limits.maxProjects && subscription?.plan) {
        const plan = subscription.plan.toLowerCase();
        if (plan === "pro") {
          limits.maxProjects = 10;
          limits.maxTargets = 50;
          limits.maxScansPerMonth = 1000;
        } else if (plan === "starter") {
          limits.maxProjects = 3;
          limits.maxTargets = 10;
          limits.maxScansPerMonth = 100;
        } else if (plan === "free") {
          limits.maxProjects = 1;
          limits.maxTargets = 2;
          limits.maxScansPerMonth = 10;
        }
      }

      // 2. Fetch projects data
      let projects = [];
      if (window.projectManager) {
        try {
          // If we have local projects already, we can use them to save a network round-trip,
          // but we also want to verify they are loaded.
          projects = window.projectManager.projects || [];
          if (projects.length === 0) {
            const { projects: fetchedProjects } = await window.projectManager.fetchProjects();
            projects = fetchedProjects || [];
          }
        } catch (err) {
          console.warn("[SidebarSystemHealth] Failed to load projects list:", err);
        }
      }

      // 3. Query targets and scans in parallel for performance
      let targetsUsed = 0;
      let scansUsed = 0;

      if (projects.length > 0 && window.apiClient) {
        try {
          // Fetch targets & scans for all projects in parallel
          const targetsPromises = projects.map(p => 
            window.projectManager.fetchTargets(p.id)
              .catch(() => [])
          );

          const scansPromises = projects.map(p => 
            window.apiClient.get(`/projects/${p.id}/scans`)
              .then(res => Array.isArray(res.scans) ? res.scans : (Array.isArray(res) ? res : []))
              .catch(() => [])
          );

          const [targetsResults, scansResults] = await Promise.all([
            Promise.all(targetsPromises),
            Promise.all(scansPromises)
          ]);

          // Calculate total target count
          const allTargets = targetsResults.flat();
          targetsUsed = allTargets.length;

          // Filter scans completed in current calendar month
          const allScans = scansResults.flat();
          const now = new Date();
          const startOfMonth = new Date(now.getFullYear(), now.getMonth(), 1);

          const scansThisMonth = allScans.filter(scan => {
            const dateStr = scan.created_at || scan.timestamp || scan.date;
            if (!dateStr) return false;
            const scanDate = new Date(dateStr);
            return !isNaN(scanDate) && scanDate >= startOfMonth && scanDate <= now;
          });

          scansUsed = scansThisMonth.length;
        } catch (err) {
          console.warn("[SidebarSystemHealth] Error loading targets or scans metrics:", err);
        }
      }

      const usage = {
        projectsUsed: projects.length,
        targetsUsed,
        scansUsed
      };

      // 4. Render usage UI
      this.updateUI(limits, usage);

    } catch (error) {
      console.error("[SidebarSystemHealth] Error loading data:", error);
    } finally {
      this._loading = false;
    }
  },

  /**
   * Reset widget numbers to 0
   */
  resetUI() {
    this.updateUI(
      { maxProjects: 0, maxTargets: 0, maxScansPerMonth: 0 },
      { projectsUsed: 0, targetsUsed: 0, scansUsed: 0 }
    );
  },

  /**
   * Map limits and usage values to DOM elements
   */
  updateUI(limits, usage) {
    // 1. Projects Used
    const projectsTextEl = document.getElementById("sidebar-projects-text");
    const projectsBarEl = document.getElementById("sidebar-projects-bar");
    if (projectsTextEl) {
      projectsTextEl.textContent = `${usage.projectsUsed}/${limits.maxProjects || "—"} Projects`;
    }
    if (projectsBarEl) {
      const pct = limits.maxProjects ? Math.min(100, Math.round((usage.projectsUsed / limits.maxProjects) * 100)) : 0;
      projectsBarEl.style.width = `${pct}%`;
    }

    // 2. Active Targets
    const targetsTextEl = document.getElementById("sidebar-targets-text");
    const targetsBarEl = document.getElementById("sidebar-targets-bar");
    if (targetsTextEl) {
      // Prompt note: limits.max_targets in Pro Plan card means Targets per Project.
      // So total limit across all projects = max_targets * max_projects.
      const totalTargetsLimit = (limits.maxTargets && limits.maxProjects) ? (limits.maxTargets * limits.maxProjects) : (limits.maxTargets || 0);
      targetsTextEl.textContent = `${usage.targetsUsed}/${totalTargetsLimit || "—"} Monitored`;
      
      if (targetsBarEl) {
        const pct = totalTargetsLimit ? Math.min(100, Math.round((usage.targetsUsed / totalTargetsLimit) * 100)) : 0;
        targetsBarEl.style.width = `${pct}%`;
      }
    }

    // 3. Scans Used
    const scansTextEl = document.getElementById("sidebar-scans-text");
    const scansBarEl = document.getElementById("sidebar-scans-bar");
    if (scansTextEl) {
      scansTextEl.textContent = `${usage.scansUsed}/${limits.maxScansPerMonth ? formatNumber(limits.maxScansPerMonth) : "—"} Used`;
    }
    if (scansBarEl) {
      const pct = limits.maxScansPerMonth ? Math.min(100, Math.round((usage.scansUsed / limits.maxScansPerMonth) * 100)) : 0;
      scansBarEl.style.width = `${pct}%`;
    }
  }
};

// Helper function to format numbers with commas (e.g. 1000 -> 1,000)
function formatNumber(num) {
  if (num == null) return "0";
  return num.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
}

// Auto-initialize on ready
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", () => SidebarSystemHealth.init());
} else {
  SidebarSystemHealth.init();
}
