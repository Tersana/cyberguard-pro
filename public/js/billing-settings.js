/**
 * Billing Settings Tab Module
 * Coordinator class that delegates loading billing order history to the global loader.
 */

class BillingSettings {
    constructor() {
        this.isDirty = false; // Billing is read-only information, never dirty
    }

    async init() {
        // Call the global loadBillingHistory function defined in dashboard.html
        if (typeof window.loadBillingHistory === "function") {
            await window.loadBillingHistory();
        } else if (typeof loadBillingHistory === "function") {
            await loadBillingHistory();
        }
    }

    reset() {
        // Read-only settings tab
    }
}

// Bind to window
window.BillingSettings = new BillingSettings();
