/**
 * Notifications Settings Tab Module
 * Handles editing user email alert and report preferences
 */

class NotificationSettings {
    constructor() {
        this.initialState = {
            securityAlerts: true,
            weeklyReports: true,
            productUpdates: false
        };
        this.currentState = { ...this.initialState };
        this.isDirty = false;
    }

    init() {
        this.loadInitialData();
        this.renderForm();
        this.setupEventListeners();
        this.checkDirtyState();
    }

    loadInitialData() {
        const user = window.authManager.getCurrentUser() || {};
        const prefs = user.preferences || {};

        this.initialState = {
            securityAlerts: prefs.notifications !== undefined ? !!prefs.notifications : true,
            weeklyReports: prefs.reports !== undefined ? !!prefs.reports : true,
            productUpdates: prefs.updates !== undefined ? !!prefs.updates : false
        };
        this.currentState = { ...this.initialState };
    }

    renderForm() {
        const pane = document.getElementById("pane-notifications");
        if (!pane) return;

        pane.innerHTML = `
            <form id="notification-settings-form" class="space-y-6" onsubmit="return false;">
                <p class="text-sm text-slate-400 mb-6">
                    Configure how and when you receive email notifications from CyberGuard.
                </p>

                <div class="space-y-4">
                    <!-- Security Alerts -->
                    <div class="flex items-center justify-between p-4 rounded-xl border border-white/5 bg-slate-900/20">
                        <div class="space-y-1">
                            <h5 class="text-sm font-semibold text-white">Critical Security Alerts</h5>
                            <p class="text-xs text-slate-400">Receive instant alerts for suspicious logins, 2FA status modifications, and system anomalies.</p>
                        </div>
                        <label class="settings-switch">
                            <input type="checkbox" id="notify-security" ${this.currentState.securityAlerts ? "checked" : ""}>
                            <span class="settings-switch-slider"></span>
                        </label>
                    </div>

                    <!-- Weekly Reports -->
                    <div class="flex items-center justify-between p-4 rounded-xl border border-white/5 bg-slate-900/20">
                        <div class="space-y-1">
                            <h5 class="text-sm font-semibold text-white">Weekly Scan Reports</h5>
                            <p class="text-xs text-slate-400">Get a consolidated summary of scan activities, detected vulnerabilities, and overall security score history.</p>
                        </div>
                        <label class="settings-switch">
                            <input type="checkbox" id="notify-reports" ${this.currentState.weeklyReports ? "checked" : ""}>
                            <span class="settings-switch-slider"></span>
                        </label>
                    </div>

                    <!-- Product Updates -->
                    <div class="flex items-center justify-between p-4 rounded-xl border border-white/5 bg-slate-900/20">
                        <div class="space-y-1">
                            <h5 class="text-sm font-semibold text-white">Product Updates & Tips</h5>
                            <p class="text-xs text-slate-400">Receive announcements about new scanner drivers, UI improvements, and security scanning recommendations.</p>
                        </div>
                        <label class="settings-switch">
                            <input type="checkbox" id="notify-updates" ${this.currentState.productUpdates ? "checked" : ""}>
                            <span class="settings-switch-slider"></span>
                        </label>
                    </div>
                </div>
            </form>
        `;
    }

    setupEventListeners() {
        const pane = document.getElementById("pane-notifications");
        if (!pane) return;

        const securityToggle = document.getElementById("notify-security");
        const reportsToggle = document.getElementById("notify-reports");
        const updatesToggle = document.getElementById("notify-updates");

        [securityToggle, reportsToggle, updatesToggle].forEach(toggle => {
            if (toggle) {
                toggle.addEventListener("change", () => {
                    this.currentState.securityAlerts = securityToggle.checked;
                    this.currentState.weeklyReports = reportsToggle.checked;
                    this.currentState.productUpdates = updatesToggle.checked;
                    this.checkDirtyState();
                });
            }
        });
    }

    checkDirtyState() {
        const dirty = 
            this.currentState.securityAlerts !== this.initialState.securityAlerts ||
            this.currentState.weeklyReports !== this.initialState.weeklyReports ||
            this.currentState.productUpdates !== this.initialState.productUpdates;
            
        this.isDirty = dirty;
        
        document.dispatchEvent(new CustomEvent("settingsTabDirtyChange", {
            detail: { tabId: "notifications", isDirty: dirty }
        }));
    }

    save() {
        try {
            const user = window.authManager.getCurrentUser() || {};
            
            // Sync structure expected by authManager references
            user.preferences = {
                notifications: this.currentState.securityAlerts,
                reports: this.currentState.weeklyReports,
                updates: this.currentState.productUpdates
            };

            // Save to localStorage
            localStorage.setItem("cyberguard_user", JSON.stringify(user));
            
            // Re-update authManager session
            window.authManager.currentUser = user;

            // Reset initial state to current state
            this.initialState = { ...this.currentState };
            this.checkDirtyState();

            CyberNotify.alert("Notification preferences saved.", { type: "success" });
            return true;
        } catch (e) {
            console.error("Failed to save notification preferences:", e);
            CyberNotify.alert("Failed to save notifications configuration.", { type: "error" });
            return false;
        }
    }

    reset() {
        this.currentState = { ...this.initialState };
        this.renderForm();
        this.setupEventListeners();
        this.checkDirtyState();
    }
}

// Bind to window
window.NotificationSettings = new NotificationSettings();
