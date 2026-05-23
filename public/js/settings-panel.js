/**
 * CyberGuard Pro — Main Settings Panel Controller
 * Handles modal display, tab navigation, dirty state coordination, focus traps, and initials sync.
 */

class SettingsPanel {
    constructor() {
        this.isOpen = false;
        this.activeTabId = "profile";
        this.dirtyRegistry = {
            profile: false,
            security: false,
            notifications: false,
            appearance: false
        };
        this.focusedElementBeforeOpen = null;
    }

    init() {
        this.setupTabNavigation();
        this.setupModalControls();
        this.setupDirtyStateListeners();
        this.updateNavbarTrigger();
    }

    // Modal Display Controls
    open() {
        if (this.isOpen) return;
        
        // Track active element to restore focus later (Accessibility)
        this.focusedElementBeforeOpen = document.activeElement;

        const modal = document.getElementById("settings-modal");
        if (modal) {
            modal.classList.remove("hidden");
            this.isOpen = true;
            document.body.style.overflow = "hidden"; // disable background scrolling

            // Switch to profile tab by default on open
            this.switchTab("profile");
            
            // Initialize tab modules
            window.ProfileSettings.init();
            window.SecuritySettings.init();
            window.NotificationSettings.init();
            window.AppearanceSettings.init();
            if (window.BillingSettings) window.BillingSettings.init();
            window.AccountSettings.init();

            // Set focus inside the modal for screen readers (Focus Trap)
            this.setupFocusTrap();
        }
    }

    close() {
        if (!this.isOpen) return;

        // Check if there are unsaved changes
        if (this.hasUnsavedChanges()) {
            // Re-use CyberNotify confirm if exists, else standard confirm
            if (window.CyberNotify && typeof window.CyberNotify.confirm === "function") {
                window.CyberNotify.confirm(
                    "You have unsaved changes. Discard changes and close settings?",
                    () => this.forceClose()
                );
            } else {
                if (confirm("You have unsaved changes. Are you sure you want to discard them?")) {
                    this.forceClose();
                }
            }
        } else {
            this.forceClose();
        }
    }

    forceClose() {
        const modal = document.getElementById("settings-modal");
        if (modal) {
            modal.classList.add("hidden");
            this.isOpen = false;
            document.body.style.overflow = ""; // restore scrolling
            
            // Discard any unsaved local drafts and reset modules
            window.ProfileSettings.reset();
            window.SecuritySettings.reset();
            window.NotificationSettings.reset();
            window.AppearanceSettings.reset();

            // Restore focus (Accessibility)
            if (this.focusedElementBeforeOpen) {
                this.focusedElementBeforeOpen.focus();
            }
            
            this.updateDirtyBarVisibility();
        }
    }

    hasUnsavedChanges() {
        return Object.values(this.dirtyRegistry).some(isDirty => isDirty === true);
    }

    // Left Tab Switcher
    setupTabNavigation() {
        const navItems = document.querySelectorAll(".settings-nav-item");
        navItems.forEach(item => {
            item.addEventListener("click", () => {
                const tabId = item.getAttribute("data-tab");
                if (tabId) {
                    this.switchTab(tabId);
                }
            });
        });
    }

    switchTab(tabId) {
        this.activeTabId = tabId;

        // Update nav item active states
        const navItems = document.querySelectorAll(".settings-nav-item");
        navItems.forEach(item => {
            if (item.getAttribute("data-tab") === tabId) {
                item.classList.add("active");
                item.setAttribute("aria-selected", "true");
            } else {
                item.classList.remove("active");
                item.setAttribute("aria-selected", "false");
            }
        });

        // Update tab pane active states
        const panes = document.querySelectorAll(".settings-tab-pane");
        panes.forEach(pane => {
            if (pane.id === `pane-${tabId}`) {
                pane.classList.add("active");
            } else {
                pane.classList.remove("active");
            }
        });

        // Accessibility announcement helper
        this.announceTabChange(tabId);
    }

    announceTabChange(tabId) {
        const label = tabId.charAt(0).toUpperCase() + tabId.slice(1);
        const liveRegion = document.createElement("div");
        liveRegion.setAttribute("role", "status");
        liveRegion.setAttribute("aria-live", "polite");
        liveRegion.className = "sr-only";
        liveRegion.textContent = `${label} settings loaded`;
        document.body.appendChild(liveRegion);
        setTimeout(() => liveRegion.remove(), 1000);
    }

    setupModalControls() {
        const trigger = document.getElementById("navbar-profile-trigger");
        const closeBtn = document.getElementById("settings-close-btn");
        const modal = document.getElementById("settings-modal");

        if (trigger) {
            trigger.addEventListener("click", () => this.open());
        }

        if (closeBtn) {
            closeBtn.addEventListener("click", () => this.close());
        }

        // Close on ESC keypress
        document.addEventListener("keydown", (e) => {
            if (e.key === "Escape" && this.isOpen) {
                // Ignore if any overlay submodal is open (like delete account modal)
                const deleteModal = document.getElementById("delete-account-confirm-modal");
                const twofaDisableDialog = document.getElementById("settings-2fa-disable-dialog");
                
                const isSubModalOpen = 
                    (deleteModal && !deleteModal.classList.contains("hidden")) ||
                    (twofaDisableDialog && !twofaDisableDialog.classList.contains("hidden"));

                if (!isSubModalOpen) {
                    this.close();
                }
            }
        });

        // Close on clicking backdrop
        if (modal) {
            modal.addEventListener("click", (e) => {
                if (e.target === modal) {
                    this.close();
                }
            });
        }
    }

    // Dirty state management
    setupDirtyStateListeners() {
        document.addEventListener("settingsTabDirtyChange", (e) => {
            const { tabId, isDirty } = e.detail;
            this.dirtyRegistry[tabId] = isDirty;
            this.updateDirtyBarVisibility();
        });

        // Setup save/discard actions inside the dirty state overlay bar
        const saveBtn = document.getElementById("settings-dirty-save-btn");
        const discardBtn = document.getElementById("settings-dirty-discard-btn");

        if (saveBtn) {
            saveBtn.addEventListener("click", () => this.saveAllDirtyTabs());
        }

        if (discardBtn) {
            discardBtn.addEventListener("click", () => this.discardAllDirtyTabs());
        }
    }

    updateDirtyBarVisibility() {
        const bar = document.getElementById("settings-dirty-bar");
        if (!bar) return;

        if (this.hasUnsavedChanges()) {
            bar.classList.remove("hidden");
        } else {
            bar.classList.add("hidden");
        }
    }

    saveAllDirtyTabs() {
        let success = true;

        if (this.dirtyRegistry.profile) {
            success = success && window.ProfileSettings.save();
        }
        if (this.dirtyRegistry.security) {
            success = success && window.SecuritySettings.savePassword();
        }
        if (this.dirtyRegistry.notifications) {
            success = success && window.NotificationSettings.save();
        }
        if (this.dirtyRegistry.appearance) {
            success = success && window.AppearanceSettings.save();
        }

        if (success) {
            this.updateDirtyBarVisibility();
        }
    }

    discardAllDirtyTabs() {
        if (this.dirtyRegistry.profile) window.ProfileSettings.reset();
        if (this.dirtyRegistry.security) window.SecuritySettings.reset();
        if (this.dirtyRegistry.notifications) window.NotificationSettings.reset();
        if (this.dirtyRegistry.appearance) window.AppearanceSettings.reset();

        this.updateDirtyBarVisibility();
        CyberNotify.alert("Unsaved changes discarded.", { type: "info" });
    }

    // Synchronize Top Navbar trigger avatar & text
    updateNavbarTrigger() {
        const user = window.authManager.getCurrentUser() || {};
        const fullName = user.fullName || user.name || "Mohamed Gamal";
        
        // Calculate initials fallback
        const parts = fullName.trim().split(/\s+/);
        let initials = "MG";
        if (parts.length >= 2) {
            initials = (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
        } else if (parts.length === 1 && parts[0].length >= 2) {
            initials = parts[0].substring(0, 2).toUpperCase();
        }

        // Apply initials
        const initialsEl = document.getElementById("navbarUserInitials");
        if (initialsEl) initialsEl.textContent = initials;

        // Apply name/email
        const nameEl = document.getElementById("userName");
        const emailEl = document.getElementById("userEmail");
        if (nameEl) nameEl.textContent = fullName;
        if (emailEl) emailEl.textContent = user.email || "gerry.mohamed951@gmail.com";

        // Handle profile image if uploaded
        const avatarContainer = document.getElementById("navbar-avatar-container");
        if (avatarContainer) {
            const avatarUrl = user.avatar || localStorage.getItem("cyberguard_user_avatar") || "";
            if (avatarUrl) {
                avatarContainer.innerHTML = `<img src="${avatarUrl}" alt="Avatar" class="w-full h-full object-cover">`;
            } else {
                avatarContainer.innerHTML = `<span class="text-xs font-bold text-white" id="navbarUserInitials">${initials}</span>`;
            }
        }
    }

    // Accessibility Keyboard Focus Trap
    setupFocusTrap() {
        const modal = document.getElementById("settings-modal");
        if (!modal) return;

        const focusableElementsSelector = 'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])';
        const firstFocusableElement = modal.querySelector(focusableElementsSelector);
        
        if (firstFocusableElement) {
            // Set initial focus
            firstFocusableElement.focus();
        }

        modal.addEventListener("keydown", (e) => {
            const isTabPressed = e.key === "Tab";
            if (!isTabPressed) return;

            const focusableContent = modal.querySelectorAll(focusableElementsSelector);
            // filter out hidden/disabled elements
            const focusableElements = Array.from(focusableContent).filter(el => {
                return !el.disabled && el.offsetParent !== null;
            });

            if (focusableElements.length === 0) return;

            const firstElement = focusableElements[0];
            const lastElement = focusableElements[focusableElements.length - 1];

            if (e.shiftKey) { // Shift + Tab
                if (document.activeElement === firstElement) {
                    lastElement.focus();
                    e.preventDefault();
                }
            } else { // Tab
                if (document.activeElement === lastElement) {
                    firstElement.focus();
                    e.preventDefault();
                }
            }
        });
    }
}

// Bind and initialize on load
document.addEventListener("DOMContentLoaded", () => {
    window.SettingsPanel = new SettingsPanel();
    window.SettingsPanel.init();
});
