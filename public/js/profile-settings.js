/**
 * Profile Settings Tab Module
 * Handles editing user name, role/title, phone, and profile photo drafts
 */

class ProfileSettings {
    constructor() {
        this.initialState = {
            fullName: "",
            jobTitle: "",
            phoneNumber: "",
            avatar: null
        };
        this.currentState = { ...this.initialState };
        this.isDirty = false;
        this.photoFile = null;
    }

    init() {
        this.loadInitialData();
        this.renderForm();
        this.setupEventListeners();
        this.checkDirtyState();
    }

    loadInitialData() {
        const user = window.authManager.getCurrentUser() || {};
        
        // Expose initials calculation logic to ensure fallback works
        const fullName = user.fullName || user.name || "Mohamed Gamal";
        const jobTitle = user.jobTitle || user.job_title || user.job_tittle || "Security Engineer";
        const phoneNumber = user.phoneNumber || user.phone || "";
        const avatar = user.avatar || user.avatarUrl || localStorage.getItem("cyberguard_user_avatar") || "";

        this.initialState = {
            fullName: fullName,
            jobTitle: jobTitle,
            phoneNumber: phoneNumber,
            avatar: avatar
        };
        this.currentState = { ...this.initialState };
    }

    renderForm() {
        const pane = document.getElementById("pane-profile");
        if (!pane) return;

        // Generate initials
        const initials = this.getInitials(this.currentState.fullName);

        pane.innerHTML = `
            <form id="profile-settings-form" class="space-y-6" onsubmit="return false;">
                <!-- Avatar Upload Section -->
                <div class="settings-avatar-section">
                    <div class="settings-avatar-big" id="profile-avatar-display">
                        ${this.currentState.avatar 
                            ? `<img src="${this.currentState.avatar}" alt="Avatar Preview" id="profile-avatar-img">`
                            : `<span id="profile-avatar-initials">${initials}</span>`
                        }
                    </div>
                    <div class="settings-avatar-actions">
                        <div class="settings-avatar-actions-row">
                            <input type="file" id="profile-photo-input" accept="image/*" class="hidden">
                            <button type="button" id="profile-upload-btn" class="cyber-btn-ghost text-xs flex items-center gap-1.5" style="opacity: 0.6; cursor: not-allowed;" disabled>
                                <span class="material-symbols-outlined" style="font-size: 1rem;">upload</span>
                                Upload Photo
                                <span class="coming-soon-badge">Coming Soon</span>
                            </button>
                            ${this.currentState.avatar 
                                ? `<button type="button" id="profile-remove-photo-btn" class="cyber-btn-danger text-xs py-1 px-2.5 rounded-lg flex items-center gap-1">
                                    <span class="material-symbols-outlined" style="font-size: 1rem;">delete</span>
                                    Remove
                                   </button>`
                                : ""
                            }
                        </div>
                        <p class="text-xs text-slate-500 mt-2">JPG, PNG or GIF. Max size of 2MB.</p>
                    </div>
                </div>

                <div class="settings-divider my-6" style="height: 1px; background-color: var(--cg-border);"></div>

                <!-- Display Name -->
                <div class="settings-form-group">
                    <label for="profile-name">Display Name <span class="required">*</span></label>
                    <div class="input-wrapper">
                        <input type="text" id="profile-name" class="cyber-input p-3 rounded-lg text-sm" value="${this.currentState.fullName}" required autocomplete="name">
                    </div>
                </div>

                <!-- Job Title / Role -->
                <div class="settings-form-group">
                    <label for="profile-role">Job Title / Role</label>
                    <div class="input-wrapper">
                        <input type="text" id="profile-role" class="cyber-input p-3 rounded-lg text-sm" value="${this.currentState.jobTitle}" autocomplete="organization-title">
                    </div>
                </div>

                <!-- Phone Number -->
                <div class="settings-form-group">
                    <label for="profile-phone">Phone Number</label>
                    <div class="input-wrapper">
                        <input type="tel" id="profile-phone" class="cyber-input p-3 rounded-lg text-sm" value="${this.currentState.phoneNumber}" autocomplete="tel" placeholder="+1 (555) 000-0000">
                    </div>
                </div>
            </form>
        `;
    }

    setupEventListeners() {
        const form = document.getElementById("profile-settings-form");
        if (!form) return;

        const nameInput = document.getElementById("profile-name");
        const roleInput = document.getElementById("profile-role");
        const phoneInput = document.getElementById("profile-phone");
        const photoInput = document.getElementById("profile-photo-input");
        const removePhotoBtn = document.getElementById("profile-remove-photo-btn");

        // Listen for input changes to track dirty state
        [nameInput, roleInput, phoneInput].forEach(input => {
            if (input) {
                input.addEventListener("input", () => {
                    this.currentState.fullName = nameInput.value.trim();
                    this.currentState.jobTitle = roleInput.value.trim();
                    this.currentState.phoneNumber = phoneInput.value.trim();
                    this.checkDirtyState();
                    
                    // Live update initials preview if no avatar exists
                    const initialsSpan = document.getElementById("profile-avatar-initials");
                    if (initialsSpan && !this.currentState.avatar) {
                        initialsSpan.textContent = this.getInitials(this.currentState.fullName);
                    }
                });
            }
        });

        // Photo Upload Handling (Mock - is disabled but we construct picker logic just in case backend is enabled)
        if (photoInput) {
            photoInput.addEventListener("change", (e) => {
                const file = e.target.files[0];
                if (!file) return;

                if (file.size > 2 * 1024 * 1024) {
                    CyberNotify.alert("File size exceeds 2MB limit.", { type: "error" });
                    return;
                }

                if (!file.type.startsWith("image/")) {
                    CyberNotify.alert("Only image files are allowed.", { type: "error" });
                    return;
                }

                const reader = new FileReader();
                reader.onload = (event) => {
                    this.currentState.avatar = event.target.result;
                    this.checkDirtyState();
                    this.renderAvatarPreview();
                };
                reader.readAsDataURL(file);
            });
        }

        // Photo Remove
        if (removePhotoBtn) {
            removePhotoBtn.addEventListener("click", () => {
                this.currentState.avatar = "";
                this.checkDirtyState();
                this.renderAvatarPreview();
            });
        }
    }

    renderAvatarPreview() {
        const container = document.getElementById("profile-avatar-display");
        if (!container) return;

        if (this.currentState.avatar) {
            container.innerHTML = `<img src="${this.currentState.avatar}" alt="Avatar Preview" id="profile-avatar-img">`;
        } else {
            const initials = this.getInitials(this.currentState.fullName);
            container.innerHTML = `<span id="profile-avatar-initials">${initials}</span>`;
        }

        // Re-setup remove button visibility dynamically
        const uploadRow = document.querySelector(".settings-avatar-actions-row");
        if (uploadRow) {
            let removeBtn = document.getElementById("profile-remove-photo-btn");
            if (this.currentState.avatar && !removeBtn) {
                removeBtn = document.createElement("button");
                removeBtn.type = "button";
                removeBtn.id = "profile-remove-photo-btn";
                removeBtn.className = "cyber-btn-danger text-xs py-1 px-2.5 rounded-lg flex items-center gap-1";
                removeBtn.innerHTML = `
                    <span class="material-symbols-outlined" style="font-size: 1rem;">delete</span>
                    Remove
                `;
                removeBtn.addEventListener("click", () => {
                    this.currentState.avatar = "";
                    this.checkDirtyState();
                    this.renderAvatarPreview();
                });
                uploadRow.appendChild(removeBtn);
            } else if (!this.currentState.avatar && removeBtn) {
                removeBtn.remove();
            }
        }
    }

    getInitials(fullName) {
        const parts = fullName.trim().split(/\s+/);
        let initials = "";
        
        if (parts.length >= 2) {
            initials = (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
        } else if (parts.length === 1 && parts[0].length >= 2) {
            initials = parts[0].substring(0, 2).toUpperCase();
        } else {
            initials = fullName.substring(0, 2).toUpperCase() || "U";
        }
        return initials;
    }

    checkDirtyState() {
        const dirty = 
            this.currentState.fullName !== this.initialState.fullName ||
            this.currentState.jobTitle !== this.initialState.jobTitle ||
            this.currentState.phoneNumber !== this.initialState.phoneNumber ||
            this.currentState.avatar !== this.initialState.avatar;
            
        this.isDirty = dirty;
        
        // Dispatch custom event to notify main Settings Panel
        document.dispatchEvent(new CustomEvent("settingsTabDirtyChange", {
            detail: { tabId: "profile", isDirty: dirty }
        }));
    }

    save() {
        if (!this.currentState.fullName) {
            CyberNotify.alert("Display Name is required.", { type: "error" });
            return false;
        }

        try {
            const user = window.authManager.getCurrentUser() || {};
            
            // Update in-memory user
            user.fullName = this.currentState.fullName;
            user.name = this.currentState.fullName; // fallback for duplicate key
            user.jobTitle = this.currentState.jobTitle;
            user.phoneNumber = this.currentState.phoneNumber;
            
            // Save avatar reference locally (simulate file upload endpoint draft)
            if (this.currentState.avatar) {
                localStorage.setItem("cyberguard_user_avatar", this.currentState.avatar);
                user.avatar = this.currentState.avatar;
            } else {
                localStorage.removeItem("cyberguard_user_avatar");
                delete user.avatar;
                delete user.avatarUrl;
            }

            // Save to localStorage
            localStorage.setItem("cyberguard_user", JSON.stringify(user));
            
            // Re-update authManager session
            window.authManager.currentUser = user;
            
            // Trigger UI update across header/sidebar
            window.authManager.updateUI();
            
            // Update initials/avatar in top navbar trigger
            if (window.SettingsPanel) {
                window.SettingsPanel.updateNavbarTrigger();
            }

            // Reset initial state to new state
            this.initialState = { ...this.currentState };
            this.checkDirtyState();

            CyberNotify.alert("Profile updated successfully.", { type: "success" });
            return true;
        } catch (e) {
            console.error("Failed to save profile changes:", e);
            CyberNotify.alert("An error occurred while saving profile.", { type: "error" });
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
window.ProfileSettings = new ProfileSettings();
