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
                    <div class="settings-avatar-big" id="profile-avatar-display"></div>
                    <div class="settings-avatar-actions">
                        <div class="settings-avatar-actions-row">
                            <input type="file" id="profile-photo-input" accept="image/*" class="hidden">
                            <button type="button" id="profile-upload-btn" class="cyber-btn-ghost text-xs flex items-center gap-1.5">
                                <span class="material-symbols-outlined" style="font-size: 1rem;">upload</span>
                                Upload Photo
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
                        <input type="text" id="profile-name" class="cyber-input p-3 rounded-lg text-sm" value="${escapeHtml(this.currentState.fullName)}" required autocomplete="name">
                    </div>
                </div>

                <!-- Job Title / Role -->
                <div class="settings-form-group">
                    <label for="profile-role">Job Title / Role</label>
                    <div class="input-wrapper">
                        <input type="text" id="profile-role" class="cyber-input p-3 rounded-lg text-sm" value="${escapeHtml(this.currentState.jobTitle)}" autocomplete="organization-title">
                    </div>
                </div>

                <!-- Phone Number -->
                <div class="settings-form-group">
                    <label for="profile-phone">Phone Number</label>
                    <div class="input-wrapper">
                        <input type="tel" id="profile-phone" class="cyber-input p-3 rounded-lg text-sm" value="${escapeHtml(this.currentState.phoneNumber)}" autocomplete="tel" placeholder="+1 (555) 000-0000">
                    </div>
                </div>
            </form>
        `;
        // Populate avatar via DOM API (createElement) to guarantee
        // referrerPolicy is set BEFORE src, fixing Google CDN images
        this.renderAvatarPreview();
    }

    setupEventListeners() {
        const form = document.getElementById("profile-settings-form");
        if (!form) return;

        const nameInput = document.getElementById("profile-name");
        const roleInput = document.getElementById("profile-role");
        const phoneInput = document.getElementById("profile-phone");
        const photoInput = document.getElementById("profile-photo-input");
        const removePhotoBtn = document.getElementById("profile-remove-photo-btn");
        const uploadBtn = document.getElementById("profile-upload-btn");

        // Trigger file input click when upload button is clicked
        if (uploadBtn && photoInput) {
            uploadBtn.addEventListener("click", () => {
                photoInput.click();
            });
        }

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

        // Photo Upload Handling
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

                this.photoFile = file;

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
            removePhotoBtn.addEventListener("click", () => this.removePhoto());
        }
    }

    removePhoto() {
        if (window.CyberNotify && typeof window.CyberNotify.confirm === "function") {
            window.CyberNotify.confirm(
                "Are you sure you want to remove your profile photo?",
                (confirmed) => {
                    if (confirmed) {
                        this.currentState.avatar = "";
                        this.photoFile = null;
                        this.checkDirtyState();
                        this.renderAvatarPreview();
                    }
                },
                { type: "warning" }
            );
        } else {
            if (confirm("Are you sure you want to remove your profile photo?")) {
                this.currentState.avatar = "";
                this.photoFile = null;
                this.checkDirtyState();
                this.renderAvatarPreview();
            }
        }
    }

    renderAvatarPreview() {
        const container = document.getElementById("profile-avatar-display");
        if (!container) return;

        // Clear existing content
        container.innerHTML = "";

        if (this.currentState.avatar) {
            // Use createElement to guarantee referrerPolicy is applied
            // BEFORE the browser begins fetching the image src.
            // innerHTML can cause the browser to start loading the src
            // before processing the referrerpolicy attribute, which makes
            // Google CDN reject the request with a 403.
            const img = document.createElement("img");
            img.id = "profile-avatar-img";
            img.alt = "Avatar Preview";
            img.referrerPolicy = "no-referrer"; // Set BEFORE src
            img.style.width = "100%";
            img.style.height = "100%";
            img.style.objectFit = "cover";
            img.style.borderRadius = "50%";
            img.style.display = "block";
            const self = this;
            img.onerror = function() {
                // Graceful fallback to initials if external image fails
                const initials = self.getInitials(self.currentState.fullName);
                container.innerHTML = `<span id="profile-avatar-initials">${escapeHtml(initials)}</span>`;
            };
            img.src = this.currentState.avatar; // Set src LAST
            container.appendChild(img);
        } else {
            const initials = this.getInitials(this.currentState.fullName);
            container.innerHTML = `<span id="profile-avatar-initials">${escapeHtml(initials)}</span>`;
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
                removeBtn.addEventListener("click", () => this.removePhoto());
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

    async save() {
        if (!this.currentState.fullName) {
            CyberNotify.alert("Display Name is required.", { type: "error" });
            return false;
        }

        try {
            if (typeof showLoading === "function") {
                showLoading("Saving profile...");
            }

            // 1. Upload photo if selected
            if (this.photoFile) {
                const formData = new FormData();
                formData.append("avatar", this.photoFile);

                // Setup header Accept: application/json for avatar upload as specified
                const avatarResponse = await window.apiClient.post("/user/profile/avatar", formData, {
                    headers: { "Accept": "application/json" }
                });

                // Extract avatar URL
                const newAvatarUrl = avatarResponse.avatar || 
                                     avatarResponse.avatar_url || 
                                     avatarResponse.url || 
                                     (avatarResponse.data && (avatarResponse.data.avatar || avatarResponse.data.avatar_url));

                if (newAvatarUrl) {
                    this.currentState.avatar = newAvatarUrl;
                }
            }

            // 2. Call profile update API (PUT or PATCH /user/profile)
            await window.apiClient.put("/user/profile", {
                full_name: this.currentState.fullName,
                job_title: this.currentState.jobTitle
            });

            const user = window.authManager.getCurrentUser() || {};
            
            // Update in-memory user
            user.fullName = this.currentState.fullName;
            user.name = this.currentState.fullName; // fallback for duplicate key
            user.jobTitle = this.currentState.jobTitle;
            user.phoneNumber = this.currentState.phoneNumber;
            
            // Save avatar reference locally
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
            this.photoFile = null; // Clear chosen file
            this.checkDirtyState();

            if (typeof hideLoading === "function") {
                hideLoading();
            }
            CyberNotify.alert("Profile updated successfully.", { type: "success" });
            return true;
        } catch (e) {
            if (typeof hideLoading === "function") {
                hideLoading();
            }
            console.error("Failed to save profile changes:", e);
            CyberNotify.alert(e.message || "An error occurred while saving profile.", { type: "error" });
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
