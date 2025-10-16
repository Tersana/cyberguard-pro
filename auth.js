/**
 * CyberGuard Pro Authentication System
 * Handles user authentication, session management, and security features
 */

class AuthManager {
  constructor() {
    this.currentUser = null;
    this.sessionTimeout = 30 * 60 * 1000; // 30 minutes
    this.init();
  }

  init() {
    this.loadUserSession();
    this.setupSessionTimeout();
    this.setupEventListeners();
  }

  // Load user session from localStorage
  loadUserSession() {
    try {
      const userData = localStorage.getItem("cyberguard_user");
      const sessionData = localStorage.getItem("cyberguard_session");

      if (userData && sessionData) {
        const user = JSON.parse(userData);
        const session = JSON.parse(sessionData);

        // Check if session is still valid
        if (Date.now() - session.timestamp < this.sessionTimeout) {
          this.currentUser = user;
          this.updateUI();
          return true;
        } else {
          this.logout();
        }
      }
    } catch (error) {
      console.error("Error loading user session:", error);
      this.logout();
    }
    return false;
  }

  // Save user session to localStorage
  saveUserSession(user) {
    try {
      const sessionData = {
        timestamp: Date.now(),
        userAgent: navigator.userAgent,
        ip: "127.0.0.1", // In a real app, this would be the actual IP
      };

      localStorage.setItem("cyberguard_user", JSON.stringify(user));
      localStorage.setItem("cyberguard_session", JSON.stringify(sessionData));
      this.currentUser = user;
      this.updateUI();
      return true;
    } catch (error) {
      console.error("Error saving user session:", error);
      return false;
    }
  }

  // Login function
  async login(email, password) {
    try {
      // Simulate API call
      const response = await this.authenticateUser(email, password);

      if (response.success) {
        const user = {
          id: response.user.id,
          email: response.user.email,
          name: response.user.name,
          company: response.user.company,
          role: response.user.role,
          lastLogin: new Date().toISOString(),
          preferences: response.user.preferences || {},
        };

        this.saveUserSession(user);
        this.trackLoginAttempt(email, true);
        return { success: true, user: user };
      } else {
        this.trackLoginAttempt(email, false);
        return { success: false, message: response.message };
      }
    } catch (error) {
      console.error("Login error:", error);
      return { success: false, message: "An error occurred during login" };
    }
  }

  // Register function
  async register(userData) {
    try {
      // Simulate API call
      const response = await this.createUser(userData);

      if (response.success) {
        const user = {
          id: response.user.id,
          email: response.user.email,
          name: response.user.name,
          company: response.user.company,
          role: "user",
          createdAt: new Date().toISOString(),
          preferences: response.user.preferences || {},
        };

        this.saveUserSession(user);
        this.trackRegistration(user.email);
        return { success: true, user: user };
      } else {
        return { success: false, message: response.message };
      }
    } catch (error) {
      console.error("Registration error:", error);
      return {
        success: false,
        message: "An error occurred during registration",
      };
    }
  }

  // Logout function
  logout() {
    try {
      // Track logout
      if (this.currentUser) {
        this.trackLogout(this.currentUser.email);
      }

      // Clear session data
      localStorage.removeItem("cyberguard_user");
      localStorage.removeItem("cyberguard_session");
      this.currentUser = null;

      // Redirect to login page
      window.location.href = "login.html";
    } catch (error) {
      console.error("Logout error:", error);
    }
  }

  // Check if user is authenticated
  isAuthenticated() {
    return this.currentUser !== null;
  }

  // Get current user
  getCurrentUser() {
    return this.currentUser;
  }

  // Update UI based on authentication status
  updateUI() {
    const authElements = document.querySelectorAll("[data-auth]");
    const guestElements = document.querySelectorAll("[data-guest]");
    const authRequiredElements = document.querySelectorAll(
      "[data-auth-required]"
    );

    if (this.isAuthenticated()) {
      // Show authenticated elements
      authElements.forEach((el) => (el.style.display = "block"));
      guestElements.forEach((el) => (el.style.display = "none"));

      // Enable all auth-required elements
      authRequiredElements.forEach((el) => {
        el.disabled = false;
        el.classList.remove("disabled");
      });

      // Update user info
      const userNameEl = document.getElementById("userName");
      const userEmailEl = document.getElementById("userEmail");

      if (userNameEl) userNameEl.textContent = this.currentUser.name;
      if (userEmailEl) userEmailEl.textContent = this.currentUser.email;
    } else {
      // Show guest elements
      authElements.forEach((el) => (el.style.display = "none"));
      guestElements.forEach((el) => (el.style.display = "block"));

      // Add visual indicators for auth-required elements but don't disable them completely
      authRequiredElements.forEach((el) => {
        el.classList.add("auth-required");
        // Add a subtle indicator that this requires authentication
        if (!el.querySelector(".auth-badge")) {
          const badge = document.createElement("span");
          badge.className =
            "auth-badge absolute -top-1 -right-1 w-3 h-3 bg-orange-400 rounded-full flex items-center justify-center";
          badge.innerHTML =
            '<svg class="w-2 h-2 text-white" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M5 9V7a5 5 0 0110 0v2a2 2 0 012 2v5a2 2 0 01-2 2H5a2 2 0 01-2-2v-5a2 2 0 012-2zm8-2v2H7V7a3 3 0 016 0z" clip-rule="evenodd"></path></svg>';
          el.style.position = "relative";
          el.appendChild(badge);
        }
      });
    }
  }

  // Setup session timeout
  setupSessionTimeout() {
    setInterval(() => {
      if (this.isAuthenticated()) {
        const sessionData = localStorage.getItem("cyberguard_session");
        if (sessionData) {
          const session = JSON.parse(sessionData);
          if (Date.now() - session.timestamp > this.sessionTimeout) {
            this.logout();
          }
        }
      }
    }, 60000); // Check every minute
  }

  // Setup event listeners
  setupEventListeners() {
    // Logout button
    const logoutBtn = document.getElementById("logoutBtn");
    if (logoutBtn) {
      logoutBtn.addEventListener("click", () => this.logout());
    }

    // Add click listeners to auth-required elements (excluding API Keys which is handled in main.js)
    document.addEventListener("click", (e) => {
      const authRequiredElement = e.target.closest("[data-auth-required]");
      if (authRequiredElement && !this.isAuthenticated()) {
        // Skip API Keys toggle as it's handled in main.js
        if (authRequiredElement.id === "api-keys-toggle") {
          return;
        }
        // For other elements, just show an informative message
        this.showFeatureLimitation();
      }
    });

    // Session activity tracking
    ["mousedown", "mousemove", "keypress", "scroll", "touchstart"].forEach(
      (event) => {
        document.addEventListener(event, () => this.updateSessionActivity());
      }
    );
  }

  // Show authentication prompt
  showAuthPrompt() {
    // Create and show a modal prompt
    const modal = document.createElement("div");
    modal.className =
      "fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50";
    modal.innerHTML = `
      <div class="bg-white rounded-2xl shadow-2xl p-8 max-w-md mx-4 text-center">
        <div class="w-16 h-16 mx-auto bg-gradient-to-br from-blue-500 to-purple-600 rounded-full flex items-center justify-center mb-6">
          <svg class="w-8 h-8 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" d="M16.5 10.5V6.75a4.5 4.5 0 1 0-9 0v3.75m-.75 11.25h10.5a2.25 2.25 0 0 0 2.25-2.25v-6.75a2.25 2.25 0 0 0-2.25-2.25H6.75a2.25 2.25 0 0 0-2.25 2.25v6.75a2.25 2.25 0 0 0 2.25 2.25Z" />
          </svg>
        </div>
        <h2 class="text-xl font-bold text-slate-800 mb-4">Authentication Required</h2>
        <p class="text-slate-600 mb-6">Please log in to access this security tool.</p>
        <div class="flex gap-4">
          <a href="login.html" class="flex-1 bg-blue-500 hover:bg-blue-600 text-white font-semibold py-3 px-4 rounded-xl transition-colors flex items-center justify-center gap-2">
            <svg class="w-5 h-5" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor">
              <path stroke-linecap="round" stroke-linejoin="round" d="M15.75 6a3.75 3.75 0 1 1-7.5 0 3.75 3.75 0 0 1 7.5 0ZM4.501 20.118a7.5 7.5 0 0 1 14.998 0A17.933 17.933 0 0 1 12 21.75c-2.676 0-5.216-.584-7.499-1.632Z" />
            </svg>
            Login
          </a>
          <a href="signup.html" class="flex-1 bg-green-500 hover:bg-green-600 text-white font-semibold py-3 px-4 rounded-xl transition-colors flex items-center justify-center gap-2">
            <svg class="w-5 h-5" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor">
              <path stroke-linecap="round" stroke-linejoin="round" d="M18 7.5v3m0 0v3m0-3h3m-3 0h-3m-2.25-4.125a3.375 3.375 0 1 1-6.75 0 3.375 3.375 0 0 1 6.75 0ZM3 19.235v-.11a6.375 6.375 0 0 1 12.75 0v.109A12.318 12.318 0 0 1 9.374 21c-2.331 0-4.512-.645-6.374-1.766Z" />
            </svg>
            Sign Up
          </a>
        </div>
        <button class="mt-4 text-slate-500 hover:text-slate-700 transition-colors" onclick="this.parentElement.parentElement.remove()">
          Cancel
        </button>
      </div>
    `;

    document.body.appendChild(modal);

    // Auto-remove after 10 seconds
    setTimeout(() => {
      if (modal.parentElement) {
        modal.remove();
      }
    }, 10000);
  }

  // Show feature limitation message
  showFeatureLimitation() {
    // Create a toast notification instead of a blocking modal
    const toast = document.createElement("div");
    toast.className =
      "fixed top-4 right-4 bg-orange-50 border border-orange-200 rounded-lg p-4 max-w-sm z-50 shadow-lg";
    toast.innerHTML = `
      <div class="flex items-start gap-3">
        <div class="w-8 h-8 bg-orange-100 rounded-full flex items-center justify-center flex-shrink-0">
          <svg class="w-4 h-4 text-orange-600" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126ZM12 15.75h.007v.008H12v-.008Z" />
          </svg>
        </div>
        <div class="flex-1">
          <h4 class="text-sm font-semibold text-orange-800 mb-1">Feature Limitation</h4>
          <p class="text-xs text-orange-700 mb-2">This feature requires authentication for full functionality. You can still explore the interface!</p>
          <div class="flex gap-2">
            <a href="login.html" class="text-xs bg-orange-500 hover:bg-orange-600 text-white font-semibold py-1 px-2 rounded transition-colors">
              Login
            </a>
            <a href="signup.html" class="text-xs bg-green-500 hover:bg-green-600 text-white font-semibold py-1 px-2 rounded transition-colors">
              Sign Up
            </a>
          </div>
        </div>
        <button class="text-orange-400 hover:text-orange-600 transition-colors" onclick="this.parentElement.parentElement.remove()">
          <svg class="w-4 h-4" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12" />
          </svg>
        </button>
      </div>
    `;

    document.body.appendChild(toast);

    // Auto-remove after 8 seconds
    setTimeout(() => {
      if (toast.parentElement) {
        toast.remove();
      }
    }, 8000);
  }

  // Show API Keys restriction message
  showApiKeysRestriction() {
    // Create a modal specifically for API Keys restriction
    const modal = document.createElement("div");
    modal.className =
      "fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50";
    modal.innerHTML = `
      <div class="bg-white rounded-2xl shadow-2xl p-8 max-w-md mx-4 text-center">
        <div class="w-20 h-20 mx-auto bg-gradient-to-br from-blue-500 to-purple-600 rounded-full flex items-center justify-center mb-6">
          <svg class="w-10 h-10 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" d="M15.75 5.25a3 3 0 0 1 3 3m3 0a6 6 0 0 1-7.029 5.912c-.563-.097-1.159.026-1.563.43L10.5 17.25H8.25v2.25H6v2.25H2.25v-2.818c0-.597.237-1.17.659-1.591l6.499-6.499c.404-.404.527-1 .43-1.563A6 6 0 1 1 21.75 8.25Z" />
          </svg>
        </div>
        <h2 class="text-2xl font-bold text-slate-800 mb-4">Authentication Required</h2>
        <p class="text-slate-600 mb-6">API Key configuration requires authentication. Please log in to configure your API keys.</p>
        <div class="flex gap-4">
          <a href="login.html" class="flex-1 bg-blue-500 hover:bg-blue-600 text-white font-semibold py-3 px-4 rounded-xl transition-colors flex items-center justify-center gap-2">
            <svg class="w-5 h-5" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor">
              <path stroke-linecap="round" stroke-linejoin="round" d="M15.75 6a3.75 3.75 0 1 1-7.5 0 3.75 3.75 0 0 1 7.5 0ZM4.501 20.118a7.5 7.5 0 0 1 14.998 0A17.933 17.933 0 0 1 12 21.75c-2.676 0-5.216-.584-7.499-1.632Z" />
            </svg>
            Login
          </a>
          <a href="signup.html" class="flex-1 bg-green-500 hover:bg-green-600 text-white font-semibold py-3 px-4 rounded-xl transition-colors flex items-center justify-center gap-2">
            <svg class="w-5 h-5" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor">
              <path stroke-linecap="round" stroke-linejoin="round" d="M18 7.5v3m0 0v3m0-3h3m-3 0h-3m-2.25-4.125a3.375 3.375 0 1 1-6.75 0 3.375 3.375 0 0 1 6.75 0ZM3 19.235v-.11a6.375 6.375 0 0 1 12.75 0v.109A12.318 12.318 0 0 1 9.374 21c-2.331 0-4.512-.645-6.374-1.766Z" />
            </svg>
            Sign Up
          </a>
        </div>
        <button class="mt-4 text-slate-500 hover:text-slate-700 transition-colors" onclick="this.parentElement.parentElement.remove()">
          Cancel
        </button>
      </div>
    `;

    document.body.appendChild(modal);

    // Auto-remove after 15 seconds
    setTimeout(() => {
      if (modal.parentElement) {
        modal.remove();
      }
    }, 15000);
  }

  // Update session activity
  updateSessionActivity() {
    if (this.isAuthenticated()) {
      const sessionData = localStorage.getItem("cyberguard_session");
      if (sessionData) {
        const session = JSON.parse(sessionData);
        session.timestamp = Date.now();
        localStorage.setItem("cyberguard_session", JSON.stringify(session));
      }
    }
  }

  // Simulate API authentication
  async authenticateUser(email, password) {
    // Simulate network delay
    await new Promise((resolve) => setTimeout(resolve, 1000));

    // Demo credentials
    const demoUsers = [
      {
        email: "admin@cyberguard.com",
        password: "admin123",
        name: "Admin User",
        company: "CyberGuard Inc.",
      },
      {
        email: "user@cyberguard.com",
        password: "user123",
        name: "John Doe",
        company: "Security Corp",
      },
      {
        email: "demo@cyberguard.com",
        password: "demo123",
        name: "Demo User",
        company: "Demo Company",
      },
    ];

    const user = demoUsers.find(
      (u) => u.email === email && u.password === password
    );

    if (user) {
      return {
        success: true,
        user: {
          id: Math.random().toString(36).substr(2, 9),
          email: user.email,
          name: user.name,
          company: user.company,
          role: email === "admin@cyberguard.com" ? "admin" : "user",
        },
      };
    } else {
      return {
        success: false,
        message: "Invalid email or password",
      };
    }
  }

  // Simulate API user creation
  async createUser(userData) {
    // Simulate network delay
    await new Promise((resolve) => setTimeout(resolve, 1500));

    // Check if email already exists
    const existingUsers = JSON.parse(
      localStorage.getItem("cyberguard_users") || "[]"
    );
    if (existingUsers.find((u) => u.email === userData.email)) {
      return {
        success: false,
        message: "Email already exists",
      };
    }

    // Create new user
    const newUser = {
      id: Math.random().toString(36).substr(2, 9),
      email: userData.email,
      name: userData.fullName,
      company: userData.company || "",
      role: "user",
      preferences: {
        notifications: true,
        reports: true,
        updates: false,
      },
    };

    // Save to localStorage (in a real app, this would be sent to server)
    existingUsers.push(newUser);
    localStorage.setItem("cyberguard_users", JSON.stringify(existingUsers));

    return {
      success: true,
      user: newUser,
    };
  }

  // Track login attempts
  trackLoginAttempt(email, success) {
    const attempts = JSON.parse(
      localStorage.getItem("cyberguard_login_attempts") || "[]"
    );
    attempts.push({
      email: email,
      success: success,
      timestamp: new Date().toISOString(),
      ip: "127.0.0.1",
      userAgent: navigator.userAgent,
    });

    // Keep only last 100 attempts
    if (attempts.length > 100) {
      attempts.splice(0, attempts.length - 100);
    }

    localStorage.setItem("cyberguard_login_attempts", JSON.stringify(attempts));
  }

  // Track registration
  trackRegistration(email) {
    const registrations = JSON.parse(
      localStorage.getItem("cyberguard_registrations") || "[]"
    );
    registrations.push({
      email: email,
      timestamp: new Date().toISOString(),
      ip: "127.0.0.1",
    });

    localStorage.setItem(
      "cyberguard_registrations",
      JSON.stringify(registrations)
    );
  }

  // Track logout
  trackLogout(email) {
    const logouts = JSON.parse(
      localStorage.getItem("cyberguard_logouts") || "[]"
    );
    logouts.push({
      email: email,
      timestamp: new Date().toISOString(),
      ip: "127.0.0.1",
    });

    localStorage.setItem("cyberguard_logouts", JSON.stringify(logouts));
  }

  // Password strength checker
  checkPasswordStrength(password) {
    let score = 0;
    const checks = {
      length: password.length >= 8,
      lowercase: /[a-z]/.test(password),
      uppercase: /[A-Z]/.test(password),
      numbers: /[0-9]/.test(password),
      symbols: /[^A-Za-z0-9]/.test(password),
    };

    score = Object.values(checks).filter(Boolean).length;

    return {
      score: score,
      maxScore: 5,
      percentage: (score / 5) * 100,
      checks: checks,
      strength:
        score < 2 ? "weak" : score < 4 ? "fair" : score < 5 ? "good" : "strong",
    };
  }

  // Validate email format
  validateEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  }

  // Validate password requirements
  validatePassword(password) {
    const requirements = {
      length: password.length >= 8,
      lowercase: /[a-z]/.test(password),
      uppercase: /[A-Z]/.test(password),
      numbers: /[0-9]/.test(password),
      symbols: /[^A-Za-z0-9]/.test(password),
    };

    return {
      valid: Object.values(requirements).every(Boolean),
      requirements: requirements,
    };
  }

  // Get security statistics
  getSecurityStats() {
    const attempts = JSON.parse(
      localStorage.getItem("cyberguard_login_attempts") || "[]"
    );
    const registrations = JSON.parse(
      localStorage.getItem("cyberguard_registrations") || "[]"
    );
    const logouts = JSON.parse(
      localStorage.getItem("cyberguard_logouts") || "[]"
    );

    return {
      totalLoginAttempts: attempts.length,
      successfulLogins: attempts.filter((a) => a.success).length,
      failedLogins: attempts.filter((a) => !a.success).length,
      totalRegistrations: registrations.length,
      totalLogouts: logouts.length,
      lastLogin: attempts.filter((a) => a.success).pop()?.timestamp,
      lastRegistration: registrations.pop()?.timestamp,
    };
  }
}

// Initialize authentication manager
const authManager = new AuthManager();

// Export for use in other scripts
window.AuthManager = AuthManager;
window.authManager = authManager;
