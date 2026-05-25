/**
 * Dashboard Tab Manager - Bridge Script
 * Manages tab switching with proper persistence and event delegation
 * Prevents DOM collision and ensures all global functionality remains active
 */

const DashboardTabManager = {
  // Track initialization state for each tab
  tabInitialized: {
    'security-dashboard': false,
    'network-tools': false,
    'web-security': false,
    'hash-tools': false,
    'ai-assistant': false,
    'projects': false,
    'threat-intel': false,
    'billing-history': false,
    'jwt-debugger': false
  },
  
  // Current active tab
  currentTab: 'security-dashboard',
  
  /**
   * Initialize the tab manager
   * Should be called once when DOM is ready
   */
  init() {
    console.log('DashboardTabManager: Initializing...');
    
    // Use event delegation for tab buttons ONLY
    // Be very specific to avoid interfering with other buttons
    document.addEventListener('click', (e) => {
      // Only handle if it's specifically a tab button
      const tabButton = e.target.closest('.tab-button[data-tab]');
      if (tabButton) {
        // Only handle tab switching, don't interfere with other functionality
        this.switchTab(tabButton.dataset.tab);
      }
    }, false); // Use bubble phase, not capture
    
    // Initialize the default active tab
    const activeButton = document.querySelector('.tab-button.active');
    if (activeButton) {
      this.currentTab = activeButton.dataset.tab;
      this.initializeTab(this.currentTab);
    }
    
    console.log('DashboardTabManager: Initialization complete');
  },
  
  /**
   * Switch to a specific tab
   * @param {string} tabId - The ID of the tab to switch to
   */
  switchTab(tabId) {
    console.log(`DashboardTabManager: Switching to tab "${tabId}"`);
    
    // Don't switch if already on this tab
    if (this.currentTab === tabId) {
      console.log('DashboardTabManager: Already on this tab, skipping');
      return;
    }
    
    const targetPane = document.getElementById(tabId);
    if (!targetPane) {
      console.error(`DashboardTabManager: Tab pane "${tabId}" not found`);
      return;
    }
    
    // Stop active scans polling if leaving Security Dashboard
    if (this.currentTab === 'security-dashboard') {
      if (typeof window.stopActiveScansPolling === 'function') {
        window.stopActiveScansPolling();
      }
    }
    
    // Update button states
    this.updateTabButtons(tabId);
    
    // Update pane visibility using display: none/block approach
    this.updateTabPanes(tabId);
    
    // Initialize tab-specific functionality if needed
    this.initializeTab(tabId);
    
    // Trigger telemetry load if entering Security Dashboard (even if already initialized)
    if (tabId === 'security-dashboard') {
      if (typeof window.loadSecurityDashboard === 'function') {
        window.loadSecurityDashboard();
      }
    }
    
    // Update current tab
    this.currentTab = tabId;
    
    // Trigger global UI updates
    this.triggerGlobalUpdates();
    
    console.log(`DashboardTabManager: Successfully switched to "${tabId}"`);
  },
  
  /**
   * Update tab button active states
   * Handles both horizontal tab buttons and sidebar navigation items
   * @param {string} activeTabId - The ID of the active tab
   */
  updateTabButtons(activeTabId) {
    // Update horizontal tab buttons (backward compatibility)
    const tabButtons = document.querySelectorAll('.tab-button');
    tabButtons.forEach(button => {
      if (button.dataset.tab === activeTabId) {
        button.classList.add('active');
      } else {
        button.classList.remove('active');
      }
    });
    
    // Update sidebar navigation items
    const navItems = document.querySelectorAll('.cyber-nav-item[onclick*="switchToTab"]');
    navItems.forEach(item => {
      const onclickAttr = item.getAttribute('onclick');
      if (onclickAttr) {
        // Extract tab ID from onclick="switchToTab('tab-id')"
        const match = onclickAttr.match(/switchToTab\('([^']+)'\)/);
        if (match && match[1] === activeTabId) {
          item.classList.add('cyber-nav-active');
        } else {
          item.classList.remove('cyber-nav-active');
        }
      }
    });
  },
  
  /**
   * Update tab pane visibility
   * Uses hidden class (display: none) to preserve DOM structure
   * @param {string} activeTabId - The ID of the active tab
   */
  updateTabPanes(activeTabId) {
    const tabPanes = document.querySelectorAll('.tab-pane');
    tabPanes.forEach(pane => {
      if (pane.id === activeTabId) {
        pane.classList.remove('hidden');
        pane.classList.add('active');
        // Animated transition using GSAP if loaded
        if (typeof gsap !== "undefined") {
          gsap.fromTo(pane, 
            { opacity: 0, y: 12 }, 
            { opacity: 1, y: 0, duration: 0.35, ease: "power2.out", clearProps: "opacity,transform" }
          );
        } else {
          // Reset any inline styles that might interfere
          pane.style.opacity = '1';
          pane.style.transform = 'none';
        }
      } else {
        pane.classList.add('hidden');
        pane.classList.remove('active');
      }
    });

    // Toggle results section visibility
    const TABS_WITHOUT_RESULTS = ['security-dashboard', 'projects', 'threat-intel', 'billing-history', 'ai-assistant', 'hash-tools', 'jwt-debugger'];
    const resultsSection = document.getElementById('professional-results-section');
    if (resultsSection) {
      if (TABS_WITHOUT_RESULTS.includes(activeTabId)) {
        resultsSection.style.display = 'none';
      } else {
        resultsSection.style.display = 'block';
      }
    }
  },
  
  /**
   * Initialize tab-specific functionality
   * Only initializes once per tab to prevent duplicate event listeners
   * @param {string} tabId - The ID of the tab to initialize
   */
  initializeTab(tabId) {
    // Skip if already initialized
    if (this.tabInitialized[tabId]) {
      console.log(`DashboardTabManager: Tab "${tabId}" already initialized`);
      return;
    }
    
    console.log(`DashboardTabManager: Initializing tab "${tabId}"`);
    
    switch (tabId) {
      case 'security-dashboard':
        this.initializeSecurityDashboard();
        break;
      case 'hash-tools':
        this.initializeHashTools();
        break;
      case 'network-tools':
        this.initializeNetworkTools();
        break;
      case 'web-security':
        this.initializeWebSecurity();
        break;
      case 'ai-assistant':
        this.initializeAIAssistant();
        break;
      case 'projects':
        this.initializeProjects();
        break;
      case 'threat-intel':
        this.initializeThreatIntel();
        break;
      case 'billing-history':
        this.initializeBillingHistory();
        break;
      case 'jwt-debugger':
        this.initializeJWTDebugger();
        break;
    }
    
    // Mark as initialized
    this.tabInitialized[tabId] = true;
  },
  
  /**
   * Initialize Security Dashboard tab
   */
  initializeSecurityDashboard() {
    console.log('DashboardTabManager: Initializing Security Dashboard tab');
    if (typeof window.loadSecurityDashboard === 'function') {
      window.loadSecurityDashboard();
    }
  },
  
  /**
   * Initialize Hash Tools tab
   */
  initializeHashTools() {
    if (typeof CyberGuardHashTools !== 'undefined') {
      try {
        CyberGuardHashTools.init();
        console.log('DashboardTabManager: Hash Tools initialized');
      } catch (error) {
        console.error('DashboardTabManager: Error initializing Hash Tools:', error);
      }
    } else {
      console.warn('DashboardTabManager: CyberGuardHashTools not found');
    }
  },
  
  /**
   * Initialize JWT Debugger tab
   */
  initializeJWTDebugger() {
    if (typeof CyberGuardJWTDebugger !== 'undefined') {
      try {
        CyberGuardJWTDebugger.init();
        console.log('DashboardTabManager: JWT Debugger initialized');
      } catch (error) {
        console.error('DashboardTabManager: Error initializing JWT Debugger:', error);
      }
    } else {
      console.warn('DashboardTabManager: CyberGuardJWTDebugger not found');
    }
  },
  
  /**
   * Initialize Network Tools tab
   */
  initializeNetworkTools() {
    // Network tools are initialized in main.js DOMContentLoaded
    // No additional initialization needed here
    console.log('DashboardTabManager: Network Tools ready');
  },
  
  /**
   * Initialize Web Security tab
   */
  initializeWebSecurity() {
    // Web security tools are initialized in main.js DOMContentLoaded
    // No additional initialization needed here
    console.log('DashboardTabManager: Web Security ready');
  },
  
  /**
   * Initialize AI Assistant tab
   */
  initializeAIAssistant() {
    // AI Assistant is already initialized via main.js IIFE
    if (window.AIAssistantInitialized) {
      console.log('DashboardTabManager: AI Assistant already initialized by main.js');
      return;
    }
    if (typeof initAIAssistant === 'function') {
      try {
        initAIAssistant();
        console.log('DashboardTabManager: AI Assistant initialized');
      } catch (error) {
        console.error('DashboardTabManager: Error initializing AI Assistant:', error);
      }
    }
  },
  
  /**
   * Initialize Projects tab
   * Loads projects when the tab is first activated
   */
  initializeProjects() {
    console.log('DashboardTabManager: Initializing Projects tab');
    
    // Check if ProjectManager is available
    if (typeof window.projectManager !== 'undefined' && window.projectManager.renderProjectsList) {
      try {
        // Use ProjectManager's renderProjectsList method
        window.projectManager.renderProjectsList();
        console.log('DashboardTabManager: Projects loaded via ProjectManager');
      } catch (error) {
        console.error('DashboardTabManager: Error loading projects via ProjectManager:', error);
      }
    } else if (typeof renderProjectsList === 'function') {
      // Fallback to global renderProjectsList function
      try {
        renderProjectsList();
        console.log('DashboardTabManager: Projects loaded via global function');
      } catch (error) {
        console.error('DashboardTabManager: Error loading projects via global function:', error);
      }
    } else {
      console.warn('DashboardTabManager: No project loading method available');
    }
  },
  
  /**
   * Initialize Threat Intel Hub tab
   * Initializes the threat intelligence aggregation module
   */
  initializeThreatIntel() {
    console.log('DashboardTabManager: Initializing Threat Intel Hub tab');
    
    // Check if ThreatIntelHub is available
    if (typeof ThreatIntelHub !== 'undefined') {
      try {
        ThreatIntelHub.init();
        console.log('DashboardTabManager: Threat Intel Hub initialized');
      } catch (error) {
        console.error('DashboardTabManager: Error initializing Threat Intel Hub:', error);
      }
    } else {
      console.warn('DashboardTabManager: ThreatIntelHub not found');
    }
  },
  
  /**
   * Initialize Billing History tab
   * Loads billing history when the tab is first activated
   */
  initializeBillingHistory() {
    console.log('DashboardTabManager: Initializing Billing History tab');
    
    // Check if loadBillingHistory function is available
    if (typeof loadBillingHistory === 'function') {
      try {
        loadBillingHistory();
        console.log('DashboardTabManager: Billing History loaded');
      } catch (error) {
        console.error('DashboardTabManager: Error loading Billing History:', error);
      }
    } else {
      console.warn('DashboardTabManager: loadBillingHistory function not found');
    }
  },
  
  /**
   * Trigger global UI updates after tab switch
   * Ensures selection managers and other global components update
   */
  triggerGlobalUpdates() {
    // Update selection manager if available
    if (typeof SelectionManager !== 'undefined' && SelectionManager.updateSelectionCount) {
      try {
        SelectionManager.updateSelectionCount();
      } catch (error) {
        console.error('DashboardTabManager: Error updating SelectionManager:', error);
      }
    }
    
    // Update select all toggle if available
    if (typeof SelectAllToggle !== 'undefined' && SelectAllToggle.updateButtonLabel) {
      try {
        SelectAllToggle.updateButtonLabel();
      } catch (error) {
        console.error('DashboardTabManager: Error updating SelectAllToggle:', error);
      }
    }
    
    // Dispatch custom event for other components to listen to
    const event = new CustomEvent('tabSwitched', {
      detail: { tabId: this.currentTab }
    });
    document.dispatchEvent(event);
  },
  
  /**
   * Get the current active tab ID
   * @returns {string} The current tab ID
   */
  getCurrentTab() {
    return this.currentTab;
  },
  
  /**
   * Check if a tab has been initialized
   * @param {string} tabId - The tab ID to check
   * @returns {boolean} True if initialized
   */
  isTabInitialized(tabId) {
    return this.tabInitialized[tabId] || false;
  },
  
  /**
   * Force re-initialization of a tab
   * Use with caution - only when you need to reset a tab's state
   * @param {string} tabId - The tab ID to re-initialize
   */
  reinitializeTab(tabId) {
    console.log(`DashboardTabManager: Force re-initializing tab "${tabId}"`);
    this.tabInitialized[tabId] = false;
    this.initializeTab(tabId);
  }
};

// Global function for backward compatibility
function switchToTab(tabId) {
  DashboardTabManager.switchTab(tabId);
}

// Auto-initialize when DOM is ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => {
    // === AUTHENTICATION CHECK ===
    if (typeof window.runAuthGuard === 'function' && !window.runAuthGuard()) {
      return; // Stop initialization if not authenticated
    }
    DashboardTabManager.init();
  });
} else {
  // DOM already loaded
  if (typeof window.runAuthGuard !== 'function' || window.runAuthGuard()) {
    DashboardTabManager.init();
  }
}

// Export for use in other scripts
if (typeof module !== 'undefined' && module.exports) {
  module.exports = DashboardTabManager;
}
