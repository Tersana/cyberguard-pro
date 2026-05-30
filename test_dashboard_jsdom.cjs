const fs = require('fs');
const path = require('path');
const jsdom = require('jsdom');
const { JSDOM } = jsdom;

const htmlPath = path.join(__dirname, 'public', 'dashboard.html');
let htmlContent = fs.readFileSync(htmlPath, 'utf8');

// Strip script tags
htmlContent = htmlContent.replace(/<script src="[^"]+"><\/script>/g, '');

const virtualConsole = new jsdom.VirtualConsole();
let hasErrors = false;
virtualConsole.on("jsdomError", (error) => {
  console.error("JSDOM Error:", error.message, error.stack);
  hasErrors = true;
});
virtualConsole.on("error", (message) => {
  console.error("Console Error:", message);
  hasErrors = true;
});
virtualConsole.on("warn", (message) => {
  console.warn("Console Warning:", message);
});
virtualConsole.on("log", (message) => {
  console.log("Console Log:", message);
});

console.log('Loading dashboard.html in clean browser JSDOM...');

const dom = new JSDOM(htmlContent, {
  url: 'http://localhost/dashboard.html',
  runScripts: 'outside-only',
  virtualConsole,
  beforeParse(window) {
    // Mock localStorage properly using defineProperty since JSDOM makes it read-only
    const mockStorage = {
      getItem: (key) => {
        if (key === 'cyberguard_jwt') return 'mock-jwt-token-long-enough-for-length-check';
        return null;
      },
      setItem: () => {},
      removeItem: () => {},
      clear: () => {}
    };
    Object.defineProperty(window, 'localStorage', {
      value: mockStorage,
      writable: true
    });
    
    // Mock window location pathname
    window.location.pathname = '/dashboard.html';
    
    // Mock other elements
    window.confirm = () => true;
    window.alert = () => {};
    
    // Mock Pusher
    window.Pusher = function() {
      return {
        subscribe: () => ({ bind: () => {} })
      };
    };
    
    // Mock requestAnimationFrame and cancelAnimationFrame
    window.requestAnimationFrame = (callback) => setTimeout(callback, 16);
    window.cancelAnimationFrame = (id) => clearTimeout(id);
  }
});

// Run external scripts inline but hide module/exports so they behave like browser
const scriptsToLoad = [
  'public/js/api-client.js',
  'public/js/data-normalizer.js',
  'public/js/billing-api.js',
  'public/js/billing-utils.js',
  'public/js/project-manager.js',
  'public/js/auth.js',
  'public/js/main.js',
  'public/js/threat-intel.js',
  'public/js/security-dashboard.js',
  'public/js/dashboard-tab-manager.js',
  'public/js/jwt-debugger.js',
  'public/js/state-manager.js',
  'public/js/dashboard-integration.js',
  'public/js/risk-gauge.js',
  'public/js/sidebar-system-health.js',
  'public/js/profile-settings.js',
  'public/js/security-settings.js',
  'public/js/notification-settings.js',
  'public/js/appearance-settings.js',
  'public/js/billing-settings.js',
  'public/js/account-settings.js',
  'public/js/settings-panel.js'
];

console.log('Evaluating scripts with browser globals...');
scriptsToLoad.forEach(script => {
  const filePath = path.join(__dirname, script);
  if (fs.existsSync(filePath)) {
    const rawCode = fs.readFileSync(filePath, 'utf8');
    // Wrap code in an anonymous block that shadows module and exports to undefined
    const browserCode = `(function(module, exports) {
      ${rawCode}
    })(undefined, undefined);`;
    
    // Explicitly expose globals in virtual window
    if (script === 'public/js/api-client.js') {
      const wrappedCode = `${rawCode}; window.APIClient = APIClient; window.APIError = APIError; window.ValidationError = ValidationError; window.NetworkError = NetworkError;`;
      try {
        dom.window.eval(wrappedCode);
      } catch (e) {
        console.error(`Error in script ${script}:`, e.message, e.stack);
        hasErrors = true;
      }
      return;
    }
    
    if (script === 'public/js/project-manager.js') {
      const wrappedCode = `${rawCode}; window.ProjectManager = ProjectManager;`;
      try {
        dom.window.eval(wrappedCode);
      } catch (e) {
        console.error(`Error in script ${script}:`, e.message, e.stack);
        hasErrors = true;
      }
      return;
    }
    
    if (script === 'public/js/auth.js') {
      const wrappedCode = `${rawCode}; window.AuthManager = AuthManager;`;
      try {
        dom.window.eval(wrappedCode);
      } catch (e) {
        console.error(`Error in script ${script}:`, e.message, e.stack);
        hasErrors = true;
      }
      return;
    }
    
    try {
      dom.window.eval(browserCode);
    } catch (e) {
      console.error(`Error in script ${script}:`, e.message, e.stack);
      hasErrors = true;
    }
  }
});

// Trigger DOMContentLoaded
console.log('Dispatching DOMContentLoaded...');
const doc = dom.window.document;
const event = doc.createEvent('Event');
event.initEvent('DOMContentLoaded', true, true);
doc.dispatchEvent(event);

console.log('Done waiting. Checking active state...');
console.log('window.AIAssistantInitialized:', dom.window.AIAssistantInitialized);
console.log('window.WebAuditing:', typeof dom.window.WebAuditing, dom.window.WebAuditing ? 'exists' : 'does NOT exist');
dom.window.close();

if (hasErrors) {
  process.exit(1);
} else {
  process.exit(0);
}
