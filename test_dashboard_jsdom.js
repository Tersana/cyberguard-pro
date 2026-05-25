const fs = require('fs');
const path = require('path');
const { JSDOM } = require('jsdom');

const htmlPath = path.join(__dirname, 'public', 'dashboard.html');
const htmlContent = fs.readFileSync(htmlPath, 'utf8');

const virtualConsole = new JSDOM.VirtualConsole();
virtualConsole.on("jsdomError", (error) => {
  console.error("JSDOM Error:", error.message, error.stack);
});
virtualConsole.on("error", (message) => {
  console.error("Console Error:", message);
});
virtualConsole.on("warn", (message) => {
  console.warn("Console Warning:", message);
});
virtualConsole.on("log", (message) => {
  console.log("Console Log:", message);
});

console.log('Loading dashboard.html in JSDOM...');

const dom = new JSDOM(htmlContent, {
  url: 'http://localhost/dashboard.html',
  runScripts: 'dangerously',
  resources: 'usable',
  virtualConsole,
  beforeParse(window) {
    // Mock localStorage
    window.localStorage = {
      getItem: (key) => {
        if (key === 'cyberguard_jwt') return 'mock-jwt-token';
        return null;
      },
      setItem: () => {},
      removeItem: () => {},
      clear: () => {}
    };
    
    // Mock other elements
    window.confirm = () => true;
    window.alert = () => {};
    
    // Mock Pusher
    window.Pusher = function() {
      return {
        subscribe: () => ({ bind: () => {} })
      };
    };
  }
});

// Wait a bit to let scripts run
setTimeout(() => {
  console.log('Done waiting. Checking active state...');
  console.log('window.AIAssistantInitialized:', dom.window.AIAssistantInitialized);
  dom.window.close();
  // Exit
  process.exit(0);
}, 2000);
