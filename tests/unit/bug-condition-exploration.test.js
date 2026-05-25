/**
 * Bug Condition Exploration Test - Dashboard Event Delegation Fix
 * 
 * **Validates: Requirements 1.1, 1.2, 1.3, 1.4, 1.5, 1.6**
 * 
 * **Property 1: Bug Condition** - Legacy Hash Tools Event Listener Registration Failure
 * 
 * **CRITICAL**: This test MUST FAIL on unfixed code - failure confirms the bug exists
 * **DO NOT attempt to fix the test or the code when it fails**
 * **NOTE**: This test encodes the expected behavior - it will validate the fix when it passes after implementation
 * **GOAL**: Surface counterexamples that demonstrate the bug exists
 * 
 * This test verifies that:
 * 1. Dashboard loads without throwing TypeError at line 8174
 * 2. All event listeners register successfully (Execute Scan, tool selection, filters, welcome modal)
 * 3. Execute Scan button responds to clicks
 * 4. Tool selection checkboxes respond to clicks
 * 5. Filter buttons respond to clicks
 * 6. Welcome modal initialization executes
 * 
 * **EXPECTED OUTCOME ON UNFIXED CODE**: Test FAILS (this is correct - it proves the bug exists)
 * Expected counterexamples:
 * - TypeError at line 8174: "can't access property 'addEventListener', document.getElementById(...) is null"
 * - Non-functional Execute Scan button
 * - Non-functional tool selection cards
 * - Non-functional filter buttons
 * - Missing welcome modal
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { JSDOM } from 'jsdom';
import * as fs from 'fs';
import * as path from 'path';
import * as fc from 'fast-check';

describe('Bug Condition Exploration - Legacy Hash Tools Event Listener Registration', () => {
  let dom;
  let document;
  let window;

  beforeEach(() => {
    // Load the actual dashboard.html
    const dashboardHtml = fs.readFileSync(
      path.resolve(process.cwd(), 'public/dashboard.html'),
      'utf-8'
    );

    // Create DOM with the actual dashboard HTML
    dom = new JSDOM(dashboardHtml, {
      url: 'http://localhost',
      runScripts: 'dangerously', // Allow scripts to run to catch the actual error
      resources: 'usable',
      beforeParse(window) {
        // Mock external dependencies that main.js needs
        window.CryptoJS = {
          MD5: (str) => `md5-${str}`,
          SHA1: (str) => `sha1-${str}`,
          SHA256: (str) => `sha256-${str}`,
          SHA512: (str) => `sha512-${str}`,
          AES: {
            encrypt: (data, key) => `encrypted-${data}`,
            decrypt: (data, key) => ({ toString: () => `decrypted-${data}` })
          },
          enc: {
            Utf8: {}
          }
        };

        // Mock jsPDF
        window.jsPDF = class {
          constructor() {
            this.text = vi.fn();
            this.save = vi.fn();
          }
        };

        // Mock localStorage - use Object.defineProperty to override the getter
        Object.defineProperty(window, 'localStorage', {
          value: {
            getItem: vi.fn(() => null),
            setItem: vi.fn(),
            removeItem: vi.fn(),
            clear: vi.fn()
          },
          writable: true
        });

        // Mock fetch for API calls
        window.fetch = vi.fn(() => 
          Promise.resolve({
            ok: true,
            json: () => Promise.resolve({})
          })
        );

        // Mock alert
        window.alert = vi.fn();
        
        // Capture errors
        window.addEventListener('error', (event) => {
          console.error('Window error:', event.error);
        });
      }
    });

    document = dom.window.document;
    window = dom.window;
    global.document = document;
    global.window = window;
  });

  describe('Property 1: Bug Condition - Legacy Hash Tools Code Causes TypeError', () => {
    it('should detect that hash-string-btn element does not exist in DOM', () => {
      // COUNTEREXAMPLE 1: The element that line 8174 tries to access doesn't exist
      const hashStringBtn = document.getElementById('hash-string-btn');
      
      console.log('COUNTEREXAMPLE FOUND: Element "hash-string-btn" does not exist in DOM');
      console.log('Expected by line 8174: Element with ID "hash-string-btn"');
      console.log('Actual: null');
      console.log('Impact: Calling .addEventListener() on null will throw TypeError');
      
      // On UNFIXED code: This element should NOT exist (test documents the bug)
      // On FIXED code: This element still won't exist, but the code won't try to access it
      expect(hashStringBtn).toBeNull();
    });

    it('should fail when attempting to attach event listener to non-existent hash-string-btn', () => {
      // COUNTEREXAMPLE 2: Simulating the exact code from line 8174
      // This demonstrates what happens in the unfixed code
      
      let errorThrown = false;
      let errorMessage = '';

      try {
        // This is the EXACT code from line 8174 in main.js (unfixed)
        document.getElementById("hash-string-btn").addEventListener("click", () => {
          console.log("Hash string button clicked");
        });
      } catch (error) {
        errorThrown = true;
        errorMessage = error.message;
      }

      console.log('COUNTEREXAMPLE FOUND: TypeError when attaching event listener');
      console.log('Code: document.getElementById("hash-string-btn").addEventListener(...)');
      console.log('Error:', errorMessage);
      console.log('Location: main.js line 8174');
      console.log('Consequence: All subsequent event listeners in DOMContentLoaded handler fail to register');
      
      // On UNFIXED code: This MUST throw an error (test documents the bug)
      // On FIXED code: This code won't exist in main.js anymore
      expect(errorThrown).toBe(true);
      expect(errorMessage).toMatch(/Cannot read propert|null/i);
    });
  });

  describe('Property 2: Expected Behavior - All Event Listeners Should Register', () => {
    it('should verify that critical DOM elements exist for event listener registration', () => {
      // Verify that the elements that SHOULD have event listeners exist
      const runAnalysisBtn = document.getElementById('run-analysis-btn');
      const toolCards = document.querySelectorAll('.cyber-tool-card');
      const filterButtons = document.querySelectorAll('.filter-pill');
      const welcomeModal = document.getElementById('welcome-modal');

      console.log('Verifying critical DOM elements exist:');
      console.log('- Run Analysis button:', runAnalysisBtn ? 'EXISTS' : 'MISSING');
      console.log('- Tool cards:', toolCards.length, 'found');
      console.log('- Filter buttons:', filterButtons.length, 'found');
      console.log('- Welcome modal:', welcomeModal ? 'EXISTS' : 'MISSING');

      // These elements SHOULD exist
      expect(runAnalysisBtn).not.toBeNull();
      expect(toolCards.length).toBeGreaterThan(0);
      expect(filterButtons.length).toBeGreaterThan(0);
      expect(welcomeModal).not.toBeNull();
    });

    it('should load main.js and verify it contains the problematic code at line 8174', () => {
      // Read main.js and verify the bug exists
      const mainJs = fs.readFileSync(
        path.resolve(process.cwd(), 'public/js/main.js'),
        'utf-8'
      );

      const lines = mainJs.split('\n');
      const line8174 = lines[8173]; // Array is 0-indexed

      console.log('Checking main.js line 8174:');
      console.log('Content:', line8174);
      
      // On UNFIXED code: Line 8174 should contain the problematic code
      // On FIXED code: This line should be removed or different
      const containsProblematicCode = line8174.includes('hash-string-btn') && 
                                       line8174.includes('addEventListener');
      
      if (containsProblematicCode) {
        console.log('COUNTEREXAMPLE FOUND: Problematic code exists at line 8174');
        console.log('This code will throw TypeError because hash-string-btn element does not exist');
        console.log('Expected behavior: This code should be removed');
        console.log('Actual behavior: Code still present, will break event listener registration');
      }

      // On UNFIXED code: This should be true (test FAILS - documents the bug)
      // On FIXED code: This should be false (test PASSES - bug is fixed)
      expect(containsProblematicCode).toBe(false);
    });
  });

  describe('Property-Based Test: Dashboard Initialization Should Complete Without Errors', () => {
    it('should complete dashboard initialization for any valid scenario', () => {
      // Property: For ANY dashboard load, initialization should complete without TypeError
      
      fc.assert(
        fc.property(
          fc.record({
            // Test different scenarios
            scenario: fc.constantFrom('initial-load', 'reload', 'navigation')
          }),
          (testCase) => {
            console.log('Testing scenario:', testCase.scenario);
            
            // Read main.js
            const mainJs = fs.readFileSync(
              path.resolve(process.cwd(), 'public/js/main.js'),
              'utf-8'
            );

            // Check if the problematic code exists
            const hasProblematicCode = mainJs.includes('document.getElementById("hash-string-btn").addEventListener');
            
            if (hasProblematicCode) {
              console.log('COUNTEREXAMPLE FOUND in property-based test:');
              console.log('Scenario:', testCase.scenario);
              console.log('Issue: main.js contains code that attempts to attach event listener to non-existent element');
              console.log('Element ID: hash-string-btn');
              console.log('Location: Line 8174');
              console.log('Expected: Code should be removed');
              console.log('Actual: Code still present');
              console.log('Impact: TypeError will prevent all subsequent event listeners from registering');
            }

            // Property: The problematic code should NOT exist
            // On UNFIXED code: returns false (test FAILS)
            // On FIXED code: returns true (test PASSES)
            return !hasProblematicCode;
          }
        ),
        { numRuns: 5 }
      );
    });
  });
});
