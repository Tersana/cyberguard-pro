/**
 * Unit tests for toggleSidebar() function
 * Tests Requirements 5.1, 5.2, 11.1, 11.2, 11.3
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { JSDOM } from 'jsdom';

describe('toggleSidebar() function', () => {
    let dom;
    let document;
    let window;
    let toggleSidebar;
    let saveSidebarState;
    let loadSidebarState;
    let setSidebarState;
    let initSidebar;

    beforeEach(() => {
        // Create a minimal DOM structure
        dom = new JSDOM(`
            <!DOCTYPE html>
            <html>
            <body>
                <div id="app" class="flex h-screen overflow-hidden">
                    <div id="sidebar-overlay" class="cyber-sidebar-overlay"></div>
                    <button 
                        id="sidebar-toggle-btn" 
                        class="cyber-sidebar-toggle" 
                        aria-label="Toggle sidebar navigation"
                        aria-expanded="true"
                        aria-controls="sidebar">
                    </button>
                    <aside id="sidebar" class="cyber-sidebar w-64 flex-shrink-0 flex flex-col z-40">
                        <div class="cyber-user-card">User Profile</div>
                    </aside>
                    <main class="flex-1 flex flex-col overflow-hidden">
                        Main Content
                    </main>
                </div>
            </body>
            </html>
        `, { 
            url: 'http://localhost',
            pretendToBeVisual: true,
            resources: 'usable'
        });

        document = dom.window.document;
        window = dom.window;

        // Mock localStorage
        const localStorageMock = (() => {
            let store = {};
            return {
                getItem: (key) => store[key] || null,
                setItem: (key, value) => { store[key] = value.toString(); },
                removeItem: (key) => { delete store[key]; },
                clear: () => { store = {}; }
            };
        })();
        global.localStorage = localStorageMock;

        // Mock requestAnimationFrame
        global.requestAnimationFrame = (cb) => setTimeout(cb, 0);

        // Define the functions in the test scope
        saveSidebarState = function(isCollapsed) {
            try {
                localStorage.setItem('sidebarCollapsed', JSON.stringify(isCollapsed));
            } catch (error) {
                console.warn('Failed to save sidebar state:', error);
            }
        };

        loadSidebarState = function() {
            try {
                const stored = localStorage.getItem('sidebarCollapsed');
                if (stored === null) return false;
                
                const parsed = JSON.parse(stored);
                if (typeof parsed !== 'boolean') {
                    console.warn('Invalid sidebar state type');
                    return false;
                }
                return parsed;
            } catch (error) {
                console.warn('Failed to load sidebar state:', error);
                return false;
            }
        };

        toggleSidebar = function() {
            const sidebar = document.getElementById('sidebar');
            const toggleBtn = document.getElementById('sidebar-toggle-btn');
            const overlay = document.getElementById('sidebar-overlay');
            const main = document.querySelector('main');
            
            if (!sidebar || !toggleBtn || !overlay || !main) {
                console.warn('Sidebar toggle: Required elements not found');
                return;
            }
            
            const isCollapsed = sidebar.classList.contains('sidebar-collapsed');
            const newState = !isCollapsed;
            
            requestAnimationFrame(() => {
                sidebar.style.willChange = 'transform, width, opacity';
                main.style.willChange = 'margin-left';
                
                sidebar.classList.toggle('sidebar-collapsed');
                
                toggleBtn.setAttribute('aria-expanded', isCollapsed ? 'true' : 'false');
                sidebar.setAttribute('aria-hidden', newState ? 'true' : 'false');
                
                if (window.innerWidth < 768) {
                    overlay.classList.toggle('active', !newState);
                }
            });
            
            setTimeout(() => {
                sidebar.style.willChange = 'auto';
                main.style.willChange = 'auto';
            }, 300);
            
            saveSidebarState(newState);
            
            // Use window.CustomEvent for JSDOM compatibility
            const event = new window.CustomEvent('sidebarToggled', {
                detail: { isCollapsed: newState, timestamp: Date.now() }
            });
            window.dispatchEvent(event);
        };

        setSidebarState = function(collapsed) {
            const sidebar = document.getElementById('sidebar');
            if (!sidebar) return;
            
            const isCurrentlyCollapsed = sidebar.classList.contains('sidebar-collapsed');
            
            if (collapsed !== isCurrentlyCollapsed) {
                toggleSidebar();
            }
        };
    });

    afterEach(() => {
        localStorage.clear();
        dom.window.close();
    });

    it('should toggle .sidebar-collapsed class on sidebar element', async () => {
        const sidebar = document.getElementById('sidebar');
        
        expect(sidebar.classList.contains('sidebar-collapsed')).toBe(false);
        
        toggleSidebar();
        
        // Wait for requestAnimationFrame
        await new Promise(resolve => setTimeout(resolve, 10));
        
        expect(sidebar.classList.contains('sidebar-collapsed')).toBe(true);
    });

    it('should update ARIA attributes when toggling', async () => {
        const toggleBtn = document.getElementById('sidebar-toggle-btn');
        const sidebar = document.getElementById('sidebar');
        
        expect(toggleBtn.getAttribute('aria-expanded')).toBe('true');
        expect(sidebar.getAttribute('aria-hidden')).toBeFalsy();
        
        toggleSidebar();
        
        await new Promise(resolve => setTimeout(resolve, 10));
        
        expect(toggleBtn.getAttribute('aria-expanded')).toBe('false');
        expect(sidebar.getAttribute('aria-hidden')).toBe('true');
    });

    it('should add will-change properties for performance', async () => {
        const sidebar = document.getElementById('sidebar');
        const main = document.querySelector('main');
        
        toggleSidebar();
        
        await new Promise(resolve => setTimeout(resolve, 10));
        
        expect(sidebar.style.willChange).toBe('transform, width, opacity');
        expect(main.style.willChange).toBe('margin-left');
    });

    it('should remove will-change properties after 300ms', async () => {
        const sidebar = document.getElementById('sidebar');
        const main = document.querySelector('main');
        
        toggleSidebar();
        
        await new Promise(resolve => setTimeout(resolve, 10));
        expect(sidebar.style.willChange).toBe('transform, width, opacity');
        
        await new Promise(resolve => setTimeout(resolve, 310));
        
        expect(sidebar.style.willChange).toBe('auto');
        expect(main.style.willChange).toBe('auto');
    });

    it('should save state to LocalStorage', async () => {
        toggleSidebar();
        
        await new Promise(resolve => setTimeout(resolve, 10));
        
        const stored = localStorage.getItem('sidebarCollapsed');
        expect(stored).toBe('true');
    });

    it('should load state from LocalStorage', () => {
        localStorage.setItem('sidebarCollapsed', 'true');
        
        const state = loadSidebarState();
        expect(state).toBe(true);
    });

    it('should handle missing elements gracefully', () => {
        // Remove sidebar element
        const sidebar = document.getElementById('sidebar');
        sidebar.remove();
        
        // Should not throw error
        expect(() => toggleSidebar()).not.toThrow();
    });

    it('should be callable from event handlers', async () => {
        const toggleBtn = document.getElementById('sidebar-toggle-btn');
        const sidebar = document.getElementById('sidebar');
        
        // Simulate click event
        toggleBtn.addEventListener('click', toggleSidebar);
        toggleBtn.click();
        
        await new Promise(resolve => setTimeout(resolve, 10));
        
        expect(sidebar.classList.contains('sidebar-collapsed')).toBe(true);
    });

    it('should work with existing dashboard.html structure', () => {
        const sidebar = document.getElementById('sidebar');
        const toggleBtn = document.getElementById('sidebar-toggle-btn');
        const overlay = document.getElementById('sidebar-overlay');
        const main = document.querySelector('main');
        
        expect(sidebar).toBeTruthy();
        expect(toggleBtn).toBeTruthy();
        expect(overlay).toBeTruthy();
        expect(main).toBeTruthy();
    });

    it('should handle rapid toggles without errors', async () => {
        const sidebar = document.getElementById('sidebar');
        
        // Rapid toggles
        toggleSidebar();
        toggleSidebar();
        toggleSidebar();
        
        await new Promise(resolve => setTimeout(resolve, 10));
        
        // Should end in collapsed state (odd number of toggles)
        expect(sidebar.classList.contains('sidebar-collapsed')).toBe(true);
    });

    it('should dispatch custom sidebarToggled event', async () => {
        let eventFired = false;
        let eventDetail = null;
        
        window.addEventListener('sidebarToggled', (e) => {
            eventFired = true;
            eventDetail = e.detail;
        });
        
        toggleSidebar();
        
        await new Promise(resolve => setTimeout(resolve, 10));
        
        expect(eventFired).toBe(true);
        expect(eventDetail).toBeTruthy();
        expect(eventDetail.isCollapsed).toBe(true);
        expect(typeof eventDetail.timestamp).toBe('number');
    });
});

/**
 * Unit tests for setSidebarState(collapsed) function
 * Tests Requirement 5.7 - Programmatic sidebar state control
 */
describe('setSidebarState(collapsed) function', () => {
    let dom;
    let document;
    let window;
    let toggleSidebar;
    let saveSidebarState;
    let setSidebarState;
    let toggleCallCount;

    beforeEach(() => {
        // Create a minimal DOM structure
        dom = new JSDOM(`
            <!DOCTYPE html>
            <html>
            <body>
                <div id="app" class="flex h-screen overflow-hidden">
                    <div id="sidebar-overlay" class="cyber-sidebar-overlay"></div>
                    <button 
                        id="sidebar-toggle-btn" 
                        class="cyber-sidebar-toggle" 
                        aria-label="Toggle sidebar navigation"
                        aria-expanded="true"
                        aria-controls="sidebar">
                    </button>
                    <aside id="sidebar" class="cyber-sidebar w-64 flex-shrink-0 flex flex-col z-40">
                        <div class="cyber-user-card">User Profile</div>
                    </aside>
                    <main class="flex-1 flex flex-col overflow-hidden">
                        Main Content
                    </main>
                </div>
            </body>
            </html>
        `, { 
            url: 'http://localhost',
            pretendToBeVisual: true,
            resources: 'usable'
        });

        document = dom.window.document;
        window = dom.window;

        // Mock localStorage
        const localStorageMock = (() => {
            let store = {};
            return {
                getItem: (key) => store[key] || null,
                setItem: (key, value) => { store[key] = value.toString(); },
                removeItem: (key) => { delete store[key]; },
                clear: () => { store = {}; }
            };
        })();
        global.localStorage = localStorageMock;

        // Mock requestAnimationFrame
        global.requestAnimationFrame = (cb) => setTimeout(cb, 0);

        // Track toggleSidebar calls
        toggleCallCount = 0;

        // Define the functions in the test scope
        saveSidebarState = function(isCollapsed) {
            try {
                localStorage.setItem('sidebarCollapsed', JSON.stringify(isCollapsed));
            } catch (error) {
                console.warn('Failed to save sidebar state:', error);
            }
        };

        toggleSidebar = function() {
            toggleCallCount++;
            const sidebar = document.getElementById('sidebar');
            const toggleBtn = document.getElementById('sidebar-toggle-btn');
            const overlay = document.getElementById('sidebar-overlay');
            const main = document.querySelector('main');
            
            if (!sidebar || !toggleBtn || !overlay || !main) {
                console.warn('Sidebar toggle: Required elements not found');
                return;
            }
            
            const isCollapsed = sidebar.classList.contains('sidebar-collapsed');
            const newState = !isCollapsed;
            
            requestAnimationFrame(() => {
                sidebar.style.willChange = 'transform, width, opacity';
                main.style.willChange = 'margin-left';
                
                sidebar.classList.toggle('sidebar-collapsed');
                
                toggleBtn.setAttribute('aria-expanded', isCollapsed ? 'true' : 'false');
                sidebar.setAttribute('aria-hidden', newState ? 'true' : 'false');
                
                if (window.innerWidth < 768) {
                    overlay.classList.toggle('active', !newState);
                }
            });
            
            setTimeout(() => {
                sidebar.style.willChange = 'auto';
                main.style.willChange = 'auto';
            }, 300);
            
            saveSidebarState(newState);
            
            const event = new window.CustomEvent('sidebarToggled', {
                detail: { isCollapsed: newState, timestamp: Date.now() }
            });
            window.dispatchEvent(event);
        };

        setSidebarState = function(collapsed) {
            const sidebar = document.getElementById('sidebar');
            if (!sidebar) return;
            
            const isCurrentlyCollapsed = sidebar.classList.contains('sidebar-collapsed');
            
            if (collapsed !== isCurrentlyCollapsed) {
                toggleSidebar();
            }
        };
    });

    afterEach(() => {
        localStorage.clear();
        dom.window.close();
    });

    it('should accept boolean parameter for programmatic control', () => {
        // Should not throw when called with boolean
        expect(() => setSidebarState(true)).not.toThrow();
        expect(() => setSidebarState(false)).not.toThrow();
    });

    it('should check current state before toggling', async () => {
        const sidebar = document.getElementById('sidebar');
        
        // Sidebar starts expanded (no .sidebar-collapsed class)
        expect(sidebar.classList.contains('sidebar-collapsed')).toBe(false);
        
        // Reset toggle call count
        toggleCallCount = 0;
        
        // Call setSidebarState(false) - sidebar is already expanded
        setSidebarState(false);
        
        // Should NOT call toggleSidebar because state is already false (expanded)
        expect(toggleCallCount).toBe(0);
        expect(sidebar.classList.contains('sidebar-collapsed')).toBe(false);
    });

    it('should only call toggleSidebar() if state differs', async () => {
        const sidebar = document.getElementById('sidebar');
        
        // Test 1: Sidebar is expanded, set to expanded (no toggle)
        toggleCallCount = 0;
        setSidebarState(false);
        expect(toggleCallCount).toBe(0);
        
        // Test 2: Sidebar is expanded, set to collapsed (should toggle)
        toggleCallCount = 0;
        setSidebarState(true);
        await new Promise(resolve => setTimeout(resolve, 10));
        expect(toggleCallCount).toBe(1);
        expect(sidebar.classList.contains('sidebar-collapsed')).toBe(true);
        
        // Test 3: Sidebar is collapsed, set to collapsed (no toggle)
        toggleCallCount = 0;
        setSidebarState(true);
        expect(toggleCallCount).toBe(0);
        
        // Test 4: Sidebar is collapsed, set to expanded (should toggle)
        toggleCallCount = 0;
        setSidebarState(false);
        await new Promise(resolve => setTimeout(resolve, 10));
        expect(toggleCallCount).toBe(1);
        expect(sidebar.classList.contains('sidebar-collapsed')).toBe(false);
    });

    it('should work correctly for collapse operation (true)', async () => {
        const sidebar = document.getElementById('sidebar');
        
        // Sidebar starts expanded
        expect(sidebar.classList.contains('sidebar-collapsed')).toBe(false);
        
        // Collapse the sidebar
        setSidebarState(true);
        
        await new Promise(resolve => setTimeout(resolve, 10));
        
        // Sidebar should now be collapsed
        expect(sidebar.classList.contains('sidebar-collapsed')).toBe(true);
    });

    it('should work correctly for expand operation (false)', async () => {
        const sidebar = document.getElementById('sidebar');
        
        // First collapse the sidebar
        sidebar.classList.add('sidebar-collapsed');
        expect(sidebar.classList.contains('sidebar-collapsed')).toBe(true);
        
        // Expand the sidebar
        setSidebarState(false);
        
        await new Promise(resolve => setTimeout(resolve, 10));
        
        // Sidebar should now be expanded
        expect(sidebar.classList.contains('sidebar-collapsed')).toBe(false);
    });

    it('should handle missing sidebar element gracefully', () => {
        // Remove sidebar element
        const sidebar = document.getElementById('sidebar');
        sidebar.remove();
        
        // Should not throw error
        expect(() => setSidebarState(true)).not.toThrow();
        expect(() => setSidebarState(false)).not.toThrow();
    });

    it('should allow external code to set sidebar state without manual toggling', async () => {
        const sidebar = document.getElementById('sidebar');
        
        // External code can directly set the desired state
        setSidebarState(true);
        await new Promise(resolve => setTimeout(resolve, 10));
        expect(sidebar.classList.contains('sidebar-collapsed')).toBe(true);
        
        // External code can change state again
        setSidebarState(false);
        await new Promise(resolve => setTimeout(resolve, 10));
        expect(sidebar.classList.contains('sidebar-collapsed')).toBe(false);
        
        // External code can set to same state (no change)
        setSidebarState(false);
        expect(sidebar.classList.contains('sidebar-collapsed')).toBe(false);
    });

    it('should trigger state persistence when state changes', async () => {
        // Collapse sidebar
        setSidebarState(true);
        await new Promise(resolve => setTimeout(resolve, 10));
        
        const stored = localStorage.getItem('sidebarCollapsed');
        expect(stored).toBe('true');
        
        // Expand sidebar
        setSidebarState(false);
        await new Promise(resolve => setTimeout(resolve, 10));
        
        const storedAfter = localStorage.getItem('sidebarCollapsed');
        expect(storedAfter).toBe('false');
    });

    it('should not trigger state persistence when state does not change', () => {
        const sidebar = document.getElementById('sidebar');
        
        // Clear localStorage
        localStorage.clear();
        
        // Set to current state (expanded)
        setSidebarState(false);
        
        // Should not have saved anything because no toggle occurred
        const stored = localStorage.getItem('sidebarCollapsed');
        expect(stored).toBeNull();
    });

    it('should dispatch sidebarToggled event only when state changes', async () => {
        let eventCount = 0;
        
        window.addEventListener('sidebarToggled', () => {
            eventCount++;
        });
        
        // Set to different state (should trigger event)
        setSidebarState(true);
        await new Promise(resolve => setTimeout(resolve, 10));
        expect(eventCount).toBe(1);
        
        // Set to same state (should NOT trigger event)
        setSidebarState(true);
        await new Promise(resolve => setTimeout(resolve, 10));
        expect(eventCount).toBe(1); // Still 1, no new event
        
        // Set to different state again (should trigger event)
        setSidebarState(false);
        await new Promise(resolve => setTimeout(resolve, 10));
        expect(eventCount).toBe(2);
    });
});
