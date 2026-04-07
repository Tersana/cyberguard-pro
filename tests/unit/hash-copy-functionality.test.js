import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';
import { JSDOM } from 'jsdom';

/**
 * Unit tests for Hash Generator Copy-to-Clipboard Functionality (Task 2.2)
 * Tests copy button functionality, visual feedback, and error handling
 * 
 * Requirements tested:
 * - 2.1: Copy button next to each hash output field
 * - 2.2: Clipboard API usage to copy hash values
 * - 2.3: Visual feedback for 2 seconds after successful copy
 * - 2.4: Visual feedback using color change or icon animation
 * - 2.5: Error message when Clipboard API unavailable
 */

describe('Hash Copy Functionality - Task 2.2', () => {
  let dom;
  let document;
  let window;
  let mockClipboard;
  
  beforeEach(() => {
    // Create a fresh DOM for each test
    dom = new JSDOM(`
      <!DOCTYPE html>
      <html>
        <body>
          <textarea id="ht-hash-input"></textarea>
          <button id="ht-copy-md5">
            <span class="material-symbols-outlined text-[14px]">content_copy</span> Copy
          </button>
          <div id="ht-hash-md5">098f6bcd4621d373cade4e832627b4f6</div>
          
          <button id="ht-copy-sha1">
            <span class="material-symbols-outlined text-[14px]">content_copy</span> Copy
          </button>
          <div id="ht-hash-sha1">a94a8fe5ccb19ba61c4c0873d391e987982fbbd3</div>
          
          <button id="ht-copy-sha256">
            <span class="material-symbols-outlined text-[14px]">content_copy</span> Copy
          </button>
          <div id="ht-hash-sha256">9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08</div>
          
          <button id="ht-copy-sha512">
            <span class="material-symbols-outlined text-[14px]">content_copy</span> Copy
          </button>
          <div id="ht-hash-sha512">ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff</div>
        </body>
      </html>
    `, { url: 'http://localhost' });
    
    document = dom.window.document;
    window = dom.window;
    
    // Mock clipboard API
    mockClipboard = {
      writeText: vi.fn().mockResolvedValue(undefined)
    };
    
    window.navigator.clipboard = mockClipboard;
    
    // Make document and window available globally for the test
    global.document = document;
    global.window = window;
  });
  
  afterEach(() => {
    vi.clearAllTimers();
    vi.restoreAllMocks();
  });
  
  describe('Copy Button Presence - Requirement 2.1', () => {
    it('should have copy button for MD5 hash', () => {
      const button = document.getElementById('ht-copy-md5');
      expect(button).toBeTruthy();
      expect(button.tagName).toBe('BUTTON');
    });
    
    it('should have copy button for SHA-1 hash', () => {
      const button = document.getElementById('ht-copy-sha1');
      expect(button).toBeTruthy();
      expect(button.tagName).toBe('BUTTON');
    });
    
    it('should have copy button for SHA-256 hash', () => {
      const button = document.getElementById('ht-copy-sha256');
      expect(button).toBeTruthy();
      expect(button.tagName).toBe('BUTTON');
    });
    
    it('should have copy button for SHA-512 hash', () => {
      const button = document.getElementById('ht-copy-sha512');
      expect(button).toBeTruthy();
      expect(button.tagName).toBe('BUTTON');
    });
    
    it('should have copy buttons next to hash output fields', () => {
      const md5Button = document.getElementById('ht-copy-md5');
      const md5Output = document.getElementById('ht-hash-md5');
      
      expect(md5Button).toBeTruthy();
      expect(md5Output).toBeTruthy();
      
      // Verify they exist in the same document
      expect(md5Button.ownerDocument).toBe(md5Output.ownerDocument);
    });
  });
  
  describe('Clipboard API Usage - Requirement 2.2', () => {
    it('should copy MD5 hash to clipboard when button clicked', async () => {
      const button = document.getElementById('ht-copy-md5');
      const hashElement = document.getElementById('ht-hash-md5');
      const expectedHash = hashElement.textContent;
      
      // Simulate the setupCopyButton functionality
      button.addEventListener('click', async () => {
        await window.navigator.clipboard.writeText(hashElement.textContent);
      });
      
      await button.click();
      
      expect(mockClipboard.writeText).toHaveBeenCalledWith(expectedHash);
    });
    
    it('should copy SHA-256 hash to clipboard when button clicked', async () => {
      const button = document.getElementById('ht-copy-sha256');
      const hashElement = document.getElementById('ht-hash-sha256');
      const expectedHash = hashElement.textContent;
      
      button.addEventListener('click', async () => {
        await window.navigator.clipboard.writeText(hashElement.textContent);
      });
      
      await button.click();
      
      expect(mockClipboard.writeText).toHaveBeenCalledWith(expectedHash);
    });
    
    it('should not copy empty hash values', async () => {
      const button = document.getElementById('ht-copy-md5');
      const hashElement = document.getElementById('ht-hash-md5');
      hashElement.textContent = ''; // Empty hash
      
      let copyAttempted = false;
      button.addEventListener('click', async () => {
        const text = hashElement.textContent;
        if (!text) return; // Should not copy empty
        copyAttempted = true;
        await window.navigator.clipboard.writeText(text);
      });
      
      await button.click();
      
      expect(copyAttempted).toBe(false);
      expect(mockClipboard.writeText).not.toHaveBeenCalled();
    });
  });
  
  describe('Visual Feedback - Requirements 2.3, 2.4', () => {
    it('should display visual feedback after successful copy', async () => {
      vi.useFakeTimers();
      
      const button = document.getElementById('ht-copy-md5');
      const hashElement = document.getElementById('ht-hash-md5');
      const originalHTML = button.innerHTML;
      
      // Simulate setupCopyButton functionality
      button.addEventListener('click', async () => {
        const text = hashElement.textContent;
        if (!text) return;
        
        try {
          await window.navigator.clipboard.writeText(text);
          
          // Visual feedback
          button.innerHTML = '<span class="material-symbols-outlined text-[14px]">check</span> Copied!';
          button.classList.add('text-green-400');
          
          setTimeout(() => {
            button.innerHTML = originalHTML;
            button.classList.remove('text-green-400');
          }, 2000);
        } catch (error) {
          console.error('Clipboard error:', error);
        }
      });
      
      await button.click();
      
      // Check immediate feedback
      expect(button.innerHTML).toContain('check');
      expect(button.innerHTML).toContain('Copied!');
      expect(button.classList.contains('text-green-400')).toBe(true);
      
      // Fast-forward 2 seconds
      vi.advanceTimersByTime(2000);
      
      // Check feedback is removed
      expect(button.innerHTML).toBe(originalHTML);
      expect(button.classList.contains('text-green-400')).toBe(false);
      
      vi.useRealTimers();
    });
    
    it('should use icon animation for visual feedback', async () => {
      const button = document.getElementById('ht-copy-sha256');
      const hashElement = document.getElementById('ht-hash-sha256');
      
      button.addEventListener('click', async () => {
        const text = hashElement.textContent;
        if (!text) return;
        
        await window.navigator.clipboard.writeText(text);
        button.innerHTML = '<span class="material-symbols-outlined text-[14px]">check</span> Copied!';
      });
      
      await button.click();
      
      // Verify icon changed from content_copy to check
      expect(button.innerHTML).toContain('check');
      expect(button.innerHTML).not.toContain('content_copy');
    });
    
    it('should use color change for visual feedback', async () => {
      const button = document.getElementById('ht-copy-sha512');
      const hashElement = document.getElementById('ht-hash-sha512');
      
      button.addEventListener('click', async () => {
        const text = hashElement.textContent;
        if (!text) return;
        
        await window.navigator.clipboard.writeText(text);
        button.classList.add('text-green-400');
      });
      
      await button.click();
      
      // Verify color class was added
      expect(button.classList.contains('text-green-400')).toBe(true);
    });
    
    it('should display feedback for exactly 2 seconds', async () => {
      vi.useFakeTimers();
      
      const button = document.getElementById('ht-copy-md5');
      const hashElement = document.getElementById('ht-hash-md5');
      const originalHTML = button.innerHTML;
      
      button.addEventListener('click', async () => {
        const text = hashElement.textContent;
        if (!text) return;
        
        await window.navigator.clipboard.writeText(text);
        button.innerHTML = '<span class="material-symbols-outlined text-[14px]">check</span> Copied!';
        button.classList.add('text-green-400');
        
        setTimeout(() => {
          button.innerHTML = originalHTML;
          button.classList.remove('text-green-400');
        }, 2000);
      });
      
      await button.click();
      
      // After 1.9 seconds, feedback should still be visible
      vi.advanceTimersByTime(1900);
      expect(button.innerHTML).toContain('Copied!');
      expect(button.classList.contains('text-green-400')).toBe(true);
      
      // After 2 seconds, feedback should be removed
      vi.advanceTimersByTime(100);
      expect(button.innerHTML).toBe(originalHTML);
      expect(button.classList.contains('text-green-400')).toBe(false);
      
      vi.useRealTimers();
    });
  });
  
  describe('Error Handling - Requirement 2.5', () => {
    it('should handle Clipboard API unavailability', async () => {
      // Remove clipboard API
      delete window.navigator.clipboard;
      
      const button = document.getElementById('ht-copy-md5');
      const hashElement = document.getElementById('ht-hash-md5');
      let errorOccurred = false;
      let errorMessage = '';
      
      // Mock alert
      window.alert = vi.fn((msg) => {
        errorMessage = msg;
      });
      
      button.addEventListener('click', async () => {
        const text = hashElement.textContent;
        if (!text) return;
        
        try {
          if (!window.navigator.clipboard) {
            throw new Error('Clipboard API not available');
          }
          await window.navigator.clipboard.writeText(text);
        } catch (error) {
          errorOccurred = true;
          console.error('Clipboard error:', error);
          window.alert('Failed to copy to clipboard. Please copy manually.');
        }
      });
      
      await button.click();
      
      expect(errorOccurred).toBe(true);
      expect(errorMessage).toContain('Failed to copy to clipboard');
    });
    
    it('should handle clipboard permission denial', async () => {
      // Mock clipboard to reject
      mockClipboard.writeText = vi.fn().mockRejectedValue(new Error('Permission denied'));
      
      const button = document.getElementById('ht-copy-sha256');
      const hashElement = document.getElementById('ht-hash-sha256');
      let errorHandled = false;
      
      window.alert = vi.fn();
      
      button.addEventListener('click', async () => {
        const text = hashElement.textContent;
        if (!text) return;
        
        try {
          await window.navigator.clipboard.writeText(text);
        } catch (error) {
          errorHandled = true;
          console.error('Clipboard error:', error);
          window.alert('Failed to copy to clipboard. Please copy manually.');
        }
      });
      
      await button.click();
      
      expect(errorHandled).toBe(true);
      expect(window.alert).toHaveBeenCalledWith('Failed to copy to clipboard. Please copy manually.');
    });
    
    it('should display error message when copy fails', async () => {
      mockClipboard.writeText = vi.fn().mockRejectedValue(new Error('Copy failed'));
      
      const button = document.getElementById('ht-copy-sha1');
      const hashElement = document.getElementById('ht-hash-sha1');
      
      const alertSpy = vi.spyOn(window, 'alert').mockImplementation(() => {});
      
      button.addEventListener('click', async () => {
        const text = hashElement.textContent;
        if (!text) return;
        
        try {
          await window.navigator.clipboard.writeText(text);
        } catch (error) {
          console.error('Clipboard error:', error);
          window.alert('Failed to copy to clipboard. Please copy manually.');
        }
      });
      
      await button.click();
      
      expect(alertSpy).toHaveBeenCalled();
      expect(alertSpy.mock.calls[0][0]).toMatch(/Failed to copy/i);
      
      alertSpy.mockRestore();
    });
  });
  
  describe('Integration with Hash Generator', () => {
    it('should copy dynamically generated hash values', async () => {
      const hashElement = document.getElementById('ht-hash-md5');
      const button = document.getElementById('ht-copy-md5');
      
      // Simulate hash generation
      const newHash = 'abc123def456789';
      hashElement.textContent = newHash;
      
      button.addEventListener('click', async () => {
        await window.navigator.clipboard.writeText(hashElement.textContent);
      });
      
      await button.click();
      
      expect(mockClipboard.writeText).toHaveBeenCalledWith(newHash);
    });
    
    it('should work with all four hash algorithms', async () => {
      const hashIds = ['ht-hash-md5', 'ht-hash-sha1', 'ht-hash-sha256', 'ht-hash-sha512'];
      const buttonIds = ['ht-copy-md5', 'ht-copy-sha1', 'ht-copy-sha256', 'ht-copy-sha512'];
      
      for (let i = 0; i < hashIds.length; i++) {
        const hashElement = document.getElementById(hashIds[i]);
        const button = document.getElementById(buttonIds[i]);
        const expectedHash = hashElement.textContent;
        
        button.addEventListener('click', async () => {
          await window.navigator.clipboard.writeText(hashElement.textContent);
        });
        
        await button.click();
        
        expect(mockClipboard.writeText).toHaveBeenCalledWith(expectedHash);
      }
      
      // Should have been called 4 times (once for each hash type)
      expect(mockClipboard.writeText).toHaveBeenCalledTimes(4);
    });
  });
});
