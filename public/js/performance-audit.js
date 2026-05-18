/**
 * Performance Optimization Audit for CyberGuard API Integration
 * Task 24.6: Performance optimization
 * 
 * This file contains utilities for:
 * - Detecting unnecessary API calls
 * - Implementing debouncing for user input
 * - Optimizing re-renders and DOM updates
 * - Testing with slow network conditions
 */

/**
 * Debounce utility function
 * Delays execution of a function until after a specified wait time has elapsed
 * since the last time it was invoked.
 * 
 * @param {Function} func - Function to debounce
 * @param {number} wait - Wait time in milliseconds
 * @param {boolean} immediate - Execute on leading edge instead of trailing
 * @returns {Function} Debounced function
 */
function debounce(func, wait = 300, immediate = false) {
  let timeout;
  
  return function executedFunction(...args) {
    const context = this;
    
    const later = function() {
      timeout = null;
      if (!immediate) func.apply(context, args);
    };
    
    const callNow = immediate && !timeout;
    
    clearTimeout(timeout);
    timeout = setTimeout(later, wait);
    
    if (callNow) func.apply(context, args);
  };
}

/**
 * Throttle utility function
 * Ensures a function is called at most once in a specified time period
 * 
 * @param {Function} func - Function to throttle
 * @param {number} limit - Time limit in milliseconds
 * @returns {Function} Throttled function
 */
function throttle(func, limit = 300) {
  let inThrottle;
  
  return function(...args) {
    const context = this;
    
    if (!inThrottle) {
      func.apply(context, args);
      inThrottle = true;
      setTimeout(() => inThrottle = false, limit);
    }
  };
}

/**
 * Request Cache
 * Caches API responses to prevent duplicate requests
 */
class RequestCache {
  constructor(ttl = 60000) { // Default TTL: 60 seconds
    this.cache = new Map();
    this.ttl = ttl;
  }
  
  /**
   * Generate cache key from endpoint and params
   */
  _generateKey(endpoint, params = {}) {
    const paramString = JSON.stringify(params);
    return `${endpoint}:${paramString}`;
  }
  
  /**
   * Get cached response if valid
   */
  get(endpoint, params = {}) {
    const key = this._generateKey(endpoint, params);
    const cached = this.cache.get(key);
    
    if (!cached) return null;
    
    // Check if cache is still valid
    if (Date.now() - cached.timestamp > this.ttl) {
      this.cache.delete(key);
      return null;
    }
    
    return cached.data;
  }
  
  /**
   * Set cache entry
   */
  set(endpoint, params = {}, data) {
    const key = this._generateKey(endpoint, params);
    this.cache.set(key, {
      data,
      timestamp: Date.now()
    });
  }
  
  /**
   * Clear cache entry or entire cache
   */
  clear(endpoint = null, params = {}) {
    if (endpoint) {
      const key = this._generateKey(endpoint, params);
      this.cache.delete(key);
    } else {
      this.cache.clear();
    }
  }
  
  /**
   * Clear expired entries
   */
  clearExpired() {
    const now = Date.now();
    for (const [key, value] of this.cache.entries()) {
      if (now - value.timestamp > this.ttl) {
        this.cache.delete(key);
      }
    }
  }
}

/**
 * API Call Tracker
 * Tracks API calls to detect duplicates and unnecessary requests
 */
class APICallTracker {
  constructor() {
    this.calls = [];
    this.enabled = false;
  }
  
  /**
   * Enable tracking
   */
  enable() {
    this.enabled = true;
    this.calls = [];
    console.log('[APICallTracker] Tracking enabled');
  }
  
  /**
   * Disable tracking
   */
  disable() {
    this.enabled = false;
    console.log('[APICallTracker] Tracking disabled');
  }
  
  /**
   * Track an API call
   */
  track(method, endpoint, timestamp = Date.now()) {
    if (!this.enabled) return;
    
    this.calls.push({
      method,
      endpoint,
      timestamp,
      stack: new Error().stack
    });
  }
  
  /**
   * Get duplicate calls within a time window
   */
  getDuplicates(timeWindow = 1000) {
    const duplicates = [];
    const seen = new Map();
    
    for (const call of this.calls) {
      const key = `${call.method}:${call.endpoint}`;
      const previous = seen.get(key);
      
      if (previous && call.timestamp - previous.timestamp < timeWindow) {
        duplicates.push({
          call,
          previous,
          timeDiff: call.timestamp - previous.timestamp
        });
      }
      
      seen.set(key, call);
    }
    
    return duplicates;
  }
  
  /**
   * Get call statistics
   */
  getStats() {
    const stats = {
      total: this.calls.length,
      byEndpoint: {},
      byMethod: {}
    };
    
    for (const call of this.calls) {
      // Count by endpoint
      stats.byEndpoint[call.endpoint] = (stats.byEndpoint[call.endpoint] || 0) + 1;
      
      // Count by method
      stats.byMethod[call.method] = (stats.byMethod[call.method] || 0) + 1;
    }
    
    return stats;
  }
  
  /**
   * Generate report
   */
  report() {
    const stats = this.getStats();
    const duplicates = this.getDuplicates();
    
    console.group('[APICallTracker] Performance Report');
    console.log('Total API calls:', stats.total);
    console.log('Calls by endpoint:', stats.byEndpoint);
    console.log('Calls by method:', stats.byMethod);
    console.log('Duplicate calls (within 1s):', duplicates.length);
    
    if (duplicates.length > 0) {
      console.warn('Duplicate calls detected:');
      duplicates.forEach(dup => {
        console.warn(`  ${dup.call.method} ${dup.call.endpoint} (${dup.timeDiff}ms apart)`);
      });
    }
    
    console.groupEnd();
    
    return { stats, duplicates };
  }
  
  /**
   * Clear tracking data
   */
  clear() {
    this.calls = [];
  }
}

/**
 * DOM Update Batcher
 * Batches DOM updates to minimize reflows and repaints
 */
class DOMUpdateBatcher {
  constructor() {
    this.updates = [];
    this.scheduled = false;
  }
  
  /**
   * Schedule a DOM update
   */
  schedule(updateFn) {
    this.updates.push(updateFn);
    
    if (!this.scheduled) {
      this.scheduled = true;
      requestAnimationFrame(() => this.flush());
    }
  }
  
  /**
   * Execute all scheduled updates
   */
  flush() {
    const updates = this.updates.slice();
    this.updates = [];
    this.scheduled = false;
    
    // Execute all updates in a single batch
    updates.forEach(fn => {
      try {
        fn();
      } catch (error) {
        console.error('[DOMUpdateBatcher] Error executing update:', error);
      }
    });
  }
}

/**
 * Network Throttler
 * Simulates slow network conditions for testing
 */
class NetworkThrottler {
  constructor() {
    this.enabled = false;
    this.delay = 0;
    this.originalFetch = null;
  }
  
  /**
   * Enable network throttling
   * @param {number} delay - Delay in milliseconds
   */
  enable(delay = 3000) {
    if (this.enabled) return;
    
    this.enabled = true;
    this.delay = delay;
    this.originalFetch = window.fetch;
    
    // Override fetch to add delay
    window.fetch = async (...args) => {
      console.log(`[NetworkThrottler] Delaying request by ${delay}ms:`, args[0]);
      await new Promise(resolve => setTimeout(resolve, delay));
      return this.originalFetch.apply(window, args);
    };
    
    console.log(`[NetworkThrottler] Enabled with ${delay}ms delay`);
  }
  
  /**
   * Disable network throttling
   */
  disable() {
    if (!this.enabled) return;
    
    this.enabled = false;
    
    if (this.originalFetch) {
      window.fetch = this.originalFetch;
      this.originalFetch = null;
    }
    
    console.log('[NetworkThrottler] Disabled');
  }
  
  /**
   * Set delay
   */
  setDelay(delay) {
    this.delay = delay;
    console.log(`[NetworkThrottler] Delay set to ${delay}ms`);
  }
}

/**
 * Performance Monitor
 * Monitors and reports on performance metrics
 */
class PerformanceMonitor {
  constructor() {
    this.metrics = {
      apiCalls: 0,
      domUpdates: 0,
      renders: 0
    };
    this.marks = new Map();
  }
  
  /**
   * Mark start of an operation
   */
  mark(name) {
    this.marks.set(name, performance.now());
  }
  
  /**
   * Measure duration since mark
   */
  measure(name) {
    const start = this.marks.get(name);
    if (!start) {
      console.warn(`[PerformanceMonitor] No mark found for: ${name}`);
      return 0;
    }
    
    const duration = performance.now() - start;
    this.marks.delete(name);
    
    return duration;
  }
  
  /**
   * Log measurement
   */
  log(name, duration) {
    console.log(`[PerformanceMonitor] ${name}: ${duration.toFixed(2)}ms`);
  }
  
  /**
   * Increment metric
   */
  increment(metric) {
    if (this.metrics.hasOwnProperty(metric)) {
      this.metrics[metric]++;
    }
  }
  
  /**
   * Get metrics
   */
  getMetrics() {
    return { ...this.metrics };
  }
  
  /**
   * Reset metrics
   */
  reset() {
    this.metrics = {
      apiCalls: 0,
      domUpdates: 0,
      renders: 0
    };
    this.marks.clear();
  }
  
  /**
   * Report metrics
   */
  report() {
    console.group('[PerformanceMonitor] Metrics Report');
    console.log('API Calls:', this.metrics.apiCalls);
    console.log('DOM Updates:', this.metrics.domUpdates);
    console.log('Renders:', this.metrics.renders);
    console.groupEnd();
  }
}

// Create global instances
const requestCache = new RequestCache();
const apiCallTracker = new APICallTracker();
const domUpdateBatcher = new DOMUpdateBatcher();
const networkThrottler = new NetworkThrottler();
const performanceMonitor = new PerformanceMonitor();

// Export utilities
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    debounce,
    throttle,
    RequestCache,
    APICallTracker,
    DOMUpdateBatcher,
    NetworkThrottler,
    PerformanceMonitor,
    requestCache,
    apiCallTracker,
    domUpdateBatcher,
    networkThrottler,
    performanceMonitor
  };
}

// Make available globally in browser
if (typeof window !== 'undefined') {
  window.debounce = debounce;
  window.throttle = throttle;
  window.requestCache = requestCache;
  window.apiCallTracker = apiCallTracker;
  window.domUpdateBatcher = domUpdateBatcher;
  window.networkThrottler = networkThrottler;
  window.performanceMonitor = performanceMonitor;
}
