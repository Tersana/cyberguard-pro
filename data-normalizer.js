/**
 * CyberGuard Pro Data Normalizer Utility
 * Handles backend data inconsistencies and provides consistent data structures
 * 
 * Validates: Requirements 2.2, 13.1, 13.2, 13.3, 13.4, 13.5
 * Version: 1.0.3 - Fixed script loading conflicts
 */

console.log('[DataNormalizer] Loading data-normalizer.js v1.0.3');

/**
 * Normalizes user data from backend API responses
 * Handles inconsistencies like job_title vs job_tittle field names
 * 
 * @param {Object} userData - Raw user data from API response
 * @returns {Object} Normalized user object with consistent structure
 * 
 * @example
 * const rawData = { id: 1, email: 'user@example.com', job_tittle: 'Analyst' };
 * const normalized = normalizeUserData(rawData);
 * // Returns: { id: 1, email: 'user@example.com', jobTitle: 'Analyst', ... }
 */
function normalizeUserData(userData) {
  // Handle null or undefined input
  if (!userData || typeof userData !== 'object') {
    console.warn('[DataNormalizer] Invalid user data provided:', userData);
    return null;
  }

  return {
    // Required fields
    id: userData.id || null,
    email: userData.email || '',
    
    // Name fields - handle both full_name and name
    name: userData.full_name || userData.name || '',
    fullName: userData.full_name || userData.name || '',
    
    // Job title - handle both job_title and job_tittle (typo in backend)
    // Normalize to jobTitle for internal use
    jobTitle: userData.job_title || userData.job_tittle || '',
    
    // Optional boolean fields with defaults
    emailVerified: userData.email_verified ?? false,
    twoFactorEnabled: userData.two_factor_enabled ?? false,
    
    // Role with default
    role: userData.role || 'user',
    
    // Timestamp fields with fallbacks
    createdAt: userData.created_at || new Date().toISOString(),
    lastLogin: userData.last_login || new Date().toISOString(),
    
    // Preferences object with default
    preferences: userData.preferences || {}
  };
}

/**
 * Validates that a normalized user object has all required fields
 * 
 * @param {Object} user - Normalized user object
 * @returns {boolean} True if user has all required fields
 */
function validateNormalizedUser(user) {
  if (!user || typeof user !== 'object') {
    return false;
  }

  // Check required fields
  const hasRequiredFields = 
    user.id !== null &&
    typeof user.email === 'string' && user.email.length > 0 &&
    typeof user.fullName === 'string' && user.fullName.length > 0;

  return hasRequiredFields;
}

/**
 * Prepares user data for API requests
 * Converts internal camelCase format to backend snake_case format
 * 
 * @param {Object} userData - User data in internal format
 * @returns {Object} User data formatted for API request
 * 
 * @example
 * const internal = { fullName: 'John Doe', jobTitle: 'Analyst' };
 * const apiFormat = prepareUserDataForAPI(internal);
 * // Returns: { full_name: 'John Doe', job_tittle: 'Analyst' }
 */
function prepareUserDataForAPI(userData) {
  if (!userData || typeof userData !== 'object') {
    console.warn('[DataNormalizer] Invalid user data for API preparation:', userData);
    return {};
  }

  const apiData = {};

  // Map internal fields to API fields
  if (userData.fullName !== undefined) {
    apiData.full_name = userData.fullName;
  }
  
  if (userData.email !== undefined) {
    apiData.email = userData.email;
  }
  
  // Backend uses job_tittle (double 't') — match the backend's field name
  if (userData.jobTitle !== undefined) {
    apiData.job_tittle = userData.jobTitle;
  }
  
  if (userData.password !== undefined) {
    apiData.password = userData.password;
  }
  
  // Add password_confirmation for registration
  if (userData.passwordConfirmation !== undefined) {
    apiData.password_confirmation = userData.passwordConfirmation;
  }
  
  if (userData.role !== undefined) {
    apiData.role = userData.role;
  }

  return apiData;
}

/**
 * Normalizes project data from backend API responses
 * Ensures consistent structure for project objects
 * 
 * @param {Object} projectData - Raw project data from API
 * @returns {Object} Normalized project object
 */
function normalizeProjectData(projectData) {
  if (!projectData || typeof projectData !== 'object') {
    console.warn('[DataNormalizer] Invalid project data provided:', projectData);
    return null;
  }

  return {
    id: projectData.id || null,
    name: projectData.name || '',
    description: projectData.description || '',
    target: projectData.target || '',
    status: projectData.status || 'active',
    ownerId: projectData.owner_id || null,
    createdAt: projectData.created_at || new Date().toISOString(),
    updatedAt: projectData.updated_at || new Date().toISOString(),
    collaborators: Array.isArray(projectData.collaborators) 
      ? projectData.collaborators.map(normalizeCollaboratorData)
      : []
  };
}

/**
 * Normalizes collaborator data from backend API responses
 * 
 * @param {Object} collaboratorData - Raw collaborator data from API
 * @returns {Object} Normalized collaborator object
 */
function normalizeCollaboratorData(collaboratorData) {
  if (!collaboratorData || typeof collaboratorData !== 'object') {
    return null;
  }

  return {
    id: collaboratorData.id || null,
    fullName: collaboratorData.full_name || collaboratorData.name || '',
    email: collaboratorData.email || '',
    role: collaboratorData.role || 'collaborator',
    // Handle job_title/job_tittle for collaborators too
    jobTitle: collaboratorData.job_title || collaboratorData.job_tittle || ''
  };
}

// Export functions for use in other modules
if (typeof module !== 'undefined' && module.exports) {
  // Node.js environment (for testing)
  module.exports = {
    normalizeUserData,
    validateNormalizedUser,
    prepareUserDataForAPI,
    normalizeProjectData,
    normalizeCollaboratorData
  };
} else {
  // Browser environment - attach to window object
  window.normalizeUserData = normalizeUserData;
  window.validateNormalizedUser = validateNormalizedUser;
  window.prepareUserDataForAPI = prepareUserDataForAPI;
  window.normalizeProjectData = normalizeProjectData;
  window.normalizeCollaboratorData = normalizeCollaboratorData;
  
  console.log('[DataNormalizer] Functions exported to window object:', {
    normalizeUserData: typeof window.normalizeUserData,
    validateNormalizedUser: typeof window.validateNormalizedUser,
    prepareUserDataForAPI: typeof window.prepareUserDataForAPI,
    normalizeProjectData: typeof window.normalizeProjectData,
    normalizeCollaboratorData: typeof window.normalizeCollaboratorData
  });
}
