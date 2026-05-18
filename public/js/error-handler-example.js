/**
 * ErrorHandler Integration Example
 * Demonstrates how to use ErrorHandler with APIClient
 */

// Example 1: Using ErrorHandler with API Client
async function loginExample() {
  const apiClient = new APIClient();
  
  try {
    const response = await apiClient.post('/auth/login', {
      email: 'user@example.com',
      password: 'password123'
    });
    
    console.log('Login successful:', response);
  } catch (error) {
    // Use the generic handler to route to appropriate error handler
    ErrorHandler.handle(error);
  }
}

// Example 2: Handling validation errors with custom options
async function registerExample() {
  const apiClient = new APIClient();
  
  try {
    const response = await apiClient.post('/auth/register', {
      full_name: 'John Doe',
      email: 'invalid-email',
      job_title: 'Developer',
      password: '123' // Too short
    });
    
    console.log('Registration successful:', response);
  } catch (error) {
    if (error.name === 'ValidationError') {
      // Show inline errors and a summary notification
      ErrorHandler.handleValidationError(error, { showSummary: true });
    } else {
      ErrorHandler.handle(error);
    }
  }
}

// Example 3: Clearing field errors before submission
function clearFormErrors() {
  const form = document.getElementById('registration-form');
  ErrorHandler.clearAllFieldErrors(form);
}

// Example 4: Manual field error display
function validateEmailField() {
  const emailField = document.getElementById('email');
  const email = emailField.value;
  
  if (!email || !email.includes('@')) {
    ErrorHandler.showFieldError(emailField, 'Please enter a valid email address');
    return false;
  }
  
  ErrorHandler.clearFieldError(emailField);
  return true;
}

// Example 5: Using with form submission
document.getElementById('login-form')?.addEventListener('submit', async (e) => {
  e.preventDefault();
  
  // Clear any previous errors
  ErrorHandler.clearAllFieldErrors(e.target);
  
  const apiClient = new APIClient();
  const formData = new FormData(e.target);
  
  try {
    const response = await apiClient.post('/auth/login', {
      email: formData.get('email'),
      password: formData.get('password')
    });
    
    // Success - redirect to dashboard
    window.location.href = '/dashboard';
  } catch (error) {
    // ErrorHandler will display appropriate error messages
    ErrorHandler.handle(error);
  }
});

// Example 6: Custom error messages for specific scenarios
async function deleteProjectExample(projectId) {
  const apiClient = new APIClient();
  
  try {
    await apiClient.delete(`/projects/${projectId}`);
    
    if (window.CyberNotify) {
      window.CyberNotify.alert('Project deleted successfully', { type: 'info' });
    }
  } catch (error) {
    if (error.status === 404) {
      ErrorHandler.handleAPIError(error, {
        customMessage: 'Project not found. It may have already been deleted.'
      });
    } else {
      ErrorHandler.handle(error);
    }
  }
}
