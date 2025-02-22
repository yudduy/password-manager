const API_BASE_URL = 'http://localhost:8000';

// Handle Google Sign-In
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'signInWithGoogle') {
    chrome.identity.getAuthToken({ interactive: true }, async function(token) {
      if (chrome.runtime.lastError || !token) {
        sendResponse({ success: false, error: 'Failed to get auth token' });
        return;
      }

      try {
        // Get user info from Google
        const userInfoResponse = await fetch(
          'https://www.googleapis.com/oauth2/v3/userinfo',
          {
            headers: { Authorization: `Bearer ${token}` }
          }
        );
        const userInfo = await userInfoResponse.json();

        // Login to our backend
        const loginResponse = await fetch(`${API_BASE_URL}/token`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
          },
          body: `username=${encodeURIComponent(userInfo.email)}&password=${encodeURIComponent(token)}`
        });

        if (!loginResponse.ok) {
          throw new Error('Failed to login to backend');
        }

        const loginData = await loginResponse.json();
        
        // Store the access token
        await chrome.storage.local.set({
          accessToken: loginData.access_token,
          userEmail: userInfo.email
        });

        sendResponse({ success: true });
      } catch (error) {
        console.error('Auth error:', error);
        sendResponse({ success: false, error: error.message });
      }
    });
    return true; // Required for async response
  }
});

// Handle API requests
async function makeAuthenticatedRequest(endpoint, options = {}) {
  const { accessToken } = await chrome.storage.local.get('accessToken');
  if (!accessToken) {
    throw new Error('Not authenticated');
  }

  const response = await fetch(`${API_BASE_URL}${endpoint}`, {
    ...options,
    headers: {
      ...options.headers,
      'Authorization': `Bearer ${accessToken}`,
      'Content-Type': 'application/json',
    },
  });

  if (!response.ok) {
    throw new Error(`API request failed: ${response.statusText}`);
  }

  return response.json();
}

// Handle password operations
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'getPasswords') {
    makeAuthenticatedRequest('/passwords')
      .then(data => sendResponse({ success: true, data }))
      .catch(error => sendResponse({ success: false, error: error.message }));
    return true;
  }

  if (request.action === 'addPassword') {
    makeAuthenticatedRequest('/passwords', {
      method: 'POST',
      body: JSON.stringify({
        domain: request.domain,
        password: request.password
      })
    })
      .then(data => sendResponse({ success: true, data }))
      .catch(error => sendResponse({ success: false, error: error.message }));
    return true;
  }

  if (request.action === 'deletePassword') {
    makeAuthenticatedRequest(`/passwords/${encodeURIComponent(request.domain)}`, {
      method: 'DELETE'
    })
      .then(data => sendResponse({ success: true, data }))
      .catch(error => sendResponse({ success: false, error: error.message }));
    return true;
  }
}); 