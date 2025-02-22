// DOM Elements
const loginView = document.getElementById('loginView');
const mainView = document.getElementById('mainView');
const addPasswordForm = document.getElementById('addPasswordForm');
const passwordsList = document.getElementById('passwordsList');
const searchInput = document.getElementById('searchDomain');

// Check authentication status on popup open
async function checkAuth() {
  const { accessToken } = await chrome.storage.local.get('accessToken');
  if (accessToken) {
    showMainView();
    loadPasswords();
  } else {
    showLoginView();
  }
}

// View management
function showLoginView() {
  loginView.classList.remove('hidden');
  mainView.classList.add('hidden');
  addPasswordForm.classList.add('hidden');
}

function showMainView() {
  loginView.classList.add('hidden');
  mainView.classList.remove('hidden');
  addPasswordForm.classList.add('hidden');
}

function showAddPasswordForm() {
  loginView.classList.add('hidden');
  mainView.classList.add('hidden');
  addPasswordForm.classList.remove('hidden');
}

// Password list management
async function loadPasswords() {
  try {
    const response = await chrome.runtime.sendMessage({ action: 'getPasswords' });
    if (response.success) {
      displayPasswords(response.data.domains);
    } else {
      console.error('Failed to load passwords:', response.error);
    }
  } catch (error) {
    console.error('Error loading passwords:', error);
  }
}

function displayPasswords(passwords) {
  passwordsList.innerHTML = '';
  const searchTerm = searchInput.value.toLowerCase();
  
  passwords
    .filter(p => p.domain.toLowerCase().includes(searchTerm))
    .forEach(password => {
      const item = document.createElement('div');
      item.className = 'password-item';
      item.innerHTML = `
        <span>${password.domain}</span>
        <div>
          <button class="btn btn-secondary copy-password" data-password="${password.password}">Copy</button>
          <button class="btn btn-secondary delete-password" data-domain="${password.domain}">Delete</button>
        </div>
      `;
      passwordsList.appendChild(item);
    });

  // Add event listeners for copy and delete buttons
  document.querySelectorAll('.copy-password').forEach(button => {
    button.addEventListener('click', async (e) => {
      const password = e.target.dataset.password;
      await navigator.clipboard.writeText(password);
      button.textContent = 'Copied!';
      setTimeout(() => {
        button.textContent = 'Copy';
      }, 1500);
    });
  });

  document.querySelectorAll('.delete-password').forEach(button => {
    button.addEventListener('click', async (e) => {
      const domain = e.target.dataset.domain;
      if (confirm(`Delete password for ${domain}?`)) {
        const response = await chrome.runtime.sendMessage({
          action: 'deletePassword',
          domain
        });
        if (response.success) {
          loadPasswords();
        }
      }
    });
  });
}

// Event Listeners
document.getElementById('loginWithGoogle').addEventListener('click', async () => {
  const response = await chrome.runtime.sendMessage({ action: 'signInWithGoogle' });
  if (response.success) {
    showMainView();
    loadPasswords();
  } else {
    alert('Failed to sign in with Google');
  }
});

document.getElementById('addPassword').addEventListener('click', () => {
  showAddPasswordForm();
});

document.getElementById('cancelAdd').addEventListener('click', () => {
  showMainView();
});

document.getElementById('passwordForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const domain = document.getElementById('domain').value;
  const password = document.getElementById('password').value;

  const response = await chrome.runtime.sendMessage({
    action: 'addPassword',
    domain,
    password
  });

  if (response.success) {
    document.getElementById('passwordForm').reset();
    showMainView();
    loadPasswords();
  } else {
    alert('Failed to add password');
  }
});

document.querySelector('.toggle-password').addEventListener('click', (e) => {
  const passwordInput = document.getElementById('password');
  const type = passwordInput.type === 'password' ? 'text' : 'password';
  passwordInput.type = type;
  e.target.textContent = type === 'password' ? '👁️' : '🔒';
});

searchInput.addEventListener('input', () => {
  loadPasswords();
});

// Add these event listeners after existing ones
document.getElementById('generatePassword').addEventListener('click', () => {
  const options = {
    length: parseInt(document.getElementById('passwordLength').value),
    includeUppercase: document.getElementById('includeUppercase').checked,
    includeLowercase: document.getElementById('includeLowercase').checked,
    includeNumbers: document.getElementById('includeNumbers').checked,
    includeSymbols: document.getElementById('includeSymbols').checked
  };

  const password = generateSecurePassword(options);
  document.getElementById('password').value = password;
});

document.getElementById('passwordLength').addEventListener('input', (e) => {
  document.getElementById('lengthValue').textContent = e.target.value;
});

// Add password strength indicator
function checkPasswordStrength(password) {
  let strength = 0;
  
  if (password.length >= 12) strength += 1;
  if (/[A-Z]/.test(password)) strength += 1;
  if (/[a-z]/.test(password)) strength += 1;
  if (/[0-9]/.test(password)) strength += 1;
  if (/[^A-Za-z0-9]/.test(password)) strength += 1;
  
  return strength;
}

document.getElementById('password').addEventListener('input', (e) => {
  const strength = checkPasswordStrength(e.target.value);
  const strengthIndicator = document.createElement('div');
  strengthIndicator.className = `strength-${strength}`;
  // Update strength indicator UI
});

// Initialize popup
checkAuth(); 