const errorBanner = document.getElementById('error-banner');
const statusBanner = document.getElementById('welcome-status');
const actionButton = document.getElementById('welcome-action');
const actionLabel = document.getElementById('welcome-action-label');

const ERROR_MESSAGES = {
  login_failed: 'Sign-in was canceled or denied.',
  missing_callback_params: 'The provider did not return the expected login response.',
  provider_config_unavailable: 'The app could not load the provider configuration.',
  server_error: 'The server could not finish the sign-in flow.',
};

function showErrorFromQuery() {
  const params = new URLSearchParams(window.location.search);
  const error = params.get('error');
  if (!error) {
    errorBanner.classList.add('hidden');
    return;
  }

  errorBanner.textContent = ERROR_MESSAGES[error] || 'Authentication failed.';
  errorBanner.classList.remove('hidden');
  window.history.replaceState({}, '', '/welcome');
}

function updateActionForAuthenticatedUser(user) {
  statusBanner.textContent = user?.name
    ? `You are already signed in as ${user.name}.`
    : 'You are already signed in.';
  actionButton.href = '/';
  actionLabel.textContent = 'Go to Profile';
}

async function syncWelcomeState() {
  try {
    const response = await fetch('/api/me', { credentials: 'same-origin' });
    if (!response.ok) {
      return;
    }

    const data = await response.json();
    if (data.authenticated) {
      updateActionForAuthenticatedUser(data.user);
    }
  } catch (error) {
    // Leave the logged-out state in place if the session check fails.
  }
}

showErrorFromQuery();
syncWelcomeState();
