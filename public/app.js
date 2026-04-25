const profileView = document.getElementById('profile-view');
const statusMessage = document.getElementById('status-message');
const logoutBtn = document.getElementById('logout-btn');
const errorBanner = document.getElementById('error-banner');

function showProfile(user) {
  profileView.classList.remove('hidden');
  statusMessage.textContent = 'Signed in';

  document.getElementById('user-avatar').src = user.picture || '';
  document.getElementById('user-avatar').alt = user.name ? `${user.name} avatar` : 'User avatar';
  document.getElementById('user-name').textContent = user.name;
  document.getElementById('user-email').textContent = user.email || 'No email returned';
  document.getElementById('user-sub').textContent = user.sub;
  document.getElementById('user-verified').textContent = user.emailVerified ? 'Verified' : 'Not verified';
}

async function init() {
  errorBanner.classList.add('hidden');

  try {
    const response = await fetch('/api/me', { credentials: 'same-origin' });
    if (!response.ok) {
      window.location.replace('/welcome');
      return;
    }

    const data = await response.json();
    if (!data.authenticated) {
      window.location.replace('/welcome');
      return;
    }

    showProfile(data.user);
  } catch (error) {
    window.location.replace('/welcome');
  }
}

logoutBtn.addEventListener('click', async () => {
  await fetch('/auth/logout', {
    method: 'POST',
    credentials: 'same-origin',
  });

  window.location.replace('/welcome');
});

init();
