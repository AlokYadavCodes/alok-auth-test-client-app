import { clearAuthCookies, readAuthenticatedUser } from '../utils/user.utils.js';

export function getCurrentUser(req, res) {
  try {
    const user = readAuthenticatedUser(req);
    if (!user) {
      return res.status(401).json({ authenticated: false });
    }

    return res.json({
      authenticated: true,
      user,
    });
  } catch (error) {
    clearAuthCookies(res);
    return res.status(401).json({ authenticated: false });
  }
}

export function logoutUser(req, res) {
  clearAuthCookies(res);
  res.status(204).end();
}
