import jwt from 'jsonwebtoken';

import {
  APP_BASE_URL,
  APP_JWT_SECRET,
  APP_TOKEN_COOKIE,
  APP_TOKEN_TTL_SECONDS,
  COOKIE_OPTIONS,
  OIDC_FLOW_COOKIE,
} from './config.js';

export function buildUserProfile(claims) {
  return {
    sub: claims.sub,
    email: claims.email || null,
    emailVerified: Boolean(claims.email_verified),
    name: claims.name || claims.email || 'OIDC User',
    picture: claims.picture || null,
  };
}

export function clearCookie(res, name) {
  res.clearCookie(name, { ...COOKIE_OPTIONS, path: '/' });
}

export function clearAuthCookies(res) {
  clearCookie(res, APP_TOKEN_COOKIE);
  clearCookie(res, OIDC_FLOW_COOKIE);
}

export function setUserSessionCookie(res, token) {
  res.cookie(APP_TOKEN_COOKIE, token, {
    ...COOKIE_OPTIONS,
    path: '/',
    maxAge: APP_TOKEN_TTL_SECONDS * 1000,
  });
}

export function issueUserSessionToken(user) {
  return jwt.sign(
    {
      iss: APP_BASE_URL,
      aud: 'my-test-app',
      sub: user.sub,
      email: user.email,
      email_verified: user.emailVerified,
      name: user.name,
      picture: user.picture,
    },
    APP_JWT_SECRET,
    {
      expiresIn: APP_TOKEN_TTL_SECONDS,
      algorithm: 'HS256',
    }
  );
}

export function readAuthenticatedUser(req) {
  const token = req.cookies[APP_TOKEN_COOKIE];
  if (!token) {
    return null;
  }

  const claims = jwt.verify(token, APP_JWT_SECRET, {
    algorithms: ['HS256'],
    issuer: APP_BASE_URL,
    audience: 'my-test-app',
  });

  return buildUserProfile({
    sub: claims.sub,
    email: claims.email,
    email_verified: claims.email_verified,
    name: claims.name,
    picture: claims.picture,
  });
}
