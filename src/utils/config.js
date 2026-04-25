import "dotenv/config";

export const PORT = process.env.PORT || 3000;
export const APP_BASE_URL = process.env.APP_BASE_URL
export const OIDC_ISSUER = process.env.OIDC_ISSUER
export const CLIENT_ID = process.env.CLIENT_ID
export const CLIENT_SECRET = process.env.CLIENT_SECRET
export const REDIRECT_URI = process.env.REDIRECT_URI
export const SCOPES = process.env.SCOPES || 'openid email profile offline_access';
export const APP_JWT_SECRET =
  process.env.APP_JWT_SECRET || 'REPLACE_WITH_A_LONG_RANDOM_SECRET';

export const APP_TOKEN_COOKIE = 'app_token';
export const OIDC_FLOW_COOKIE = 'oidc_flow';
export const APP_TOKEN_TTL_SECONDS = 60 * 60 * 8;
export const OIDC_FLOW_TTL_SECONDS = 60 * 10;

export const COOKIE_OPTIONS = {
  httpOnly: true,
  sameSite: 'lax',
  secure: process.env.NODE_ENV === 'production',
};
