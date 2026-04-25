import crypto from 'crypto';
import jwt from 'jsonwebtoken';

import {
  APP_BASE_URL,
  APP_JWT_SECRET,
  CLIENT_ID,
  CLIENT_SECRET,
  COOKIE_OPTIONS,
  OIDC_FLOW_COOKIE,
  OIDC_FLOW_TTL_SECONDS,
  OIDC_ISSUER,
  REDIRECT_URI,
  SCOPES,
} from './config.js';

let cachedDiscovery = { expiresAt: 0, config: null };
const cachedJwks = new Map();

function base64UrlDecode(input) {
  const normalized = input.replace(/-/g, '+').replace(/_/g, '/');
  const padding = normalized.length % 4 === 0 ? '' : '='.repeat(4 - (normalized.length % 4));
  return Buffer.from(normalized + padding, 'base64');
}

function decodeJwt(token) {
  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new Error('Malformed JWT');
  }

  const decoded = jwt.decode(token, { complete: true });
  if (!decoded?.header || !decoded?.payload) {
    throw new Error('Unable to decode JWT');
  }

  return {
    header: decoded.header,
    payload: decoded.payload,
    signature: parts[2],
    signingInput: `${parts[0]}.${parts[1]}`,
  };
}

function generateRandomString(bytes = 32) {
  return crypto.randomBytes(bytes).toString('base64url');
}

function createPkceChallenge(verifier) {
  return crypto.createHash('sha256').update(verifier).digest('base64url');
}

function getDiscoveryUrl(issuer) {
  const normalizedIssuer = issuer.endsWith('/') ? issuer.slice(0, -1) : issuer;
  return `${normalizedIssuer}/.well-known/openid-configuration`;
}

function getMaxAgeMilliseconds(response, fallbackSeconds = 3600) {
  const cacheControl = response.headers.get('cache-control') || '';
  const maxAgeMatch = cacheControl.match(/max-age=(\d+)/i);
  const maxAgeSeconds = maxAgeMatch ? Number(maxAgeMatch[1]) : fallbackSeconds;
  return maxAgeSeconds * 1000;
}

function matchesExpectedIssuer(tokenIssuer, expectedIssuer) {
  const normalizedTokenIssuer = String(tokenIssuer || '').replace(/\/$/, '');
  const normalizedExpectedIssuer = String(expectedIssuer || '').replace(/\/$/, '');
  return normalizedTokenIssuer === normalizedExpectedIssuer;
}

function matchesExpectedAudience(tokenAudience, expectedAudience) {
  if (Array.isArray(tokenAudience)) {
    return tokenAudience.includes(expectedAudience);
  }

  return tokenAudience === expectedAudience;
}

export async function getOidcDiscovery() {
  if (Date.now() < cachedDiscovery.expiresAt && cachedDiscovery.config) {
    return cachedDiscovery.config;
  }

  const response = await fetch(getDiscoveryUrl(OIDC_ISSUER));
  if (!response.ok) {
    throw new Error('Unable to fetch OIDC discovery document');
  }

  const body = await response.json();
  if (!body.authorization_endpoint || !body.token_endpoint || !body.jwks_uri) {
    throw new Error('OIDC discovery document is missing required endpoints');
  }

  cachedDiscovery = {
    config: body,
    expiresAt: Date.now() + getMaxAgeMilliseconds(response),
  };

  return body;
}

async function getSigningKeys(jwksUri) {
  const cached = cachedJwks.get(jwksUri);
  if (cached && Date.now() < cached.expiresAt && cached.keys.length > 0) {
    return cached.keys;
  }

  const response = await fetch(jwksUri);
  if (!response.ok) {
    throw new Error('Unable to fetch signing keys');
  }

  const body = await response.json();
  const keys = Array.isArray(body.keys) ? body.keys : [];

  cachedJwks.set(jwksUri, {
    keys,
    expiresAt: Date.now() + getMaxAgeMilliseconds(response),
  });

  return keys;
}

export function getOidcProviderLabel(discovery) {
  return new URL(discovery.issuer || OIDC_ISSUER).hostname;
}

export function createAuthorizationRedirectUrl(res, discovery) {
  const state = generateRandomString();
  const nonce = generateRandomString();
  const codeVerifier = generateRandomString(48);
  const codeChallenge = createPkceChallenge(codeVerifier);

  const flowToken = jwt.sign(
    { state, nonce, codeVerifier, iss: APP_BASE_URL, aud: 'oidc-flow' },
    APP_JWT_SECRET,
    {
      expiresIn: OIDC_FLOW_TTL_SECONDS,
      algorithm: 'HS256',
    }
  );

  res.cookie(OIDC_FLOW_COOKIE, flowToken, {
    ...COOKIE_OPTIONS,
    path: '/',
    maxAge: OIDC_FLOW_TTL_SECONDS * 1000,
  });

  const authorizeUrl = new URL(discovery.authorization_endpoint);
  authorizeUrl.searchParams.set('client_id', CLIENT_ID);
  authorizeUrl.searchParams.set('redirect_uri', REDIRECT_URI);
  authorizeUrl.searchParams.set('response_type', 'code');
  authorizeUrl.searchParams.set('scope', SCOPES);
  authorizeUrl.searchParams.set('state', state);
  authorizeUrl.searchParams.set('nonce', nonce);
  authorizeUrl.searchParams.set('code_challenge', codeChallenge);
  authorizeUrl.searchParams.set('code_challenge_method', 'S256');
  authorizeUrl.searchParams.set('prompt', 'select_account');

  return authorizeUrl.toString();
}

export function verifyOidcFlowCookie(flowToken) {
  return jwt.verify(flowToken, APP_JWT_SECRET, {
    algorithms: ['HS256'],
    issuer: APP_BASE_URL,
    audience: 'oidc-flow',
  });
}

export async function exchangeAuthorizationCode(code, codeVerifier, discovery) {
  const tokenResponse = await fetch(discovery.token_endpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Accept: 'application/json',
    },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      redirect_uri: REDIRECT_URI,
      code_verifier: codeVerifier,
    }).toString(),
  });

  const tokenPayload = await tokenResponse.json();
  if (!tokenResponse.ok || !tokenPayload.id_token) {
    console.error('OIDC token exchange failed:', {
      status: tokenResponse.status,
      error: tokenPayload.error,
      error_description: tokenPayload.error_description,
    });
    throw new Error(
      tokenPayload.error_description ||
        tokenPayload.error ||
        'Failed to exchange authorization code'
    );
  }

  return tokenPayload;
}

export async function verifyOidcIdToken(idToken, expectedNonce, discovery) {
  const { header, payload, signature, signingInput } = decodeJwt(idToken);

  if (header.alg !== 'RS256' || !header.kid) {
    throw new Error('Unexpected token header');
  }

  const keys = await getSigningKeys(discovery.jwks_uri);
  const matchingKey = keys.find((key) => key.kid === header.kid);
  if (!matchingKey) {
    throw new Error('No matching signing key');
  }

  const publicKey = crypto.createPublicKey({ key: matchingKey, format: 'jwk' });
  const isValidSignature = crypto.verify(
    'RSA-SHA256',
    Buffer.from(signingInput),
    publicKey,
    base64UrlDecode(signature)
  );

  if (!isValidSignature) {
    throw new Error('Invalid token signature');
  }

  const now = Math.floor(Date.now() / 1000);

  if (!matchesExpectedAudience(payload.aud, CLIENT_ID)) {
    throw new Error('Invalid token audience');
  }
  if (!matchesExpectedIssuer(payload.iss, discovery.issuer || OIDC_ISSUER)) {
    throw new Error('Invalid token issuer');
  }
  if (typeof payload.exp !== 'number' || payload.exp <= now) {
    throw new Error('ID token expired');
  }
  if (typeof payload.iat !== 'number' || payload.iat > now + 60) {
    throw new Error('Invalid issue time');
  }
  if (payload.nonce !== expectedNonce) {
    throw new Error('Invalid nonce');
  }
  if (!payload.sub) {
    throw new Error('Missing subject claim');
  }

  return payload;
}
